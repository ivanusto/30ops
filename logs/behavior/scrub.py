#!/usr/bin/env python3
"""scrub: the free-text half of the privacy step. pseudonymize.py keeps a closed
schema and drops everything else; this file is for the copy of a site's export
that keeps its log lines, so they have to be cleaned, not dropped.

    scrub.py dict   --key-file K --csv file.csv:col,col --wazuh-tar raw.tar.gz --out terms.jsonl
    scrub.py csv    --key-file K --terms terms.jsonl --level standard --in a.csv --out a.deid.csv.gz --policy wazuh --templates t.tsv
    scrub.py wazuh  --key-file K --terms terms.jsonl --level standard --in raw.tar.gz --out alerts.deid.jsonl.gz --which alerts --templates t.tsv
    scrub.py verify --terms terms.jsonl FILE...

The dictionary is built from the site's own structured columns (agent, computer,
VM and account names, and the domains they end in), and every occurrence in free
text gets the same pseudonym the events have. After it come the patterns: URL
queries, addresses, MAC, mail, UPN, DOMAIN\\user, home directories, credential
shaped pairs, Taiwanese ID and phone numbers, other domain names.

A pattern cannot know a person's name in a sentence or an employee number;
pii_audit.py measures how much of that is left. Nothing here claims zero, and a
pseudonymised log is personal data still: the key and the table bring it back.

Levels are pseudonymize.py's. minimal: dictionary and addresses. standard:
everything above, domains cut to the registered domain. strict: free text
columns and log lines are dropped, only the structure stays.

All counts, never values, go to the terminal. terms.jsonl holds real names and
belongs with the key.

Standard library only.
"""
import argparse, collections, csv, gzip, hashlib, json, os, re, sys, tarfile, time

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "lib", "python"))
from pseudonymize import KIND_PREFIX, LEVELS, Pseudonymizer, TWO_LEVEL_TLD  # noqa: E402

# words too common to treat as names, wherever a site's columns happen to use them
GENERIC = {"root", "admin", "administrator", "system", "user", "users", "test", "guest", "www", "www-data", "mail", "web", "server", "host", "localhost", "ubuntu",
           "debian", "centos", "windows", "linux", "nobody", "daemon", "backup", "ftp", "nginx", "apache", "mysql", "postgres", "unknown", "none", "null", "manager",
           "wazuh", "ossec", "sshd", "cron", "local", "default", "com", "net", "org", "tw", "lan", "internal", "corp", "gov", "edu", "support", "service", "sys", "bin", "pi", "git",
           # tools and daemons a reviewer or the model can take for a name
           "sudo", "systemd", "pam_unix", "kernel", "bash", "sh", "haproxy", "apache2", "docker", "pm2", "wazuh-agent", "grafana", "bitdefender", "cis", "ucf",
           # role accounts as common as admin or test
           "dev", "app", "prometheus"}
# a reviewed domain is a domain: dotted, with a TLD of letters
RE_DOMAIN = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,10}")
# the host field of a syslog header, after a BSD or an ISO timestamp
RE_SYSLOG_HOST = re.compile(r"^(<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(\s+)([^\s:\[]+)")
PUBLIC_SUFFIX = {"com", "net", "org", "info", "biz", "io", "gov", "edu", "tw", "local", "lan", "internal", "corp", "cn", "jp", "hk", "uk", "au", "de", "ru", "xyz", "top", "cc", "me", "co", "ai", "app", "dev"}

RE_URLQ = re.compile(r"([\w/.%~:-]*/[\w/.%~:-]*)\?[^\s\"'<>]*")
RE_EMAIL = re.compile(r"[\w.+%-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
RE_TOKEN = re.compile(r"[a-z]-[0-9a-f]{10}")     # what Pseudonymizer.name() writes: never a site term
RE_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
RE_IP4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# whole addresses or ones with "::"; three groups of digits is a time of day
RE_IP6 = re.compile(r"(?<![\w:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5})?|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})(?![\w:])")
RE_DOMUSER = re.compile(r"\b[A-Za-z][A-Za-z0-9_-]{1,30}\\{1,2}(?![A-Za-z]:)[A-Za-z0-9_.$-]{2,}")
RE_WINHOME = re.compile(r"(?i)((?:[a-z]:)?\\{1,2}users\\{1,2})[^\\\"'\s]+")
RE_UNIXHOME = re.compile(r"(/(?:home|Users)/)[^/\"'\s:]+")
RE_SECRET = re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|session(?:id)?|auth)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&;,]+)")
RE_AUTHHDR = re.compile(r"(?i)\b(authorization|set-cookie|cookie)(\s*[=:]\s*)[^\r\n\"]*")
RE_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9+/._=-]{8,}")
RE_TWID = re.compile(r"\b[A-Z][12]\d{8}\b")
RE_MOBILE = re.compile(r"(?<!\d)(?:\+?886[- ]?9|09)\d{2}[- ]?\d{3}[- ]?\d{3}(?!\d)")
RE_FQDN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:com|net|org|info|biz|io|gov|edu|tw|local|lan|internal|corp|cn|jp|hk|uk|au|de|ru|xyz|top|cc|me|co|ai|app|dev)\b", re.I)
RE_TOKEN = re.compile(r"\b(?:[uhsi]-[0-9a-f]{10})\b")
TEMPLATE = [(RE_TOKEN, "<id>"), (RE_IP4, "<ip>"), (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "<hex>"), (re.compile(r"\d+"), "<n>")]


def term_regex(names):
    """A name counts wherever it stands apart from letters and digits, so
    srv01-backup, srv01_db and backup.srv01 all give srv01 away. Longest first."""
    if not names:
        return None
    parts = []
    for n in sorted(names, key=len, reverse=True):
        parts.append(re.escape(n) if not n.isascii() else r"(?<![A-Za-z0-9])" + re.escape(n) + r"(?![A-Za-z0-9])")
    return re.compile("|".join(parts), re.I)


class Scrubber:
    def __init__(self, key, level, terms=()):
        self.p = Pseudonymizer(key, level)
        self.level = level
        self.hits = collections.Counter()
        self.map = {}
        self.keys = {}
        for t in terms:
            real = t["real"].lower()
            self.map[real] = self.p.name(t["kind"], real, KIND_PREFIX.get(t["kind"], "h"))
        self.re = term_regex(self.map)

    def _ip(self, m):
        s = m.group(0)
        if not all(int(x) < 256 for x in s.split(".")):
            return s
        self.hits["ip"] += 1
        return self.p.ip(s)

    def _fqdn(self, m):
        self.hits["domain"] += 1
        labels = m.group(0).lower().split(".")
        keep = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_TLD else 2
        cut = ".".join(labels[-keep:])
        return self.map.get(cut, cut)

    def _syslog_host(self, m):
        h = m.group(4)
        if RE_TOKEN.fullmatch(h.lower()) or h.startswith("<") or RE_IP4.fullmatch(h) or ":" in h:     # addresses are rewritten later, once
            return m.group(0)
        self.hits["syslog_host"] += 1
        return (m.group(1) or "") + m.group(2) + m.group(3) + self.host(h)

    def _term(self, m):
        self.hits["dictionary"] += 1
        return self.map[m.group(0).lower()]

    def _sub(self, name, rx, repl, s):
        s, n = rx.subn(repl, s)
        if n:
            self.hits[name] += n
        return s

    def text(self, s):
        if not s:
            return s
        s = str(s)
        s = self._sub("secret", RE_AUTHHDR, lambda m: m.group(1) + m.group(2) + "<secret>", s)
        s = self._sub("secret", RE_SECRET, lambda m: m.group(1) + m.group(2) + "<secret>", s)
        s = self._sub("secret", RE_BEARER, lambda m: m.group(1) + " <secret>", s)
        s = self._sub("url_query", RE_URLQ, lambda m: m.group(1) + "?<query>", s)
        s = self._sub("email", RE_EMAIL, "<email>", s)
        s = RE_SYSLOG_HOST.sub(self._syslog_host, s, count=1)
        if self.re:
            s = self.re.sub(self._term, s)
        s = self._sub("dom_user", RE_DOMUSER, "<domain_user>", s)
        s = self._sub("home", RE_WINHOME, lambda m: m.group(1) + "<user>", s)
        s = self._sub("home", RE_UNIXHOME, lambda m: m.group(1) + "<user>", s)
        s = self._sub("mac", RE_MAC, "<mac>", s)
        s = RE_IP4.sub(self._ip, s)
        s = self._sub("ip6", RE_IP6, "<ip6>", s)
        s = self._sub("tw_id", RE_TWID, "<tw_id>", s)
        s = self._sub("phone", RE_MOBILE, "<phone>", s)
        if self.level != "minimal":
            s = RE_FQDN.sub(self._fqdn, s)
        return s

    def key(self, k):
        """A field name can be an account's name too. Paths are matched on the
        original, so this only changes what is written."""
        if k not in self.keys:
            self.keys[k] = self.re.sub(self._term, k) if self.re else k
        return self.keys[k]

    def host(self, v):
        return self.map.get(str(v).lower()) or self.p.host_or_ip(str(v).lower()) if v else v

    def user(self, v):
        if not v:
            return v
        low = str(v).lower()
        return v if low in GENERIC else self.map.get(low) or self.p.name("user", low, "u")

    def ip(self, v):
        return self.p.ip(str(v).strip()) if v else v

    def when(self, v):
        if not v or self.level == "minimal":
            return v
        s = str(v)
        m = re.match(r"(\d{4}-\d\d-\d\dT\d\d)(:\d\d)(:\d\d(?:\.\d+)?)?(.*)", s)
        if not m:
            return s
        return m.group(1) + (":00:00" if self.level == "strict" else m.group(2) + ":00") + m.group(4)


# ------------------------------------------------------------------ policies
# column -> treatment; anything not named is free text at standard and gone at
# strict, so a column added by a later export fails safe.

KEEP = "keep"; HOST = "host"; USER = "user"; IP = "ip"; TIME = "time"; TEXT = "text"; DROP = "drop"
POLICIES = {
    "wazuh": {"timestamp": TIME, "agent_id": KEEP, "agent_name": HOST, "agent_ip": IP, "rule_id": KEEP, "rule_level": KEEP, "rule_groups": KEEP, "decoder": KEEP, "mitre_id": KEEP,
              "mitre_tactic": KEEP, "srcip": IP, "srcuser": USER, "dstuser": USER, "location": TEXT, "rule_description": TEXT, "full_log": TEXT},
    "wazuh_daily": {"date": KEEP, "agent_name": HOST, "agent_ip": IP, "rule_id": KEEP, "rule_level": KEEP, "rule_groups": KEEP, "rule_description": TEXT, "event_count": KEEP},
    "bitdefender": {"created_Or_timestamp": TIME, "last_updated": TIME, "module": KEEP, "incident_id": HOST, "incident_number": KEEP, "severity": KEEP, "severity_score": KEEP, "main_action": KEEP,
                    "attack_types": KEEP, "mitre_att_ck_ids": KEEP, "computer_name": HOST, "computer_fqdn": HOST, "computer_ip": IP, "username": USER, "process_path": TEXT, "parent_process_path": TEXT,
                    "process_command_line": TEXT, "endpoints_involved": TEXT, "detection_name": TEXT, "file_hash_sha256": KEEP},
    "vcenter": {"vm_name": HOST, "vm_id": HOST, "ip": IP, "datastore_name": HOST, "datastore_id": HOST, "datastore_type": KEEP, "ds_capacity_gb": KEEP, "ds_used_gb": KEEP, "ds_free_gb": KEEP,
                "power_state": KEEP, "cpus": KEEP, "ram_mb": KEEP, "vm_committed_gb": KEEP, "vm_uncommitted_gb": KEEP, "os": TEXT},
    "metrics": {"timestamp_utc": TIME, "metric_name": TEXT, "job": TEXT, "value": KEEP, "role": TEXT, "instance": TEXT, "hostname": HOST, "ip": IP, "device_or_item": TEXT, "labels_json": TEXT},
}
# JSON paths of a manager's alert or archive line
JSON_HOST = {"agent.name", "manager.name", "predecoder.hostname", "data.computer_name", "data.computer_fqdn", "data.dstname", "data.hostname", "data.nodes.id", "data.nodes.details.hardware_id"}
JSON_USER = {"data.srcuser", "data.dstuser", "syscheck.uname_after", "syscheck.uname_before", "data.username", "data.process.euser", "data.process.ruser", "data.process.suser", "data.process.fuser",
             "data.user.name", "data.user.id", "data.nodes.details.process.user.user_name", "data.nodes.details.process.user.user_sid"}
JSON_IP = {"agent.ip", "data.srcip", "data.dstip", "data.computer_ip", "data.source_ip", "data.nodes.details.ip", "data.nodes.details.ips"}
JSON_TIME = {"timestamp", "@timestamp", "data.nodes.details.process.execution_date"}
JSON_DROP = {"data.command", "data.pwd", "previous_output", "data.process.cmd", "data.process.argvs",
             "data.nodes.details.process.command_line", "data.process_command_line", "data.process_info_command_line", "data.command_line_parameters"}
# only the closed vocabulary of a feed; its titles, references and package names are text like any other
JSON_KEEP_PREFIX = ("rule.", "decoder.", "data.vulnerability.cve", "data.vulnerability.cvss.", "data.vulnerability.score.", "data.vulnerability.severity", "data.vulnerability.status",
                    "data.vulnerability.classification", "data.vulnerability.enumeration", "data.vulnerability.type", "data.vulnerability.published", "data.vulnerability.updated",
                    "data.vulnerability.scanner.reference", "data.vulnerability.package.architecture", "syscheck.mode", "syscheck.event", "syscheck.size_", "syscheck.perm_", "syscheck.changed_")
# public catalogue text: scrubbed, but sampling it for the audit only measures the feed
JSON_NO_SAMPLE = ("data.vulnerability.", "data.sca.")


class Templates:
    """distinct scrubbed lines reduced to a shape, with a count and one example"""
    def __init__(self, path, limit=2000000):
        self.path, self.limit, self.seen, self.dropped = path, limit, {}, 0

    def add(self, source, s):
        if not self.path or not s:
            return
        t = s[:400]
        for rx, rep in TEMPLATE:
            t = rx.sub(rep, t)
        k = hashlib.blake2b(t.encode("utf-8", "replace"), digest_size=8).digest()
        cur = self.seen.get(k)
        if cur:
            cur[0] += 1
        elif len(self.seen) < self.limit:
            self.seen[k] = [1, source, s[:400]]
        else:
            self.dropped += 1

    def write(self):
        if not self.path:
            return
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for n, source, ex in sorted(self.seen.values(), key=lambda x: -x[0]):
                f.write(json.dumps({"n": n, "source": source, "text": ex}, ensure_ascii=False) + "\n")


def load_key(path):
    with open(path, "rb") as f:
        k = f.read().strip()
    if len(k) < 32:
        sys.exit("scrub: key must be at least 32 bytes")
    return k


def load_terms(path):
    if not path:
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def private_gzip(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    raw = os.fdopen(fd, "wb")
    return gzip.open(raw, "wt", encoding="utf-8", compresslevel=6, newline="")


# ------------------------------------------------------------------ dictionary

def is_name(v):
    """A name has letters (10.1:443 is not one) and is not one of our own pseudonyms."""
    return bool(v) and v not in GENERIC and len(v) >= 3 and bool(re.search(r"[^\W\d_]", v)) and not RE_TOKEN.search(v)


def residual_names(span):
    """A span copied from scrubbed text can carry our pseudonyms (h-0123456789.portal).
    Only the pieces outside them can still be the site's; a person has to say which."""
    return [x for x in re.split(r"[\s.:/\\<>=,;'\"()\[\]{}|]+|-(?=>)|>", RE_TOKEN.sub(" ", span.strip().lower())) if is_name(x.strip("-_"))]


def add_term(out, kind, value):
    v = str(value or "").strip().lower()
    if not is_name(v):
        return
    out[v] = kind if out.get(v) != "user" else "user"
    if kind == "host" and "." in v:
        labels = v.split(".")
        if is_name(labels[0]):
            out.setdefault(labels[0], "host")
        keep = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_TLD else 2
        dom = ".".join(labels[-keep:])
        # a private zone's registered name is the organisation's name
        if len(labels) >= 2 and labels[-1] in PUBLIC_SUFFIX and is_name(labels[-keep]):
            out.setdefault(dom, "domain")
            out.setdefault(labels[-keep], "domain")


def extra_reject(kind, v):
    """Why a reviewed term is not taken, or None."""
    v = v.strip().lower()
    if kind not in KIND_PREFIX:
        return "kind"
    if kind == "domain" and not RE_DOMAIN.fullmatch(v):
        return "domain_shape"
    if not is_name(v):
        return "generic_or_no_letters"
    return None


def add_user(out, value):
    """An account as logged, DOMAIN\\name or name: the name is the term."""
    v = str(value or "").strip()
    add_term(out, "user", v.rsplit("\\", 1)[-1])


def cmd_dict(a):
    csv.field_size_limit(1 << 30)
    terms, n = {}, 0
    for spec in a.csv:
        path, cols = spec.rsplit(":", 1)
        kinds = [c.split("=") if "=" in c else (c, "host") for c in cols.split(",")]
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
            for r in csv.DictReader(f):
                n += 1
                for c, kind in kinds:
                    add_term(terms, kind, r.get(c))
    for t in a.wazuh_tar:
        import events
        for x in events.wazuh_tar_alerts(t):
            n += 1
            ag, d = x.get("agent") or {}, x.get("data") if isinstance(x.get("data"), dict) else {}
            add_term(terms, "host", ag.get("name"))
            add_term(terms, "host", (x.get("manager") or {}).get("name"))
            add_term(terms, "host", (x.get("predecoder") or {}).get("hostname"))
            for k in ("computer_name", "computer_fqdn"):
                add_term(terms, "host", d.get(k))
            for k in ("srcuser", "dstuser"):
                add_term(terms, "user", d.get(k))
            sc = x.get("syscheck") if isinstance(x.get("syscheck"), dict) else {}
            add_term(terms, "user", sc.get("uname_after"))
            u = d.get("user") if isinstance(d.get("user"), dict) else {}
            add_user(terms, u.get("name")); add_user(terms, d.get("username"))
            for node in d.get("nodes") if isinstance(d.get("nodes"), list) else ():
                if not isinstance(node, dict):
                    continue
                if node.get("type") in ("endpoint", "container_or_container_host"):
                    add_term(terms, "host", node.get("name"))
                det = node.get("details") if isinstance(node.get("details"), dict) else {}
                proc = det.get("process") if isinstance(det.get("process"), dict) else {}
                add_user(terms, (proc.get("user") or {}).get("user_name") if isinstance(proc.get("user"), dict) else None)
    rejected = collections.Counter()
    for path in a.extra:      # one term per line: <kind><TAB><value>, what the site knows and the logs do not say
        with open(path, encoding="utf-8") as f:
            for line in f:
                if "\t" in line:
                    kind, v = line.rstrip("\n").split("\t", 1)
                    why = extra_reject(kind, v)
                    if why:
                        rejected[why] += 1
                    else:
                        add_term(terms, kind, v)
    dropped = 0
    for spec in a.vocab:      # words of the product's own rule vocabulary: an account called the same is not a secret
        path, cols = spec.rsplit(":", 1)
        vocab = set()
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
            for r in csv.DictReader(f):
                for c in cols.split(","):
                    vocab.update(x.strip().lower() for x in re.split(r"[,|_\-\s]", r.get(c) or ""))
        for v in vocab:
            if terms.get(v) == "user":
                del terms[v]
                dropped += 1
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for v, kind in sorted(terms.items()):
            f.write(json.dumps({"kind": kind, "real": v}, ensure_ascii=False) + "\n")
    c = collections.Counter(terms.values())
    print(f"scrub dict: {n} rows read, {len(terms)} terms {dict(c)}, {dropped} dropped as rule vocabulary, extra rejected {dict(rejected)}")


# ------------------------------------------------------------------ csv

def cmd_csv(a):
    sc = Scrubber(load_key(a.key_file), a.level, load_terms(a.terms))
    policy = POLICIES[a.policy]
    tpl = Templates(a.templates)
    csv.field_size_limit(1 << 30)
    t0 = time.perf_counter(); n = 0
    unknown = collections.Counter()
    with open(a.inp, newline="", encoding="utf-8-sig", errors="replace") as fi, private_gzip(a.out) as fo:
        r = csv.DictReader(fi)
        w = None
        for row in r:
            out = {}
            for k, v in row.items():
                if k is None:
                    continue
                how = policy.get(k)
                if how is None:
                    unknown[k] += 1
                    how = TEXT
                if how == KEEP:
                    out[k] = v
                elif how == HOST:
                    out[k] = sc.host(v)
                elif how == USER:
                    out[k] = sc.user(v)
                elif how == IP:
                    out[k] = sc.ip(v)
                elif how == TIME:
                    out[k] = sc.when(v)
                elif how == TEXT:
                    if a.level == "strict":
                        continue
                    out[k] = sc.text(v)
                    if k in ("full_log", "rule_description", "process_command_line", "labels_json", "device_or_item"):
                        tpl.add(f"{a.policy}.{k}", out[k])
            if w is None:
                w = csv.DictWriter(fo, fieldnames=list(out))
                w.writeheader()
            w.writerow({k: out.get(k, "") for k in w.fieldnames})
            n += 1
    tpl.write()
    report(a, n, t0, sc, tpl, unknown)


# ------------------------------------------------------------------ wazuh json

_GONE = object()


def scrub_value(sc, path, v, tpl):
    """One JSON value by its path. A list holds what the path holds, objects
    included, so nothing in a line escapes by being one level further down."""
    if path in JSON_DROP:
        return _GONE
    if isinstance(v, dict):
        return scrub_json(sc, v, tpl, path)
    if isinstance(v, list):
        out = [x for x in (scrub_value(sc, path, y, tpl) for y in v) if x is not _GONE]
        return out if out or not v else _GONE
    if not isinstance(v, str):
        return v
    if path in JSON_HOST:
        return sc.host(v)
    if path in JSON_USER:
        return sc.user(v)
    if path in JSON_IP:
        return sc.ip(v)
    if path in JSON_TIME:
        return sc.when(v)
    if path.startswith(JSON_KEEP_PREFIX) and path != "rule.description":
        return v
    if sc.level == "strict":
        return _GONE
    t = sc.text(v)
    if not path.startswith(JSON_NO_SAMPLE):
        tpl.add(path, t)
    return t


def scrub_json(sc, obj, tpl, pre=""):
    out = {}
    for k, v in obj.items():
        path = f"{pre}.{k}" if pre else k
        x = scrub_value(sc, path, v, tpl)
        if x is not _GONE:
            out[sc.key(k)] = x
    return out


def cmd_wazuh(a):
    sc = Scrubber(load_key(a.key_file), a.level, load_terms(a.terms))
    tpl = Templates(a.templates, a.template_limit)
    rx = re.compile({"alerts": r"(^|/)logs/alerts/(alerts\.json|\d{4}/\w{3}/ossec-alerts-\d+\.json(\.gz)?)$",
                     "archives": r"(^|/)logs/archives/(archives\.json|\d{4}/\w{3}/ossec-archive-\d+\.json(\.gz)?)$"}[a.which])
    t0 = time.perf_counter(); n = bad = 0
    with tarfile.open(a.inp, "r|gz") as t, private_gzip(a.out) as fo:
        for m in t:
            if not (m.isfile() and rx.search(m.name)):
                continue
            raw = t.extractfile(m)
            fh = gzip.open(raw, "rt", encoding="utf-8", errors="replace") if m.name.endswith(".gz") else (x.decode("utf-8", "replace") for x in raw)
            for line in fh:
                try:
                    e = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                fo.write(json.dumps(scrub_json(sc, e, tpl), ensure_ascii=False, separators=(",", ":")) + "\n")
                n += 1
    tpl.write()
    report(a, n, t0, sc, tpl, {}, bad)


def report(a, n, t0, sc, tpl, unknown, bad=0):
    ms = (time.perf_counter() - t0) * 1000
    print(f"scrub {os.path.basename(a.out)}: {n} rows, level {a.level}, {ms / 1000:.0f} s ({ms / max(n, 1):.3f} ms/row), templates {len(tpl.seen)}, unparsed {bad}, "
          f"unknown columns {len(unknown)}, hits {dict(sc.hits)}")
    if a.timing:
        with open(a.timing, "a", encoding="utf-8") as f:
            f.write(json.dumps({"stage": "scrub", "file": os.path.basename(a.out), "level": a.level, "rows": n, "ms": round(ms, 1), "hits": dict(sc.hits), "templates": len(tpl.seen)}) + "\n")


# ------------------------------------------------------------------ verify

def verify_json_paths(path, rx, kinds):
    """Where in a JSON log the hits are: dotted path, kind, and term number. A
    name inside a key would show up here, so a key that hits prints as <key>."""
    if not rx:
        return
    order = {t: i for i, t in enumerate(sorted(kinds))}
    by, terms = collections.Counter(), collections.Counter()

    def walk(o, pre):
        if isinstance(o, dict):
            for k, v in o.items():
                for m in rx.finditer(k):
                    by[(f"{pre}.<key>" if pre else "<key>", kinds.get(m.group(0).lower(), "?"))] += 1
                    terms[(order.get(m.group(0).lower(), -1), "<key>")] += 1
                walk(v, f"{pre}.<key>" if rx.search(k) else (f"{pre}.{k}" if pre else k))
        elif isinstance(o, list):
            for v in o:
                walk(v, pre)
        elif isinstance(o, str):
            for m in rx.finditer(o):
                by[(pre, kinds.get(m.group(0).lower(), "?"))] += 1
                terms[(order.get(m.group(0).lower(), -1), pre)] += 1

    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if rx.search(line):
                walk(json.loads(line), "")
    for k, v in sorted(by.items(), key=lambda x: -x[1]):
        print(f"  {re.sub(r'[0-9]+', 'N', k[0])[:60]:60s} {k[1]:7s} {v}")
    for k, v in sorted(terms.items(), key=lambda x: -x[1])[:40]:
        print(f"  term#{k[0]:<4d} {re.sub(r'[0-9]+', 'N', k[1])[:60]:60s} {v}")


def cmd_verify(a):
    """How often each file still contains a dictionary term. Counts per file and
    per kind only; the terms themselves never go to the terminal."""
    terms = load_terms(a.terms)
    kinds = {t["real"]: t["kind"] for t in terms}
    rx = term_regex(kinds)
    total = 0
    for path in a.files:
        if a.by_column and ".csv" in path:
            by = collections.Counter()
            csv.field_size_limit(1 << 30)
            with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as f:
                for row in csv.DictReader(f):
                    for col, v in row.items():
                        if rx and v:
                            for m in rx.finditer(v):
                                by[(col, kinds.get(m.group(0).lower(), "?"), "gap" if len(m.group(0)) < 5 else "long")] += 1
            for k, v in sorted(by.items()):
                print(f"  {k[0]:20s} {k[1]:7s} {k[2]:5s} {v}")
        if a.by_column and ".jsonl" in path:
            verify_json_paths(path, rx, kinds)
        c, lines = collections.Counter(), 0
        op = gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.endswith(".gz") else open(path, encoding="utf-8", errors="replace")
        with op as f:
            for line in f:
                lines += 1
                if rx:
                    for m in rx.finditer(line):
                        c[kinds.get(m.group(0).lower(), "?")] += 1
        print(f"verify {os.path.basename(path)}: {lines} lines, {sum(c.values())} dictionary hits {dict(c)}")
        total += sum(c.values())
    sys.exit(1 if total else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("dict")
    d.add_argument("--csv", action="append", default=[], help="file.csv:col,col=user,col=host")
    d.add_argument("--vocab", action="append", default=[], help="file.csv:col,col words that are the product's, not the site's")
    d.add_argument("--wazuh-tar", action="append", default=[]); d.add_argument("--extra", action="append", default=[]); d.add_argument("--out", required=True)
    for name in ("csv", "wazuh"):
        p = sub.add_parser(name)
        p.add_argument("--key-file", required=True); p.add_argument("--terms"); p.add_argument("--level", choices=LEVELS, default="standard")
        p.add_argument("--in", dest="inp", required=True); p.add_argument("--out", required=True); p.add_argument("--templates"); p.add_argument("--timing")
        if name == "csv":
            p.add_argument("--policy", choices=sorted(POLICIES), required=True)
        else:
            p.add_argument("--which", choices=("alerts", "archives"), default="alerts")
            p.add_argument("--template-limit", type=int, default=2000000, help="distinct shapes kept in memory; the rest are counted, not sampled")
    v = sub.add_parser("verify")
    v.add_argument("--terms", required=True); v.add_argument("--by-column", action="store_true"); v.add_argument("files", nargs="+")
    a = ap.parse_args()
    {"dict": cmd_dict, "csv": cmd_csv, "wazuh": cmd_wazuh, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    main()
