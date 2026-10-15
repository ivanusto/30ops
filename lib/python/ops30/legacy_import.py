"""import-legacy: draft a site.yaml from a legacy root (see legacy.py).

Everything the old files say about the site is read back: targets and
their labels, the cron arguments (NAS and PVE logins, the FortiGate API,
drills paths, capture nodes, admin workstations, the archive skip list),
the allowlist, the WORM mount, the receivers and the gate targets. What
the old files cannot say (the timezone when /etc/timezone is missing, which
of two addresses is the same device, a host's vendor when nothing scrapes
it) becomes a TODO line at the top of the draft. Secret values are never
read; credentials point at /etc/30ops/secrets/<name>, to be filled from
the old files by hand.
"""
import ipaddress
import os
import re
from urllib.parse import urlparse

from . import legacy as L, plugins, site as S, yamlio

SECRETS = "/etc/30ops/secrets"


class Draft:
    def __init__(self):
        self.hosts = []          # in the order they were found
        self.todo = []

    def find(self, address):
        for h in self.hosts:
            if address == h["address"] or address in h.get("also", []):
                return h
        return None

    def named(self, name):
        return next((h for h in self.hosts if h["name"] == name), None)

    def host(self, address, name=None):
        h = self.find(address)
        if h is None:
            h = {"name": name or self._auto(address), "address": address, "roles": []}
            self.hosts.append(h)
        elif name and h["name"].startswith("host-") and not self.named(name):
            h["name"] = name
        return h

    def _auto(self, address):
        try:
            tail = str(ipaddress.ip_address(address)).replace(":", ".").split(".")[-1]
        except ValueError:
            tail = re.sub(r"[^a-z0-9-]", "-", address.lower().split(".")[0])
        n, i = f"host-{tail}", 2
        while self.named(n):
            n, i = f"host-{tail}-{i}", i + 1
        return n


def role(h, r):
    if r not in h["roles"]:
        h["roles"].append(r)


def _read(root, rel):
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def _addr(hostport):
    return hostport.rsplit(":", 1)[0] if hostport.count(":") == 1 else hostport


def draft(root):
    """(site.yaml document, TODO list, path of the legacy assets.tsv or None)."""
    d = Draft()
    doc = {"version": 1}
    creds = {}
    collector = {}

    prom = yamlio.loads(_read(root, L.FILES["prometheus"]) or "{}", "prometheus.yml") or {}
    sid = ((prom.get("global") or {}).get("external_labels") or {}).get("site")
    tz = (_read(root, "etc/timezone") or "").strip()
    if not sid:
        d.todo.append("site.id: prometheus.yml has no external_labels.site")
    if not tz:
        d.todo.append("site.timezone: the snapshot has no etc/timezone")
    doc["site"] = {"id": sid or "site", "timezone": tz or "UTC", "locale": "zh-TW"}

    # targets: the job decides vendor and role
    jobs = {j.get("job_name"): j for j in prom.get("scrape_configs") or []}

    def tgroups(job):
        j = jobs.get(job) or {}
        files = [f for c in j.get("file_sd_configs", []) for f in c.get("files", [])]
        for f in files:
            for g in yamlio.loads(_read(root, f"{L.M}/prometheus/{f}") or "[]", f) or []:
                for t in g.get("targets") or []:
                    yield _addr(t), dict(g.get("labels") or {})

    for a, labels in tgroups("collector-host"):
        h = d.host(a, "collector")
        h.update(vendor="linux", labels=labels)
        role(h, "collector")
    for name in plugins.available():
        sc = plugins.scrape(name)
        for a, labels in tgroups(sc["job"]) if sc else ():
            h = d.host(a)
            h.update(vendor="linux", labels=labels, plugins=sorted(set(h.get("plugins") or []) | {name}))
            role(h, "node")
    for a, labels in tgroups("node"):
        h = d.host(a)
        h.update(vendor="linux", labels=labels)
        role(h, "node")
    for a, labels in tgroups("pve"):
        h = d.host(a)
        h.update(vendor="pve", labels=labels)
        role(h, "hypervisor")
    nas_auth = ((jobs.get("nas-snmp") or {}).get("params") or {}).get("auth", [None])[0]
    for a, labels in tgroups("nas-snmp"):
        auth = labels.pop("__param_auth", nas_auth)
        h = d.host(a, f"nas-{labels['nas']}" if "nas" in labels else None)
        h.update(vendor="qnap", labels=labels, snmp={"auth": auth})
        role(h, "nas")

    # cron
    text = "".join(_read(root, f"{L.FILES['cron']}/{n}") or "" for n in L.CRON_FILES)
    entries, glob_env = L.parse_cron(text)
    if glob_env:
        d.todo.append(f"cron variables {', '.join(sorted(glob_env))} are not carried over")
    fenv = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
        if m and m.group(1) in L.FILE_ENV:
            fenv[m.group(1)] = L.unquote(m.group(2).strip())
    clone = None
    for _sched, _user, env, cmd in entries:
        argv = cmd.split()
        prog = os.path.basename(argv[0]) if argv else ""
        m = re.search(r"--out (\S+)/(drills|nas|eol|changes|audit)\.prom", cmd) or re.search(r"(\S+)/\.nas\.tmp", cmd)
        if m and m.group(1) != S.DEFAULTS["collector"]["textfile_dir"]:
            collector["textfile_dir"] = m.group(1)
        if prog == "nas-textfile.sh":
            for arg in argv[1:]:
                if arg in (">", "&&") or arg.startswith(">"):
                    break
                label, _, login = arg.partition("=")
                user, _, a = login.rpartition("@")
                h = d.host(a, f"nas-{label}")
                h.setdefault("vendor", "qnap")
                h.setdefault("labels", {}).setdefault("nas", label)
                h["ssh"] = {"user": user}
                role(h, "nas")
        elif prog == "pve-quorum-textfile.sh":
            for arg in argv[1:]:
                if arg.startswith(">") or arg == "&&":
                    break
                cluster, _, logins = arg.partition("=")
                for login in logins.split(","):
                    user, _, a = login.rpartition("@")
                    h = d.host(a)
                    h.setdefault("vendor", "pve")
                    h["ssh"] = {"user": user}
                    h["pve"] = {"cluster": cluster}
                    role(h, "hypervisor")
        elif prog == "drills-textfile.py":
            drills = {}
            for arg in argv[1:]:
                k, eq, v = arg.partition("=")
                if eq and k in S.DRILL_SOURCES:
                    drills[k] = v
                elif eq and k == "changes":
                    clone = v.removesuffix("/drills/drills.jsonl")
            drills = {k: v for k, v in drills.items() if S.DEFAULTS["collector"]["drills"][k] != v}
            if drills:
                collector["drills"] = drills
        elif prog == "eol-textfile.py":
            opt = dict(re.findall(r"--(fortigate|token-file|fortigate-asset|cache) (\S+)", cmd))
            if opt.get("cache") and opt["cache"] != S.DEFAULTS["collector"]["eol_cache"]:
                collector["eol_cache"] = opt["cache"]
            if opt.get("fortigate"):
                u = urlparse(opt["fortigate"])
                h = d.host(u.hostname, opt.get("fortigate-asset", "fgt-edge"))
                h.update(vendor="fortigate")
                role(h, "firewall")
                h["api"] = {"url": opt["fortigate"], "token": "fortigate-api"}
                if "--insecure" in argv:
                    h["api"]["insecure"] = True
                creds["fortigate-api"] = {"file": f"{SECRETS}/fortigate-api.token"}
                d.todo.append(f"credentials.fortigate-api: copy the token from {opt.get('token-file', '?')}")
        elif prog == "archive-day.sh":
            if env.get("ARCHIVE"):
                doc.setdefault("worm", {})["mount"] = os.path.dirname(env["ARCHIVE"].rstrip("/"))
            doc.setdefault("logs", {})["archive"] = {"skip": env.get("ARCHIVE_SKIP", "").split()} \
                if env.get("ARCHIVE_SKIP") else {}
            if env.get("VL") and env["VL"] != S.DEFAULTS["collector"]["victorialogs"]:
                collector["victorialogs"] = env["VL"]
        elif prog == "pcap-pull.sh":
            for node in env.get("PCAP_NODES", "").split():
                name, _, src = node.partition("=")
                user, _, a = src.rstrip("/").rstrip(":").rpartition("@")
                h = d.host(a, name)
                role(h, "pcap")
                if user != "pcap":
                    h["pcap"] = {"user": user}
            if env.get("SSH_KEY"):
                creds["pcap-pull"] = {"file": env["SSH_KEY"]}
                doc.setdefault("logs", {})["pcap"] = {"key": "pcap-pull"}
        elif "changes-textfile.py" in cmd:
            m = re.match(r"cd (\S+) &&", cmd)
            clone = clone or (m.group(1) if m else None)
        if prog in ("fw-report.py", "aup-report.py", "audit-report.py"):
            m = re.search(r"--out (\S+)/(fw|aup|audit)-", cmd)
            if m and m.group(1) != S.DEFAULTS["collector"]["reports_dir"]:
                collector["reports_dir"] = m.group(1)

    for item in fenv.get("FW_EXPECT", "").split():
        src, _, dev = item.partition(":")
        fw = [h for h in d.hosts if h.get("vendor") == src]
        if len(fw) == 1:
            fw[0]["syslog"] = {"devname": dev}
        else:
            d.todo.append(f"FW_EXPECT {item}: no single {src} host to give syslog.devname {dev}")
    for dev in fenv.get("AUP_EXPECT", "").split():
        h = next((h for h in d.hosts if (h.get("syslog") or {}).get("devname") == dev), None)
        if h is None:
            fw = [h for h in d.hosts if "firewall" in h["roles"]]
            h = fw[0] if len(fw) == 1 else None
            if h:
                h["syslog"] = {"devname": dev}
        if h:
            role(h, "webfilter")
        else:
            d.todo.append(f"AUP_EXPECT {dev}: no firewall host found")
    k = 0
    for a in fenv.get("AUDIT_QUIET_FROM", "").split():
        h = d.find(a)
        if h is None:
            k += 1
            h = d.host(a, f"admin{k}")
        role(h, "admin")

    # allowlist
    al = L.env_file(_read(root, L.FILES["allowlist"]) or "")
    for a in al.get("JOURNALD_FROM", "").split():
        role(d.host(a), "journal")
    for a in al.get("SYSLOG_FROM", "").split():
        h = d.host(a)
        role(h, "syslog")
        if h["name"].startswith("host-"):
            d.todo.append(f"hosts {h['name']} ({a}) only sends syslog: if it is a second address of "
                          "another host, move it to that host's also: list")
    for a in al.get("AUDIT_FROM", "").split():
        role(d.host(a), "audit-source")
    admin_from = [d.host(a)["name"] for a in al.get("ADMIN_FROM", "").split()]
    if admin_from:
        doc.setdefault("logs", {})["admin_from"] = admin_from

    # WORM mount
    for name in sorted(os.listdir(os.path.join(root, L.FILES["units"]))) if os.path.isdir(os.path.join(root, L.FILES["units"])) else []:
        if not name.endswith(".mount"):
            continue
        u = L.unit(_read(root, f"{L.FILES['units']}/{name}") or "")
        what, where = u.get(("Mount", "What"), ""), u.get(("Mount", "Where"))
        if ":" in what and where == (doc.get("worm") or {}).get("mount", where):
            a, _, export = what.partition(":")
            h = d.find(a) or d.host(a)
            w = doc.setdefault("worm", {})
            w.update(host=h["name"], export=export, mount=where)
            opts = u.get(("Mount", "Options"))
            if opts and opts != S.DEFAULTS["worm"]["options"]:
                w["options"] = opts

    # pve exporter, snmp auths
    pve = (yamlio.loads(_read(root, L.FILES["pve"]) or "{}", "pve.yml") or {}).get("default")
    if pve:
        doc["pve"] = {"exporter": {"user": pve.get("user"), "token_name": pve.get("token_name"),
                                   "token": "pve-exporter", "verify_ssl": bool(pve.get("verify_ssl", False))}}
        creds["pve-exporter"] = {"file": f"{SECRETS}/pve-exporter.token"}
        d.todo.append(f"credentials.pve-exporter: copy token_value from /{L.FILES['pve']}")
    auths = (yamlio.loads(_read(root, L.FILES["snmp"]) or "{}", "snmp-auth.yml") or {}).get("auths") or {}
    if auths:
        out = {}
        for name, a in auths.items():
            n = name.replace("_", "-")
            x = {"username": a.get("username")}
            if a.get("security_level", "authPriv") != "authPriv":
                x["security_level"] = a["security_level"]
            for k, sk in (("auth_protocol", None), ("password", "auth"), ("priv_protocol", None), ("priv_password", "priv")):
                if a.get(k) is None:
                    continue
                if sk:
                    creds[f"snmp-{n}-{sk}"] = {"file": f"{SECRETS}/snmp-{n}-{sk}.pass"}
                    x[k] = f"snmp-{n}-{sk}"
                else:
                    x[k] = a[k]
            out[name] = x
        doc["snmp"] = {"auths": out}
        d.todo.append(f"credentials.snmp-*: copy the passphrases from /{L.FILES['snmp']}")

    # alertmanager
    am = yamlio.loads(_read(root, L.FILES["alertmanager"]) or "{}", "alertmanager.yml") or {}
    g = am.get("global") or {}
    alerting = {}
    if g.get("smtp_smarthost"):
        smtp = {"smarthost": g["smtp_smarthost"], "from": g.get("smtp_from", "")}
        if g.get("smtp_auth_username"):
            smtp["username"] = g["smtp_auth_username"]
        if g.get("smtp_auth_password") or g.get("smtp_auth_password_file"):
            smtp["password"] = "smtp"
            creds["smtp"] = {"file": g.get("smtp_auth_password_file") or f"{SECRETS}/smtp.pass"}
            if not g.get("smtp_auth_password_file"):
                d.todo.append("credentials.smtp: copy smtp_auth_password from alertmanager.yml")
        if g.get("smtp_require_tls") is False:
            smtp["require_tls"] = False
        alerting["smtp"] = smtp
    recv = {}
    for r in am.get("receivers") or []:
        x = {}
        cfgs = (r.get("email_configs") or []) + (r.get("webhook_configs") or [])
        if r.get("email_configs"):
            x["email"] = [c["to"] for c in r["email_configs"]]
        if r.get("webhook_configs"):
            x["webhook"] = [c["url"] for c in r["webhook_configs"]]
        if cfgs and not any(c.get("send_resolved", True) for c in cfgs):
            x["send_resolved"] = False
        recv[r["name"]] = x
    alerting["receivers"] = recv

    # changes and gate
    gate_cfg = _read(root, L.FILES["gate"])
    changes = {}
    if clone:
        changes["clone"] = clone
    gate = {}
    if gate_cfg:
        import json
        gc = json.loads(gate_cfg)
        if gc.get("state_dir") and gc["state_dir"] != S.DEFAULTS["changes"]["state_dir"]:
            changes["state_dir"] = gc["state_dir"]
        for k in ("principal", "approval_ttl_s", "approvers"):
            if k in gc and gc[k] != S.DEFAULTS["gate"][k]:
                gate[k] = gc[k]
        home = os.path.dirname(gc.get("audit", ""))
        if home and home != S.DEFAULTS["gate"]["home"]:
            gate["home"] = home
        gate["targets"] = [{"asset": a, "ssh": s} for a, s in (gc.get("targets") or {}).items()]

    # assemble, in the order of docs/site-yaml.md
    for h in d.hosts:
        if h["roles"] and set(h["roles"]) & S.MANAGED and not h.get("vendor"):
            h["vendor"] = "linux"
            d.todo.append(f"hosts {h['name']}: vendor guessed as linux")
    col = next((h["name"] for h in d.hosts if "collector" in h["roles"]), None)
    if not col:
        d.todo.append("collector.host: no collector-host target found")
    cs = L.compose_settings(root)
    if cs:
        dc = S.DEFAULTS["collector"]
        vols = {k: v for k, v in cs["volumes"].items() if v != dc["volumes"][k]}
        if vols:
            collector["volumes"] = vols
        ret = {k: v for k, v in cs["retention"].items() if v != dc["retention"][k]}
        if ret:
            collector["retention"] = ret
        if cs.get("grafana_port", dc["grafana_port"]) != dc["grafana_port"]:
            collector["grafana_port"] = cs["grafana_port"]
        tz = doc.get("site", {}).get("timezone")
        if cs.get("timezone") and tz and cs["timezone"] != tz:
            d.todo.append(f"site.timezone: the host is {tz} but VictoriaLogs reads syslog as {cs['timezone']}; "
                          "30ops uses site.timezone for both")
    doc["collector"] = {"host": col or "collector", **collector}
    if creds:
        doc["credentials"] = dict(sorted(creds.items()))
    keys = ("name", "address", "also", "vendor", "roles", "plugins", "labels", "ssh", "snmp", "pve",
            "api", "syslog", "pcap")
    doc["hosts"] = [{k: h[k] for k in keys if h.get(k) not in (None, [], {})} for h in d.hosts]
    for k in ("pve", "snmp", "worm", "logs"):
        if k in doc:
            doc[k] = doc.pop(k)
    if "worm" in doc:
        if "host" not in doc["worm"]:
            d.todo.append("worm: the archive cron names a mount but no .mount unit matches it")
        doc["worm"] = {k: doc["worm"][k] for k in ("host", "export", "mount", "options") if k in doc["worm"]}
    doc["alerting"] = alerting
    if changes:
        doc["changes"] = changes
    if gate:
        doc["gate"] = gate
    la = L.cron_assets(text)
    if la:
        doc["assets"] = "assets.tsv"
    d.todo.append("cost: not part of the old collector; add cost.yaml by hand if wanted")
    if (doc.get("logs") or {}).get("pcap") is not None and "peer" not in doc["logs"]["pcap"]:
        d.todo.append("logs.pcap.peer: the NAS the nodes' nfs and syslog capture profiles should point at")
    return doc, d.todo, la.lstrip("/") if la else None


def dumps(doc, todo, source):
    head = [f"# Drafted by 30ops import-legacy from {source}.",
            "# Check every line, fill the credentials files, then run 30ops validate",
            "# and 30ops render --compare-legacy against the same snapshot."]
    if todo:
        head.append("# TODO:")
        head += [f"#   {t}" for t in todo]
    return "\n".join(head) + "\n" + yamlio.dumps(doc)
