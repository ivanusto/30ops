"""site.yaml version 1: load, validate, fill defaults.

validate(doc, base) returns (errors, warnings), two lists of strings that
start with the path of the offending field (`hosts[3].vendor ...`). Every
problem is collected; nothing stops at the first one. resolve(doc, base)
returns the same document with every default filled in, which is what
render reads. The field reference is docs/site-yaml.md.
"""
import importlib.util
import ipaddress
import os
import re
import zoneinfo

from . import plugins, yamlio
from .adapters import registry, schema

VERSION = 1
LOCALES = ("zh-TW", "en")
VENDORS = ("linux", "pve", "qnap", "fortigate", "generic-snmp")
ROLES = ("collector", "node", "journal", "pcap", "hypervisor", "qdevice", "nas", "syslog",
         "firewall", "audit-source", "webfilter", "admin", "switch", "ap", "deadman")
# A Linux or PVE host in one of these roles ships its journal to the
# collector unless it says journal: false (resolve() adds the role). The
# collector is left out: it is where the journals go.
JOURNAL_BY_DEFAULT = {"node", "qdevice", "hypervisor", "deadman"}
JOURNAL_VENDORS = ("linux", "pve")
# roles that need a vendor, because something on the collector talks to the host
MANAGED = {"collector", "node", "journal", "pcap", "hypervisor", "qdevice", "nas", "firewall", "switch", "ap",
           "deadman"}
PLUGINS = plugins.available()   # plugins/*/plugin.yaml
SNMP_AUTH = ("MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512")
SNMP_PRIV = ("DES", "AES", "AES192", "AES256", "AES192C", "AES256C")
SNMP_LEVEL = ("noAuthNoPriv", "authNoPriv", "authPriv")
RECEIVERS = ("ops-critical", "ops-warning", "ops-digest")   # the route tree in alertmanager.base.yml
DRILL_SOURCES = ("pve", "nas", "cloud", "logs")
VOLUMES = ("prometheus", "alertmanager", "grafana", "victorialogs")
VOLUME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]+$")
# a duration both Prometheus and VictoriaLogs read the same way
RETENTION_RE = re.compile(r"^[1-9][0-9]*[hdwy]$")
SIZE_RE = re.compile(r"^[1-9][0-9]*([KMGT]i?B)?$")
# keys whose value is a secret: in site.yaml they name an entry of credentials
SECRET_KEYS = {"password", "priv_password", "token", "passphrase", "secret", "key", "healthchecks"}
# alerting.deadman: the port 30ops-deadman listens on and how long a silence
# it allows (Alertmanager pushes the Watchdog every one to two minutes)
DEADMAN_PORT = 9095
DEADMAN_AFTER_S = 300
DEADMAN_MIN_AFTER_S = 180

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
LABEL_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

DEFAULTS = {
    "collector": {
        "root": "/opt/30ops",
        "user": "metrics",
        "textfile_dir": "/var/lib/node_exporter/textfile",
        "log_dir": "/var/log/30ops",
        "reports_dir": "/srv/reports",
        "eol_cache": "/var/lib/onprem-metrics/eol",
        "victorialogs": "http://127.0.0.1:9428",
        # docker volumes of the compose project, always external: compose
        # never creates an empty one in place of a missing one. A collector
        # that moves from the pre-30ops stacks names its old volumes here.
        "volumes": {"prometheus": "30ops_prometheus-data", "alertmanager": "30ops_alertmanager-data",
                    "grafana": "30ops_grafana-data", "victorialogs": "30ops_victorialogs-data"},
        "retention": {"metrics": "90d", "logs": "90d", "logs_max_disk": "12GiB"},
        "grafana_port": 3000,
        # the drills.jsonl each drill writes; the paths the drills used before
        # 30ops, so a cutover does not move history
        "drills": {
            "pve": "/srv/drills/pve-backup-drill/drills.jsonl",
            "nas": "/srv/drills/nas-backup-drill/drills.jsonl",
            "cloud": "/srv/drills/cloud-offload-drill/drills.jsonl",
            "logs": "/srv/drills/onprem-logs/drills.jsonl",
        },
    },
    "worm": {"options": "rw,hard,timeo=600,retrans=2,noatime,nofail,vers=4.1,noexec,nosuid,nodev"},
    "changes": {"clone": "/var/lib/30ops/changes", "state_dir": "/var/lib/onprem-changes"},
    "gate": {"principal": "agent:ops", "home": "/var/lib/onprem-agent-gate", "approval_ttl_s": 600,
             "approvers": ["implementer", "approver"], "targets": []},
}


class SiteError(ValueError):
    pass


def load(path):
    try:
        doc = yamlio.load(path)
    except OSError as e:
        raise SiteError(f"{path}: {e.strerror}") from None
    except yamlio.YamlError as e:
        raise SiteError(str(e)) from None
    if not isinstance(doc, dict):
        raise SiteError(f"{path}: the top level must be a mapping")
    return doc


# ---------- schema ----------
# A field spec is a type name, a tuple ("list", item) / ("map", value), an
# enum tuple ("enum", values) or a dict {key: (spec, required)}.

S, I, B, N = "str", "int", "bool", "num"


def _f(spec, req=False):
    return (spec, req)


HOST = {
    "name": _f(S, True), "address": _f(S, True), "also": _f(("list", S)),
    "vendor": _f(("enum", VENDORS)), "roles": _f(("list", ("enum", ROLES)), True),
    "labels": _f(("map", S)), "plugins": _f(("list", ("enum", PLUGINS))),
    "ssh": _f({"user": _f(S, True)}),
    "snmp": _f({"auth": _f(S, True)}),
    "pve": _f({"cluster": _f(S, True)}),
    "api": _f({"url": _f(S, True), "token": _f(S, True), "insecure": _f(B)}),
    "syslog": _f({"devname": _f(S, True)}),
    "pcap": _f({"user": _f(S), "iface": _f(S)}),
    "journal": _f(B),
    "ups": _f(("enum", ("none",))),
    "note": _f(S),
}

SCHEMA = {
    "version": _f(I, True),
    "site": _f({"id": _f(S, True), "name": _f(S), "timezone": _f(S, True),
                "locale": _f(("enum", LOCALES))}, True),
    "collector": _f({"host": _f(S, True), "root": _f(S), "user": _f(S),
                     "textfile_dir": _f(S), "log_dir": _f(S), "reports_dir": _f(S), "eol_cache": _f(S),
                     "victorialogs": _f(S),
                     "volumes": _f({k: _f(S) for k in VOLUMES}),
                     "retention": _f({"metrics": _f(S), "logs": _f(S), "logs_max_disk": _f(S)}),
                     "grafana_port": _f(I),
                     "drills": _f({k: _f(S) for k in DRILL_SOURCES})}, True),
    "credentials": _f(("map", {"file": _f(S, True), "note": _f(S)})),
    "hosts": _f(("list", HOST), True),
    "pve": _f({"exporter": _f({"user": _f(S, True), "token_name": _f(S, True), "token": _f(S, True),
                               "verify_ssl": _f(B)})}),
    "snmp": _f({"auths": _f(("map", {"username": _f(S, True), "security_level": _f(("enum", SNMP_LEVEL)),
                                      "auth_protocol": _f(("enum", SNMP_AUTH)), "password": _f(S),
                                      "priv_protocol": _f(("enum", SNMP_PRIV)), "priv_password": _f(S)}))}),
    "worm": _f({"host": _f(S, True), "export": _f(S, True), "mount": _f(S, True), "options": _f(S)}),
    "logs": _f({"archive": _f({"skip": _f(("list", S))}),
                "admin_from": _f(("list", S)),
                "pcap": _f({"key": _f(S, True), "peer": _f(S)})}),
    "alerting": _f({"smtp": _f({"smarthost": _f(S, True), "from": _f(S, True), "username": _f(S),
                                "password": _f(S), "require_tls": _f(B)}),
                    "receivers": _f(("map", {"email": _f(("list", S)), "webhook": _f(("list", S)),
                                             "send_resolved": _f(B)}), True),
                    "thresholds": _f(("map", N)),
                    "deadman": _f({"host": _f(S), "port": _f(I), "after_s": _f(I),
                                   "email": _f(("list", S)), "webhook": _f(("list", S)),
                                   "healthchecks": _f(S)})}),
    "changes": _f({"clone": _f(S), "state_dir": _f(S), "remote": _f(S)}),
    "gate": _f({"principal": _f(S), "home": _f(S), "approval_ttl_s": _f(I),
                "approvers": _f(("list", S)),
                "targets": _f(("list", {"asset": _f(S, True), "ssh": _f(S, True)}))}),
    "assets": _f(S),
    "cost": _f(S),
    "readiness": _f({"accept": _f(("map", S)), "answers": _f(("map", S))}),
}


def _type_ok(spec, v):
    if spec == S:
        return isinstance(v, str)
    if spec == I:
        return isinstance(v, int) and not isinstance(v, bool)
    if spec == B:
        return isinstance(v, bool)
    if spec == N:
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    raise AssertionError(spec)


def _check(spec, v, path, errs):
    if isinstance(spec, dict):
        if not isinstance(v, dict):
            errs.append(f"{path} must be a mapping")
            return
        for k in v:
            if k not in spec:
                errs.append(f"{path}.{k}: unknown key" if path else f"{k}: unknown key")
        for k, (sub, req) in spec.items():
            p = f"{path}.{k}" if path else k
            if k not in v or v[k] is None:
                if req:
                    errs.append(f"{p} is required")
                continue
            _check(sub, v[k], p, errs)
        return
    if isinstance(spec, tuple):
        kind, inner = spec
        if kind == "enum":
            if v not in inner:
                errs.append(f"{path} must be one of {', '.join(inner)} (got {v!r})")
        elif kind == "list":
            if not isinstance(v, list):
                errs.append(f"{path} must be a list")
                return
            for i, x in enumerate(v):
                _check(inner, x, f"{path}[{i}]", errs)
        elif kind == "map":
            if not isinstance(v, dict):
                errs.append(f"{path} must be a mapping")
                return
            for k, x in v.items():
                if not isinstance(k, str):
                    errs.append(f"{path}: key {k!r} must be a string")
                    continue
                _check(inner, x, f"{path}.{k}", errs)
        return
    if not _type_ok(spec, v):
        want = {S: "a string", I: "an integer", B: "true or false", N: "a number"}[spec]
        errs.append(f"{path} must be {want} (got {type(v).__name__})")


# ---------- cross checks ----------

def _secrets(v, path, creds, errs):
    """Every secret-named key must name a credentials entry."""
    if isinstance(v, dict):
        for k, x in v.items():
            p = f"{path}.{k}" if path else str(k)
            if k in SECRET_KEYS and path != "credentials" and isinstance(x, str):
                if x not in creds:
                    errs.append(f"{p} must name an entry in credentials (plain-text secrets are not allowed)")
            elif path != "credentials" and k != "labels":
                _secrets(x, p, creds, errs)
    elif isinstance(v, list):
        for i, x in enumerate(v):
            _secrets(x, f"{path}[{i}]", creds, errs)


def _address_ok(a):
    try:
        ipaddress.ip_address(a)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(a))


def _load_script(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))


THRESHOLDS = os.path.join(REPO, "collector", "prometheus", "thresholds.yml")
# pairs that must stay in order: (lower, higher)
THRESHOLD_ORDER = (("nas_pool_warn_pct", "nas_pool_crit_pct"), ("eol_crit_days", "eol_warn_days"),
                   ("nas_login_failures_warn", "nas_login_failures_crit"))


def threshold_catalogue():
    """key -> {default, unit, alerts, help}: collector/prometheus/thresholds.yml,
    then every plugin's thresholds.yml. A site may set a plugin's keys
    whether or not a host lists the plugin; render only uses them when one does."""
    cat = dict(yamlio.load(THRESHOLDS))
    for name in plugins.available():
        f = plugins.threshold_file(name)
        if f:
            cat.update(yamlio.load(f) or {})
    return cat


def threshold_order():
    """Pairs (lower, higher) that must stay in order, the plugins' included."""
    return THRESHOLD_ORDER + tuple(p for n in plugins.available() for p in plugins.threshold_order(n))


def thresholds(site):
    """Every threshold key -> the site's value or the default."""
    vals = {k: v["default"] for k, v in threshold_catalogue().items()}
    vals.update((site.get("alerting") or {}).get("thresholds") or {})
    return vals


def read_assets(path):
    """The rows of an assets.tsv, parsed exactly as eol-textfile.py does."""
    mod = _load_script(os.path.join(REPO, "collector", "textfile", "eol-textfile.py"), "_ops30_eol")
    try:
        return mod.read_assets(path)
    except SystemExit as e:
        raise SiteError(str(e)) from None


def _cross(doc, base, secrets, errs, warns):
    creds = doc.get("credentials") or {}
    hosts = [h for h in doc.get("hosts") or [] if isinstance(h, dict)]
    by_name = {}
    seen_addr = {}
    for i, h in enumerate(hosts):
        p = f"hosts[{i}]"
        name = h.get("name")
        if isinstance(name, str):
            if not NAME_RE.match(name):
                errs.append(f"{p}.name {name!r} must be lower case letters, digits and -")
            if name in by_name:
                errs.append(f"{p}.name {name!r} is used twice")
            by_name[name] = h
        for j, a in enumerate([h.get("address")] + list(h.get("also") or [])):
            if not isinstance(a, str):
                continue
            ap = f"{p}.address" if j == 0 else f"{p}.also[{j - 1}]"
            if not _address_ok(a):
                errs.append(f"{ap} {a!r} is not an IP address or host name")
            if a in seen_addr:
                errs.append(f"{ap} {a!r} is also the address of {seen_addr[a]}")
            seen_addr[a] = name
        roles = set(h.get("roles") or []) if isinstance(h.get("roles"), list) else set()
        vendor = h.get("vendor")
        if roles & MANAGED and not vendor:
            errs.append(f"{p}.vendor is required for roles {', '.join(sorted(roles & MANAGED))}")
        if vendor in VENDORS:
            for r in sorted(roles):
                if schema.kind_of_role(r) and not registry.for_role(vendor, r):
                    have = sorted(v for k, v in registry.available() if k == schema.kind_of_role(r))
                    errs.append(f"{p}: no adapter serves role {r} for vendor {vendor} "
                                f"(adapters/{schema.kind_of_role(r)}/ has {', '.join(have)})")
        for k, v in (h.get("labels") or {}).items() if isinstance(h.get("labels"), dict) else ():
            if not LABEL_RE.match(str(k)):
                errs.append(f"{p}.labels.{k} is not a valid Prometheus label name")
        if "nas" in roles and not h.get("snmp"):
            warns.append(f"{p}: a nas without snmp is not scraped")
        if "nas" in roles and not h.get("ssh"):
            warns.append(f"{p}: a nas without ssh gets no nas.prom (nas-textfile.sh)")
        if roles & {"switch", "ap"} and not h.get("snmp"):
            warns.append(f"{p}: a switch or ap without snmp is not scraped")
        if "hypervisor" in roles and not h.get("pve"):
            warns.append(f"{p}: a hypervisor without pve.cluster is left out of the quorum check")
        if "hypervisor" in roles and h.get("pve") and not h.get("ssh"):
            errs.append(f"{p}.ssh is required for the quorum check (pve.cluster is set)")
        if roles & {"webfilter", "audit-source"} and not h.get("syslog"):
            errs.append(f"{p}.syslog.devname is required for roles webfilter and audit-source")
        for j, pl in enumerate(h.get("plugins") or []) if isinstance(h.get("plugins"), list) else ():
            if pl in PLUGINS and (why := plugins.fits(pl, h)):
                errs.append(f"{p}.plugins[{j}]: {why}")
        if h.get("ups") and "nas" not in roles:
            errs.append(f"{p}.ups is for a host with role nas")
        if h.get("journal") is False and "journal" in roles:
            errs.append(f"{p}: journal: false and role journal contradict each other")
        if isinstance(h.get("snmp"), dict):
            auths = ((doc.get("snmp") or {}).get("auths") or {})
            if h["snmp"].get("auth") not in auths:
                errs.append(f"{p}.snmp.auth {h['snmp'].get('auth')!r} is not in snmp.auths")

    def ref(path, n, role=None):
        if n not in by_name:
            errs.append(f"{path} {n!r} is not a host name")
        elif role and role not in (by_name[n].get("roles") or []):
            errs.append(f"{path} {n!r} does not have role {role}")

    col = (doc.get("collector") or {}).get("host")
    if isinstance(col, str):
        ref("collector.host", col, "collector")
    ncol = sum(1 for h in hosts if "collector" in (h.get("roles") or []))
    if ncol != 1:
        errs.append(f"hosts: exactly one host must have role collector (found {ncol})")

    _secrets({k: v for k, v in doc.items() if k != "credentials"}, "", creds, errs)
    for n, c in creds.items() if isinstance(creds, dict) else ():
        f = c.get("file") if isinstance(c, dict) else None
        if not isinstance(f, str):
            continue
        if not os.path.isabs(f):
            errs.append(f"credentials.{n}.file must be an absolute path")
        elif secrets:
            try:
                st = os.stat(f)
            except OSError:
                errs.append(f"credentials.{n}.file {f} does not exist")
                continue
            if st.st_mode & 0o077:
                errs.append(f"credentials.{n}.file {f} is mode {st.st_mode & 0o777:o}, must be 0600 or 0400")
    used = set()

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                if k in SECRET_KEYS and isinstance(x, str):
                    used.add(x)
                elif k != "credentials":
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    walk({k: v for k, v in doc.items() if k != "credentials"})
    for n in sorted(set(creds) - used) if isinstance(creds, dict) else ():
        warns.append(f"credentials.{n} is not used")

    tz = (doc.get("site") or {}).get("timezone")
    if isinstance(tz, str):
        try:
            zoneinfo.ZoneInfo(tz)
        except (zoneinfo.ZoneInfoNotFoundError, ValueError):
            errs.append(f"site.timezone {tz!r} is not in the zoneinfo database")
    sid = (doc.get("site") or {}).get("id")
    if isinstance(sid, str) and not NAME_RE.match(sid):
        errs.append(f"site.id {sid!r} must be lower case letters, digits and -")

    col = doc.get("collector") or {}
    for k in ("root", "textfile_dir", "log_dir", "reports_dir", "eol_cache"):
        v = col.get(k)
        if isinstance(v, str) and not os.path.isabs(v):
            errs.append(f"collector.{k} must be an absolute path")
    vols = col.get("volumes") if isinstance(col.get("volumes"), dict) else {}
    for k, v in vols.items():
        if isinstance(v, str) and not VOLUME_RE.match(v):
            errs.append(f"collector.volumes.{k} {v!r} is not a docker volume name")
    names = [v for v in vols.values() if isinstance(v, str)]
    for v in sorted({v for v in names if names.count(v) > 1}):
        errs.append(f"collector.volumes: {v} is used twice")
    ret = col.get("retention") if isinstance(col.get("retention"), dict) else {}
    for k in ("metrics", "logs"):
        if isinstance(ret.get(k), str) and not RETENTION_RE.match(ret[k]):
            errs.append(f"collector.retention.{k} {ret[k]!r} must be a number and h, d, w or y (90d)")
    if isinstance(ret.get("logs_max_disk"), str) and not SIZE_RE.match(ret["logs_max_disk"]):
        errs.append(f"collector.retention.logs_max_disk {ret['logs_max_disk']!r} must be bytes or KiB, MiB, GiB, TiB (12GiB)")
    gp = col.get("grafana_port")
    if isinstance(gp, int) and not isinstance(gp, bool) and not 0 < gp < 65536:
        errs.append(f"collector.grafana_port {gp} is not a port")

    worm = doc.get("worm")
    if isinstance(worm, dict):
        if isinstance(worm.get("host"), str):
            ref("worm.host", worm["host"])
        m = worm.get("mount")
        if isinstance(m, str) and (not os.path.isabs(m) or m == "/"):
            errs.append("worm.mount must be an absolute path below /")
    logs = doc.get("logs") or {}
    if isinstance(logs, dict):
        for i, n in enumerate(logs.get("admin_from") or []):
            ref(f"logs.admin_from[{i}]", n)
        pc = logs.get("pcap") or {}
        if isinstance(pc, dict) and isinstance(pc.get("peer"), str):
            ref("logs.pcap.peer", pc["peer"])
    if any("pcap" in (h.get("roles") or []) for h in hosts) and not (logs.get("pcap") if isinstance(logs, dict) else None):
        errs.append("logs.pcap is required when a host has role pcap")
    if any("hypervisor" in (h.get("roles") or []) for h in hosts) and not (doc.get("pve") or {}).get("exporter"):
        warns.append("pve.exporter is not set: the pve job gets no exporter config")
    if (logs.get("archive") if isinstance(logs, dict) else None) and not worm:
        errs.append("logs.archive needs worm")

    al = doc.get("alerting") or {}
    rec = al.get("receivers") if isinstance(al, dict) else None
    if isinstance(rec, dict):
        for r in RECEIVERS:
            if r not in rec:
                errs.append(f"alerting.receivers.{r} is required (the route tree sends to it)")
        for r, v in rec.items():
            if r == "deadman":
                errs.append("alerting.receivers.deadman is reserved: set alerting.deadman instead")
                continue
            if r not in RECEIVERS:
                warns.append(f"alerting.receivers.{r}: no route sends to it")
            if isinstance(v, dict) and not (v.get("email") or v.get("webhook")):
                warns.append(f"alerting.receivers.{r} has no email and no webhook: its alerts go nowhere")
        if any(isinstance(v, dict) and v.get("email") for v in rec.values()) and not al.get("smtp"):
            errs.append("alerting.smtp is required when a receiver has email")
    dm = al.get("deadman") if isinstance(al, dict) else None
    deadmen = [h.get("name") for h in hosts if "deadman" in (h.get("roles") or [])]
    if isinstance(dm, dict):
        if not dm.get("host") and not dm.get("healthchecks"):
            errs.append("alerting.deadman needs a host (30ops-deadman) or healthchecks (an external check URL), or both")
        if isinstance(dm.get("host"), str):
            ref("alerting.deadman.host", dm["host"], "deadman")
            if dm["host"] in by_name and "collector" in (by_name[dm["host"]].get("roles") or []):
                errs.append("alerting.deadman.host must not be the collector: it watches the collector from outside")
        a = dm.get("after_s")
        if isinstance(a, int) and not isinstance(a, bool) and a < DEADMAN_MIN_AFTER_S:
            errs.append(f"alerting.deadman.after_s must be at least {DEADMAN_MIN_AFTER_S} "
                        "(the Watchdog is pushed every one to two minutes)")
        pt = dm.get("port")
        if isinstance(pt, int) and not isinstance(pt, bool) and not 1024 <= pt < 65536:
            errs.append(f"alerting.deadman.port {pt} must be 1024 to 65535 (30ops-deadman runs unprivileged)")
        if dm.get("email") and not al.get("smtp"):
            errs.append("alerting.smtp is required when alerting.deadman has email")
    for n in deadmen:
        if not (isinstance(dm, dict) and dm.get("host") == n):
            warns.append(f"host {n} has role deadman but alerting.deadman.host does not name it")
    th = al.get("thresholds") if isinstance(al, dict) else None
    if isinstance(th, dict):
        cat = threshold_catalogue()
        for k, v in th.items():
            if k not in cat:
                errs.append(f"alerting.thresholds.{k} is not a threshold (see collector/prometheus/thresholds.yml)")
            elif _type_ok(N, v) and v <= 0:
                errs.append(f"alerting.thresholds.{k} must be above 0")
        vals = {k: v["default"] for k, v in cat.items()}
        vals.update((k, v) for k, v in th.items() if _type_ok(N, v))
        for lo, hi in threshold_order():
            if (lo in th or hi in th) and not vals[lo] < vals[hi]:
                errs.append(f"alerting.thresholds: {lo} ({vals[lo]}) must be below {hi} ({vals[hi]})")

    for i, t in enumerate((doc.get("gate") or {}).get("targets") or []):
        if isinstance(t, dict) and isinstance(t.get("asset"), str) and "/" not in t["asset"]:
            errs.append(f"gate.targets[{i}].asset must be asset/component")

    from . import readiness
    readiness.validate_site(doc, errs, warns)

    _files(doc, base, errs, warns)


def _files(doc, base, errs, warns):
    a = doc.get("assets")
    rows = None
    if isinstance(a, str):
        p = os.path.join(base, a)
        if not os.path.isfile(p):
            errs.append(f"assets {a!r}: no such file next to site.yaml")
        else:
            try:
                rows = read_assets(p)
            except SiteError as e:
                errs.append(f"assets: {e}")
    if rows is not None:
        have = {(r["asset"], r["component"]) for r in rows}
        for i, t in enumerate((doc.get("gate") or {}).get("targets") or []):
            if isinstance(t, dict) and isinstance(t.get("asset"), str) and "/" in t["asset"]:
                if tuple(t["asset"].split("/", 1)) not in have:
                    errs.append(f"gate.targets[{i}].asset {t['asset']!r} is not a row of {a}")
        tools = os.path.join(REPO, "gate", "tools.json")
        try:
            import json
            with open(tools, encoding="utf-8") as f:
                names = sorted({t.get("asset") for t in json.load(f) if isinstance(t, dict) and t.get("asset")})
        except (OSError, ValueError):
            names = []
        for n in names:
            if "/" in n and tuple(n.split("/", 1)) not in have:
                warns.append(f"gate/tools.json asset {n!r} is not a row of {a}: the gate refuses those tools")
    c = doc.get("cost")
    if isinstance(c, str):
        p = os.path.join(base, c)
        if not os.path.isfile(p):
            errs.append(f"cost {c!r}: no such file next to site.yaml")
        else:
            try:
                cost = _load_script(os.path.join(REPO, "inventory", "cost.py"), "_ops30_cost")
                for e in cost.validate(yamlio.load(p) or {}):
                    errs.append(f"cost: {e}")
            except (yamlio.YamlError, OSError) as e:
                errs.append(f"cost: {e}")


def validate(doc, base=".", strict=False, secrets=False):
    """strict turns warnings into errors; secrets also checks that every
    credentials file exists with no group or other access (on the collector)."""
    errs, warns = [], []
    if not isinstance(doc, dict):
        return ["the top level must be a mapping"], []
    _check(SCHEMA, doc, "", errs)
    if isinstance(doc.get("version"), int) and doc["version"] != VERSION:
        errs.append(f"version must be {VERSION}")
    _cross(doc, base, secrets, errs, warns)
    if strict:
        errs += [f"{w} (--strict)" for w in warns]
        warns = []
    return errs, warns


# ---------- defaults ----------

def _merge(d, defaults):
    out = dict(defaults)
    for k, v in (d or {}).items():
        out[k] = _merge(v, defaults[k]) if isinstance(v, dict) and isinstance(defaults.get(k), dict) else v
    return out


def resolve(doc, base="."):
    """A copy of a valid doc with every default filled in."""
    r = dict(doc)
    r["site"] = {"locale": "zh-TW", "name": "", **doc["site"]}
    for k in ("collector", "worm", "changes", "gate"):
        if k == "worm" and not doc.get("worm"):
            r["worm"] = None
            continue
        r[k] = _merge(doc.get(k) or {}, DEFAULTS[k])
    r["credentials"] = doc.get("credentials") or {}
    hosts = []
    for h in doc["hosts"]:
        h = {"also": [], "labels": {}, "plugins": [], "vendor": None, **h}
        h["roles"] = list(h["roles"])
        if (h["vendor"] in JOURNAL_VENDORS and set(h["roles"]) & JOURNAL_BY_DEFAULT
                and "journal" not in h["roles"] and h.get("journal") is not False):
            h["roles"].append("journal")
            h["journal_default"] = True
        if "pcap" in h["roles"]:
            h["pcap"] = {"user": "pcap", **(h.get("pcap") or {})}
        hosts.append(h)
    r["hosts"] = hosts
    r["logs"] = doc.get("logs") or {}
    r["readiness"] = doc.get("readiness") or {}
    r["alerting"] = dict(doc.get("alerting") or {})
    if r["alerting"].get("deadman"):
        dm = {"port": DEADMAN_PORT, "after_s": DEADMAN_AFTER_S, **r["alerting"]["deadman"]}
        crit = (r["alerting"].get("receivers") or {}).get("ops-critical") or {}
        dm.setdefault("email", list(crit.get("email") or []))
        dm.setdefault("webhook", list(crit.get("webhook") or []))
        r["alerting"]["deadman"] = dm
    r["base"] = os.path.abspath(base)
    return r


def host(site, name):
    for h in site["hosts"]:
        if h["name"] == name:
            return h
    raise KeyError(name)


def with_role(site, role):
    return [h for h in site["hosts"] if role in h["roles"]]


def deadman_host(site):
    """The host alerting.deadman.host names, or None."""
    n = (site["alerting"].get("deadman") or {}).get("host")
    return host(site, n) if n else None


def secret_file(site, name):
    return site["credentials"][name]["file"]
