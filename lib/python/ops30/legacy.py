"""The pre-30ops layout of a collector, and a semantic comparison with it.

A legacy root is a directory that looks like / on an old collector (a
snapshot from scripts/fetch-legacy.sh, or tests/fixtures/legacy-root):
/opt/onprem-{metrics,logs,changes,agent-gate}, /etc/cron.d/onprem-*,
/etc/default/onprem-logs-allowlist and so on. compare() says whether the
files render made for a site do the same as those: the same targets and
labels, the same cron jobs with the same arguments, the same allowlist,
mount, receivers and gate targets. Paths of the old clones are mapped to
collector.root first; secrets are not compared (snapshots have them
masked). Every difference is a line of text; none means "same".
"""
import collections
import glob
import json
import os
import re

from . import yamlio

M = "opt/onprem-metrics"
FILES = {
    "prometheus": f"{M}/prometheus/prometheus.yml",
    "targets": f"{M}/prometheus/targets",
    "pve": f"{M}/prometheus/pve.yml",
    "snmp": f"{M}/prometheus/snmp-auth.yml",
    "alertmanager": f"{M}/alertmanager/alertmanager.yml",
    "datasources": f"{M}/grafana/provisioning/datasources",
    "cron": "etc/cron.d",
    "allowlist": "etc/default/onprem-logs-allowlist",
    "service": "etc/systemd/system/onprem-logs-allowlist.service",
    "units": "etc/systemd/system",
    "gate": "etc/onprem-agent-gate/config.json",
    "tools": "etc/onprem-agent-gate/tools.json",
}
CRON_FILES = ("onprem-metrics", "onprem-logs", "onprem-changes", "onprem-agent-gate")
# the two compose projects; the project name (and so the volume prefix) was
# the directory name
COMPOSE_FILES = (("onprem-metrics", f"{M}/docker-compose.yml"),
                 ("onprem-logs", "opt/onprem-logs/docker-compose.yml"))
# compose volume key -> collector.volumes key
VOLUME_KEYS = {"prometheus-data": "prometheus", "alertmanager-data": "alertmanager",
               "grafana-data": "grafana", "victorialogs-data": "victorialogs"}
# collector/compose.yml profile -> the service it starts
PROFILE_SERVICES = {"pve": "pve-exporter", "snmp": "snmp-exporter", "logs": "victorialogs"}
# file-level cron variables and the script that reads each; the variable
# belongs to that script's lines, wherever in the file it was set
FILE_ENV = {"AUDIT_QUIET_FROM": "audit-report.py", "FW_EXPECT": "fw-report.py", "AUP_EXPECT": "aup-report.py"}
GATE_CONFIG_DEFAULT = "/etc/onprem-agent-gate/config.json"
ENV_RE = re.compile(r'''^([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|\S*)(\s+|$)''')
SECRET_KEYS = ("password", "priv_password", "token_value", "smtp_auth_password", "smtp_auth_password_file")


def path_map(site):
    root, log = site["collector"]["root"], site["collector"]["log_dir"]
    return [
        ("/etc/onprem-agent-gate/config.json", "/etc/30ops/gate/config.json"),
        ("/etc/onprem-agent-gate/tools.json", "/etc/30ops/gate/tools.json"),
        ("/etc/default/onprem-logs-allowlist", "/etc/default/30ops-allowlist"),
        ("/opt/onprem-metrics/textfile/", f"{root}/collector/textfile/"),
        ("/opt/onprem-logs/", f"{root}/logs/"),
        ("/opt/onprem-agent-gate/", f"{root}/gate/"),
        ("/var/log/onprem-metrics/", f"{log}/"),
        ("/var/log/onprem-logs/", f"{log}/"),
    ]


def remap(v, pm):
    if isinstance(v, str):
        for a, b in pm:
            v = v.replace(a, b)
        return v
    if isinstance(v, list):
        return [remap(x, pm) for x in v]
    if isinstance(v, dict):
        return {k: remap(x, pm) for k, x in v.items()}
    return v


def unquote(v):
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v


# ---------- cron ----------

def parse_cron(text):
    """(entries, globals): entries are (schedule, user, env dict, command)."""
    entries, fenv, glob_env = [], {}, {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if m and " " not in m.group(1):
            k, v = m.group(1), unquote(m.group(2).strip())
            if k in FILE_ENV:
                fenv[k] = v
            else:
                glob_env[k] = v
            continue
        f = line.split(None, 6 if not line.startswith("@") else 2)
        if line.startswith("@"):
            sched, user, rest = f[0], f[1], f[2] if len(f) > 2 else ""
        else:
            sched, user, rest = " ".join(f[:5]), f[5], f[6] if len(f) > 6 else ""
        env = {}
        while True:
            m = ENV_RE.match(rest)
            if not m:
                break
            env[m.group(1)] = unquote(m.group(2))
            rest = rest[m.end():]
        for k, v in fenv.items():
            if FILE_ENV[k] in rest:
                env[k] = v
        entries.append((sched, user, env, " ".join(rest.split())))
    return entries, glob_env


def _norm_cmd(cmd):
    cmd = re.sub(r"--token-file \S+", "--token-file @secret", cmd)
    cmd = re.sub(r"--assets \S+", "--assets @assets", cmd)
    return cmd


def legacy_cron(text, site, pm):
    root = site["collector"]["root"]
    entries, g = parse_cron(text)
    out = []
    for sched, user, env, cmd in entries:
        cmd = re.sub(r"cd (\S+) && git pull -q --ff-only && \./scripts/changes-textfile\.py",
                      lambda m: (f"cd {m.group(1)} && git pull -q --ff-only && {root}/changes/scripts/changes-textfile.py "
                                 f"--dir {m.group(1)}/changes --drills {m.group(1)}/drills/drills.jsonl"), cmd)
        if "/onprem-agent-gate/bin/gatectl" in cmd and "GATE_CONFIG" not in env:
            env = {**env, "GATE_CONFIG": GATE_CONFIG_DEFAULT}
        out.append((sched, user, remap(env, pm), remap(cmd, pm)))
    return out, g


def _key(e):
    sched, user, env, cmd = e
    return (sched, user, tuple(sorted(env.items())), _norm_cmd(cmd))


def _fmt(k):
    sched, user, env, cmd = k
    e = " ".join(f"{a}={b}" for a, b in env)
    return f"{sched} {user} {e + ' ' if e else ''}{cmd}"


def cron_assets(text):
    m = re.search(r"--assets (\S+)", text)
    return m.group(1) if m else None


# ---------- small parsers ----------

def env_file(text):
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if m:
            out[m.group(1)] = unquote(m.group(2).strip())
    return out


def unit(text):
    out, sec = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            sec = line.strip("[]")
            continue
        k, _, v = line.partition("=")
        out[(sec, k.strip())] = v.strip()
    return out


def _mask(v):
    """Secrets are masked in snapshots and never rendered: compare that one
    is set, not its value. smtp_auth_password and its _file form are the same."""
    if isinstance(v, dict):
        return {k.removesuffix("_file") if k == "smtp_auth_password_file" else k:
                ("@secret" if k in SECRET_KEYS else _mask(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [_mask(x) for x in v]
    return v


def _flag(cmd, name):
    for c in cmd or []:
        if isinstance(c, str) and c.startswith(name + "="):
            return c.split("=", 1)[1]
    return None


def compose_settings(root):
    """What the old compose files say that site.yaml now carries: services,
    effective volume names, retention, the syslog time zone and the Grafana
    port. None when neither file is there."""
    out, found = {"services": [], "volumes": {}, "retention": {}}, False
    for project, rel in COMPOSE_FILES:
        try:
            with open(os.path.join(root, rel), encoding="utf-8") as f:
                doc = yamlio.loads(f.read(), rel) or {}
        except OSError:
            continue
        found = True
        vols = doc.get("volumes") or {}
        for name, svc in (doc.get("services") or {}).items():
            out["services"].append(name)
            for v in svc.get("volumes") or []:
                key = v.split(":", 1)[0] if isinstance(v, str) else None
                if key in VOLUME_KEYS:
                    out["volumes"][VOLUME_KEYS[key]] = (vols.get(key) or {}).get("name") or f"{project}_{key}"
            cmd = svc.get("command")
            if name == "prometheus" and _flag(cmd, "--storage.tsdb.retention.time"):
                out["retention"]["metrics"] = _flag(cmd, "--storage.tsdb.retention.time")
            if name == "victorialogs":
                for k, flag in (("logs", "-retentionPeriod"), ("logs_max_disk", "-retention.maxDiskSpaceUsageBytes")):
                    if _flag(cmd, flag):
                        out["retention"][k] = _flag(cmd, flag)
                if _flag(cmd, "-syslog.timezone"):
                    out["timezone"] = _flag(cmd, "-syslog.timezone")
            if name == "grafana":
                for p in svc.get("ports") or []:
                    parts = str(p).split(":")
                    if len(parts) >= 2 and parts[-1] == "3000":
                        out["grafana_port"] = int(parts[-2])
    if not found:
        return None
    out["services"] = sorted(out["services"])
    return out


def compose_env(text):
    env = {}
    for line in (text or "").splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return env


def rendered_compose_settings(text):
    """compose_settings() for a rendered compose.env and collector/compose.yml."""
    env = compose_env(text)
    profiles = [p for p in env.get("COMPOSE_PROFILES", "").split(",") if p]
    out = {"services": sorted(["prometheus", "alertmanager", "grafana"] + [PROFILE_SERVICES[p] for p in profiles]),
           "volumes": {k: env[f"OPS30_VOL_{k.upper()}"] for k in ("prometheus", "alertmanager", "grafana")},
           "retention": {"metrics": env["OPS30_RETENTION_METRICS"]},
           "grafana_port": int(env["OPS30_GRAFANA_PORT"])}
    if "logs" in profiles:
        out["volumes"]["victorialogs"] = env["OPS30_VOL_VICTORIALOGS"]
        out["retention"]["logs"] = env["OPS30_RETENTION_LOGS"]
        out["retention"]["logs_max_disk"] = env["OPS30_LOGS_MAX_DISK"]
        out["timezone"] = env["OPS30_TZ"]
    return out


def _diff(a, b, path=""):
    """Paths where two parsed documents differ, at most a few levels deep."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b), key=str):
            p = f"{path}.{k}" if path else str(k)
            if k not in a:
                out.append(f"{p}: only in render ({json.dumps(b[k], ensure_ascii=False)[:120]})")
            elif k not in b:
                out.append(f"{p}: only in legacy ({json.dumps(a[k], ensure_ascii=False)[:120]})")
            else:
                out += _diff(a[k], b[k], p)
        return out
    if a != b:
        return [f"{path}: legacy {json.dumps(a, ensure_ascii=False)[:160]} != render {json.dumps(b, ensure_ascii=False)[:160]}"]
    return []


def _targets_set(groups):
    s = set()
    for g in groups or []:
        labels = tuple(sorted((g.get("labels") or {}).items()))
        for t in g.get("targets") or []:
            s.add((t, labels))
    return s


# ---------- compare ----------

def compare(tree, legacy, site):
    """Differences between a rendered tree and a legacy root (list of str)."""
    pm = path_map(site)
    diffs = []

    def L(rel):
        return os.path.join(legacy, rel)

    def lread(rel):
        try:
            with open(L(rel), encoding="utf-8") as f:
                return f.read()
        except OSError:
            return None

    def R(path):
        o = tree.get(path)
        return o.text if o else None

    def ydoc(text, name):
        return yamlio.loads(text, name) if text is not None else None

    def pair(name, ltext, rtext, parse, fix=lambda x: x):
        if ltext is None and rtext is None:
            return
        if ltext is None:
            diffs.append(f"{name}: legacy has no such file")
            return
        if rtext is None:
            diffs.append(f"{name}: render does not write it")
            return
        diffs.extend(f"{name}: {d}" for d in _diff(fix(parse(ltext, f"legacy {name}")), parse(rtext, f"render {name}")))

    # prometheus.yml: the scrape jobs by name
    lp, rp = ydoc(lread(FILES["prometheus"]), "prometheus.yml"), ydoc(R("etc/30ops/prometheus/prometheus.yml"), "prometheus.yml")
    if lp is None:
        diffs.append("prometheus.yml: legacy has no such file")
    elif rp:
        for d in (lp, rp):
            d["scrape_configs"] = {j["job_name"]: j for j in d.get("scrape_configs") or []}
        diffs.extend(f"prometheus.yml: {d}" for d in _diff(lp, rp))
        files = sorted({f for j in rp["scrape_configs"].values() for c in j.get("file_sd_configs", [])
                        for f in c.get("files", [])} | {f for j in lp["scrape_configs"].values()
                                                         for c in j.get("file_sd_configs", []) for f in c.get("files", [])})
        for f in files:
            lt = ydoc(lread(f"{M}/prometheus/{f}"), f)
            rt = ydoc(R(f"etc/30ops/prometheus/{f}"), f)
            a, b = _targets_set(lt), _targets_set(rt)
            for t in sorted(a - b):
                diffs.append(f"{f}: {t[0]} {dict(t[1])} only in legacy")
            for t in sorted(b - a):
                diffs.append(f"{f}: {t[0]} {dict(t[1])} only in render")

    pair("pve.yml", lread(FILES["pve"]), R("etc/30ops/prometheus/pve.yml"), lambda t, n: _mask(ydoc(t, n)))
    pair("snmp-auth.yml", lread(FILES["snmp"]), R("etc/30ops/prometheus/snmp-auth.yml"), lambda t, n: _mask(ydoc(t, n)))
    pair("alertmanager.yml", lread(FILES["alertmanager"]), R("etc/30ops/alertmanager/alertmanager.yml"),
         lambda t, n: _mask(ydoc(t, n)))

    # Grafana datasources, by uid
    def ds(texts):
        out = {}
        for t in texts:
            for d in (ydoc(t, "datasource") or {}).get("datasources") or []:
                out[d.get("uid") or d.get("name")] = d
        return out
    ld = [open(p, encoding="utf-8").read() for p in sorted(glob.glob(L(FILES["datasources"]) + "/*.y*ml"))]
    rd = [o.text for p, o in tree.items() if p.startswith("etc/30ops/grafana/datasources/")]
    diffs.extend(f"datasources: {d}" for d in _diff(ds(ld), ds(rd)))

    # cron: every job, as a multiset
    lentries, lglob, ltext = [], {}, ""
    for n in CRON_FILES:
        t = lread(f"{FILES['cron']}/{n}")
        if t is None:
            diffs.append(f"cron: legacy has no /etc/cron.d/{n}")
            continue
        ltext += t
        e, g = legacy_cron(t, site, pm)
        lentries += e
        lglob.update(g)
    rtext = R("etc/cron.d/30ops") or ""
    rentries, rglob = parse_cron(rtext)
    a = collections.Counter(_key(e) for e in lentries)
    b = collections.Counter(_key(e) for e in rentries)
    for k in sorted(a - b):
        diffs.append(f"cron: only in legacy: {_fmt(k)}")
    for k in sorted(b - a):
        diffs.append(f"cron: only in render: {_fmt(k)}")
    diffs.extend(f"cron variables: {d}" for d in _diff(lglob, rglob))

    # assets.tsv rows (the file the legacy eol line names)
    la = cron_assets(ltext)
    if la and "etc/30ops/assets.tsv" in tree:
        from .site import read_assets
        import tempfile
        lt = lread(la.lstrip("/"))
        if lt is None:
            diffs.append(f"assets: legacy has no {la}")
        else:
            with tempfile.TemporaryDirectory() as d:
                for name, text in (("l", lt), ("r", R("etc/30ops/assets.tsv"))):
                    with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                        f.write(text)
                lr = read_assets(os.path.join(d, "l"))
                rr = read_assets(os.path.join(d, "r"))
            ls = {tuple(sorted(r.items())) for r in lr}
            rs = {tuple(sorted(r.items())) for r in rr}
            for r in sorted(ls - rs):
                diffs.append(f"assets: row only in legacy: {dict(r)['asset']}/{dict(r)['component']} {dict(r)['milestone']}")
            for r in sorted(rs - ls):
                diffs.append(f"assets: row only in render: {dict(r)['asset']}/{dict(r)['component']} {dict(r)['milestone']}")

    # allowlist
    lt, rt = lread(FILES["allowlist"]), R("etc/default/30ops-allowlist")
    if lt is not None or rt is not None:
        le, re_ = env_file(lt or ""), env_file(rt or "")
        for k in sorted(set(le) | set(re_)):
            x, y = set(le.get(k, "").split()), set(re_.get(k, "").split())
            if x != y:
                diffs.append(f"allowlist {k}: only in legacy {sorted(x - y)}, only in render {sorted(y - x)}")

    # units: the allowlist service and the WORM mount (by Where=)
    lt, rt = lread(FILES["service"]), R("etc/systemd/system/30ops-allowlist.service")
    if lt is not None or rt is not None:
        lu = {k: remap(v, pm) for k, v in unit(lt or "").items() if k[1] != "Description"}
        ru = {k: v for k, v in unit(rt or "").items() if k[1] != "Description"}
        diffs.extend(f"allowlist service: {d}" for d in _diff({f"{a}.{b}": v for (a, b), v in lu.items()},
                                                                {f"{a}.{b}": v for (a, b), v in ru.items()}))

    def mounts(items):
        out = {}
        for name, text in items:
            u = unit(text)
            out[u.get(("Mount", "Where"), name)] = {
                "unit": name, **{k: u.get(("Mount", k)) for k in ("What", "Type", "Options")}}
        return out
    lm = mounts((os.path.basename(p), open(p, encoding="utf-8").read())
                for p in sorted(glob.glob(L(FILES["units"]) + "/*.mount")))
    rm = mounts((os.path.basename(p), o.text) for p, o in tree.items()
                if p.startswith("etc/systemd/system/") and p.endswith(".mount"))
    diffs.extend(f"mount: {d}" for d in _diff(lm, rm))

    # gate
    def jload(t, n):
        try:
            return json.loads(t)
        except ValueError as e:
            raise ValueError(f"{n}: {e}") from None
    pair("gate config.json", lread(FILES["gate"]), R("etc/30ops/gate/config.json"), jload, lambda x: remap(x, pm))
    pair("gate tools.json", lread(FILES["tools"]), R("etc/30ops/gate/tools.json"), jload)

    # compose: the settings, not the files (the images and mounts are product)
    lc, renv = compose_settings(legacy), R("etc/30ops/compose.env")
    if lc is not None and renv is not None:
        diffs.extend(f"compose: {d}" for d in _diff(lc, rendered_compose_settings(renv)))
    elif lc is not None or renv is not None:
        diffs.append("compose: " + ("legacy has no compose files" if lc is None else "render does not write compose.env"))
    return diffs
