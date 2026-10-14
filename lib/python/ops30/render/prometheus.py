"""prometheus.yml, targets/*.yml, pve.yml and snmp-auth.yml.

prometheus.yml is the repo's collector/prometheus/prometheus.yml (the job
definitions are product, not site) with three changes: the site label, the
jobs that have no target dropped, and the victorialogs job from
logs/collector/prometheus-scrape.yml added when the site collects logs.
"""
import textwrap

from .. import site as S, yamlio
from . import SECRET, Output, header

P = "etc/30ops/prometheus"
BASE = f"{S.REPO}/collector/prometheus/prometheus.yml"
LOGS_JOB = f"{S.REPO}/logs/collector/prometheus-scrape.yml"
NODE_JOB = {"job_name": "node", "scrape_interval": "60s", "file_sd_configs": [{"files": ["targets/node.yml"]}]}


def groups(hosts, port=None, extra=None):
    """file_sd groups: hosts with the same labels share a group, in order."""
    out = []
    for h in hosts:
        labels = dict(h["labels"])
        labels.update(extra(h) if extra else {})
        t = f"{h['address']}:{port}" if port else h["address"]
        for g in out:
            if g["labels"] == labels:
                g["targets"].append(t)
                break
        else:
            out.append({"targets": [t], "labels": labels})
    return [g if g["labels"] else {"targets": g["targets"]} for g in out]


def targets(site):
    """job name -> (targets file, groups); a job without hosts is absent."""
    hs = site["hosts"]
    gb10 = [h for h in hs if "gb10-ops" in h["plugins"]]
    jobs = {
        "collector-host": ("collector.yml", groups(S.with_role(site, "collector"), 9100)),
        "gb10": ("gb10.yml", groups(gb10, 9100)),
        "node": ("node.yml", groups([h for h in S.with_role(site, "node") if h not in gb10], 9100)),
        "pve": ("pve.yml", groups([h for h in S.with_role(site, "hypervisor") if h["vendor"] == "pve"])),
    }
    nas = [h for h in S.with_role(site, "nas") if h.get("snmp")]
    auths = [h["snmp"]["auth"] for h in nas]
    default = auths[0] if auths else None
    jobs["nas-snmp"] = ("nas-snmp.yml", groups(
        nas, extra=lambda h: {} if h["snmp"]["auth"] == default else {"__param_auth": h["snmp"]["auth"]}))
    return {k: v for k, v in jobs.items() if v[1]}, default


def logs_enabled(site):
    return bool(S.with_role(site, "journal") or S.with_role(site, "syslog") or site["logs"])


def prometheus_yml(site, jobs, nas_auth):
    doc = yamlio.load(BASE)
    doc["global"]["external_labels"] = {**doc["global"].get("external_labels", {}), "site": site["site"]["id"]}
    files = {f"targets/{v[0]}": k for k, v in jobs.items()}
    keep = []
    for j in doc["scrape_configs"]:
        sd = [f for c in j.get("file_sd_configs", []) for f in c.get("files", [])]
        if sd and not any(f in files for f in sd):
            continue
        if j["job_name"] == "nas-snmp" and nas_auth:
            j["params"]["auth"] = [nas_auth]
        keep.append(j)
    if "node" in jobs:
        keep.append(NODE_JOB)
    if logs_enabled(site):
        with open(LOGS_JOB, encoding="utf-8") as f:
            keep += yamlio.loads(textwrap.dedent(f.read()), LOGS_JOB)
    doc["scrape_configs"] = keep
    return doc


def render(site, sha):
    jobs, nas_auth = targets(site)
    out = {f"{P}/prometheus.yml": Output(header(sha) + yamlio.dumps(prometheus_yml(site, jobs, nas_auth)))}
    for _, (fname, gs) in jobs.items():
        out[f"{P}/targets/{fname}"] = Output(header(sha) + yamlio.dumps(gs))
    ex = (site.get("pve") or {}).get("exporter")
    if ex:
        doc = {"default": {"user": ex["user"], "token_name": ex["token_name"],
                           "token_value": SECRET + ex["token"], "verify_ssl": ex.get("verify_ssl", False)}}
        # the exporter container runs as uid 101
        out[f"{P}/pve.yml"] = Output(header(sha) + yamlio.dumps(doc), 0o640, "root:101", True)
    auths = (site.get("snmp") or {}).get("auths") or {}
    if auths:
        doc = {"auths": {}}
        for name, a in auths.items():
            x = {"version": 3, "username": a["username"], "security_level": a.get("security_level", "authPriv")}
            if a.get("auth_protocol"):
                x["auth_protocol"] = a["auth_protocol"]
            if a.get("password"):
                x["password"] = SECRET + a["password"]
            if a.get("priv_protocol"):
                x["priv_protocol"] = a["priv_protocol"]
            if a.get("priv_password"):
                x["priv_password"] = SECRET + a["priv_password"]
            doc["auths"][name] = x
        # snmp_exporter runs as nobody
        out[f"{P}/snmp-auth.yml"] = Output(header(sha) + yamlio.dumps(doc), 0o640, "root:65534", True)
    return out
