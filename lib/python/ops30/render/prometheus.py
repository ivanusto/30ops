"""prometheus.yml, targets/*.yml, pve.yml (from the pve adapter) and snmp-auth.yml.

prometheus.yml is the repo's collector/prometheus/prometheus.yml (the job
definitions are product, not site) with four changes: the site label, the
jobs that have no target dropped (victorialogs when the site collects no
logs), a node job for the plain Linux nodes, and the scrape job of each
plugin a host lists (plugin.yaml scrape:), before collector-host. A host
whose plugin job replaces node is scraped by that job only.
"""
from .. import plugins, site as S, yamlio
from ..adapters import registry
from . import SECRET, Output, header

P = "etc/30ops/prometheus"
BASE = f"{S.REPO}/collector/prometheus/prometheus.yml"
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
    jobs = {"collector-host": ("collector.yml", groups(S.with_role(site, "collector"), 9100))}
    taken = []
    for job, sc, hs in plugin_jobs(site):
        jobs[job] = (f"{job}.yml", groups(hs, sc["port"]))
        if sc.get("replaces") == "node":
            taken += hs
    jobs["node"] = ("node.yml", groups([h for h in S.with_role(site, "node") if h not in taken], 9100))
    jobs["pve"] = ("pve.yml", groups([h for h in S.with_role(site, "hypervisor") if h["vendor"] == "pve"]))
    dh = S.deadman_host(site)
    if dh:
        jobs["deadman"] = ("deadman.yml", groups([dh], site["alerting"]["deadman"]["port"]))
    nas = [h for h in S.with_role(site, "nas") if h.get("snmp")]
    auths = [h["snmp"]["auth"] for h in nas]
    default = auths[0] if auths else None
    jobs["nas-snmp"] = ("nas-snmp.yml", groups(
        nas, extra=lambda h: {} if h["snmp"]["auth"] == default else {"__param_auth": h["snmp"]["auth"]}))
    return {k: v for k, v in jobs.items() if v[1]}, default


def plugin_jobs(site):
    """[(job name, plugin.yaml scrape, hosts)] of the enabled plugins that have a job."""
    out = []
    for name in plugins.enabled(site):
        sc = plugins.scrape(name)
        if sc:
            out.append((sc["job"], sc, plugins.hosts(site, name)))
    return out


def plugin_job(job, sc):
    """The prometheus.yml job: the scrape settings first, then the targets
    file, then the rest (relabelling), the order the jobs are written in."""
    cfg = dict(sc.get("config") or {})
    j = {"job_name": job}
    for k in ("scrape_interval", "scrape_timeout", "metrics_path", "params"):
        if k in cfg:
            j[k] = cfg.pop(k)
    j["file_sd_configs"] = [{"files": [f"targets/{job}.yml"]}]
    j.update(cfg)
    return j


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
        if j["job_name"] == "victorialogs" and not logs_enabled(site):
            continue
        if j["job_name"] == "nas-snmp" and nas_auth:
            j["params"]["auth"] = [nas_auth]
        keep.append(j)
    at = next((i for i, j in enumerate(keep) if j["job_name"] == "collector-host"), 0)
    for job, sc, _ in reversed(plugin_jobs(site)):
        if job in jobs:
            keep.insert(at, plugin_job(job, sc))
    if "node" in jobs:
        # before victorialogs, where v0.3 put it
        at = next((i for i, j in enumerate(keep) if j["job_name"] == "victorialogs"), len(keep))
        keep.insert(at, NODE_JOB)
    doc["scrape_configs"] = keep
    return doc


def render(site, sha):
    jobs, nas_auth = targets(site)
    out = {f"{P}/prometheus.yml": Output(header(sha) + yamlio.dumps(prometheus_yml(site, jobs, nas_auth)))}
    for _, (fname, gs) in jobs.items():
        out[f"{P}/targets/{fname}"] = Output(header(sha) + yamlio.dumps(gs))
    out.update(registry.module("hypervisor", "pve").render(site, sha))
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
