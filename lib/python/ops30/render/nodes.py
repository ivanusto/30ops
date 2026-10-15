"""What each node needs from the site: nodes/<host>/install.env for the
node installers, for capture nodes the pcap profiles and the sudoers
drop-in that names them, and for the deadman host the settings of
30ops-deadman (etc/30ops-deadman/deadman.env). The profiles are the repo's
logs/pcap/profiles/*.env with the site's peer and interface put in."""
import os
import re

from .. import site as S
from . import Output, header

PROFILES = f"{S.REPO}/logs/pcap/profiles"
NODE_EXPORTER = "1.9.1"
ASSIGN = re.compile(r'^([A-Z_]+)=(.*)$')


def profile_names(h):
    names = sorted(f[:-4] for f in os.listdir(PROFILES) if f.endswith(".env"))
    # corosync is the PVE cluster link: only a hypervisor has one
    return [n for n in names if n != "corosync" or "hypervisor" in h["roles"]]


def unq(v):
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v


def profile(name, h, peer):
    with open(f"{PROFILES}/{name}.env", encoding="utf-8") as f:
        src = f.read().splitlines()
    old = next((unq(m.group(2)) for m in map(ASSIGN.match, src) if m and m.group(1) == "PEER"), None)
    out = []
    for line in src:
        m = ASSIGN.match(line)
        if m and m.group(1) == "PEER" and peer:
            line = f"PEER={peer}"
        elif m and m.group(1) == "FILTER" and old and peer:
            line = line.replace(old, peer)
        elif m and m.group(1) == "IFACE" and h["pcap"].get("iface") and name == "corosync":
            line = f"IFACE={h['pcap']['iface']}"
        out.append(line)
    return "\n".join(out) + "\n"


def sudoers(names):
    def alias(verb):
        return ", ".join(f"/usr/bin/systemctl {verb} pcap@{n}" for n in names)
    return ("# /etc/sudoers.d/pcap (0440): pcap-ops may start, stop and look at these capture units\n"
            f"Cmnd_Alias PCAP_START  = {alias('start')}\n"
            f"Cmnd_Alias PCAP_STOP   = {alias('stop')}\n"
            f"Cmnd_Alias PCAP_STATUS = {alias('status')}\n"
            "%pcap-ops ALL=(root) NOPASSWD: PCAP_START, PCAP_STOP, PCAP_STATUS\n")


def deadman_env(site):
    """30ops-deadman's settings (collector/deadman/30ops-deadman.py)."""
    dm, al = site["alerting"]["deadman"], site["alerting"]
    col = S.host(site, site["collector"]["host"])
    env = {"SITE": site["site"]["id"], "LISTEN": f"0.0.0.0:{dm['port']}",
           "COLLECTOR": " ".join([col["address"]] + col["also"]), "AFTER_S": str(dm["after_s"])}
    if dm["email"] and al.get("smtp"):
        smtp = al["smtp"]
        env.update(EMAIL_TO=" ".join(dm["email"]), SMTP_SMARTHOST=smtp["smarthost"], SMTP_FROM=smtp["from"],
                   SMTP_USERNAME=smtp.get("username", ""),
                   SMTP_REQUIRE_TLS="true" if smtp.get("require_tls", True) else "false")
    if dm["webhook"]:
        env["WEBHOOK"] = " ".join(dm["webhook"])
    return env


def render(site, sha):
    col = S.host(site, site["collector"]["host"])["address"]
    peer = site["logs"].get("pcap", {}).get("peer")
    peer = S.host(site, peer)["address"] if peer else None
    out = {}
    for h in site["hosts"]:
        roles = set(h["roles"])
        if not roles & {"node", "journal", "pcap", "collector", "deadman"}:
            continue
        env = {"HOST": h["name"], "ROLES": " ".join(h["roles"]), "COLLECTOR": col,
               "SCRAPE_FROM": col, "NODE_EXPORTER_VERSION": NODE_EXPORTER}
        if "journal" in roles:
            env["JOURNAL_URL"] = f"http://{col}:9428"
        if h["plugins"]:
            env["PLUGINS"] = " ".join(h["plugins"])
        if "pcap" in roles:
            env["PCAP_PROFILES"] = " ".join(profile_names(h))
        d = f"nodes/{h['name']}"
        if "deadman" in roles and S.deadman_host(site) and S.deadman_host(site)["name"] == h["name"]:
            out[f"{d}/etc/30ops-deadman/deadman.env"] = Output(header(sha) + "".join(
                f'{k}="{v}"\n' for k, v in deadman_env(site).items()))
        out[f"{d}/install.env"] = Output(header(sha) + "".join(f'{k}="{v}"\n' for k, v in env.items()))
        if "pcap" in roles:
            names = profile_names(h)
            for n in names:
                out[f"{d}/etc/pcap/{n}.env"] = Output(header(sha) + profile(n, h, peer))
            out[f"{d}/etc/sudoers.d/pcap"] = Output(header(sha) + sudoers(names), 0o440)
    return out
