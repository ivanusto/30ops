"""The collector's log-intake pieces: the DOCKER-USER allowlist (env file
and the unit that applies it) and the WORM share's mount unit."""
from .. import site as S
from . import Output, header

ALLOW = "etc/default/30ops-allowlist"
SERVICE = "etc/systemd/system/30ops-allowlist.service"


def escape_path(p):
    """systemd-escape --path: the unit name of a mount point."""
    p = p.strip("/")
    if not p:
        return "-"
    out = []
    for i, ch in enumerate(p):
        if ch == "/":
            out.append("-")
        elif ch.isascii() and (ch.isalnum() or ch in ":_") or (ch == "." and i > 0):
            out.append(ch)
        else:
            out.extend(f"\\x{b:02x}" for b in ch.encode())
    return "".join(out)


def allowlist(site):
    def addrs(hosts, also=False):
        return " ".join(a for h in hosts for a in [h["address"]] + (h["also"] if also else []))
    return {
        "JOURNALD_FROM": addrs(S.with_role(site, "journal")),
        "SYSLOG_FROM": addrs(S.with_role(site, "syslog"), also=True),
        "AUDIT_FROM": addrs(S.with_role(site, "audit-source")),
        "ADMIN_FROM": addrs([S.host(site, n) for n in site["logs"].get("admin_from") or []]),
    }


def render(site, sha):
    from .prometheus import logs_enabled
    out = {}
    root = site["collector"]["root"]
    if logs_enabled(site):
        env = allowlist(site)
        out[ALLOW] = Output(header(sha) + "# who may reach VictoriaLogs (9428), syslog (514) and the audit port (515)\n"
                            + "".join(f'{k}="{v}"\n' for k, v in env.items()))
        out[SERVICE] = Output(header(sha) + f"""[Unit]
Description=30ops: only log sources may reach VictoriaLogs
After=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=/{ALLOW}
ExecStart={root}/logs/collector/docker-user-allowlist.sh apply
ExecStop={root}/logs/collector/docker-user-allowlist.sh remove

[Install]
WantedBy=docker.service
""")
    w = site["worm"]
    if w:
        what = f"{S.host(site, w['host'])['address']}:{w['export']}"
        out[f"etc/systemd/system/{escape_path(w['mount'])}.mount"] = Output(header(sha) + f"""[Unit]
Description=30ops WORM archive ({what})
Wants=network-online.target
After=network-online.target

[Mount]
What={what}
Where={w['mount']}
Type=nfs4
Options={w['options']}

[Install]
WantedBy=remote-fs.target
""")
    return out
