"""/etc/cron.d/30ops: the five cron fragments of the old repos in one file.

cron runs in the collector's local time. The daily and weekly jobs are
fixed in UTC here (the log archive must start after the UTC day it
archives has closed) and converted with the site timezone's standard
offset; on a site with daylight saving they run an hour later in summer.
Paths of the scripts are under collector.root; state paths, textfile names
and the cron users are the ones the old crons used.
"""
from datetime import datetime
from zoneinfo import ZoneInfo

from .. import site as S
from . import Output, header

# UTC (minute, hour, weekday or None)
ARCHIVE = (10, 0, None)
VERIFY = (20, 0, None)
EOL = (35, 23, None)
FW_WEEKLY = (15, 0, 1)
AUP_WEEKLY = (25, 0, 1)
AUDIT_WEEKLY = (45, 0, 1)
EOL_DEFAULT_ASSET = "fgt-edge"   # eol-textfile.py --fortigate-asset default
TODAY = r"$(date +\%F)"
YESTERDAY = r'"$(date -u -d yesterday +\%Y-\%m-\%d)"'


def std_offset_min(tz):
    z = ZoneInfo(tz)
    return min(int(z.utcoffset(datetime(2026, m, 15)).total_seconds()) // 60 for m in (1, 7))


def at(utc, tz):
    """cron fields for a UTC time in the site's local standard time."""
    minute, hour, dow = utc
    t = hour * 60 + minute + std_offset_min(tz)
    day, t = divmod(t, 1440)
    f = f"{t % 60} {t // 60} * * "
    return f + ("*" if dow is None else str((dow + day) % 7))


# every textfile a cron job writes, the metric prefix of its
# *_last_run_timestamp, and the age at which its stale alert fires (doctor
# uses the same numbers; tests/unit/test_doctor.py holds them to the rules)
TEXTFILES = {
    "nas.prom": ("nas_textfile", 600),
    "drills.prom": ("drills_textfile", 7200),
    "pve-quorum.prom": ("pve_quorum_textfile", 300),
    "eol.prom": ("eol_textfile", 2 * 86400),
    "fw.prom": ("fw_report", 1800),
    "aup.prom": ("aup_report", 1800),
    "audit.prom": ("audit_report", 1800),
    "changes.prom": ("changes_textfile", 3600),
    "agent-gate.prom": ("agent_gate_textfile", 1800),
    "readiness.prom": ("readiness_textfile", 3600),
}


def q(v):
    return f'"{v}"' if " " in v else v


def lines(site):
    c = site["collector"]
    tz = site["site"]["timezone"]
    root, tf, log, user = c["root"], c["textfile_dir"], c["log_dir"], c["user"]
    vl = c["victorialogs"]
    clone = site["changes"]["clone"]
    py = f"{root}/collector/textfile"
    out = []

    def add(*ls):
        out.extend(ls)

    nas = [h for h in S.with_role(site, "nas") if h.get("ssh")]
    if nas:
        args = " ".join(f"{h['labels'].get('nas', h['name'])}={h['ssh']['user']}@{h['address']}" for h in nas)
        add("# NAS health over ssh, every minute",
            f"* * * * * {user} {py}/nas-textfile.sh {args} > {tf}/.nas.tmp && mv {tf}/.nas.tmp {tf}/nas.prom")
    d = c["drills"]
    add("# drill results from every drills.jsonl",
        f"*/15 * * * * {user} {py}/drills-textfile.py --out {tf}/drills.prom pve={d['pve']} nas={d['nas']} "
        f"cloud={d['cloud']} logs={d['logs']} changes={clone}/drills/drills.jsonl")
    clusters = {}
    for h in S.with_role(site, "hypervisor"):
        if h.get("pve") and h.get("ssh"):
            clusters.setdefault(h["pve"]["cluster"], []).append(f"{h['ssh']['user']}@{h['address']}")
    if clusters:
        args = " ".join(f"{k}={','.join(v)}" for k, v in clusters.items())
        add("# corosync votes, one entry per cluster, nodes tried in order",
            f"* * * * * {user} {py}/pve-quorum-textfile.sh {args} > {tf}/.pve-quorum.tmp && mv {tf}/.pve-quorum.tmp {tf}/pve-quorum.prom")
    if site.get("assets"):
        fgt = [h for h in S.with_role(site, "firewall") if h["vendor"] == "fortigate" and h.get("api")]
        opt = ""
        if fgt:
            a = fgt[0]["api"]
            opt = f" --fortigate {a['url']} --token-file {S.secret_file(site, a['token'])}"
            if a.get("insecure"):
                opt += " --insecure"
            if fgt[0]["name"] != EOL_DEFAULT_ASSET:
                opt += f" --fortigate-asset {fgt[0]['name']}"
        add("# asset lifecycle and licence expiry, daily",
            f"{at(EOL, tz)} {user} {py}/eol-textfile.py --assets /etc/30ops/assets.tsv --refresh "
            f"--cache {c['eol_cache']}{opt} --out {tf}/eol.prom >> {log}/eol.log 2>&1")

    if site["worm"] and site["logs"].get("archive") is not None:
        arc = f"{site['worm']['mount']}/logs"
        skip = " ".join(site["logs"]["archive"].get("skip") or [])
        env = f"VL={vl} ARCHIVE={arc}" + (f" ARCHIVE_SKIP={q(skip)}" if skip else "")
        add("# the closed UTC day of logs to the WORM share, then a verify against the live store",
            f"{at(ARCHIVE, tz)} {user} {env} {root}/logs/archive/archive-day.sh >> {log}/archive.log 2>&1",
            f"{at(VERIFY, tz)} {user} VL={vl} ARCHIVE={arc} DRILLS={d['logs']} {root}/logs/archive/verify-archive.sh "
            f"{YESTERDAY} --against-live >> {log}/verify.log 2>&1")
    if S.with_role(site, "syslog") or S.with_role(site, "journal"):
        fw = [h for h in S.with_role(site, "firewall") if h.get("syslog")]
        if fw:
            add("# walls that must drop something every hour, as source:host (FwSilent)",
                "FW_EXPECT=" + q(" ".join(f"{h['vendor']}:{h['syslog']['devname']}" for h in fw)))
        r = site["collector"]["reports_dir"]
        add(f"*/10 * * * * {user} VL={vl} {root}/logs/firewall/fw-report.py --window 1h --baseline 7d "
            f"--textfile {tf}/fw.prom --out /dev/null >> {log}/fw-report.log 2>&1",
            f"{at(FW_WEEKLY, tz)} {user} VL={vl} {root}/logs/firewall/fw-report.py --window 7d --baseline 30d "
            f"--out {r}/fw-{TODAY}.md >> {log}/fw-report.log 2>&1")
        wf = [h for h in S.with_role(site, "webfilter") if h.get("syslog")]
        if wf:
            add("# the web-filter log of these devices must not go quiet (AupSilent)",
                "AUP_EXPECT=" + q(" ".join(h["syslog"]["devname"] for h in wf)),
                f"*/10 * * * * {user} VL={vl} {root}/logs/firewall/aup-report.py --window 1h "
                f"--textfile {tf}/aup.prom --out /dev/null >> {log}/aup-report.log 2>&1",
                f"{at(AUP_WEEKLY, tz)} {user} VL={vl} {root}/logs/firewall/aup-report.py --window 7d "
                f"--out {r}/aup-{TODAY}.md >> {log}/aup-report.log 2>&1")
        admins = S.with_role(site, "admin")
        if admins:
            add("# admin workstations: their logins are reported, marked, not counted as unattributed",
                "AUDIT_QUIET_FROM=" + q(" ".join(h["address"] for h in admins)))
        cd = f"CHANGES_DIR={clone}/changes"
        add(f"*/10 * * * * {user} VL={vl} {cd} {root}/logs/audit/audit-report.py --window 1h "
            f"--textfile {tf}/audit.prom --out /dev/null >> {log}/audit-report.log 2>&1",
            f"{at(AUDIT_WEEKLY, tz)} {user} VL={vl} {cd} {root}/logs/audit/audit-report.py --window 7d "
            f"--out {r}/audit-{TODAY}.md >> {log}/audit-report.log 2>&1")
    pc = S.with_role(site, "pcap")
    if pc and site["worm"]:
        arc = f"{site['worm']['mount']}/pcap"
        nodes = " ".join(f"{h['name']}={h['pcap']['user']}@{h['address']}:/" for h in pc)
        add("# captures pulled hourly from every node, verified after the share has locked them",
            f'40 * * * * {user} PCAP_NODES="{nodes}" SSH_KEY={S.secret_file(site, site["logs"]["pcap"]["key"])} '
            f"ARCHIVE={arc} {root}/logs/pcap/pcap-pull.sh >> {log}/pcap-pull.log 2>&1",
            f"55 * * * * {user} ARCHIVE={arc} DRILLS={d['logs']} {root}/logs/pcap/verify-pcap.sh --latest "
            f"--against-index >> {log}/pcap-verify.log 2>&1")
    add("# the change records: fast-forward pull of the clone, then changes.prom",
        f"*/15 * * * * {user} cd {clone} && git pull -q --ff-only && {root}/changes/scripts/changes-textfile.py "
        f"--dir {clone}/changes --drills {clone}/drills/drills.jsonl --out {tf}/changes.prom >> {log}/changes.log 2>&1")
    if site["gate"]["targets"]:
        add("# the agent gate's textfile, as the gate's own user",
            f"*/5 * * * * agent-gate GATE_CONFIG=/etc/30ops/gate/config.json {root}/gate/bin/gatectl textfile "
            f"--out {tf}/agent-gate.prom >> {log}/agent-gate.log 2>&1")
    add("# the readiness checklist against the local Prometheus (the plan render wrote), as readiness.prom;",
        "# it exits 1 while an item is no, which is what readiness.prom says, not a failed run",
        f"*/15 * * * * {user} {root}/bin/30ops readiness --plan /etc/30ops/readiness.json --no-local "
        f"--format json --textfile {tf}/readiness.prom > {log}/readiness.json 2>> {log}/readiness.log || true")
    return out


def render(site, sha):
    text = header(sha) + "# local time is " + site["site"]["timezone"] + "\n" + "\n".join(lines(site)) + "\n"
    return {"etc/cron.d/30ops": Output(text)}
