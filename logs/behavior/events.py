#!/usr/bin/env python3
"""events: the one event shape the behaviour pipeline reads, and the loaders
that produce it from what a site already has.

    events.py probe --from-jsonl events.jsonl
    events.py load  --zeek conn.log --zeek files.log --fortigate fgt.log --winsec sec.jsonl --out events.jsonl
    events.py load  --vl http://127.0.0.1:9428 --window 7d --fw-host fgt-edge --out events.jsonl
    events.py load  --wazuh-tar wazuh_raw_logs.tar.gz --bitdefender bd.csv --spill-dir /srv/tmp/spill --out events.jsonl
    events.py load  --wazuh-csv alerts.csv --out events.jsonl
    events.py load  --wazuh-tar MIRROR --wazuh-archives MIRROR --only-users t_alpha,t_bravo --out events.jsonl
    events.py load  --wazuh-tar MIRROR --wazuh-archives MIRROR --fortigate-sessions ws-w1=192.0.2.10:t_delta --out events.jsonl

One line per event, JSON, UTF-8. Keys that every kind carries:

    ts        RFC 3339, UTC
    kind      net.conn | net.file | auth.logon | file.access | print.job | usb.attach | fw.utm
              | sec.alert | priv.exec | file.integrity | pkg.change | malware.detect
    user      account the action is attributed to ("" when the source has none)
    src_host  workstation or server the action came from
    source    zeek | fortigate | ad | speslog | print | endpoint | synth | wazuh | bitdefender | qulog
    asset     the monitored machine that reported the event (host-day analysis); optional

Per kind (absent keys mean "the source did not say"):

    net.conn    dst, dst_name, dst_port, proto, service, bytes_out, bytes_in, duration_s, category, action
    net.file    dst, dst_name, filename, bytes, direction (up|down)
    auth.logon  dst (the host logged on to), logon_type, result (success|failure), method
    file.access dst (file server), share, path, action (read|write|delete|rename|copy), bytes
    print.job   dst (print server), pages, filename
    usb.attach  device
    fw.utm      dst, dst_name, category, app, action (allow|block)
    sec.alert   rule_id, rule_level, rule_group, mitre (SIEM alert with no more specific shape; no free text)
    priv.exec   dst, target (account run as), category ("evasion" when the command names such a tool)
    file.integrity  dst, path, action (added|modified|deleted)
    pkg.change  dst, action, category ("evasion" when the package is such a tool)
    malware.detect  dst, rule_level, category (module), incident (opaque id)

The SIEM loaders keep no rule description, log line, command or URL: those are
free text, and free text is scrub.py's business, not this schema's.

Hostnames and addresses are the site's real ones at this stage; pseudonymize.py
is the next step and nothing after it sees these files.

Standard library only.
"""
import argparse, collections, csv, gzip, json, os, re, sys, tarfile, urllib.parse, urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "lib", "python"))
from ops30 import rfc3339  # noqa: E402

KINDS = ("net.conn", "net.file", "auth.logon", "file.access", "print.job", "usb.attach", "fw.utm",
         "sec.alert", "priv.exec", "file.integrity", "pkg.change", "malware.detect")
REQUIRED = ("ts", "kind", "user", "src_host", "source")

# ------------------------------------------------------------------ helpers

def read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line:
                yield line


def write_jsonl(path, events):
    n = 0
    out = sys.stdout if path in (None, "-") else open(path, "w", encoding="utf-8")
    try:
        for e in events:
            out.write(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n")
            n += 1
    finally:
        if out is not sys.stdout:
            out.close()
    return n


def epoch_to_ts(x):
    try:
        return rfc3339.from_epoch(int(float(x)))
    except (TypeError, ValueError):
        return None


def valid(e):
    """A loader's output must carry the common keys and a known kind."""
    return all(k in e for k in REQUIRED) and e["kind"] in KINDS and rfc3339.parse(e["ts"]) is not None


def check(events):
    bad = 0
    for e in events:
        if not valid(e):
            bad += 1
        else:
            yield e
    if bad:
        print(f"events: {bad} line(s) dropped, missing keys or bad time", file=sys.stderr)


# ------------------------------------------------------------------ jsonl

def from_jsonl(path):
    for line in read_lines(path):
        try:
            yield json.loads(line)
        except ValueError:
            continue


# ------------------------------------------------------------------ zeek
# conn.log and files.log, TSV with the #fields header or JSON lines
# (LogAscii::use_json=T). Zeek has no user; the site joins user to source
# address through its logon events, summarize.py does that join.

ZEEK_SERVICE_PORT = {"ssl": 443, "http": 80, "dns": 53, "smb": 445, "rdp": 3389, "ssh": 22}


def zeek_rows(path):
    fields = None
    for line in read_lines(path):
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except ValueError:
                continue
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or fields is None:
            continue
        cols = line.split("\t")
        yield {k: (None if v == "-" else v) for k, v in zip(fields, cols)}


def num(x, default=0):
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return default


def from_zeek(path):
    for r in zeek_rows(path):
        ts = epoch_to_ts(r.get("ts"))
        if ts is None:
            continue
        if "id.orig_h" in r and "orig_bytes" in r:          # conn.log
            yield {"ts": ts, "kind": "net.conn", "user": "", "src_host": r.get("id.orig_h", ""),
                   "src_ip": r.get("id.orig_h", ""), "dst": r.get("id.resp_h", ""), "dst_port": num(r.get("id.resp_p")),
                   "proto": (r.get("proto") or "").lower(), "service": r.get("service") or "",
                   "bytes_out": num(r.get("orig_bytes")), "bytes_in": num(r.get("resp_bytes")),
                   "duration_s": num(r.get("duration")), "source": "zeek"}
        elif "fuid" in r:                                     # files.log
            src = (r.get("tx_hosts") or [""])[0] if isinstance(r.get("tx_hosts"), list) else (r.get("tx_hosts") or "").split(",")[0]
            dst = (r.get("rx_hosts") or [""])[0] if isinstance(r.get("rx_hosts"), list) else (r.get("rx_hosts") or "").split(",")[0]
            yield {"ts": ts, "kind": "net.file", "user": "", "src_host": src, "src_ip": src, "dst": dst,
                   "filename": r.get("filename") or "", "bytes": num(r.get("total_bytes") or r.get("seen_bytes")),
                   "direction": "up" if r.get("is_orig") in (True, "T") else "down", "source": "zeek"}


# ------------------------------------------------------------------ fortigate
# syslog key=value lines: traffic (forward), utm (webfilter, app-ctrl) and
# event/vpn logins. The same lines whether read from a file or VictoriaLogs.

LOGFMT = re.compile(r'(\w+)=("([^"\\]|\\.)*"|\S+)')


def logfmt(line):
    d = {}
    for m in LOGFMT.finditer(line):
        v = m.group(2)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        d[m.group(1)] = v
    return d


def fgt_ts(d):
    if d.get("eventtime"):                      # nanoseconds since epoch on 6.2 and later
        t = d["eventtime"]
        return epoch_to_ts(int(t) / 1e9 if len(t) > 12 else t)
    if d.get("date") and d.get("time"):
        tz = d.get("tz", "+0000")
        return rfc3339.format(rfc3339.parse(f"{d['date']}T{d['time']}{tz[:3]}:{tz[3:]}")) if rfc3339.parse(f"{d['date']}T{d['time']}{tz[:3]}:{tz[3:]}") else None
    return None


def from_fortigate_lines(lines):
    for line in lines:
        d = logfmt(line)
        ts = fgt_ts(d)
        if ts is None or "type" not in d:
            continue
        user = d.get("user") or d.get("unauthuser") or ""
        src = d.get("srcname") or d.get("srcip") or ""
        base = {"ts": ts, "user": user, "src_host": src, "src_ip": d.get("srcip", ""), "source": "fortigate"}
        if d["type"] == "traffic":
            yield {**base, "kind": "net.conn", "dst": d.get("dstip", ""), "dst_name": d.get("hostname") or d.get("dstname") or "",
                   "dst_port": num(d.get("dstport")), "proto": {"6": "tcp", "17": "udp"}.get(d.get("proto"), d.get("proto", "")),
                   "service": (d.get("service") or "").lower(), "bytes_out": num(d.get("sentbyte")), "bytes_in": num(d.get("rcvdbyte")),
                   "duration_s": num(d.get("duration")), "category": d.get("catdesc", ""), "action": d.get("action", "")}
        elif d["type"] == "utm":
            yield {**base, "kind": "fw.utm", "dst": d.get("dstip", ""), "dst_name": d.get("hostname") or d.get("url", "").split("/")[0],
                   "category": d.get("catdesc") or d.get("appcat", ""), "app": d.get("app", ""),
                   "action": "block" if d.get("action") in ("blocked", "block", "deny") else "allow"}
        elif d["type"] == "event" and d.get("subtype") in ("vpn", "user"):
            if d.get("action") in ("tunnel-up", "ssl-login-fail", "auth-logon", "ssl-new-con") or d.get("logdesc", "").lower().find("login") >= 0:
                ok = d.get("result", d.get("status", "")) in ("OK", "success", "")  and "fail" not in d.get("action", "")
                yield {**base, "kind": "auth.logon", "dst": d.get("devname", "vpn"), "logon_type": "vpn",
                       "result": "success" if ok else "failure", "method": d.get("tunneltype", "vpn")}


def from_fortigate(path):
    return from_fortigate_lines(read_lines(path))


# ------------------------------------------------------------------ windows security (speslog export)
# One JSON object per line with at least EventID, TimeCreated and the
# EventData the site's collector flattened. Keys differ by exporter, so
# every lookup tries the common spellings.

def pick(d, *names, default=""):
    for n in names:
        if n in d and d[n] not in (None, ""):
            return d[n]
        ed = d.get("EventData") or d.get("event_data") or {}
        if isinstance(ed, dict) and n in ed and ed[n] not in (None, ""):
            return ed[n]
    return default


def from_winsec(path):
    for line in read_lines(path):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        eid = str(pick(d, "EventID", "event_id", "winlog.event_id"))
        t = pick(d, "TimeCreated", "@timestamp", "timestamp", "ts")
        ts = rfc3339.format(rfc3339.parse(t)) if rfc3339.parse(str(t)) else epoch_to_ts(t)
        if ts is None:
            continue
        host = pick(d, "Computer", "computer_name", "host")
        user = pick(d, "TargetUserName", "SubjectUserName", "user")
        if eid in ("4624", "4625"):
            yield {"ts": ts, "kind": "auth.logon", "user": user, "src_host": pick(d, "WorkstationName", "IpAddress") or host,
                   "src_ip": pick(d, "IpAddress"), "dst": host, "logon_type": num(pick(d, "LogonType"), 0),
                   "result": "success" if eid == "4624" else "failure", "method": pick(d, "AuthenticationPackageName"), "source": "ad"}
        elif eid in ("5145", "4663"):
            path_ = pick(d, "RelativeTargetName", "ObjectName")
            yield {"ts": ts, "kind": "file.access", "user": user, "src_host": pick(d, "IpAddress") or host, "dst": host,
                   "share": pick(d, "ShareName"), "path": path_,
                   "action": "write" if re.search(r"Write|Add|%%4417|%%4418", str(pick(d, "AccessMask", "AccessList"))) else
                             ("delete" if re.search(r"DELETE|%%1537", str(pick(d, "AccessMask", "AccessList"))) else "read"),
                   "bytes": num(pick(d, "Bytes", "bytes"), 0), "source": "speslog"}
        elif eid in ("307",):                                   # PrintService operational: document printed
            yield {"ts": ts, "kind": "print.job", "user": user, "src_host": pick(d, "Param4", "ClientMachine") or host, "dst": host,
                   "pages": num(pick(d, "Param8", "Pages"), 0), "filename": pick(d, "Param2", "Document"), "source": "print"}
        elif eid in ("6416", "2003", "2100"):                   # PnP new device / DriverFrameworks-UserMode
            yield {"ts": ts, "kind": "usb.attach", "user": user, "src_host": host,
                   "device": pick(d, "DeviceDescription", "ClassName", default="usb"), "source": "endpoint"}


# ------------------------------------------------------------------ wazuh
# Alerts from the CSV export (flat columns) or from the manager's own
# logs/alerts JSON (streamed out of a tar, or read from a mirror directory of
# the manager's logs/). Both go through flat -> wazuh_event, so the two can be
# counted against each other.
#
# Two kinds of line reach a manager as syslog and are activity, not alerts:
# FortiGate traffic and web/app-control lines become the events the FortiGate
# loader makes (with the alert's agent, rule_id and rule_level kept, so a
# host-day still counts them where it did); FortiGate lines Wazuh files under
# recon, web_scan or attack stay alerts. Most of these lines fire no rule
# (in a two-day sample every app-ctrl line was an alert, 0.2% of traffic and no
# webfilter line), so --wazuh-archives reads them from logs/archives, along
# with the QuLog connection lines (SMB and the like), which also fire none.
# Given both, the alerts path leaves the FortiGate activity to the archives.

EVASION_TOOL = re.compile(r"(?i)\b(openvpn|wireguard|wg-quick|tor|torsocks|proxychains|cloudflared|ngrok|frpc?|chisel|socat|tailscale|zerotier|dnscrypt|stubby)\b")
WAZUH_ALERT_MEMBER = re.compile(r"(^|/)logs/alerts/(alerts\.json|\d{4}/\w{3}/ossec-alerts-\d+\.json(\.gz)?)$")
WAZUH_ARCHIVE_MEMBER = re.compile(r"(^|/)logs/archives/(archives\.json|\d{4}/\w{3}/ossec-archive-\d+\.json(\.gz)?)$")
FGT_ACTIVITY = {("traffic", "forward"), ("traffic", "local"), ("utm", "webfilter"), ("utm", "app-ctrl")}
FGT_STAYS_ALERT = {"recon", "web_scan", "attack"}
QULOG = re.compile(r"conn log: Users: (?P<user>.*?), Source IP: (?P<ip>.*?), Computer name: (?P<cn>.*?), Connection type: (?P<ct>.*?), "
                   r"Accessed resources: (?P<res>.*), Action: (?P<act>[^,]*?)\s*$")
QULOG_ACTION = {"read": "read", "write": "write", "add": "write", "delete": "delete", "rename": "rename", "move": "rename", "copy": "copy"}


def low(x):
    return str(x or "").strip().lower()


def wazuh_ts(t):
    d = rfc3339.parse(str(t).replace("+0000", "+00:00").replace("+0800", "+08:00"))
    return rfc3339.format(d) if d else None


def wazuh_event(r):
    """flat dict -> one event, or None when the time cannot be read"""
    ts = wazuh_ts(r.get("timestamp"))
    if ts is None:
        return None
    groups = {g.strip() for g in re.split(r"[,|]", r.get("rule_groups") or "") if g.strip()}
    asset, dec, ip = low(r.get("agent_name")), low(r.get("decoder")), (r.get("srcip") or "").strip()
    base = {"ts": ts, "user": "", "src_host": asset, "asset": asset, "source": "wazuh", "rule_id": str(r.get("rule_id") or ""),
            "rule_level": num(r.get("rule_level"))}
    if ip:
        base["src_ip"] = ip
    if "bitdefender" in groups or "malware" in groups:
        real = low(r.get("computer_name")) or asset
        return {**base, "kind": "malware.detect", "asset": real, "src_host": real, "dst": real, "category": "wazuh", "incident": ""}
    if groups & {"authentication_success", "authentication_failed", "authentication_failures", "invalid_login"}:
        ok = "authentication_success" in groups
        lt = "ssh" if dec.startswith("ssh") else (num(r.get("logon_type")) if r.get("logon_type") not in (None, "") else "local")
        return {**base, "kind": "auth.logon", "user": low(r.get("dstuser") or r.get("srcuser")), "src_host": ip or asset, "dst": asset,
                "logon_type": lt, "result": "success" if ok else "failure", "method": dec}
    if "sudo" in groups:
        return {**base, "kind": "priv.exec", "user": low(r.get("srcuser")), "dst": asset, "target": low(r.get("dstuser")),
                "category": "evasion" if EVASION_TOOL.search(r.get("command") or "") else ""}
    if groups & {"syscheck", "syscheck_file"}:
        return {**base, "kind": "file.integrity", "dst": asset, "path": r.get("syscheck_path") or "", "action": low(r.get("syscheck_event")) or "modified"}
    if groups & {"dpkg", "yum", "rpm"}:
        return {**base, "kind": "pkg.change", "dst": asset, "action": low(r.get("dpkg_status")) or "changed",
                "category": "evasion" if EVASION_TOOL.search(r.get("package") or "") else ""}
    if "usb" in groups:
        return {**base, "kind": "usb.attach", "device": "usb"}
    group = sorted(groups)[0] if groups else ""
    for g in ("recon", "web_scan", "attack", "access_denied", "spam", "low_diskspace", "rootcheck", "vulnerability-detector", "sca", "config_changed"):
        if g in groups:
            group = g
            break
    return {**base, "kind": "sec.alert", "rule_group": group, "mitre": str(r.get("mitre_id") or "")}


def flatten_alert(a):
    """a manager alert object -> the flat columns the CSV export has"""
    rule, agent, data = a.get("rule") or {}, a.get("agent") or {}, a.get("data") if isinstance(a.get("data"), dict) else {}
    sc = a.get("syscheck") if isinstance(a.get("syscheck"), dict) else {}
    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    wev = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}   # Windows event channel: the account is here
    mitre = (rule.get("mitre") or {}).get("id") or []
    return {"timestamp": a.get("timestamp"), "agent_name": agent.get("name"), "agent_ip": agent.get("ip"), "rule_id": rule.get("id"),
            "rule_level": rule.get("level"), "rule_groups": ",".join(rule.get("groups") or []), "decoder": (a.get("decoder") or {}).get("name"),
            "srcip": data.get("srcip"), "srcuser": data.get("srcuser"), "dstuser": data.get("dstuser") or wev.get("targetUserName"),
            "logon_type": wev.get("logonType"), "mitre_id": ",".join(mitre) if isinstance(mitre, list) else mitre,
            "command": data.get("command"), "package": data.get("package"), "dpkg_status": data.get("dpkg_status"),
            "computer_name": data.get("computer_name"), "syscheck_path": sc.get("path"), "syscheck_event": sc.get("event")}


def csv_rows(path):
    csv.field_size_limit(1 << 30)
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        yield from csv.DictReader(f)


def from_wazuh_csv(path):
    for r in csv_rows(path):
        e = wazuh_event(r)
        if e:
            yield e


def wazuh_members(path, rx):
    """(name, text lines) for each file whose path matches rx, in a tar or
    under a mirror directory of the manager's logs/; nothing else is read"""
    def lines(name, raw):
        return gzip.open(raw, "rt", encoding="utf-8", errors="replace") if name.endswith(".gz") else (line.decode("utf-8", "replace") for line in raw)
    if os.path.isdir(path):
        found = []
        for root, dirs, files in os.walk(path):
            dirs.sort()
            found += [os.path.join(root, f) for f in files if rx.search(os.path.relpath(os.path.join(root, f), path).replace(os.sep, "/"))]
        for p in sorted(found):
            with open(p, "rb") as raw:
                yield p, lines(p, raw)
        return
    with tarfile.open(path, "r|*") as t:
        for m in t:
            if m.isfile() and rx.search(m.name):
                yield m.name, lines(m.name, t.extractfile(m))


def wazuh_tar_alerts(path):
    """every alert object in logs/alerts JSON (a tar or a mirror directory)"""
    for _, fh in wazuh_members(path, WAZUH_ALERT_MEMBER):
        for line in fh:
            try:
                yield json.loads(line)
            except ValueError:
                continue


def wazuh_fortigate(a, flat):
    """a FortiGate traffic or web/app line relayed through Wazuh -> the FortiGate
    loader's event, keeping the alert's agent and rule; None keeps it an alert"""
    if not low((a.get("decoder") or {}).get("name")).startswith("fortigate"):
        return None
    if set((a.get("rule") or {}).get("groups") or []) & FGT_STAYS_ALERT:
        return None
    line = a.get("full_log") or ""
    d = logfmt(line)
    if (d.get("type"), d.get("subtype")) not in FGT_ACTIVITY:
        return None
    for e in from_fortigate_lines([line]):
        e.update(asset=low(flat.get("agent_name")), rule_id=str(flat.get("rule_id") or ""), rule_level=num(flat.get("rule_level")))
        return e
    return None


def wazuh_alert_event(a):
    flat = flatten_alert(a)
    return wazuh_fortigate(a, flat) or wazuh_event(flat)


def from_wazuh_tar(path, archives_too=False):
    skipped = 0
    for a in wazuh_tar_alerts(path):
        flat = flatten_alert(a)
        f = wazuh_fortigate(a, flat)
        if f is not None and archives_too:
            skipped += 1                        # the same line is in logs/archives
            continue
        e = f or wazuh_event(flat)
        if e:
            yield e
    if skipped:
        print(f"events: {skipped} FortiGate activity alert(s) left to --wazuh-archives", file=sys.stderr)


def qulog_event(ts, nas, line):
    """one QuLog "conn log:" line -> auth.logon (Login ...) or file.access; None when unread"""
    m = QULOG.search(line)
    if not m:
        return None
    ip, cn = m["ip"].strip(), m["cn"].strip()
    ip = "" if ip in ("", "---") else ip
    base = {"ts": ts, "user": low(m["user"].rsplit("\\", 1)[-1]), "src_host": ip or ("" if cn in ("", "---") else low(cn)),
            "asset": nas, "dst": nas, "source": "qulog"}
    if ip:
        base["src_ip"] = ip
    act, ct = m["act"].strip().lower(), m["ct"].strip().lower()
    if act.startswith("login"):
        return {**base, "kind": "auth.logon", "logon_type": ct, "result": "success" if "success" in act else "failure", "method": ct}
    if act not in QULOG_ACTION:
        return None
    share, _, rest = m["res"].strip().partition("/")
    return {**base, "kind": "file.access", "share": share, "path": rest, "action": QULOG_ACTION[act]}


def from_wazuh_archives(path):
    """FortiGate traffic and web/app lines and QuLog connection lines in
    logs/archives JSON; every other archived line is skipped unparsed"""
    for _, fh in wazuh_members(path, WAZUH_ARCHIVE_MEMBER):
        for line in fh:
            qulog, fgt = "conn log:" in line, "devid=" in line
            if not (qulog or fgt):
                continue
            try:
                a = json.loads(line)
            except ValueError:
                continue
            fl = a.get("full_log") or ""
            if qulog and "conn log:" in fl:
                ts = wazuh_ts(a.get("timestamp"))
                nas = low((a.get("predecoder") or {}).get("hostname")) or low((a.get("agent") or {}).get("name"))
                e = qulog_event(ts, nas, fl) if ts else None
            elif fgt:
                e = wazuh_fortigate(a, flatten_alert(a))
            else:
                e = None
            if e:
                yield e


# ------------------------------------------------------------------ FortiGate within account sessions
# A firewall line names an address, not a person. On a machine that a test
# account shares with other people, --fortigate-sessions AGENT=IP[,IP]:ACCOUNT[,ACCOUNT]
# keeps that machine's FortiGate lines only while one of ACCOUNTS is logged on
# there, as the Windows logon and logoff events the agent sent say; the rest
# is dropped at load and counted. Fixed rules:
#   session      4624 of the account with logon type 2 (interactive), 7 (unlock),
#                10 (remote interactive) or 11 (cached interactive); network,
#                service and batch logons do not count
#   end          4634 or 4647 with the same logon id; none -> 12 h after the logon
#   other people an interactive session (same types) of any other account that
#                is not a system one (ends in $, dwm-N, umfd-N, system, local
#                service, network service, anonymous logon) is cut out of it
#   clock        the session is widened by 5 s each side (two NTP clocks)
#   time         a connection (net.conn) counts by when it started, eventtime
#                less its duration; other lines by their own time
#   kept lines   take the account as their user
# The Windows events come from the alerts (the Wazuh rules for 4624 and 4634
# fire); their own systemTime is used, not the manager's arrival time.

SESSION_TYPES = {2, 7, 10, 11}
SESSION_CAP_S = 12 * 3600
SESSION_SKEW_S = 5
SYSTEM_ACCOUNT = re.compile(r"(.*\$|dwm-\d+|umfd-\d+|system|local service|network service|anonymous logon)$")


def parse_sessions_spec(specs):
    """["agent=ip,ip:acct,acct", ...] -> {agent: (set of ips, set of accounts)}"""
    out = {}
    for spec in specs:
        m = re.fullmatch(r"([^=]+)=([^:]+):(.+)", spec.strip())
        if not m:
            raise SystemExit(f"--fortigate-sessions {spec!r}: want AGENT=IP[,IP]:ACCOUNT[,ACCOUNT]")
        out[low(m[1])] = ({i.strip() for i in m[2].split(",") if i.strip()}, {low(u) for u in m[3].split(",") if u.strip()})
    return out


def win_time(x):
    """Windows systemTime (UTC, up to 7 fraction digits) -> epoch seconds"""
    m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z?", str(x or "").strip())
    d = rfc3339.parse(m[1] + "+00:00") if m else None
    return d.timestamp() + float("0" + (m[2] or "")) if d else None


def windows_logon_events(alerts, agents):
    """-> [(agent, epoch, "on"|"off", logon id, account, logon type)] from 4624, 4634, 4647"""
    out = []
    for a in alerts:
        agent = low((a.get("agent") or {}).get("name"))
        if agent not in agents:
            continue
        data = a.get("data") if isinstance(a.get("data"), dict) else {}
        win = data.get("win") if isinstance(data.get("win"), dict) else {}
        sysd = win.get("system") if isinstance(win.get("system"), dict) else {}
        ev = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
        eid = str(sysd.get("eventID", ""))
        if eid not in ("4624", "4634", "4647"):
            continue
        t = win_time(sysd.get("systemTime"))
        if t is None:
            d = rfc3339.parse(wazuh_ts(a.get("timestamp")) or "")
            t = d.timestamp() if d else None
        if t is None:
            continue
        out.append((agent, t, "on" if eid == "4624" else "off", str(ev.get("targetLogonId") or ""),
                    low(ev.get("targetUserName")), num(ev.get("logonType"))))
    return out


def build_sessions(logons, spec):
    """-> {agent: [(start, end, account)]} for the listed accounts, other people's time cut out; and stats"""
    opened, ended = {}, {}
    for agent, t, what, lid, acct, lt in sorted(logons, key=lambda x: x[1]):
        if what == "on":
            if lt in SESSION_TYPES and acct and not SYSTEM_ACCOUNT.fullmatch(acct) and (agent, lid) not in opened:
                opened[(agent, lid)] = (t, acct)
        elif (agent, lid) in opened and (agent, lid) not in ended:
            ended[(agent, lid)] = t
    mine, others, stats = collections.defaultdict(list), collections.defaultdict(list), collections.Counter()
    for (agent, lid), (t, acct) in opened.items():
        end = ended.get((agent, lid))
        capped = end is None or end - t > SESSION_CAP_S
        end = t + SESSION_CAP_S if capped else end
        if acct in spec[agent][1]:
            mine[agent].append((t - SESSION_SKEW_S, end + SESSION_SKEW_S, acct))
            stats[(agent, "sessions")] += 1
            stats[(agent, "capped at 12 h" if capped else "closed by logoff")] += 1
        else:
            others[agent].append((t - SESSION_SKEW_S, end + SESSION_SKEW_S))
    out = {}
    for agent in spec:
        pieces = []
        for s0, s1, acct in sorted(mine[agent]):
            segs = [(s0, s1)]
            for o0, o1 in others[agent]:
                segs = [p for a0, a1 in segs for p in ((a0, min(a1, o0)), (max(a0, o1), a1)) if p[1] > p[0]]
            pieces += [(a0, a1, acct) for a0, a1 in segs]
        out[agent] = sorted(pieces)
        stats[(agent, "other accounts' sessions")] = len(others[agent])
    return out, stats


class SessionFilter:
    def __init__(self, spec, sessions, stats):
        self.by_ip = {ip: agent for agent, (ips, _) in spec.items() for ip in ips}
        self.sessions, self.stats = sessions, stats

    def __call__(self, events):
        for e in events:
            agent = self.by_ip.get(e.get("src_ip", "")) if e.get("source") == "fortigate" else None
            if agent is None:
                yield e
                continue
            t = rfc3339.parse(e["ts"]).timestamp()
            if e["kind"] == "net.conn":
                t -= float(e.get("duration_s") or 0)
            hit = [acct for s0, s1, acct in self.sessions[agent] if s0 <= t <= s1]
            if hit:
                self.stats[(agent, "fortigate kept")] += 1
                if not e.get("user"):
                    e["user"] = hit[0]
                yield e
            else:
                self.stats[(agent, "fortigate dropped outside sessions")] += 1
        for (agent, what), n in sorted(self.stats.items()):
            print(f"fortigate-sessions {agent}: {what} {n}", file=sys.stderr)


def only_users(events, users):
    """drop events attributed to an account outside `users`; events without an account stay"""
    dropped = 0
    for e in events:
        if e.get("user") and e["user"] not in users:
            dropped += 1
            continue
        yield e
    if dropped:
        print(f"events: {dropped} event(s) of other accounts dropped (--only-users)", file=sys.stderr)


# ------------------------------------------------------------------ bitdefender

def from_bitdefender(path):
    for r in csv_rows(path):
        ts = wazuh_ts(r.get("created_Or_timestamp") or r.get("last_updated"))
        asset = low(r.get("computer_name") or r.get("computer_fqdn") or r.get("computer_ip"))
        if ts is None or not asset:
            continue
        e = {"ts": ts, "kind": "malware.detect", "user": low(r.get("username")), "src_host": asset, "asset": asset, "dst": asset, "source": "bitdefender",
             "rule_level": num(r.get("severity_score")), "category": low(r.get("module")), "incident": r.get("incident_id") or ""}
        if r.get("computer_ip"):
            e["src_ip"] = r["computer_ip"].strip()
        yield e


# ------------------------------------------------------------------ VictoriaLogs

def vl_query(vl, query, limit):
    data = urllib.parse.urlencode({"query": query, "limit": str(limit)}).encode()
    with urllib.request.urlopen(urllib.request.Request(vl.rstrip("/") + "/select/logsql/query", data=data), timeout=120) as r:
        for line in r.read().decode("utf-8", "replace").splitlines():
            if line.strip():
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


def from_vl(vl, window, fw_host, limit):
    """FortiGate traffic and utm from the 514 listener, SSH logins and
    failures from journald. The same shapes audit-report.py reads."""
    fw = f'hostname:={fw_host} ' if fw_host else ""
    for r in vl_query(vl, f'_time:{window} {fw}("type=\\"traffic\\"" OR "type=\\"utm\\"" OR "subtype=\\"vpn\\"")', limit):
        for e in from_fortigate_lines([r.get("_msg", "")]):
            yield e
    for r in vl_query(vl, f'_time:{window} SYSLOG_IDENTIFIER:in(sshd, sshd-session) ("Accepted " OR "Failed password")', limit):
        m = re.search(r"(Accepted|Failed) (\S+) for (?:invalid user )?(\S+) from (\S+)", r.get("_msg", ""))
        ts = rfc3339.format(rfc3339.parse(r.get("_time", ""))) if rfc3339.parse(r.get("_time", "")) else None
        if not m or ts is None:
            continue
        yield {"ts": ts, "kind": "auth.logon", "user": m.group(3), "src_host": m.group(4), "src_ip": m.group(4),
               "dst": r.get("_HOSTNAME", r.get("hostname", "")), "logon_type": "ssh",
               "result": "success" if m.group(1) == "Accepted" else "failure", "method": m.group(2), "source": "ad"}


# ------------------------------------------------------------------ cli

def spill_sort(events, spill_dir):
    """Time order without holding the events in memory: one file per UTC day,
    each sorted on its own, days in order. The spill holds real names and is
    removed afterwards."""
    os.makedirs(spill_dir, mode=0o700, exist_ok=True)
    handles = {}
    try:
        for e in events:
            day = e["ts"][:10]
            if day not in handles:
                handles[day] = open(os.path.join(spill_dir, day + ".jsonl"), "w", encoding="utf-8")
            handles[day].write(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n")
    finally:
        for h in handles.values():
            h.close()
    for day in sorted(handles):
        p = os.path.join(spill_dir, day + ".jsonl")
        with open(p, encoding="utf-8") as f:
            rows = [json.loads(line) for line in f]
        rows.sort(key=lambda e: e["ts"])
        yield from rows
        os.unlink(p)


def probe(events):
    by = collections.Counter(); users = set(); lo = hi = None
    for e in events:
        by[(e["kind"], e["source"])] += 1
        if e.get("user"):
            users.add(e["user"])
        lo = e["ts"] if lo is None or e["ts"] < lo else lo
        hi = e["ts"] if hi is None or e["ts"] > hi else hi
    print(f"{sum(by.values())} events, {len(users)} users, {lo} to {hi}")
    for (k, s), n in sorted(by.items()):
        print(f"  {k:12s} {s:10s} {n}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("load", "probe"):
        p = sub.add_parser(name)
        p.add_argument("--from-jsonl", action="append", default=[])
        p.add_argument("--zeek", action="append", default=[])
        p.add_argument("--fortigate", action="append", default=[])
        p.add_argument("--winsec", action="append", default=[])
        p.add_argument("--wazuh-csv", action="append", default=[])
        p.add_argument("--wazuh-tar", action="append", default=[], help="tar of the manager's logs/, or a mirror directory of it (alerts)")
        p.add_argument("--wazuh-archives", action="append", default=[], help="same, read for the QuLog connection lines in logs/archives")
        p.add_argument("--only-users", default="", help="comma-separated accounts; events of any other account are dropped at load")
        p.add_argument("--fortigate-sessions", action="append", default=[], metavar="AGENT=IP[,IP]:ACCOUNT[,ACCOUNT]",
                       help="keep that machine's FortiGate lines only while one of the accounts is logged on to it (Windows 4624/4634 in --wazuh-tar)")
        p.add_argument("--bitdefender", action="append", default=[])
        p.add_argument("--spill-dir", help="sort through per-day files here instead of in memory; holds real names until done")
        p.add_argument("--vl"); p.add_argument("--window", default="7d"); p.add_argument("--fw-host", default="")
        p.add_argument("--limit", type=int, default=500000)
        p.add_argument("--out", default="-")
    a = ap.parse_args()

    def gen():
        for p in a.from_jsonl:
            yield from from_jsonl(p)
        for p in a.zeek:
            yield from from_zeek(p)
        for p in a.fortigate:
            yield from from_fortigate(p)
        for p in a.winsec:
            yield from from_winsec(p)
        for p in a.wazuh_csv:
            yield from from_wazuh_csv(p)
        for p in a.wazuh_tar:
            yield from from_wazuh_tar(p, archives_too=bool(a.wazuh_archives))
        for p in a.wazuh_archives:
            yield from from_wazuh_archives(p)
        for p in a.bitdefender:
            yield from from_bitdefender(p)
        if a.vl:
            yield from from_vl(a.vl, a.window, a.fw_host, a.limit)

    src = check(gen())
    if a.fortigate_sessions:
        spec = parse_sessions_spec(a.fortigate_sessions)
        logons = [x for p in a.wazuh_tar for x in windows_logon_events(wazuh_tar_alerts(p), spec)]
        src = SessionFilter(spec, *build_sessions(logons, spec))(src)
    if a.only_users:
        src = only_users(src, {low(u) for u in a.only_users.split(",") if u.strip()})
    events = spill_sort(src, a.spill_dir) if a.spill_dir else sorted(src, key=lambda e: e["ts"])
    if a.cmd == "probe":
        probe(events)
    else:
        n = write_jsonl(a.out, events)
        if a.out != "-":
            print(f"wrote {n} events to {a.out}")


if __name__ == "__main__":
    main()
