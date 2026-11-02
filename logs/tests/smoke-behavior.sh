#!/bin/sh
# smoke-behavior: the behaviour pipeline on a synthetic site with the rules
# backend, no model and no VictoriaLogs needed.
#   1. run.sh leaves every file; the schedule has all six scenarios
#   2. nothing after pseudonymize.py carries a raw account, host or address
#   3. the same key gives the same output twice; strict floors time to the hour
#   4. the detection chain verifies, a changed line breaks it, a second run
#      into the same directory is refused
#   5. the rules baseline finds most injections with a low false positive
#      rate per user-day, the report and the textfile carry the numbers
#   6. events.py reads a Zeek conn.log and FortiGate lines into the schema
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
B="$here/behavior"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

sh "$B/run.sh" --out "$tmp/run" --users 24 --days 28 --baseline-days 21 --bootstrap 200 >"$tmp/run.log"
for f in raw/events.jsonl raw/schedule.tsv raw/site.json events.p.jsonl schedule.p.tsv summaries.jsonl baseline.json detections.jsonl run-manifest.json report.md metrics.json behavior.prom timing.jsonl; do
  [ -s "$tmp/run/$f" ] || fail "missing $f"
done
for s in S1 S2 S3 S4 S5 S6; do grep -q "	$s	" "$tmp/run/raw/schedule.tsv" || fail "schedule lacks $s"; done

# 2. raw names must not survive: every user and workstation of site.json, the address ranges, the share names
python3 - "$tmp/run" <<'PY'
import json, sys, re
d = sys.argv[1]
site = json.load(open(d + "/raw/site.json", encoding="utf-8"))
names = {u["name"] for u in site["users"]} | {u["ws"] for u in site["users"]} | set(site["servers"]) | {"svc-backup"}
pat = re.compile(r"\b(" + "|".join(map(re.escape, sorted(names))) + r")\b|192\.0\.2\.|198\.51\.100\.|example\.net\b(?!$)")
for f in ("events.p.jsonl", "schedule.p.tsv", "summaries.jsonl", "detections.jsonl", "report.md"):
    txt = open(f"{d}/{f}", encoding="utf-8").read()
    m = pat.search(txt)
    if m and not (f == "events.p.jsonl" and m.group(0) == "example.net"):   # standard level keeps the registered domain
        sys.exit(f"FAIL: raw name {m.group(0)!r} in {f}")
print("no raw names after pseudonymize")
PY

# 3. deterministic for one key; strict floors the hour
python3 "$B/pseudonymize.py" --demo-key --in "$tmp/run/raw/events.jsonl" --out "$tmp/again.jsonl" 2>/dev/null
cmp -s "$tmp/run/events.p.jsonl" "$tmp/again.jsonl" || fail "pseudonymize not deterministic"
python3 "$B/pseudonymize.py" --demo-key --level strict --in "$tmp/run/raw/events.jsonl" --out "$tmp/strict.jsonl" 2>/dev/null
grep -qv '"ts":"[0-9T:-]*:00:00Z"' "$tmp/strict.jsonl" && fail "strict level left minutes in a timestamp"
grep -q '"dst_name":"\[' "$tmp/strict.jsonl" || fail "strict level kept a domain name"
python3 "$B/pseudonymize.py" --in "$tmp/run/raw/events.jsonl" --out "$tmp/nokey.jsonl" 2>/dev/null && fail "ran without a key"

# 4. the chain
python3 "$B/detect.py" verify --in "$tmp/run/detections.jsonl" >/dev/null || fail "chain does not verify"
sed '3s/"risk":[0-9]*/"risk":1/' "$tmp/run/detections.jsonl" >"$tmp/tampered.jsonl"
cmp -s "$tmp/run/detections.jsonl" "$tmp/tampered.jsonl" && sed '3s/"verdict":"[A-Z]*"/"verdict":"NORMAL"/' "$tmp/run/detections.jsonl" >"$tmp/tampered.jsonl"
python3 "$B/detect.py" verify --in "$tmp/tampered.jsonl" >/dev/null 2>&1 && fail "tampered chain verified"
python3 "$B/detect.py" run --in "$tmp/run/summaries.jsonl" --out "$tmp/run/detections.jsonl" --backend rules >/dev/null 2>&1 && fail "appended to an existing chain without --append"
sh "$B/run.sh" --out "$tmp/run" >/dev/null 2>&1 && fail "run.sh reused a non-empty directory"

# 5. the numbers
python3 - "$tmp/run/metrics.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
o = m["overall"]
assert m["positives"] >= 20, m["positives"]
assert o["recall"] >= 0.6, o
assert o["fpr"] <= 0.03, o
assert 0 <= m["ci95"]["f1"][0] <= o["f1"] <= m["ci95"]["f1"][1] <= 1, (o["f1"], m["ci95"]["f1"])
assert m["stage2"]["calls"] < m["user_days"], "stage 2 saw every user-day"
assert m["per_scenario"]["S6"]["detected"] >= 3, m["per_scenario"]["S6"]
print(f"rules baseline: P {o['precision']:.2f} R {o['recall']:.2f} F1 {o['f1']:.2f} FPR {o['fpr']:.4f}, stage2 {m['stage2']['calls']}/{m['user_days']}")
PY
grep -q '^behavior_f1 ' "$tmp/run/behavior.prom" || fail "textfile lacks behavior_f1"
grep -q '^behavior_scenario_recall{scenario="S3"} ' "$tmp/run/behavior.prom" || fail "textfile lacks per-scenario recall"
grep -q '## 六類情境' "$tmp/run/report.md" || fail "report lacks the scenario table"
grep -q '"prompt1_sha256"' "$tmp/run/run-manifest.json" || fail "manifest lacks the prompt hash"

# 6. loaders
printf '#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\n1759000000.5\tC1\t192.0.2.21\t50000\t203.0.113.30\t443\ttcp\tssl\t600.0\t900000000\t2000000\n' >"$tmp/conn.log"
printf 'date=2026-09-30 time=23:33:10 tz="+0800" devname="fgt" type="traffic" subtype="forward" srcip=192.0.2.21 srcname="ws-021" user="sa-008" dstip=203.0.113.31 dstport=587 proto=6 service="SMTP" action="accept" sentbyte=965000000 rcvdbyte=10000 duration=1800 catdesc="Web-based Email" hostname="webmail-personal.example.net"\n' >"$tmp/fgt.log"
printf 'date=2026-09-30 time=12:00:00 tz="+0800" devname="fgt" type="utm" subtype="webfilter" srcip=192.0.2.30 user="op-033" dstip=203.0.113.41 hostname="vpn-free.example.net" catdesc="Proxy Avoidance" action="blocked"\n' >>"$tmp/fgt.log"
python3 "$B/events.py" load --zeek "$tmp/conn.log" --fortigate "$tmp/fgt.log" --out "$tmp/loaded.jsonl" >/dev/null
[ "$(wc -l <"$tmp/loaded.jsonl" | tr -d ' ')" = 3 ] || fail "loaders produced $(wc -l <"$tmp/loaded.jsonl") events, want 3"
grep -q '"kind":"net.conn".*"source":"zeek"' "$tmp/loaded.jsonl" || fail "zeek conn not loaded"
grep '"ts":"2026-09-30T15:33:10Z"' "$tmp/loaded.jsonl" | grep '"kind":"net.conn"' | grep -q '"user":"sa-008"' || fail "fortigate traffic time or user wrong"
grep -q '"kind":"fw.utm".*"action":"block"' "$tmp/loaded.jsonl" || fail "fortigate utm not loaded"

# a SIEM site: alerts and an endpoint product, no schedule; host-days, triage, overlay
python3 - "$tmp" <<'PYEOF2'
import csv, datetime as dt, gzip, io, json, os, random, sys, tarfile
tmp = sys.argv[1]
rnd = random.Random(3)
cols = ["timestamp", "agent_id", "agent_name", "agent_ip", "rule_id", "rule_level", "rule_description", "rule_groups", "decoder", "srcip", "srcuser", "dstuser", "mitre_id", "mitre_tactic", "location", "full_log"]
alerts = []
day = dt.date(2026, 5, 1)
for d in range(120):
    for agent in ("web01.corp.example.net", "mail01.corp.example.net", "db01.corp.example.net"):
        ts = lambda h: f"{day + dt.timedelta(days=d)}T{h:02d}:{rnd.randrange(60):02d}:00.000+0000"
        for _ in range(rnd.randrange(5, 12)):
            ip = f"203.0.113.{rnd.randrange(1, 250)}"
            alerts.append(dict(timestamp=ts(rnd.randrange(24)), agent_name=agent, rule_id="31101", rule_level="5", rule_description="scan seen on " + agent, rule_groups="web,recon,web_scan", decoder="web-accesslog", srcip=ip,
                               full_log=f'{ip} - - "GET /a?token=abc123 HTTP/1.1" 404 admin@corp.example.net', location="/var/log/apache2/access.log"))
        alerts.append(dict(timestamp=ts(2), agent_name=agent, rule_id="5715", rule_level="3", rule_description="login", rule_groups="syslog,sshd,authentication_success", decoder="sshd", srcip="198.51.100.7", dstuser="carol",
                           full_log=f"sshd: Accepted publickey for carol from 198.51.100.7 on {agent}", location="journald"))
with open(f"{tmp}/wazuh.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, cols, restval=""); w.writeheader(); [w.writerow(a) for a in alerts]
with open(f"{tmp}/bd.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, ["created_Or_timestamp", "module", "computer_name", "computer_fqdn", "computer_ip", "username", "incident_id", "severity_score", "process_path", "detection_name", "last_updated"], restval="")
    w.writeheader(); w.writerow({"created_Or_timestamp": "2026-08-20T01:00:00.000Z", "module": "edr", "computer_name": "DB01", "computer_ip": "198.51.100.20", "username": "CORP\\\\dave", "incident_id": "inc-1", "severity_score": "80", "process_path": "C:\\\\Users\\\\dave\\\\x.exe"})
def alert_obj(a):
    return {"timestamp": a["timestamp"], "agent": {"name": a["agent_name"], "ip": "198.51.100.3"}, "rule": {"id": a["rule_id"], "level": int(a["rule_level"]), "groups": a["rule_groups"].split(","), "description": a["rule_description"]},
            "decoder": {"name": a["decoder"]}, "data": {k: a[k] for k in ("srcip", "dstuser") if a.get(k)}, "full_log": a["full_log"], "location": a["location"]}
buf = gzip.compress("".join(json.dumps(alert_obj(a)) + "\n" for a in alerts).encode())
with tarfile.open(f"{tmp}/raw.tar.gz", "w:gz") as t:
    for name, data in (("var/ossec/logs/alerts/2026/May/ossec-alerts-01.json.gz", buf), ("var/ossec/logs/api/2026/May/api.log-01.gz", b"not read"), ("onprem/vsphere.env", b"SHOULD_NOT_BE_READ=1")):
        ti = tarfile.TarInfo(name); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
print(len(alerts))
PYEOF2
openssl rand -hex 32 >"$tmp/k"; chmod 0400 "$tmp/k"
python3 "$B/scrub.py" dict --csv "$tmp/wazuh.csv:agent_name,dstuser=user,srcuser=user" --csv "$tmp/bd.csv:computer_name" --wazuh-tar "$tmp/raw.tar.gz" --out "$tmp/terms.jsonl" >/dev/null
python3 "$B/scrub.py" csv --key-file "$tmp/k" --terms "$tmp/terms.jsonl" --in "$tmp/wazuh.csv" --out "$tmp/wazuh.deid.csv.gz" --policy wazuh --templates "$tmp/t.tsv" >/dev/null
python3 "$B/scrub.py" csv --key-file "$tmp/k" --terms "$tmp/terms.jsonl" --in "$tmp/bd.csv" --out "$tmp/bd.deid.csv.gz" --policy bitdefender >/dev/null
python3 "$B/scrub.py" wazuh --key-file "$tmp/k" --terms "$tmp/terms.jsonl" --in "$tmp/raw.tar.gz" --out "$tmp/alerts.deid.jsonl.gz" --which alerts >/dev/null
python3 "$B/scrub.py" verify --terms "$tmp/terms.jsonl" "$tmp/wazuh.deid.csv.gz" "$tmp/bd.deid.csv.gz" "$tmp/alerts.deid.jsonl.gz" >/dev/null || fail "dictionary terms left after scrub"
if gzip -dc "$tmp/wazuh.deid.csv.gz" "$tmp/alerts.deid.jsonl.gz" | grep -Eq 'abc123|admin@|corp\.example'; then fail "query string, mail or domain left after scrub"; fi
if gzip -dc "$tmp/bd.deid.csv.gz" | grep -q dave; then fail "account left in the endpoint export"; fi
python3 "$B/events.py" load --wazuh-tar "$tmp/raw.tar.gz" --bitdefender "$tmp/bd.csv" --spill-dir "$tmp/spill" --out "$tmp/siem.jsonl" >/dev/null
python3 "$B/events.py" load --wazuh-csv "$tmp/wazuh.csv" --out "$tmp/siem-csv.jsonl" >/dev/null
[ "$(($(wc -l <"$tmp/siem.jsonl") - 1))" = "$(wc -l <"$tmp/siem-csv.jsonl" | tr -d ' ')" ] || fail "csv and raw json disagree on the alert count"
python3 "$B/pseudonymize.py" --key-file "$tmp/k" --level standard --in "$tmp/siem.jsonl" --out "$tmp/siem.p.jsonl" --timing "$tmp/siem.timing" >/dev/null
if grep -Eq 'carol|web01|dave|example' "$tmp/siem.p.jsonl"; then fail "a real name in the pseudonymized siem events"; fi
python3 "$B/summarize.py" --entity host --exclude-kinds malware.detect --in "$tmp/siem.p.jsonl" --out "$tmp/siem.s.jsonl" --baseline-until 2026-07-15 >/dev/null
python3 "$B/detect.py" run --entity host --in "$tmp/siem.s.jsonl" --out "$tmp/siem.d.jsonl" --backend rules --manifest "$tmp/siem.m.json" >/dev/null
python3 "$B/evaluate.py" --triage --detections "$tmp/siem.d.jsonl" --events "$tmp/siem.p.jsonl" --out "$tmp/siem.r.md" --json "$tmp/siem.m2.json" >/dev/null
if grep -q '^| F1' "$tmp/siem.r.md"; then fail "a triage report must not print F1"; fi
if python3 "$B/evaluate.py" --detections "$tmp/siem.d.jsonl" --out "$tmp/x.md" 2>/dev/null; then fail "evaluate must refuse to score without a schedule"; fi
python3 "$B/overlay.py" --in "$tmp/siem.p.jsonl" --out "$tmp/siem.o.jsonl" --schedule "$tmp/siem.sch.tsv" --from 2026-07-15 --to 2026-08-28 --per-scenario 4 >/dev/null
python3 "$B/summarize.py" --entity host --exclude-kinds malware.detect --in "$tmp/siem.o.jsonl" --out "$tmp/siem.os.jsonl" --baseline-until 2026-07-15 >/dev/null
python3 "$B/detect.py" run --entity host --in "$tmp/siem.os.jsonl" --out "$tmp/siem.od.jsonl" --backend rules --t1 3 --t2 3 >/dev/null
python3 "$B/evaluate.py" --detections "$tmp/siem.od.jsonl" --schedule "$tmp/siem.sch.tsv" --out "$tmp/siem.or.md" --json "$tmp/siem.om.json" --cluster --bootstrap 100 >/dev/null
python3 -c "
import json, sys
m = json.load(open(sys.argv[1]))
assert m['positives'] == 12, m['positives']
assert m['overall']['recall'] >= 0.8, m['overall']
print('siem overlay rules: R %.2f P %.2f' % (m['overall']['recall'], m['overall']['precision']))
" "$tmp/siem.om.json" || fail "overlay injections do not reach the summaries"
echo "smoke-behavior OK"
