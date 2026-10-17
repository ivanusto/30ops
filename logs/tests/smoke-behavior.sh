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
echo "smoke-behavior OK"
