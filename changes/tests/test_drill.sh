#!/bin/sh
# test_drill: drill.sh against a verification command that starts passing
# after a few seconds (OK, rto_s >= 4), one that never passes (-t 3, FAIL),
# argument checks, and the v1 record read back by collector/textfile/
# drills-textfile.py as source "changes".
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/logger" <<'EOF'
#!/bin/sh
echo "$@" >> "${LOGGER_LOG}"
EOF
chmod +x "$tmp/logger"
export DRILLS="$tmp/drills/drills.jsonl" LOGGER="$tmp/logger" LOGGER_LOG="$tmp/logger.log"
drill="$here/drills/drill.sh"

# 1. passes once the flag appears (4 s later): OK, rto_s between 4 and 10
( sleep 4; touch "$tmp/flag" ) &
NOTE='snapshot "before" reverted' sh "$drill" flag-appears CR-2026-0011 CR-2026-0001 -t 30 -- test -e "$tmp/flag" > "$tmp/1.out"
grep -q '^drill: flag-appears OK after [0-9]* s ([0-9]* checks)' "$tmp/1.out" || { cat "$tmp/1.out"; exit 1; }
line=$(tail -n 1 "$DRILLS")
python3 - "$line" <<'EOF'
import json, sys
r = json.loads(sys.argv[1])
assert r["v"] == 1 and r["kind"] == "change-rollback", r
assert r["label"] == "flag-appears" and r["cr"] == "CR-2026-0011" and r["rollback_of"] == "CR-2026-0001", r
assert r["result"] == "pass" and 4 <= r["rto_s"] <= 10 and r["extra"]["checks"] >= 2, r
assert r["extra"]["note"] == 'snapshot "before" reverted', r
assert r["t0"].endswith("Z") and len(r["t0"]) == 20, r
EOF
grep -q 'drill -p notice flag-appears start CR-2026-0011 rollback of CR-2026-0001' "$LOGGER_LOG" || { cat "$LOGGER_LOG"; exit 1; }
grep -q 'drill -p notice flag-appears OK CR-2026-0011 rto_s=' "$LOGGER_LOG" || { cat "$LOGGER_LOG"; exit 1; }

# 2. never passes: FAIL after the timeout, exit status 1
if sh "$drill" never CR-2026-0011 CR-2026-0004 -t 3 -- false > "$tmp/2.out"; then echo "FAIL drill must exit non-zero"; exit 1; fi
grep -q '^drill: never FAIL after [3-6] s' "$tmp/2.out" || { cat "$tmp/2.out"; exit 1; }
python3 - "$(tail -n 1 "$DRILLS")" <<'EOF' || { tail -n 1 "$DRILLS"; exit 1; }
import json, sys
r = json.loads(sys.argv[1])
assert (r["label"], r["cr"], r["rollback_of"], r["result"]) == ("never", "CR-2026-0011", "CR-2026-0004", "fail"), r
assert 3 <= r["rto_s"] <= 6, r
EOF

# 3. argument checks exit 64 and write nothing
n=$(wc -l < "$DRILLS")
for args in "" "x CR-2026-0011" "bad/label CR-2026-0011 CR-2026-0001 -- true" "ok CR-8 CR-2026-0001 -- true" "ok CR-2026-0011 CR-2026-0001 true" "ok CR-2026-0011 CR-2026-0001 --"; do
  # shellcheck disable=SC2086
  if sh "$drill" $args >/dev/null 2>&1; then echo "should reject: $args"; exit 1; fi
  # shellcheck disable=SC2086
  sh "$drill" $args >/dev/null 2>&1 || [ $? -eq 64 ] || { echo "exit 64 expected: $args"; exit 1; }
done
[ "$(wc -l < "$DRILLS")" = "$n" ] || { echo "rejected runs must not write"; exit 1; }

# 4. collector/textfile/drills-textfile.py reads the file as source "changes"
python3 "$here/../collector/textfile/drills-textfile.py" "changes=$DRILLS" > "$tmp/drills.prom"
grep -q '^drill_last_result{source="changes",label="flag-appears"} 1$' "$tmp/drills.prom" || { cat "$tmp/drills.prom"; exit 1; }
grep -q '^drill_last_result{source="changes",label="never"} 0$' "$tmp/drills.prom" || { cat "$tmp/drills.prom"; exit 1; }
grep -q '^drill_last_success_timestamp{source="changes",label="flag-appears"} ' "$tmp/drills.prom" || { cat "$tmp/drills.prom"; exit 1; }
grep -q '^drill_last_rto_seconds{source="changes",label="never"} [3-6]$' "$tmp/drills.prom" || { cat "$tmp/drills.prom"; exit 1; }
echo "test_drill: OK"
