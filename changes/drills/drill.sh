#!/bin/sh
# drill: time a rollback. Start it the moment the rollback begins (the
# snapshot revert is clicked, the PUT is sent, `docker compose up` runs);
# it polls a verification command every 2 s until that command exits 0,
# then appends one JSON line to drills/drills.jsonl in this repository, in
# the shape Day 16 to 18 use. The line is committed with the drill record;
# the collector's clone (collector.cron) is what onprem-metrics'
# drills-textfile.py reads as source "changes", so Day 20's DrillFailed /
# DrillStale rules cover rollbacks too, and changes-textfile.py turns
# rollback_of into change_rollback_last_drill_* per record.
#
#   drill.sh <label> <drill CR> <rollback of CR> [-t SECONDS] -- <verify command...>
#
#   drill.sh qdevice-snapshot-revert CR-2026-0011 CR-2026-0001 -t 600 -- \
#       sh -c 'ssh root@pve1 /root/pve-qdevice-on-qnap/check.sh && ssh qdevice test ! -e /var/tmp/CR-2026-0011-marker'
#
# Output line (DRILLS, default drills/drills.jsonl next to this script)
#   {"t0":"2026-10-12T14:00:00Z","label":"qdevice-snapshot-revert","cr":"CR-2026-0011",
#    "rollback_of":"CR-2026-0001","result":"OK","rto_s":47,"checks":24,"note":"..."}
#
# rto_s is the wall-clock time from start to the first passing check, so it
# includes the human steps between. result is FAIL when -t SECONDS (default
# 900, Day 16's RTO target) pass without a passing check. The start and the
# end are also written to the journal with tag "drill" (LOGGER for tests),
# which Day 27's audit report sees next to the change marks.
#
#   NOTE="..." adds a free-text note to the line.
set -u

DRILLS=${DRILLS:-$(cd "$(dirname "$0")" && pwd)/drills.jsonl}
LOGGER=${LOGGER:-logger}
timeout=900
label=${1:-}; cr=${2:-}; of=${3:-}
if [ -z "$label" ] || [ -z "$cr" ] || [ -z "$of" ]; then sed -n '2,27p' "$0"; exit 64; fi
shift 3
if [ "${1:-}" = -t ]; then timeout=$2; shift 2; fi
[ "${1:-}" = -- ] || { echo "verify command must follow --" >&2; exit 64; }
shift
[ $# -gt 0 ] || { echo "verify command is empty" >&2; exit 64; }
case "$label" in *[!A-Za-z0-9_.-]*) echo "label: letters, digits, . _ - only" >&2; exit 64 ;; esac
for c in "$cr" "$of"; do
  case "$c" in CR-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]) ;; *) echo "$c is not CR-YYYY-NNNN" >&2; exit 64 ;; esac
done

t0=$(date +%s)
t0_iso=$(date -u -d "@$t0" +%Y-%m-%dT%H:%M:%SZ)
"$LOGGER" -t drill -p notice "$label start $cr rollback of $of"
echo "drill: $label started $t0_iso, waiting for: $*"
checks=0; result=FAIL; rto=""
while :; do
  checks=$((checks + 1))
  if "$@" >/dev/null 2>&1; then
    result=OK; rto=$(( $(date +%s) - t0 )); break
  fi
  if [ $(( $(date +%s) - t0 )) -ge "$timeout" ]; then
    rto=$(( $(date +%s) - t0 )); break
  fi
  sleep 2
done
"$LOGGER" -t drill -p notice "$label $result $cr rto_s=$rto"
mkdir -p "$(dirname "$DRILLS")"
note=$(printf '%s' "${NOTE:-}" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf '{"t0":"%s","label":"%s","cr":"%s","rollback_of":"%s","result":"%s","rto_s":%s,"checks":%s,"note":"%s"}\n' \
  "$t0_iso" "$label" "$cr" "$of" "$result" "$rto" "$checks" "$note" >> "$DRILLS"
echo "drill: $label $result after $rto s ($checks checks) -> $DRILLS"
[ "$result" = OK ]
