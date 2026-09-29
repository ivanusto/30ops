#!/bin/sh
# record.sh: timestamped log for a drill. Every 2 s, one line with the
# check.sh exit code, votes, and the state of one HA resource.
#
#   ./record.sh <label> [ha-sid]      e.g. ./record.sh drill2 vm:900
#
# Writes /root/drills/<label>.log. Run it under systemd-run so it outlives
# the SSH session:  systemd-run --unit=drill2 ./record.sh drill2 vm:900
set -u
L="${1:?usage: $0 <label> [ha-sid]}"
SID="${2:-}"
DIR=$(cd "$(dirname "$0")" && pwd)
mkdir -p /root/drills
OUT=/root/drills/$L.log
while :; do
    S=$("$DIR/check.sh" 2>&1); RC=$?
    V=""
    [ -n "$SID" ] && V=" $SID=$(ha-manager status 2>/dev/null | awk -v s="$SID" '$2 == s {print $3 $4}' | tr -d '()')"
    echo "$(date '+%F %T') rc=$RC $(echo "$S" | head -1)$V" >> "$OUT"
    sync "$OUT" 2>/dev/null
    sleep 2
done
