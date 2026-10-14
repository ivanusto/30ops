# Piped to `sh -s` on the NAS by the qnap adapter's health capability; nothing
# is copied to the NAS and a non-root key is enough for zfs and zpool.
# Prints raw sections, one "@@name" line before each; the adapter parses
# them. "@@end" comes last, so output cut short by a dropped session is
# recognised and reported as nas_up 0 instead of half a textfile.
# NAS_BUDDYINFO and NAS_PROC_STAT replace the /proc paths (tests).
set -u
echo "@@now $(date -u +%s)"
ok=0
if command -v zpool >/dev/null 2>&1 && zpool list -Hp -o name >/dev/null 2>&1; then ok=1; fi
echo "@@ok $ok"
echo "@@pagesize $(getconf PAGESIZE 2>/dev/null || echo 4096)"
B="${NAS_BUDDYINFO:-/proc/buddyinfo}"
if [ -r "$B" ]; then
  echo "@@buddyinfo"
  cat "$B"
fi
echo "@@stat"
awk '/^btime / { print }' "${NAS_PROC_STAT:-/proc/stat}" 2>/dev/null
if [ "$ok" = 1 ]; then
  echo "@@zpool"
  zpool list -Hp -o name,size,alloc,cap,health 2>/dev/null
  echo "@@zfs"
  zfs list -Hp -t filesystem,volume -o name,used 2>/dev/null
  echo "@@snapshots"
  zfs list -Hp -t snapshot -o name,creation,used 2>/dev/null
  echo "@@hbs"
  getcfg HybridBackup Version -f /etc/config/qpkg.conf 2>/dev/null
fi
echo "@@end"
exit 0
