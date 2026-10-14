# shellcheck shell=sh
# Shared helpers for the collector-side and drill-orchestrating scripts of
# 30ops. POSIX sh; GNU date or busybox date (both take -d @EPOCH).
#
#   HERE=$(cd "$(dirname "$0")" && pwd)
#   OPS30_SH=${OPS30_SH:-$HERE/../../lib/sh/ops30.sh}
#   # shellcheck source=../../lib/sh/ops30.sh
#   . "$OPS30_SH"
#
# Scripts that are copied to a node and run there on their own (canary.sh,
# share-canary.sh, nas-audit.sh, replica-verify.sh, the qnap remote.sh) do not
# source this file; see docs/lib.md.

# the checkout this file belongs to (OPS30_SH is set by the caller, see above)
OPS30_ROOT=${OPS30_ROOT:-$(cd "$(dirname "${OPS30_SH:?set OPS30_SH to this file before sourcing it}")/../.." && pwd)}

# Unix time now, UTC.
ops30_now() { date -u +%s; }

# EPOCH (default now) -> 2026-10-13T12:30:00Z
ops30_iso() { date -u -d "@${1:-$(ops30_now)}" +%Y-%m-%dT%H:%M:%SZ; }

# EPOCH or anything date -d understands -> EPOCH
ops30_to_epoch() {
  case "$1" in
    ''|*[!0-9]*) date -u -d "$1" +%s ;;
    *) printf '%s\n' "$1" ;;
  esac
}

# seconds since EPOCH
ops30_since() { printf '%d\n' "$(( $(ops30_now) - $1 ))"; }

# true once LIMIT seconds have passed since EPOCH
ops30_expired() { [ "$(ops30_since "$1")" -ge "$2" ]; }

# message to stderr, prefixed with the script name, exit 1
ops30_die() { printf '%s: %s\n' "${OPS30_PROG:-${0##*/}}" "$*" >&2; exit 1; }

# every argument must be a command on PATH
ops30_need() {
  for _c in "$@"; do
    command -v "$_c" >/dev/null 2>&1 || ops30_die "$_c not found"
  done
}

# FILE -> its sha256 in hex (sha256sum, else openssl)
ops30_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else openssl dgst -sha256 "$1" | awk '{print $NF}'; fi
}

# Append a drills.jsonl v1 record: ops30_drill --file F --kind K --label L ...
# (all options of `30ops drill record`). OPS30_BIN overrides the command.
ops30_drill() { "${OPS30_BIN:-$OPS30_ROOT/bin/30ops}" drill record "$@"; }

# FILE DOTTED.PATH -> that field of the last JSON line, as JSON (tests)
ops30_last_field() {
  python3 -I -c 'import json, sys
r = json.loads(open(sys.argv[1], encoding="utf-8").read().splitlines()[-1])
for k in sys.argv[2].split("."):
    r = r[k]
print(json.dumps(r, ensure_ascii=False))' "$1" "$2"
}
