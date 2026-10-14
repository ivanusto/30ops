#!/bin/sh
# lib/sh/ops30.sh: every helper, plus ops30_drill writing a valid v1 record.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OPS30_SH=$ROOT/lib/sh/ops30.sh
# shellcheck source=../../lib/sh/ops30.sh
. "$OPS30_SH"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
n=0
ok() { n=$((n + 1)); }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[ "$OPS30_ROOT" = "$ROOT" ] || fail "OPS30_ROOT=$OPS30_ROOT"; ok
[ "$(ops30_iso 1791894600)" = 2026-10-13T12:30:00Z ] || fail iso; ok
case "$(ops30_iso)" in 20[0-9][0-9]-*Z) ;; *) fail "iso now" ;; esac; ok
[ "$(ops30_to_epoch 2026-10-13T12:30:00Z)" = 1791894600 ] || fail to_epoch; ok
[ "$(ops30_to_epoch 1791894600)" = 1791894600 ] || fail "to_epoch number"; ok
t=$(( $(ops30_now) - 5 ))
s=$(ops30_since "$t")
if [ "$s" -lt 5 ] || [ "$s" -gt 7 ]; then fail "since $s"; fi; ok
ops30_expired "$t" 3 || fail "expired"; ok
! ops30_expired "$t" 60 || fail "not expired"; ok
printf 'abc' > "$tmp/f"
[ "$(ops30_sha256 "$tmp/f")" = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ] || fail sha256; ok
rc=0; msg=$(OPS30_SH=$OPS30_SH OPS30_PROG=t sh -c '. "$OPS30_SH"; ops30_die "boom"' 2>&1) || rc=$?
[ "$rc" -eq 1 ] || fail "die rc=$rc"
[ "$msg" = "t: boom" ] || fail "die message $msg"; ok
rc=0; msg=$(OPS30_SH=$OPS30_SH OPS30_PROG=t sh -c '. "$OPS30_SH"; ops30_need sh no-such-command-30ops' 2>&1) || rc=$?
[ "$rc" -eq 1 ] || fail "need rc=$rc"
[ "$msg" = "t: no-such-command-30ops not found" ] || fail "need message $msg"; ok

ops30_drill --file "$tmp/d.jsonl" --kind qdevice --label 'q "x"' --result partial --rto-s 3 --extra-str note=hi
[ "$(ops30_last_field "$tmp/d.jsonl" label)" = '"q \"x\""' ] || fail "drill label"; ok
[ "$(ops30_last_field "$tmp/d.jsonl" extra.note)" = '"hi"' ] || fail "drill extra"; ok
"$ROOT/bin/30ops" drill migrate "$tmp/d.jsonl" > /dev/null || fail "record does not validate"; ok
if ops30_drill --file "$tmp/d.jsonl" --kind qdevice --label x --result OK 2>/dev/null; then fail "bad result accepted"; fi; ok
[ "$(wc -l < "$tmp/d.jsonl")" -eq 1 ] || fail "rejected record written"; ok

echo "test_ops30_sh: $n passed"
