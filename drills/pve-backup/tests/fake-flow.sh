#!/bin/sh
# fake-flow: runs canary.sh and restore-drill.sh end to end with fake
# qm, ping, nc and ssh, so the logic can be checked without a cluster.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
OPS30_SH=$ROOT/../../lib/sh/ops30.sh
# shellcheck source=../../../lib/sh/ops30.sh
. "$OPS30_SH"
field() { ops30_last_field "$OUT" "$1"; }

mkdir -p "$T/bin" "$T/canary"
export CANARY_DIR="$T/canary"

# fake guest: ssh runs the requested canary command locally
cat > "$T/bin/ssh" <<EOF
#!/bin/sh
for last; do :; done
exec sh -c "\$(printf '%s' "\$last" | sed 's#/usr/local/bin/canary.sh#$ROOT/canary.sh#')"
EOF
printf '#!/bin/sh\nexit 0\n' > "$T/bin/ok"
cat > "$T/bin/qm" <<'EOF'
#!/bin/sh
case "$1" in
  list) printf '      VMID NAME STATUS\n       104 drill-recovered running\n' ;;
  status) echo "status: running" ;;
esac
EOF
chmod +x "$T/bin/"*
export QM="$T/bin/qm" PING="$T/bin/ok" NC="$T/bin/ok" SSH="$T/bin/ssh" OUT="$T/drills.jsonl"

# guest state: payload, and a beat log with an older, larger gap (a
# shutdown) followed by the restore gap; the restore point must be the
# beat before the most recent gap, not before the largest one
dd if=/dev/urandom of="$CANARY_DIR/payload.bin" bs=1k count=64 status=none
sha256sum "$CANARY_DIR/payload.bin" | cut -d' ' -f1 > "$CANARY_DIR/payload.sha256"
now=$(date -u +%s)
beat() { printf '%s %s fake\n' "$1" "$(date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ)"; }
{
  beat $((now - 9000)); beat $((now - 8940))
  beat $((now - 3000)); beat $((now - 2940))   # 5940 s shutdown gap
  beat $((now - 2880))                          # restore point
} > "$CANARY_DIR/beats.log"
rp=$(date -u -d "@$((now - 2880))" +%Y-%m-%dT%H:%M:%SZ)
failed=$(date -u -d "@$((now - 2280))" +%Y-%m-%dT%H:%M:%SZ)

# 1. canary verify finds the most recent gap and the RPO
out=$("$ROOT/canary.sh" verify "$failed") || fail "verify rc=$?"
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q "^restore point     : $rp" || fail "wrong restore point"
printf '%s\n' "$out" | grep -q '^RPO (data lost)   : 600 s' || fail "wrong RPO"

# 2. restore-drill on PVE
"$ROOT/restore-drill.sh" 9001 192.0.2.10 --label pve --failed-at "$failed" --timeout 30 || fail "pve drill rc=$?"
case "$(field extra.t_exists),$(field extra.t_running)" in [01],[01]) ;; *) fail "pve json" ;; esac   # 1 when a second boundary passes
[ "$(field rpo_s)" = 600 ] || fail "pve json rpo"
[ "$(field kind),$(field result),$(field label)" = '"pve-backup","pass","pve"' ] || fail "pve json kind/result/label"

# 2b. --name resolves the VMID the restore tool assigned
"$ROOT/restore-drill.sh" auto 192.0.2.10 --name drill-recovered --label byname --timeout 30 || fail "name drill rc=$?"
[ "$(field extra.vmid)" = 104 ] || fail "name json vmid"

# 3. --no-pve never calls qm (a qm that always fails would time out)
QM=false "$ROOT/restore-drill.sh" 9002 192.0.2.10 --no-pve --label vs --timeout 30 || fail "no-pve drill rc=$?"
[ "$(field extra.t_exists),$(field extra.t_running)" = null,null ] || fail "no-pve json"
[ "$(field result)" = '"pass"' ] || fail "no-pve result"

# 4. corrupted payload ends the drill with rc 2
printf 'x' >> "$CANARY_DIR/payload.bin"
rc=0; "$ROOT/restore-drill.sh" 9003 192.0.2.10 --label bad --timeout 30 >/dev/null || rc=$?
[ "$rc" -eq 2 ] || fail "mismatch rc=$rc, want 2"
[ "$(field result)" = '"fail"' ] || fail "mismatch result"

# 5. no gap yet: verify says so and exits 1
sha256sum "$CANARY_DIR/payload.bin" | cut -d' ' -f1 > "$CANARY_DIR/payload.sha256"
now=$(date -u +%s)
{ beat $((now - 120)); beat $((now - 60)); } > "$CANARY_DIR/beats.log"
rc=0; "$ROOT/canary.sh" verify >/dev/null || rc=$?
[ "$rc" -eq 1 ] || fail "no-gap rc=$rc, want 1"

printf '\nall fake-flow checks passed\n'
