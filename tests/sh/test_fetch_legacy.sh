#!/bin/sh
# scripts/fetch-legacy.sh against a fake host: ssh and sudo are shims that
# run on this machine with / mapped to a copy of tests/fixtures/legacy-root.
# No secret value may reach the snapshot, and the snapshot must compare
# equal to the sample site's render.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
n=0
ok() { n=$((n + 1)); }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

FAKE=$tmp/host
cp -r "$ROOT/tests/fixtures/legacy-root" "$FAKE"
# a stale /etc/timezone, as on Ubuntu after timedatectl set-timezone
printf 'Etc/UTC\n' > "$FAKE/etc/timezone"
ln -s /usr/share/zoneinfo/Asia/Taipei "$FAKE/etc/localtime"
printf 'secret-pve-token-42\n' > "$FAKE/etc/fgt.token"
sed -i 's/REPLACE-WITH-TOKEN/secret-pve-token-42/' "$FAKE/opt/onprem-metrics/prometheus/pve.yml"
sed -i 's/REPLACE-AUTH-PASSPHRASE/secret-auth-42/; s/REPLACE-PRIV-PASSPHRASE/secret-priv-42/' \
  "$FAKE/opt/onprem-metrics/prometheus/snmp-auth.yml"
sed -i 's/"CHANGE_ME"/"secret-smtp-42"/' "$FAKE/opt/onprem-metrics/alertmanager/alertmanager.yml"

mkdir "$tmp/bin"
cat > "$tmp/bin/ssh" <<'EOF'
#!/bin/sh
# ssh -o BatchMode=yes DEST CMD...: run CMD here
shift 3
exec "$@"
EOF
cat > "$tmp/bin/sudo" <<EOF
#!/bin/sh
FAKE=$FAKE
EOF
cat >> "$tmp/bin/sudo" <<'EOF'
[ "$1" = -n ] && shift
if [ "$1" = sh ]; then
  sh -c "$(printf '%s' "$3" | sed "s# /# $FAKE/#g")" | sed "s#^$FAKE##"
  exit 0
fi
cmd=$1; shift; n=$#
for a do
  case $a in /*) a=$FAKE$a ;; esac
  set -- "$@" "$a"
done
shift "$n"
exec "$cmd" "$@"
EOF
chmod +x "$tmp/bin/ssh" "$tmp/bin/sudo"

PATH=$tmp/bin:$PATH sh "$ROOT/scripts/fetch-legacy.sh" ops@fake "$tmp/snap" > /dev/null
[ -f "$tmp/snap/FETCHED" ] || fail "no FETCHED"; ok
if grep -r 'secret-.*-42' "$tmp/snap" > /dev/null; then fail "a secret reached the snapshot: $(grep -rl 'secret-.*-42' "$tmp/snap")"; fi; ok
[ ! -e "$tmp/snap/etc/fgt.token" ] || fail "token file fetched"; ok
for f in etc/cron.d/onprem-logs etc/systemd/system/mnt-worm.mount etc/onprem-agent-gate/tools.json etc/30ops/assets.tsv \
         opt/onprem-metrics/prometheus/targets/gb10.yml; do
  cmp -s "$FAKE/$f" "$tmp/snap/$f" || fail "$f changed in transit"
done; ok
[ "$(cat "$tmp/snap/etc/timezone")" = Asia/Taipei ] || fail "timezone $(cat "$tmp/snap/etc/timezone"), not the /etc/localtime zone"; ok
grep -q '^  token_name: exporter$' "$tmp/snap/opt/onprem-metrics/prometheus/pve.yml" || fail "token_name masked"; ok
grep -q '^  token_value: "MASKED"$' "$tmp/snap/opt/onprem-metrics/prometheus/pve.yml" || fail "token_value not masked"; ok
grep -q 'smtp_auth_password: "MASKED"' "$tmp/snap/opt/onprem-metrics/alertmanager/alertmanager.yml" || fail "smtp password"; ok
out=$("$ROOT/bin/30ops" render --site "$ROOT/examples/sample-site/site.yaml" --compare-legacy "$tmp/snap" 2>&1) || fail "compare: $out"; ok
if PATH=$tmp/bin:$PATH sh "$ROOT/scripts/fetch-legacy.sh" ops@fake "$tmp/snap" 2>/dev/null; then fail "non-empty OUTDIR accepted"; fi; ok

echo "test_fetch_legacy: $n passed"
