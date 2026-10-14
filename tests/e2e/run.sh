#!/bin/sh
# run.sh: the 30ops end-to-end test, on a disposable Ubuntu 24.04 host.
#
#   sudo OPS30_E2E_DISPOSABLE=1 tests/e2e/run.sh 30ops-X.Y.Z.tar.gz
#
# The host becomes the collector of tests/e2e/site.yaml: the release
# tarball goes to /opt/30ops, `30ops install collector` sets it up, and the
# fake LAN of tests/e2e/fakes/netns.sh stands in for the NAS, the PVE
# nodes, the FortiGate and the alert receiver. Then:
#   1. a second install changes nothing
#   2. every target is up, the metric names of expected-metrics.txt exist,
#      every rendered alerting rule is loaded
#   3. nas-primary's pool goes DEGRADED: NasPoolNotOnline reaches the
#      webhook receiver through Alertmanager
#   4. syslog from the NAS, the FortiGate event log and the collector's own
#      journal land in VictoriaLogs; a sender off the allowlist is dropped
#   5. the day is archived to the WORM share over NFS and verified
#   6. doctor: no failure, warnings only as allowed-warn.txt says
#   7. the containers use less than 3 GiB together
# It changes the host for good (accounts, /etc/30ops, cron, docker, an NFS
# export), so it refuses to run without OPS30_E2E_DISPOSABLE=1. Evidence
# goes to $OUT (default /var/tmp/ops30e2e); $OUT/summary.txt has the result.
set -eu
TARBALL=${1:?usage: OPS30_E2E_DISPOSABLE=1 run.sh 30ops-X.Y.Z.tar.gz}
OUT=${OUT:-/var/tmp/ops30e2e}
R=/opt/30ops
SITE=/opt/30ops-site/site.yaml
MEM_LIMIT=$((3 * 1024 * 1024 * 1024))
T0=$(date +%s)

die() { echo "run.sh: $*" >&2; exit 2; }
[ "${OPS30_E2E_DISPOSABLE:-}" = 1 ] || die "this changes the host for good; set OPS30_E2E_DISPOSABLE=1 on a throwaway host"
[ "$(id -u)" = 0 ] || die "run as root"
[ -f "$TARBALL" ] || die "no tarball $TARBALL"
TARBALL=$(readlink -f "$TARBALL")

rm -rf "$OUT"
mkdir -p "$OUT"
step() { printf '\n== %s (%ss)\n' "$*" "$(( $(date +%s) - T0 ))"; }
fail() { printf 'FAIL: %s\n' "$*" | tee -a "$OUT/summary.txt"; exit 1; }
ops30() { (cd "$R" && bin/30ops "$@"); }
check() { python3 "$R/tests/e2e/check.py" "$@"; }

collect() {
  rc=$?
  set +e
  cp /etc/cron.d/30ops "$OUT/cron.d-30ops" 2>/dev/null
  cp -r /run/ops30e2e/*.log /run/ops30e2e/webhook.jsonl "$OUT/" 2>/dev/null
  mkdir -p "$OUT/var-log-30ops" && cp /var/log/30ops/* "$OUT/var-log-30ops/" 2>/dev/null
  cp /var/lib/node_exporter/textfile/*.prom "$OUT/" 2>/dev/null
  docker compose -p 30ops logs --no-color > "$OUT/compose.log" 2>&1
  curl -fsS 'http://127.0.0.1:9090/api/v1/targets?state=active' > "$OUT/targets.json" 2>/dev/null
  curl -fsS http://127.0.0.1:9090/api/v1/alerts > "$OUT/prometheus-alerts.json" 2>/dev/null
  curl -fsS http://127.0.0.1:9093/api/v2/alerts > "$OUT/alertmanager-alerts.json" 2>/dev/null
  journalctl -b --no-pager -u mnt-worm.mount -u 30ops-allowlist -u systemd-journal-upload -u nfs-server > "$OUT/units.log" 2>&1
  printf 'exit %s after %ss\n' "$rc" "$(( $(date +%s) - T0 ))" >> "$OUT/summary.txt"
  chmod -R a+rX "$OUT"
}
trap collect EXIT

# ---------------------------------------------------------------------------
step "packages"
timedatectl set-timezone Asia/Taipei
pkgs="python3-yaml git openssh-server nfs-kernel-server snmpd snmp netcat-openbsd curl"
command -v docker >/dev/null 2>&1 || pkgs="$pkgs docker.io"
docker compose version >/dev/null 2>&1 || pkgs="$pkgs docker-compose-v2"
DEBIAN_FRONTEND=noninteractive apt-get update -qq
# shellcheck disable=SC2086 # a list of package names
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pkgs >/dev/null
# the packaged daemons stay out of the way of the fakes in the namespace
systemctl disable --now snmpd ssh.socket 2>/dev/null || true
docker --version && docker compose version

step "the release tarball at $R"
rm -rf "$R" && mkdir -p "$R"
tar xzf "$TARBALL" -C "$R" --strip-components=1
v=$(cat "$R/VERSION")
[ "$(ops30 --version)" = "30ops $v" ] || fail "bin/30ops --version is not 30ops $v"
echo "30ops $v from $(basename "$TARBALL") ($(sha256sum "$TARBALL" | cut -c1-12))"

step "site, secrets, changes upstream, fake LAN"
mkdir -p /opt/30ops-site
cp "$R/tests/e2e/site.yaml" "$R/tests/e2e/assets.tsv" /opt/30ops-site/
install -d -m 0750 /etc/30ops /etc/30ops/secrets
rnd() { head -c 18 /dev/urandom | base64 | tr -d '/+='; }
for s in pve-exporter.token snmp-auth.pass snmp-priv.pass fortigate-api.token; do
  [ -s "/etc/30ops/secrets/$s" ] || { umask 077; rnd > "/etc/30ops/secrets/$s"; }
done
sh "$R/tests/fakes/changes-repo.sh"
"$R/tests/e2e/fakes/netns.sh" down >/dev/null 2>&1 || true
"$R/tests/e2e/fakes/netns.sh" up

# ---------------------------------------------------------------------------
step "install collector, first run"
ops30 install collector --site "$SITE" --create-volumes | tee "$OUT/install-1.log"
grep -q '^30ops install collector: .* change(s)' "$OUT/install-1.log" || fail "install collector did not finish"
grep -q 'failed$' "$OUT/install-1.log" && fail "install collector: a step failed"

# what install prints for the operator: authorize the collector's key on
# the NAS and the PVE nodes, pin their host keys as metrics
home=$(getent passwd metrics | cut -d: -f6)
"$R/tests/e2e/fakes/netns.sh" authorize ops30 "$home/.ssh/id_ed25519.pub"
"$R/tests/e2e/fakes/netns.sh" authorize root "$home/.ssh/id_ed25519.pub"
runuser -u metrics -- sh -c 'ssh-keyscan -t ed25519 192.0.2.2 192.0.2.9 192.0.2.5 2>/dev/null > ~/.ssh/known_hosts.e2e && mv ~/.ssh/known_hosts.e2e ~/.ssh/known_hosts'

# the collector ships its own journal (role journal): its node bundle
ops30 install node collector --site "$SITE" --bundle /var/tmp/ | tee "$OUT/bundle.log"
(cd /var/tmp && tar xzf 30ops-node-collector.tar.gz && sh 30ops-node-collector/node-install.sh) > "$OUT/node-install.log" 2>&1 \
  || { cat "$OUT/node-install.log"; fail "node-install on the collector"; }

# run a textfile job of /etc/cron.d/30ops now, as cron would
job() {
  python3 - "$1" <<'PYEOF' > "$OUT/job.sh"
import shlex, sys
sys.path.insert(0, "/opt/30ops/lib/python")
from ops30.install.collector import textfile_jobs
for user, env, cmd, tf in textfile_jobs(open("/etc/cron.d/30ops").read()):
    if tf.endswith("/" + sys.argv[1]):
        envs = " ".join(shlex.quote(f"{k}={v}") for k, v in env.items())
        print(f"runuser -u {user} -- env {envs} sh -c {shlex.quote(cmd)}")
        break
else:
    sys.exit(f"no cron job writes {sys.argv[1]}")
PYEOF
  sh "$OUT/job.sh" || fail "the job for $1 failed"
}
job nas.prom
job pve-quorum.prom
grep -q '^nas_up{nas="primary"} 1$' /var/lib/node_exporter/textfile/nas.prom || fail "nas_up is not 1 after authorizing the key"
grep -q '^pve_quorum_up{cluster="lab"} 1$' /var/lib/node_exporter/textfile/pve-quorum.prom || fail "pve_quorum_up is not 1"

step "install collector, second run"
ops30 install collector --site "$SITE" | tee "$OUT/install-2.log"
grep -q '^30ops install collector: 0 change(s), 0 warning(s)$' "$OUT/install-2.log" || fail "the second install changed something"

# ---------------------------------------------------------------------------
step "baseline: targets, metric names, rules"
check baseline --rules /etc/30ops/prometheus/rules --expected "$R/tests/e2e/expected-metrics.txt" \
  | tee "$OUT/check-baseline.txt" || fail "baseline"

step "fault: nas-primary's pool DEGRADED"
"$R/tests/e2e/fakes/netns.sh" degrade
job nas.prom
grep -q 'state="DEGRADED"} 1$' /var/lib/node_exporter/textfile/nas.prom || fail "nas.prom does not show DEGRADED"
check alert --sink /run/ops30e2e/webhook.jsonl | tee "$OUT/check-alert.txt" || fail "alert"

step "logs: syslog, audit, journal, allowlist"
token="e2e$(date +%s)"
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
since=$(date '+%Y-%m-%d %H:%M:%S')
printf '<134>1 %s nas-primary qulogd - - - [System] %s-nas\n' "$ts" "$token" \
  | "$R/tests/e2e/fakes/netns.sh" send 192.0.2.2 514
printf '<189>1 %s fgt-edge fortigate - - - logid="0100032102" type="event" subtype="system" devname="fgt-edge" msg="%s-audit"\n' "$ts" "$token" \
  | "$R/tests/e2e/fakes/netns.sh" send 192.0.2.99 515
printf '<134>1 %s intruder test - - - %s-blocked\n' "$ts" "$token" \
  | "$R/tests/e2e/fakes/netns.sh" send 192.0.2.66 514 && fail "192.0.2.66 got through to 514" || true
logger -t ops30-e2e "$token-journal"
sleep 2
journalctl -k --since "$since" --no-pager > "$OUT/kernel.log"
check logs --token "$token" --kernel-log "$OUT/kernel.log" | tee "$OUT/check-logs.txt" || fail "logs"

step "archive the day to the WORM share, then verify"
day=$(date -u +%Y-%m-%d)
findmnt /mnt/worm > "$OUT/worm-mount.txt" || fail "/mnt/worm is not mounted"
runuser -u metrics -- env VL=http://127.0.0.1:9428 ARCHIVE=/mnt/worm/logs ARCHIVE_SKIP=syslog-fgt-edge \
  "$R/logs/archive/archive-day.sh" "$day" > "$OUT/archive.log" 2>&1 || { cat "$OUT/archive.log"; fail "archive-day"; }
runuser -u metrics -- env VL=http://127.0.0.1:9428 ARCHIVE=/mnt/worm/logs DRILLS=/srv/drills/onprem-logs/drills.jsonl \
  "$R/logs/archive/verify-archive.sh" "$day" --against-live > "$OUT/verify.log" 2>&1 || { cat "$OUT/verify.log"; fail "verify-archive"; }
check archive --day-dir "/mnt/worm/logs/$(echo "$day" | tr - /)" --drills /srv/drills/onprem-logs/drills.jsonl \
  | tee "$OUT/check-archive.txt" || fail "archive"

step "recover, doctor"
"$R/tests/e2e/fakes/netns.sh" recover
job nas.prom
ops30 doctor --site "$SITE" --format json > "$OUT/doctor.json" || true
check doctor --json "$OUT/doctor.json" --allowed "$R/tests/e2e/allowed-warn.txt" | tee "$OUT/check-doctor.txt" || fail "doctor"

step "memory"
docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}' > "$OUT/memory.txt"
mem=$(python3 - "$OUT/memory.txt" <<'PYEOF'
import re, sys
units = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "kB": 1000, "MB": 10**6, "GB": 10**9}
total = 0
for line in open(sys.argv[1]):
    m = re.match(r"\S+\t([\d.]+)(\w+) /", line)
    if m:
        total += float(m.group(1)) * units[m.group(2)]
print(int(total))
PYEOF
)
cat "$OUT/memory.txt"
echo "containers together: $((mem / 1048576)) MiB"
[ "$mem" -lt "$MEM_LIMIT" ] || fail "containers use $((mem / 1048576)) MiB, over 3 GiB"

step "passed"
{
  echo "30ops e2e passed: $v, $(( $(date +%s) - T0 )) s"
  echo "containers: $((mem / 1048576)) MiB"
  tail -n1 "$OUT/check-doctor.txt"
} | tee -a "$OUT/summary.txt"
