#!/bin/sh
# Start collector/compose.yml on a render of the sample site, with
# throwaway volumes and secrets, and check what the merged stack must do:
#   - Prometheus loaded the 69 rendered alert rules;
#   - Grafana has the VictoriaLogs plugin baked in, the three provisioned
#     datasources (VictoriaLogs answers its health check) and the dashboard;
#   - Prometheus scrapes VictoriaLogs over the project network.
# Everything is removed afterwards. Needs docker, curl and python3-yaml;
# uses host ports 3000, 9090, 9093, 9428, 514 and 515.
#
#   sh collector/tests/compose-smoke.sh
set -eu

here=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
p=ops30smoke$$
fail() { echo "compose-smoke: $*" >&2; exit 1; }

export COMPOSE_PROJECT_NAME=$p
export OPS30_ETC="$tmp/etc/30ops"
export OPS30_GRAFANA_ADMIN_FILE="$tmp/secrets/grafana-admin.pass"
export OPS30_SMTP_PASSWORD_FILE="$tmp/secrets/smtp.pass"
export OPS30_VOL_PROMETHEUS=$p-prometheus OPS30_VOL_ALERTMANAGER=$p-alertmanager
export OPS30_VOL_GRAFANA=$p-grafana OPS30_VOL_VICTORIALOGS=$p-victorialogs
compose() { docker compose --env-file "$OPS30_ETC/compose.env" -f "$here/collector/compose.yml" "$@"; }

cleanup() {
  compose down -t 5 > /dev/null 2>&1 || true
  for v in prometheus alertmanager grafana victorialogs; do docker volume rm -f "$p-$v" > /dev/null 2>&1 || true; done
  rm -rf "$tmp"
}
trap cleanup EXIT

"$here/bin/30ops" render --site "$here/examples/sample-site/site.yaml" --out "$tmp" > /dev/null 2>&1
# the containers run as nobody, 472 and 65534: let them read the tree
chmod -R a+rX "$tmp"
mkdir -p "$tmp/secrets"
printf 'smoke-admin\n' > "$OPS30_GRAFANA_ADMIN_FILE"
printf 'not-a-password\n' > "$OPS30_SMTP_PASSWORD_FILE"
chmod 0644 "$tmp/secrets"/*

# external volumes: compose must refuse to start without them
if compose up -d prometheus > /dev/null 2>&1; then fail "started without its external volumes"; fi
for v in prometheus alertmanager grafana victorialogs; do docker volume create "$p-$v" > /dev/null; done
compose up -d --quiet-pull prometheus alertmanager grafana victorialogs

get() { curl -fsS --max-time 5 "$@"; }
wait_for() {   # wait_for SECONDS CMD...: until CMD succeeds
  n=$1; shift
  while ! "$@" > /dev/null 2>&1; do
    n=$((n - 2)); [ "$n" -gt 0 ] || return 1; sleep 2
  done
}
G=http://admin:smoke-admin@127.0.0.1:3000

wait_for 60 get http://127.0.0.1:9090/-/ready || fail "prometheus not ready"
rules=$(get http://127.0.0.1:9090/api/v1/rules | python3 -c '
import json, sys
d = json.load(sys.stdin)["data"]["groups"]
print(sum(1 for g in d for r in g["rules"] if r["type"] == "alerting"))')
[ "$rules" = 69 ] || fail "prometheus loaded $rules alert rules, want 69"
echo "prometheus: $rules alert rules"

wait_for 90 get "$G/api/health" || fail "grafana not healthy"
get "$G/api/plugins/victoriametrics-logs-datasource/settings" > /dev/null || fail "VictoriaLogs plugin missing"
uids=$(get "$G/api/datasources" | python3 -c 'import json, sys; print(" ".join(sorted(d["uid"] for d in json.load(sys.stdin))))')
[ "$uids" = "alertmanager prometheus victorialogs" ] || fail "datasources: $uids"
wait_for 30 get "$G/api/datasources/uid/victorialogs/health" || fail "VictoriaLogs datasource health check failed"
get "$G/api/dashboards/uid/onprem-overview" > /dev/null || fail "dashboard onprem-overview not provisioned"
echo "grafana: plugin, datasources ($uids), dashboard"

vl_up() {
  get 'http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22victorialogs%22%7D' |
    python3 -c 'import json, sys; r = json.load(sys.stdin)["data"]["result"]; sys.exit(0 if r and r[0]["value"][1] == "1" else 1)'
}
wait_for 120 vl_up || fail "prometheus does not scrape victorialogs"
echo "prometheus: victorialogs up"
echo "compose-smoke: ok"
