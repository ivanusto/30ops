#!/bin/sh
# Copy the site configuration of an old (pre-30ops) collector into a local
# directory laid out like its /, for `30ops import-legacy --from DIR` and
# `30ops render --compare-legacy DIR`.
#
#   scripts/fetch-legacy.sh USER@HOST OUTDIR
#
# Read only: one ssh session that runs `sudo -n cat` on a fixed list of
# files and writes nothing on the host. Secrets do not leave it:
# - in pve.yml and snmp-auth.yml every value is "MASKED" on the host
#   except the keys that are not secret (user, token_name, username,
#   protocols, ...);
# - in every other file a key whose name contains password, secret, token
#   or api_key gets the value "MASKED" on the host, before it is sent;
# - grafana/admin_password, *.token files and ssh keys are not in the list.
# Look through OUTDIR before you commit it anywhere.
set -eu

[ $# -eq 2 ] || { echo "usage: $0 USER@HOST OUTDIR" >&2; exit 2; }
dest=$1
out=$2
[ ! -e "$out" ] || [ -z "$(ls -A "$out")" ] || { echo "$0: $out exists and is not empty" >&2; exit 2; }
mkdir -p "$out"
mark="--30ops-fetch-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')--"

# The remote side, run by sh on the host with $mark as $1.
# shellcheck disable=SC2016
remote='
set -u
mark=$1
M=/opt/onprem-metrics
mask() { sed -E "s/^([[:space:]]*\"?[A-Za-z0-9_]*([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Aa][Pp][Ii]_?[Kk][Ee][Yy])[A-Za-z0-9_]*\"?[[:space:]]*[:=][[:space:]]*)[^[:space:]].*/\\1\"MASKED\"/"; }
keys() { sed -E "/^[[:space:]]*#/d
/^[[:space:]]*([A-Za-z0-9_]+:[[:space:]]*$|(user|token_name|verify_ssl|version|username|security_level|auth_protocol|priv_protocol|context_name):)/b
s/^([[:space:]]*[A-Za-z0-9_]+:).*/\1 \"MASKED\"/"; }
emit() {
  f=$1; how=$2
  sudo -n test -f "$f" || return 0
  printf "%s %s\n" "$mark" "$f"
  case $how in
    keys) sudo -n cat "$f" | keys ;;
    *) sudo -n cat "$f" | mask ;;
  esac
  printf "\n%s\n" "$mark"
}
assets=$(sudo -n sed -n "s/.*--assets \([^ ]*\).*/\1/p" /etc/cron.d/onprem-metrics 2>/dev/null | head -n 1)
# etc/timezone in the snapshot is the zone /etc/localtime points at: cron
# follows that link, and Ubuntu does not keep /etc/timezone in step with it
z=$(sudo -n readlink -f /etc/localtime 2>/dev/null | sed -n "s#^.*/zoneinfo/##p")
if [ -n "$z" ]; then
  printf "%s %s\n%s\n\n%s\n" "$mark" /etc/timezone "$z" "$mark"
else
  emit /etc/timezone mask
fi
for f in /etc/cron.d/onprem-metrics /etc/cron.d/onprem-logs /etc/cron.d/onprem-changes \
         /etc/cron.d/onprem-agent-gate /etc/default/onprem-logs-allowlist \
         /etc/systemd/system/onprem-logs-allowlist.service \
         /etc/onprem-agent-gate/config.json /etc/onprem-agent-gate/tools.json \
         $M/prometheus/prometheus.yml $M/alertmanager/alertmanager.yml $M/docker-compose.yml \
         /opt/onprem-logs/docker-compose.yml /opt/onprem-logs/audit/ignore.txt.site ${assets:-}; do
  emit "$f" mask
done
for f in $(sudo -n sh -c "ls /etc/systemd/system/*.mount $M/prometheus/targets/*.yml $M/grafana/provisioning/datasources/*.yml 2>/dev/null"); do
  emit "$f" mask
done
emit $M/prometheus/pve.yml keys
emit $M/prometheus/snmp-auth.yml keys
'

printf '%s\n' "$remote" | ssh -o BatchMode=yes "$dest" sh -s -- "$mark" > "$out/.stream"

# Split the stream: "<mark> /path" starts a file, a line "<mark>" ends it
# (the newline printed before it is not part of the file).
awk -v mark="$mark" -v out="$out" '
  index($0, mark " ") == 1 { f = out substr($0, length(mark) + 2); d = f; sub(/\/[^\/]*$/, "", d)
                            system("mkdir -p \"" d "\""); printf "" > f; first = 1; prev = ""; inside = 1; next }
  $0 == mark && inside    { if (!first) printf "%s", prev > f; close(f); inside = 0; next }
  inside                  { if (!first) printf "%s\n", prev > f; prev = $0; first = 0 }
' "$out/.stream"
rm -f "$out/.stream"
{
  echo "# fetched by 30ops scripts/fetch-legacy.sh from $dest at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  (cd "$out" && find . -type f ! -name FETCHED | sort)
} > "$out/FETCHED"
echo "$0: $(($(wc -l < "$out/FETCHED") - 1)) files in $out"
