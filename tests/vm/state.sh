#!/bin/sh
# state.sh: what 30ops install leaves on the collector, one line per fact,
# sorted, so two runs can be compared with diff. Run as root on the VM.
# Files: content sha256, mode, owner, inode and mtime (an unchanged inode and
# mtime show that the second run did not rewrite the file). Directories:
# mode and owner only (cron jobs write into them). Left out: the textfiles
# the jobs write, logs, TSDB data.
set -eu
TF=${TF:-/var/lib/node_exporter/textfile}
file() { [ -e "$1" ] && printf 'file %s %s %s\n' "$1" "$(stat -c '%a %U:%G %i %Y' "$1")" "$(sha256sum < "$1" | cut -c1-16)"; }
dir() { [ -d "$1" ] && printf 'dir %s %s\n' "$1" "$(stat -c '%a %U:%G' "$1")"; }
{
  find /etc/30ops -path /etc/30ops/.backup -prune -o -type f -print | while read -r f; do file "$f"; done
  for f in /etc/cron.d/30ops /etc/default/30ops-allowlist /etc/systemd/system/30ops-allowlist.service \
           /etc/systemd/system/node_exporter.service /usr/local/bin/node_exporter "$TF/30ops-adapters.prom" \
           /var/lib/metrics/.ssh/id_ed25519 /var/lib/metrics/.ssh/id_ed25519.pub; do file "$f" || true; done
  for d in /etc/30ops /etc/30ops/secrets "$TF" /var/log/30ops /srv/reports /var/lib/onprem-metrics/eol \
           /var/lib/onprem-changes /var/lib/30ops/changes /srv/drills/pve-backup-drill /srv/drills/nas-backup-drill \
           /srv/drills/cloud-offload-drill /srv/drills/onprem-logs /var/lib/metrics/.ssh; do dir "$d" || true; done
  printf 'backups %s\n' "$(find /etc/30ops/.backup -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
  for u in metrics node-exporter; do printf 'user %s\n' "$(id "$u" 2>&1)"; done
  for u in node_exporter 30ops-allowlist cron docker systemd-journal-upload; do
    printf 'unit %s %s\n' "$u" "$(systemctl show -p UnitFileState -p ActiveState -p ActiveEnterTimestampMonotonic --value "$u" | tr '\n' ' ')"
  done
  docker ps -a --no-trunc --format 'container {{.Names}} {{.ID}} {{.State}}'
  docker volume ls -q | sed 's/^/volume /'
} | sort
