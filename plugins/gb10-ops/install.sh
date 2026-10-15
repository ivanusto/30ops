#!/bin/sh
# gb10-ops install hook. node-install.sh runs it as root, after
# collector/install-node.sh, on a host whose site.yaml entry lists the
# plugin (docs/plugins.md). It installs gb10-textfile, the metrics the
# plugin's rules and dashboard row read, with its timer and the /run/gb10
# flag directory. A second run changes nothing. The guards in guards/ are
# not installed here: each one runs in front of a workload (README.md).
# Self-contained: it does not source lib/ (docs/lib.md, node-side files).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
changed=0
put() {   # put MODE SRC DST: install SRC as DST unless it is already that file
  if ! cmp -s "$2" "$3"; then
    install -m "$1" "$2" "$3"
    changed=1
  fi
}
getent group node-exporter >/dev/null || { echo "node-exporter group missing: run collector/install-node.sh first" >&2; exit 1; }
put 0755 "$HERE/textfile/gb10-textfile.py" /usr/local/bin/gb10-textfile.py
getent passwd gb10-metrics >/dev/null || useradd --system -g node-exporter -s /usr/sbin/nologin gb10-metrics
# hw-sample.py --hot-flag /run/gb10/HOT drops the flag here; sticky and
# world-writable like /tmp so whoever runs the sampler can write it, and
# only that user can remove it. tmpfiles recreates it after every boot.
tmpf=$(mktemp)
printf 'd /run/gb10 1777 root root -\n' > "$tmpf"
put 0644 "$tmpf" /etc/tmpfiles.d/gb10.conf
rm -f "$tmpf"
systemd-tmpfiles --create /etc/tmpfiles.d/gb10.conf
put 0644 "$HERE/systemd/gb10-textfile.service" /etc/systemd/system/gb10-textfile.service
put 0644 "$HERE/systemd/gb10-textfile.timer" /etc/systemd/system/gb10-textfile.timer
if [ "$changed" = 1 ]; then systemctl daemon-reload; fi
systemctl enable --quiet gb10-textfile.timer
if [ "$changed" = 1 ] || ! systemctl is-active --quiet gb10-textfile.timer; then
  systemctl restart gb10-textfile.timer
  sleep 12
  curl -fsS localhost:9100/metrics | grep -E '^gb10_(zone_temp|soak_seconds|textfile_errors)' \
    || echo "gb10 metrics not visible yet; check: journalctl -u gb10-textfile" >&2
fi
echo "gb10-ops: installed"
