#!/bin/sh
# Install node_exporter + gb10-textfile on a DGX Spark (arm64, DGX OS).
# Downloads the node_exporter release from GitHub, verifies sha256 against
# the release's sha256sums.txt, installs the systemd units.
#   sudo ./install-node.sh [NODE_EXPORTER_VERSION]
#   sudo ./install-node.sh --collector [NODE_EXPORTER_VERSION]
#   sudo ./install-node.sh --plain [NODE_EXPORTER_VERSION]
# --collector is for the collector VM and --plain for any other Linux node:
# node_exporter and the textfile directory only. When the installed binary
# is already that version, nothing is downloaded, and a unit that did not
# change is not restarted, so a second run changes nothing. The version is
# NODE_EXPORTER in lib/python/ops30/render/nodes.py; 30ops install passes it.
set -eu
MODE=gb10
case "${1:-}" in --collector|--plain) MODE=plain; shift ;; esac
VER=${1:-1.9.1}
ARCH=$(uname -m); case "$ARCH" in aarch64) A=arm64 ;; x86_64) A=amd64 ;; *) echo "unsupported arch $ARCH" >&2; exit 1 ;; esac
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
restart=0
if /usr/local/bin/node_exporter --version 2>&1 | grep -q "version $VER "; then
  echo "node_exporter $VER is installed"
else
  T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
  base="https://github.com/prometheus/node_exporter/releases/download/v$VER"
  curl -fsSL -o "$T/ne.tgz" "$base/node_exporter-$VER.linux-$A.tar.gz"
  curl -fsSL -o "$T/sums" "$base/sha256sums.txt"
  (cd "$T" && grep "node_exporter-$VER.linux-$A.tar.gz" sums | sed 's#  .*#  ne.tgz#' | sha256sum -c -)
  tar xzf "$T/ne.tgz" -C "$T"
  install -m 0755 "$T/node_exporter-$VER.linux-$A/node_exporter" /usr/local/bin/node_exporter
  restart=1
fi
getent group node-exporter >/dev/null || groupadd --system node-exporter
getent passwd node-exporter >/dev/null || useradd --system -g node-exporter -s /usr/sbin/nologin node-exporter
install -d -o node-exporter -g node-exporter -m 2775 /var/lib/node_exporter/textfile
if ! cmp -s "$HERE/systemd/node_exporter.service" /etc/systemd/system/node_exporter.service; then
  install -m 0644 "$HERE/systemd/node_exporter.service" /etc/systemd/system/
  systemctl daemon-reload
  restart=1
fi
systemctl enable --quiet node_exporter
if [ "$restart" = 1 ] || ! systemctl is-active --quiet node_exporter; then systemctl restart node_exporter; fi
if [ "$MODE" = plain ]; then
  sleep 2
  curl -fsS localhost:9100/metrics | grep -m1 '^node_textfile_scrape_error' || echo "node_exporter not answering yet" >&2
  exit 0
fi
install -m 0755 "$HERE/textfile/gb10-textfile.py" /usr/local/bin/gb10-textfile.py
getent passwd gb10-metrics >/dev/null || useradd --system -g node-exporter -s /usr/sbin/nologin gb10-metrics
# hw-sample.py --hot-flag /run/gb10/HOT drops the flag here; sticky and
# world-writable like /tmp so whoever runs the sampler can write it, and
# only that user can remove it. tmpfiles recreates it after every boot.
printf 'd /run/gb10 1777 root root -\n' > /etc/tmpfiles.d/gb10.conf
systemd-tmpfiles --create /etc/tmpfiles.d/gb10.conf
install -m 0644 "$HERE/systemd/gb10-textfile.service" /etc/systemd/system/
install -m 0644 "$HERE/systemd/gb10-textfile.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now node_exporter gb10-textfile.timer
sleep 12
curl -fsS localhost:9100/metrics | grep -E '^gb10_(zone_temp|soak_seconds|textfile_errors)' || echo "gb10 metrics not visible yet; check: journalctl -u gb10-textfile" >&2
