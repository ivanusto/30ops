#!/bin/sh
# Install node_exporter and the textfile directory on a Linux host (arm64
# or amd64): the collector VM, a node, a DGX Spark. Downloads the
# node_exporter release from GitHub, verifies sha256 against the release's
# sha256sums.txt, installs the systemd unit.
#   sudo ./install-node.sh [--collector|--plain] [NODE_EXPORTER_VERSION]
# --collector and --plain are accepted and mean the same. What a plugin
# adds on top (gb10-textfile on a DGX Spark) is the plugin's install.sh,
# which node-install.sh runs next (plugins/<name>/install.sh). When the
# installed binary is already that version, nothing is downloaded, and a
# unit that did not change is not restarted, so a second run changes
# nothing. The version is NODE_EXPORTER in lib/python/ops30/render/nodes.py;
# 30ops install passes it.
set -eu
case "${1:-}" in --collector|--plain) shift ;; esac
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
sleep 2
curl -fsS localhost:9100/metrics | grep -m1 '^node_textfile_scrape_error' || echo "node_exporter not answering yet" >&2
