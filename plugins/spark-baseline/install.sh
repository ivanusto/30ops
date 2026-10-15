#!/bin/sh
# spark-baseline install hook. node-install.sh runs it as root on a host
# whose site.yaml entry lists the plugin (docs/plugins.md). It installs
# baseline-snapshot.sh as /usr/local/sbin/baseline-snapshot and nothing
# else: harden-ssh.sh changes how people log in, so it is run by hand, with
# a second session open (README.md). A second run changes nothing.
# Self-contained: it does not source lib/ (docs/lib.md, node-side files).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
if ! cmp -s "$HERE/baseline-snapshot.sh" /usr/local/sbin/baseline-snapshot; then
  install -m 0755 "$HERE/baseline-snapshot.sh" /usr/local/sbin/baseline-snapshot
fi
echo "spark-baseline: installed /usr/local/sbin/baseline-snapshot"
