#!/bin/sh
# nfs-model-library install hook. node-install.sh runs it as root on a host
# whose site.yaml entry lists the plugin (docs/plugins.md). It installs
# mlib.py as /usr/local/bin/mlib. Mounting the library (mounts.md) and a
# scheduled `mlib verify` are left to the site. A second run changes nothing.
# Self-contained: it does not source lib/ (docs/lib.md, node-side files).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
if ! cmp -s "$HERE/mlib.py" /usr/local/bin/mlib; then
  install -m 0755 "$HERE/mlib.py" /usr/local/bin/mlib
fi
echo "nfs-model-library: installed /usr/local/bin/mlib"
