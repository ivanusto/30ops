#!/bin/sh
# node-install.sh: run as root on a node, from the bundle `30ops install
# node` builds (it unpacks to /tmp/30ops-node-<host>/). It reads install.env
# and runs the installers for the host's roles; each is safe to run again,
# and a second run changes nothing.
#   node        node_exporter; ufw, when active, lets SCRAPE_FROM reach 9100
#   journal     systemd-journal-upload to JOURNAL_URL, from now on
#   pcap        the capture units with the site's profiles and sudoers, and
#               the collector's pull key forced to rrsync -ro
#   hypervisor  the collector's key for the quorum check, forced to
#               `pvecm status` and only from COLLECTOR, and linger for root
# Then, for each plugin in PLUGINS, the plugin's own plugins/<name>/install.sh
# (docs/plugins.md).
# Self-contained: it does not source lib/ (docs/lib.md, node-side files).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
# shellcheck source=/dev/null
. "$HERE/install.env"
has() { case " $ROLES " in *" $1 "*) return 0 ;; esac; return 1; }

if has node; then
  sh "$HERE/collector/install-node.sh" --plain "$NODE_EXPORTER_VERSION"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow proto tcp from "$SCRAPE_FROM" to any port 9100 comment '30ops node_exporter' >/dev/null
  fi
fi

if has journal; then
  sh "$HERE/logs/node/install-journal-upload.sh" "$JOURNAL_URL" --from-now
fi

if has pcap; then
  set -- --profiles "$HERE/etc/pcap" --sudoers "$HERE/etc/sudoers.d/pcap"
  if [ -s "$HERE/keys/pcap-pull.pub" ]; then set -- "$@" --pull-key "$HERE/keys/pcap-pull.pub"; fi
  sh "$HERE/logs/pcap/install-pcap.sh" "$@"
fi

if has hypervisor && [ -s "$HERE/keys/quorum.pub" ]; then
  # On PVE /root/.ssh/authorized_keys is a symlink into /etc/pve/priv
  # (pmxcfs, shared by the cluster): append to the real file in place, never
  # replace it, or the symlink becomes a local file and the key stops being
  # cluster-wide.
  mkdir -p /root/.ssh
  ak=$(readlink -f /root/.ssh/authorized_keys)
  line="from=\"$COLLECTOR\",command=\"/usr/bin/pvecm status\",restrict $(head -n1 "$HERE/keys/quorum.pub")"
  if ! grep -qxF "$line" "$ak" 2>/dev/null; then
    printf '%s\n' "$line" >> "$ak"
    echo "quorum key added to $ak"
  fi
  # the per-minute login would otherwise start and stop a root user manager
  if [ "$(loginctl show-user root -p Linger --value 2>/dev/null || true)" != yes ]; then
    loginctl enable-linger root
  fi
fi
for p in ${PLUGINS:-}; do
  if [ -f "$HERE/plugins/$p/install.sh" ]; then
    sh "$HERE/plugins/$p/install.sh"
  fi
done
echo "30ops node-install: $HOST ($ROLES${PLUGINS:+; plugins $PLUGINS}) done"
