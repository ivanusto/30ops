#!/bin/sh
# setup.sh: add a QDevice (corosync-qnetd on another host) to a two node
# Proxmox VE cluster. Run once, on one cluster node, as root.
#
#   ./setup.sh <qnetd-ip>
#
# Idempotent: re-running with the same address is a no-op after the first
# successful setup. Refuses to run on a cluster that already has a QDevice
# pointing somewhere else (remove it first with: pvecm qdevice remove).
#
# Node count comes from corosync.conf, not from `pvecm nodes`: a node that is
# powered off is missing from `pvecm nodes` but still counts toward Expected
# votes. A three node cluster with one node off looks like two nodes there.
set -eu

CONF=/etc/pve/corosync.conf
QNETD="${1:?usage: $0 <qnetd-ip>}"
[ "$(id -u)" -eq 0 ] || { echo "run as root on a cluster node"; exit 1; }
command -v pvecm >/dev/null || { echo "pvecm not found; is this a Proxmox VE node?"; exit 1; }
[ -r "$CONF" ] || { echo "$CONF not found; is this node in a cluster?"; exit 1; }

# "name addr" per node from the nodelist section
NODES=$(awk '/^nodelist/,/^}/' "$CONF" \
    | awk '/ name:/ {n=$2} /ring0_addr:/ {a=$2} n && a {print n, a; n=""; a=""}')
N=$(echo "$NODES" | grep -c .)
ONLINE=$(pvecm nodes 2>/dev/null | awk '$1 ~ /^[0-9]+$/' | grep -c .)
echo "nodes in corosync.conf ($N): $(echo "$NODES" | awk '{print $1}' | tr '\n' ' ')"
echo "nodes online: $ONLINE"
if [ "$ONLINE" -ne "$N" ]; then
    echo "a node listed in $CONF is not online. Power it on, or remove it with"
    echo "'pvecm delnode <name>' if it has left for good, then run this again."
    exit 1
fi
if [ "$N" -ne 2 ]; then
    echo "this cluster has $N nodes; a QDevice is meant for an even count and this"
    echo "script only handles two. See the Proxmox VE docs before going further."
    exit 1
fi

if grep -q 'model: *net' "$CONF"; then
    CUR=$(awk '/device *\{/,0' "$CONF" | awk '/host:/ {print $2; exit}')
    if [ "$CUR" = "$QNETD" ]; then
        echo "QDevice already configured for $QNETD; nothing to do"
        pvecm status | grep -E 'Quorate|Expected votes|Total votes|Qdevice'
        exit 0
    fi
    echo "a QDevice is already configured (host $CUR); run 'pvecm qdevice remove' first"; exit 1
fi

# Every node needs the client daemon; setup does not install it for you.
echo "$NODES" | while read -r NAME ADDR; do
    echo "== $NAME ($ADDR): installing corosync-qdevice"
    if [ "$NAME" = "$(hostname)" ]; then
        apt-get install -y corosync-qdevice >/dev/null
    else
        ssh -o BatchMode=yes "root@$ADDR" 'apt-get install -y corosync-qdevice >/dev/null' </dev/null
    fi
done

echo "== reaching $QNETD:5403"
if command -v nc >/dev/null; then
    nc -z -w3 "$QNETD" 5403 || { echo "cannot reach $QNETD:5403; is corosync-qnetd running and the firewall open?"; exit 1; }
fi

echo "== pvecm qdevice setup $QNETD (connects to root@$QNETD over SSH once)"
pvecm qdevice setup "$QNETD"

echo "== result"
pvecm status | grep -E 'Nodes|Expected votes|Total votes|Quorum:|Quorate|Flags'
pvecm status | awk '/Membership information/,0' | grep -E '^ *0x'
echo
echo "Expected votes should be 3, Quorate Yes, and a Qdevice row above."
echo "Now run drills.md before trusting HA with anything."
