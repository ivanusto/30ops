#!/bin/sh
# check.sh: one screen of cluster health for a two node cluster with a
# QDevice. Exit 0 when quorate with all three votes, 1 when quorate but the
# cluster cannot lose anything more (a vote missing, no QDevice configured,
# a node whose HA daemon has stopped reporting, or an HA service in error
# state), 2 when not quorate.
# Suitable for cron or the Day 19 exporter.
set -u
CONF=/etc/pve/corosync.conf
S=$(pvecm status 2>/dev/null) || { echo "pvecm status failed"; exit 2; }
EXP=$(echo "$S" | awk '/Expected votes:/ {print $3}')
TOT=$(echo "$S" | awk '/Total votes:/ {print $3}')
QUO=$(echo "$S" | awk '/Quorate:/ {print $2}')
echo "quorate=$QUO votes=$TOT/$EXP"
# Membership rows start at column 0 ("0x00000001  1  ...")
echo "$S" | awk '/Membership information/,0' | grep -E '^ *0x' | sed 's/^/  /'

RC=0
if ! grep -q 'model: *net' "$CONF" 2>/dev/null; then
    echo "no QDevice configured: losing either node loses quorum"
    RC=1
fi
if command -v ha-manager >/dev/null; then
    H=$(ha-manager status 2>/dev/null)
    echo "ha:"
    echo "$H" | sed 's/^/  /'
    # An LRM that stopped reporting (daemon masked, node gone) is not taking
    # part in fencing or recovery, even while the node itself is up.
    if echo "$H" | grep -q 'old timestamp'; then
        echo "an HA LRM has an old timestamp: that node is not part of HA right now"
        RC=1
    fi
    # A service in error state will not be recovered by HA until fixed by hand.
    if echo "$H" | grep -q '^service .*, error)'; then
        echo "an HA service is in error state: HA will not recover it"
        RC=1
    fi
fi
[ "$QUO" = "Yes" ] || exit 2
[ "$TOT" = "$EXP" ] || exit 1
exit $RC
