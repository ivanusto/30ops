#!/bin/sh
# pve-quorum-textfile.sh LABEL=root@n1[,root@n2] ... > pve-quorum.prom: the pve
# adapter's quorum capability (adapters/hypervisor/pve), kept under this name for the cron lines.
exec "$(dirname "$(readlink -f "$0")")/../../bin/30ops" textfile pve-quorum "$@"
