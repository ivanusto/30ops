#!/bin/sh
# nas-textfile.sh LABEL=user@host ... > nas.prom: the qnap adapter's health
# capability (adapters/nas/qnap), kept under this name for the cron lines.
exec "$(dirname "$(readlink -f "$0")")/../../bin/30ops" textfile ${NAS_TEXTFILE_LOCAL:+--local} nas "$@"
