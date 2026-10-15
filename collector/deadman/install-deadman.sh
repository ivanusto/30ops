#!/bin/sh
# install-deadman.sh ENV_FILE: install 30ops-deadman on the deadman host, as
# root. node-install.sh runs it for a host with role deadman, with the
# deadman.env render wrote (nodes/<host>/etc/30ops-deadman/deadman.env).
# The SMTP password, when the site sends mail, is /etc/30ops-deadman/smtp.pass
# (root, 0600): `30ops install node` over ssh puts it in
# /tmp/30ops-deadman-smtp for this script to move; with --bundle you put it
# there yourself. Without it the file is empty and mail goes out without a
# login. ufw, when active, lets COLLECTOR reach the port. A second run
# changes nothing.
# Self-contained: it does not source lib/ (docs/lib.md, node-side files).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ENV=${1:?usage: install-deadman.sh ENV_FILE}
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
changed=0
put() {   # put MODE SRC DST
  if ! cmp -s "$2" "$3"; then
    install -m "$1" "$2" "$3"
    changed=1
  fi
}
install -d -m 0755 /etc/30ops-deadman /usr/local/lib/30ops-deadman
put 0644 "$ENV" /etc/30ops-deadman/deadman.env
put 0755 "$HERE/30ops-deadman.py" /usr/local/lib/30ops-deadman/30ops-deadman.py
put 0644 "$HERE/30ops-deadman.service" /etc/systemd/system/30ops-deadman.service
if [ -f /tmp/30ops-deadman-smtp ]; then
  put 0600 /tmp/30ops-deadman-smtp /etc/30ops-deadman/smtp.pass
  rm -f /tmp/30ops-deadman-smtp
elif [ ! -f /etc/30ops-deadman/smtp.pass ]; then
  install -m 0600 /dev/null /etc/30ops-deadman/smtp.pass
  if grep -q '^SMTP_USERNAME="..*"' /etc/30ops-deadman/deadman.env; then
    echo "warning: /etc/30ops-deadman/smtp.pass is empty; put the SMTP password there (root, 0600) and restart 30ops-deadman" >&2
  fi
fi
if [ "$changed" = 1 ]; then systemctl daemon-reload; fi
systemctl enable --quiet 30ops-deadman
if [ "$changed" = 1 ] || ! systemctl is-active --quiet 30ops-deadman; then systemctl restart 30ops-deadman; fi
# shellcheck source=/dev/null
. /etc/30ops-deadman/deadman.env
port=${LISTEN##*:}
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  for a in $COLLECTOR; do
    ufw allow proto tcp from "$a" to any port "$port" comment '30ops deadman' >/dev/null
  done
fi
echo "30ops-deadman: listening on $LISTEN for $COLLECTOR"
