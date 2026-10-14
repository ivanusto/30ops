#!/bin/sh
# netns.sh: the e2e fake LAN. One network namespace, ops30e2e, joined to the
# host by a veth pair: the host end is the collector (192.0.2.49/24), the
# namespace end carries the fake hosts of tests/e2e/site.yaml.
#
#   netns.sh up            namespace, addresses, sshd, snmpd, HTTP fakes, NFS
#   netns.sh authorize USER PUBKEY   let PUBKEY log in as USER (from .49 only)
#   netns.sh degrade|recover         nas-primary's pool DEGRADED / ONLINE
#   netns.sh send ADDR PORT          stdin to ADDR's view of 192.0.2.49:PORT/tcp
#   netns.sh down
#
#   192.0.2.2    nas-primary  ssh (fake zpool/zfs/getcfg), SNMPv3, NFS for the WORM share
#   192.0.2.9    pve1         ssh (pvecm status), PVE API on 8006
#   192.0.2.5    pve2         the same
#   192.0.2.99   fgt-edge     FortiGate API on 10443
#   192.0.2.250  webhook sink for Alertmanager, port 9999
#   192.0.2.66   a sender that is not on the syslog allowlist
#
# The NFS server runs in the host namespace (nfsd in a namespace of its own
# is not dependable on every kernel); the collector reaches it as
# 192.0.2.2:2049 through a DNAT in the host's nat OUTPUT chain, so the
# rendered mnt-worm.mount is used unchanged. Secrets are read from
# $SECRETS (default /etc/30ops/secrets), written there by run.sh. Root only.
set -eu
NS=ops30e2e
STATE=${STATE:-/run/ops30e2e}
SECRETS=${SECRETS:-/etc/30ops/secrets}
WORM=${WORM:-/srv/ops30e2e-worm}
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
HERE=$REPO/tests/e2e/fakes
ADDRS="192.0.2.2 192.0.2.9 192.0.2.5 192.0.2.99 192.0.2.250 192.0.2.66"
in_ns() { ip netns exec "$NS" "$@"; }
die() { echo "netns.sh: $*" >&2; exit 1; }
fill() { sed -e "s|@STATE@|$STATE|g" -e "s|@REPO@|$REPO|g" "$@"; }

up() {
  [ "$(id -u)" = 0 ] || die "run as root"
  ip netns list | grep -qw "$NS" && die "$NS exists; run down first"
  rm -rf "$STATE"
  mkdir -p "$STATE/nas" "$STATE/authorized_keys" "$STATE/snmp"
  chmod 755 "$STATE" "$STATE/authorized_keys"

  ip netns add "$NS"
  ip link add e2e0 type veth peer name e2e1
  ip link set e2e1 netns "$NS"
  ip addr add 192.0.2.49/24 dev e2e0
  ip link set e2e0 up
  in_ns ip link set lo up
  for a in $ADDRS; do in_ns ip addr add "$a/24" dev e2e1; done
  in_ns ip link set e2e1 up

  # NFSv4 export for worm.host nas-primary:/LogArchive; the share stands in
  # for the WORM folder (writes once, but nothing locks the files)
  mkdir -p "$WORM/LogArchive/logs"
  chmod 0777 "$WORM/LogArchive" "$WORM/LogArchive/logs"
  mkdir -p /etc/exports.d
  printf '%s 192.0.2.49(rw,sync,fsid=0,crossmnt,no_subtree_check,no_root_squash)\n' "$WORM" > /etc/exports.d/ops30e2e.exports
  systemctl restart nfs-server
  exportfs -ra
  iptables -t nat -A OUTPUT -d 192.0.2.2 -p tcp --dport 2049 -j DNAT --to-destination 192.0.2.49:2049

  # sshd: nas-primary, pve1, pve2
  ssh-keygen -q -t ed25519 -N '' -f "$STATE/ssh_host_ed25519_key"
  fill "$HERE/sshd_config.in" > "$STATE/sshd_config"
  id ops30 >/dev/null 2>&1 || useradd --system --create-home --shell /bin/sh ops30
  mkdir -p /run/sshd
  # the daemons get no terminal fds: an ssh session that started run.sh
  # (tests/vm/e2e.sh) would otherwise wait for them to close at the end
  in_ns /usr/sbin/sshd -f "$STATE/sshd_config" -E "$STATE/sshd.log" < /dev/null > /dev/null 2>&1

  # snmpd: nas-primary
  python3 "$HERE/snmp/build-data.py" > "$STATE/qnap.data"
  fill "$HERE/snmp/snmpd.conf.in" | sed -e "s|@USER@|ops30|" \
    -e "s|@AUTH@|$(cat "$SECRETS/snmp-auth.pass")|" -e "s|@PRIV@|$(cat "$SECRETS/snmp-priv.pass")|" > "$STATE/snmpd.conf"
  chmod 600 "$STATE/snmpd.conf"
  SNMP_PERSISTENT_DIR="$STATE/snmp" in_ns snmpd -C -c "$STATE/snmpd.conf" -p "$STATE/snmpd.pid" -Lf "$STATE/snmpd.log" < /dev/null > /dev/null 2>&1

  # HTTP: PVE API, FortiGate API, webhook sink
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=ops30-e2e \
    -keyout "$STATE/tls.key" -out "$STATE/tls.crt" 2>/dev/null
  # a plain command, not in_ns: a function sent to the background runs in a
  # subshell that waits for its child, keeps the caller's stdout and stderr
  # on saved fds (an ssh session running this never ends) and is what $!
  # names. ip netns exec execs python, so $! is the fake itself.
  ip netns exec "$NS" python3 -I "$HERE/httpfakes.py" --state "$STATE" --cert "$STATE/tls.crt" --key "$STATE/tls.key" \
    --pve pve1=192.0.2.9 --pve pve2=192.0.2.5 --pve-cluster lab \
    --pve-token "prometheus@pve!exporter=$(cat "$SECRETS/pve-exporter.token")" \
    --fortigate 192.0.2.99 --fortigate-token "$(cat "$SECRETS/fortigate-api.token")" \
    --fortigate-body "$REPO/tests/fixtures/adapters/fortigate/licences/license-status/001.out" \
    --sink 192.0.2.250 < /dev/null >> "$STATE/http.log" 2>&1 &
  echo $! > "$STATE/http.pid"
  # every listener answers, or the fake LAN is not up
  for hp in 192.0.2.250:9999 192.0.2.9:8006 192.0.2.5:8006 192.0.2.99:10443 192.0.2.2:22 192.0.2.9:22; do
    n=0
    until in_ns python3 -I -c 'import socket, sys; h, p = sys.argv[1].split(":"); socket.create_connection((h, int(p)), 1).close()' "$hp" 2>/dev/null; do
      n=$((n + 1))
      [ "$n" -lt 20 ] || { tail -n 20 "$STATE/http.log" "$STATE/sshd.log" >&2; die "nothing listens on $hp"; }
      sleep 0.5
    done
  done
  if ! { [ -s "$STATE/snmpd.pid" ] && kill -0 "$(cat "$STATE/snmpd.pid")"; }; then
    tail -n 20 "$STATE/snmpd.log" >&2; die "snmpd is not running"
  fi
  echo "netns.sh: $NS up ($ADDRS)"
}

down() {
  for p in http sshd snmpd; do
    if [ -f "$STATE/$p.pid" ]; then kill "$(cat "$STATE/$p.pid")" 2>/dev/null || true; fi
  done
  ip netns del "$NS" 2>/dev/null || true
  ip link del e2e0 2>/dev/null || true
  while iptables -t nat -D OUTPUT -d 192.0.2.2 -p tcp --dport 2049 -j DNAT --to-destination 192.0.2.49:2049 2>/dev/null; do :; done
  rm -f /etc/exports.d/ops30e2e.exports
  exportfs -ra 2>/dev/null || true
  echo "netns.sh: $NS down"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  authorize)
    u=${2:?usage: netns.sh authorize USER PUBKEY}; k=${3:?usage: netns.sh authorize USER PUBKEY}
    printf 'from="192.0.2.49",restrict %s\n' "$(head -n1 "$k")" > "$STATE/authorized_keys/$u"
    chmod 644 "$STATE/authorized_keys/$u" ;;
  degrade) touch "$STATE/nas/degraded" ;;
  recover) rm -f "$STATE/nas/degraded" ;;
  send)
    a=${2:?usage: netns.sh send ADDR PORT}; p=${3:?usage: netns.sh send ADDR PORT}
    in_ns nc -q1 -w5 -s "$a" 192.0.2.49 "$p" ;;
  *) sed -n '2,25p' "$0"; exit 64 ;;
esac
