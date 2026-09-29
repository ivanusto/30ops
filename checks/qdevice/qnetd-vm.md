# The QDevice VM on QNAP Virtualization Station

One small Debian VM whose only job is to run `corosync-qnetd` and answer the
two Proxmox VE nodes on TCP 5403. It holds the third vote.

It runs on the same NAS that serves the cluster's NFS storage. That is on
purpose: the vote then fails together with something the cluster already
depends on, instead of adding a new box that can fail on its own schedule.
See drills.md for what that costs during a NAS reboot.

| Setting | Value | Why |
|---|---|---|
| OS | Debian 12 (bookworm) netinst, no desktop | `corosync-qnetd` is in main; nothing else is needed |
| vCPU / RAM / disk | 1 vCPU, 1 GiB, 8 GiB | qnetd idles at a few MB |
| Network | Virtualization Station virtual switch bridged to the node LAN, static IP | the nodes must reach it without DHCP or DNS |
| Autostart | on, start order before any other VM | it must be up before the nodes need a vote after a NAS reboot |
| Snapshots / backup | none needed | there is no state worth keeping; rebuild in ten minutes from this file |
| Hostname | `qnetd` | easy to recognise in logs |
| Clock | `timedatectl set-timezone <your zone>`, `timedatectl set-local-rtc 1`, NTP on | Virtualization Station hands the guest an RTC in local time; Debian reads it as UTC, so every boot starts off by the UTC offset until NTP corrects it |

## Install

```sh
apt update && apt install -y corosync-qnetd
systemctl enable --now corosync-qnetd
ss -tlnp | grep 5403          # listening
```

The Proxmox setup step (`pvecm qdevice setup`) connects to this VM over SSH as
root once, to exchange certificates. Allow root SSH with a key for that one
step, then set `PermitRootLogin no` again (Day 11's drop-in works here too).

## Firewall on the VM

Allow TCP 5403 from the two node addresses only, SSH from the node LAN.

```sh
apt install -y nftables
cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    ip protocol icmp accept
    tcp dport 5403 ip saddr { NODE_A_IP, NODE_B_IP } accept
    tcp dport 22 ip saddr NODE_LAN/24 accept
  }
}
EOF
systemctl enable --now nftables
```

## What the NAS reboot does to it

Virtualization Station stops the VM when QuTS hero reboots and restarts it
after the NAS is back. The VM is gone for at least as long as NFS is. While it
is gone the cluster has 2 of 3 votes and stays quorate. See drills.md for what
happens if a node fails in the same window.
