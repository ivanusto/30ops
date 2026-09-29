# pve-qdevice-on-qnap

Third vote for a two node Proxmox VE cluster, hosted as a small Debian VM on
QNAP Virtualization Station, on the same NAS that serves the cluster's NFS
storage.

| File | What |
|---|---|
| `qnetd-vm.md` | The VM: size, network, autostart, `corosync-qnetd` install, firewall |
| `setup.sh` | On a cluster node: check the node count from `corosync.conf`, install `corosync-qdevice` on both nodes, `pvecm qdevice setup <ip>`, print the result |
| `check.sh` | One screen of quorum and HA state; exit code for cron or an exporter |
| `record.sh` | Timestamped log of `check.sh` and one HA resource, every 2 s, for drills |
| `drills.md` | Four failures with expected and observed outcomes |

`check.sh` exit codes: 0 all three votes present, 1 quorate but nothing more
can fail (a vote missing, no QDevice configured, an HA LRM that stopped
reporting, or an HA service in error state), 2 not quorate.

Apache-2.0.
