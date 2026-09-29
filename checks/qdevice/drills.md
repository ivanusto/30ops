# Drills

Four failures, each a planned change with a start time, an expected outcome
and a place to write what actually happened. Run them before HA is trusted
with anything, and again after any change to the nodes, the NAS or the VM.

Start a recorder on the node that stays up, then cause the failure:

```sh
systemctl reset-failed drillN 2>/dev/null
systemd-run --unit=drillN /root/pve-qdevice-on-qnap/record.sh drillN vm:<id>
# ... drill ...
systemctl stop drillN; cat /root/drills/drillN.log
```

`record.sh` writes one line every 2 s with the `check.sh` exit code, the
votes and the state of one HA resource, so every duration below can be
recomputed from the log. Use a small test VM on the NFS storage as the HA
resource; inside it, write a timestamp to disk once a second with `dsync` so
an I/O stall shows up as a gap. Expected votes 3, quorum 2.

| # | Failure | Votes left | Expected | Observed (date, duration, notes) |
|---|---|---|---|---|
| 1 | NAS reboot (QDevice VM gone, NFS gone) | 2 of 3 | Quorate stays Yes. Guests on NFS freeze on I/O until NFS returns plus the NFSv4.1 grace period. Guests on local storage keep running. `check.sh` exits 1 until the QDevice VM is back. | pending |
| 2 | Node A powered off hard (QDevice up) | 2 of 3 | Quorate Yes on B. HA resources on A are fenced and restarted on B after the fence timeout (about 2 minutes). | pending |
| 3 | Node A off **and** NAS rebooting at the same time | 1 of 3 | Quorate **No** on B. If B has active HA resources, `pve-ha-lrm` loses its lock and B self-fences (watchdog reboot) after about 60 s, taking its local guests with it. Everything is down until the NAS is back. | pending |
| 4 | QDevice VM stopped by hand, both nodes up | 2 of 3 | Quorate Yes. `check.sh` exits 1. Confirms the VM is optional day to day and only matters during a node failure. | pending |

Drill 3 is the one to understand. The NAS is both shared storage and the
third vote, so a NAS maintenance window is also a window in which a single
node failure takes the whole cluster down. Treat NAS reboots as a change
(Day 26) and, during that window, either accept the exposure or set the HA
resources to `ignored` so that neither node self-fences.

"Powered off hard" means no clean shutdown: pull the plug, use IPMI, or
`echo o > /proc/sysrq-trigger`. A clean shutdown lets HA stop or migrate
the resources first, which is a different test.

Never fix a lost quorum with `pvecm expected 1` unless you have confirmed by
hand that the other node is really off. Two nodes each believing they are
alone is how a shared disk gets written from both sides.
