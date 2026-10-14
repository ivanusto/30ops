"""Proxmox VE.

quorum: corosync votes as pve-quorum.prom. pve-exporter reports quorate yes
or no; it does not report that one vote is already missing, and that is the
state in which the next failure ends everything.

Arguments are LABEL=root@node1[,root@node2...], one per cluster. Any one
node is enough (the output is cluster-wide); the others are tried in order
when the first does not answer, because the moment a node is down is the
moment the vote count matters. pvecm needs root, so the key logs in as root
and is restricted on the node with
  from="COLLECTOR_IP",command="/usr/bin/pvecm status",restrict
On PVE /root/.ssh/authorized_keys is a symlink into /etc/pve/priv, shared
by every node, so one line covers the cluster.

The output is the one pve-quorum-textfile.sh printed
(tests/golden/textfile/pve-quorum.prom). With more than one cluster the
samples are now grouped per family; the shell version interleaved them per
cluster, which the text format does not allow.
"""
import re

from ops30.adapters.base import Metrics

FAMILIES = [
    ("pve_quorum_up", "1 when pvecm status was read", "gauge"),
    ("pve_quorum_expected_votes", "Expected votes from pvecm status", "gauge"),
    ("pve_quorum_total_votes", "Total votes currently present", "gauge"),
    ("pve_quorum_quorum", "Votes needed for quorum", "gauge"),
    ("pve_quorum_quorate", "1 when the Quorate flag is set", "gauge"),
    ("pve_quorum_qdevice_votes", "Votes contributed by the QDevice, 0 when absent", "gauge"),
    ("pve_quorum_node_votes", "Votes per member node", "gauge"),
]
LAST_RUN = [("pve_quorum_textfile_last_run_timestamp", "Unix time of the last run", "gauge")]
ROW = re.compile(r"^0x[0-9a-f]+[ \t]+[0-9]+")
FLAGS = re.compile(r"^N?A,N?V,N?MW$")


def _int(s):
    m = re.match(r"\s*[-+]?\d+", s or "")
    return int(m.group(0)) if m else 0


def parse(text, label, m):
    """Adds one cluster's samples from a `pvecm status` transcript."""
    exp_v = tot = q = name = qd = None
    quorate = 0
    votes = {}
    for line in text.splitlines():
        f = line.split()
        if line.startswith("Expected votes:"):
            exp_v = f[2] if len(f) > 2 else ""
        elif line.startswith("Total votes:"):
            tot = f[2] if len(f) > 2 else ""
        elif line.startswith("Quorum:"):
            q = f[1] if len(f) > 1 else ""
        elif line.startswith("Flags:"):
            quorate = 1 if "Quorate" in line else 0
        elif line.startswith("Name:"):
            if not name:
                name = f[1] if len(f) > 1 else ""
        # membership rows. With a QDevice configured and connected there is a
        # flags column:  0x00000001 1 A,V,NMW 192.0.2.9 (local)
        #                0x00000000 1 Qdevice
        # When corosync-qdevice is not running the column is gone altogether:
        #                0x00000001 1 192.0.2.9 (local)
        if ROW.match(line):
            if len(f) > 2 and f[2] == "Qdevice":
                qd = f[1]
            else:
                node = (f[3] if len(f) > 3 else "") if len(f) > 2 and FLAGS.match(f[2]) else (f[2] if len(f) > 2 else "")
                votes[node] = f[1]
    if not label:
        label = name or "pve"
    L = [("cluster", label)]
    if not exp_v:
        m.add("pve_quorum_up", L, "0")
        return
    m.add("pve_quorum_up", L, "1")
    m.add("pve_quorum_expected_votes", L, _int(exp_v))
    m.add("pve_quorum_total_votes", L, _int(tot))
    m.add("pve_quorum_quorum", L, _int(q))
    m.add("pve_quorum_quorate", L, quorate)
    m.add("pve_quorum_qdevice_votes", L, _int(qd))
    for node, v in votes.items():
        m.add("pve_quorum_node_votes", L + [("node", node)], _int(v))


def _emit(m, now):
    last = Metrics(LAST_RUN)
    last.add("pve_quorum_textfile_last_run_timestamp", [], int(now))
    return m.headers_first() + last.blocks()


def quorum(targets, transport, now):
    m = Metrics(FAMILIES)
    for t in targets:
        out = ""
        for dest in t.dests:
            r = transport.run(dest, ["pvecm", "status"])
            out = r.out.decode("utf-8", "replace") if r.rc == 0 else ""
            if "Expected votes:" in out:
                break
        parse(out, t.label, m)
    return _emit(m, now)


def quorum_from_text(text, now):
    """One transcript on stdin, label from its Name: line (tests, debugging)."""
    m = Metrics(FAMILIES)
    parse(text, "", m)
    return _emit(m, now)
