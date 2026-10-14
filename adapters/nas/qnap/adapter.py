"""QNAP NAS on QuTS hero.

health: what the QTS MIB does not have (ZFS pools by name, datasets,
snapshots, HBS 3, memory fragmentation) as nas.prom, collected over one ssh
session per NAS. remote.sh is piped to the NAS's sh and prints raw command
output; everything is parsed here. Hardware (disk temperature, SMART, fans,
pools by SNMP index, UPS) comes from snmp_exporter (snmp_module).

buddyinfo is here because a GPU on the NAS stops initialising once host
memory is fragmented: the NVIDIA driver wants physically contiguous blocks,
MemFree can be 15 GB while every high order is empty, and only a reboot
brings them back. The alert reads the share of free memory still in blocks
of 2 MiB (order 9) and up.

The output is the one nas-textfile.sh printed (tests/golden/textfile/nas.prom):
same families, labels and value text. The one change: a session that ends
before "@@end" now yields nas_up 0 alone. The shell version printed the
samples it had and then a second nas_up, and node_exporter rejected the
whole file, for every NAS.
"""
from pathlib import Path

from ops30.adapters.base import Metrics

REMOTE = (Path(__file__).parent / "remote.sh").read_bytes()

FAMILIES = [
    ("nas_up", "1 when ssh and zfs answered", "gauge"),
    ("nas_zpool_size_bytes", "Pool size", "gauge"),
    ("nas_zpool_alloc_bytes", "Pool allocated bytes", "gauge"),
    ("nas_zpool_capacity_percent", "Pool capacity used, percent", "gauge"),
    ("nas_zpool_health", "1 for the current pool state", "gauge"),
    ("nas_zfs_used_bytes", "Dataset used bytes", "gauge"),
    ("nas_zfs_snapshots", "Snapshots per dataset, excluding :init:", "gauge"),
    ("nas_zfs_snapshot_used_bytes", "Space held by snapshots per dataset", "gauge"),
    ("nas_zfs_snapshot_newest_timestamp", "Creation time of the newest snapshot", "gauge"),
    ("nas_zfs_snapshot_oldest_timestamp", "Creation time of the oldest snapshot", "gauge"),
    ("nas_hbs_installed", "1 when HBS 3 is installed", "gauge"),
    ("nas_buddyinfo_free_blocks", "Free blocks of 2^order pages per zone, from /proc/buddyinfo", "gauge"),
    ("nas_memory_free_bytes", "Free memory per zone, summed from /proc/buddyinfo", "gauge"),
    ("nas_memory_free_highorder_ratio", "Share of free memory per zone in blocks of order 9 (2 MiB) and up", "gauge"),
    ("nas_boot_time_seconds", "Unix time the NAS booted", "gauge"),
    ("nas_textfile_last_run_timestamp", "Unix time of the last run per NAS", "gauge"),
]


def sections(text):
    """{name: (inline value, [lines])} from remote.sh output."""
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith("@@"):
            name, _, val = line[2:].partition(" ")
            cur = out[name] = (val, [])
        elif cur is not None:
            cur[1].append(line)
    return out


def _num(s):
    """awk's numeric value of a field: the leading number, 0 when there is none."""
    import re
    m = re.match(r"\s*[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?", s)
    return float(m.group(0)) if m else 0.0


def _one(m, label, s):
    L = [("nas", label)]
    ok = s["ok"][0] == "1"
    m.add("nas_up", L, "1" if ok else "0")
    # memory state does not depend on zfs, so it is reported even when nas_up is 0
    if "buddyinfo" in s:
        ps = _num(s["pagesize"][0]) or 4096 if "pagesize" in s else 4096
        tot, hi, zones = {}, {}, []
        for line in s["buddyinfo"][1]:
            f = line.split()
            if len(f) < 4 or f[0] != "Node":
                continue
            node, zone = f[1].replace(",", "", 1), f[3]
            if zone not in tot:
                zones.append(zone)
                tot[zone], hi[zone] = 0.0, 0.0
            for o, v in enumerate(f[4:]):
                m.add("nas_buddyinfo_free_blocks", L + [("node", node), ("zone", zone), ("order", str(o))], v)
                p = _num(v) * 2 ** o
                tot[zone] += p
                if o >= 9:
                    hi[zone] += p
        for z in zones:
            m.add("nas_memory_free_bytes", L + [("zone", z)], "%.0f" % (tot[z] * ps))
            m.add("nas_memory_free_highorder_ratio", L + [("zone", z)], "%.6f" % (hi[z] / tot[z] if tot[z] else 0))
    for line in s.get("stat", ("", []))[1]:
        f = line.split()
        if len(f) > 1 and f[0] == "btime" and f[1]:
            m.add("nas_boot_time_seconds", L, f[1])
            break
    if not ok:
        return
    for line in s.get("zpool", ("", []))[1]:
        name, size, alloc, cap, health = (line.split("\t", 4) + [""] * 5)[:5]
        P = L + [("pool", name)]
        m.add("nas_zpool_size_bytes", P, size)
        m.add("nas_zpool_alloc_bytes", P, alloc)
        m.add("nas_zpool_capacity_percent", P, cap[:-1] if cap.endswith("%") else cap)
        m.add("nas_zpool_health", P + [("state", health)], "1")
    for line in s.get("zfs", ("", []))[1]:
        name, used = (line.split("\t", 1) + [""])[:2]
        m.add("nas_zfs_used_bytes", L + [("dataset", name)], used)
    n, u, old, new, order = {}, {}, {}, {}, []
    for line in s.get("snapshots", ("", []))[1]:
        f = line.split("\t")
        ds, _, sn = f[0].partition("@")
        if ":init:" in sn:
            continue
        created = _num(f[1]) if len(f) > 1 else 0.0
        if ds not in n:
            order.append(ds)
            n[ds], u[ds], old[ds], new[ds] = 0, 0.0, created, 0.0
        n[ds] += 1
        u[ds] += _num(f[2]) if len(f) > 2 else 0.0
        old[ds] = min(old[ds], created)
        new[ds] = max(new[ds], created)
    for ds in order:
        D = L + [("dataset", ds)]
        m.add("nas_zfs_snapshots", D, "%d" % n[ds])
        m.add("nas_zfs_snapshot_used_bytes", D, "%d" % u[ds])
        m.add("nas_zfs_snapshot_newest_timestamp", D, "%d" % new[ds])
        m.add("nas_zfs_snapshot_oldest_timestamp", D, "%d" % old[ds])
    hbs = "1" if any(x.strip() for x in s.get("hbs", ("", []))[1]) else "0"
    m.add("nas_hbs_installed", L, hbs)
    m.add("nas_textfile_last_run_timestamp", L, s["now"][0])


def health(targets, transport, now):
    m = Metrics(FAMILIES)
    for t in targets:
        r = transport.run(t.dests[0], ["sh", "-s"], REMOTE)
        s = sections(r.out.decode("utf-8", "replace"))
        if r.rc != 0 or "end" not in s or "ok" not in s:
            m.add("nas_up", [("nas", t.label)], "0")
            continue
        _one(m, t.label, s)
    return m.blocks()
