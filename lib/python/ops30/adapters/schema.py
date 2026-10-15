"""The contract of every adapter kind.

KINDS lists, per kind, the roles of site.yaml it serves and the capabilities
an adapter of that kind may declare. FAMILIES locks the metric families each
collect capability writes, with their label names in output order: a
capability whose output has a family or a label that is not listed here
fails the contract test, so no metric is renamed or relabelled by accident
(TSDB continuity, see docs/rules.md).
"""

KINDS = {
    "nas": {"roles": ("nas",),
            "capabilities": ("facts", "health", "snapshots", "share_canary", "snmp_module", "syslog_profile")},
    "firewall": {"roles": ("firewall", "audit-source", "webfilter"),
                 "capabilities": ("facts", "licences", "audit_source", "config_backup", "syslog_profile",
                                  "managed_aps")},
    "hypervisor": {"roles": ("hypervisor",),
                   "capabilities": ("facts", "quorum", "backup_jobs", "restore_test", "exporter_config")},
    "network": {"roles": ("switch", "ap"),
                "capabilities": ("interfaces", "sensors", "uptime")},
    "os": {"roles": ("collector", "node", "journal", "pcap", "qdevice", "deadman"),
           "capabilities": ("journal", "node_exporter", "pcap", "deadman")},
}

# how a capability is delivered
FACES = ("collect", "data", "snmp", "render", "descriptor", "install")
STATUSES = ("implemented", "planned")

FAMILIES = {
    ("nas", "health"): {
        "nas_up": ("nas",),
        "nas_zpool_size_bytes": ("nas", "pool"),
        "nas_zpool_alloc_bytes": ("nas", "pool"),
        "nas_zpool_capacity_percent": ("nas", "pool"),
        "nas_zpool_health": ("nas", "pool", "state"),
        "nas_zfs_used_bytes": ("nas", "dataset"),
        "nas_zfs_snapshots": ("nas", "dataset"),
        "nas_zfs_snapshot_used_bytes": ("nas", "dataset"),
        "nas_zfs_snapshot_newest_timestamp": ("nas", "dataset"),
        "nas_zfs_snapshot_oldest_timestamp": ("nas", "dataset"),
        "nas_hbs_installed": ("nas",),
        "nas_buddyinfo_free_blocks": ("nas", "node", "zone", "order"),
        "nas_memory_free_bytes": ("nas", "zone"),
        "nas_memory_free_highorder_ratio": ("nas", "zone"),
        "nas_boot_time_seconds": ("nas",),
        "nas_textfile_last_run_timestamp": ("nas",),
    },
    ("hypervisor", "quorum"): {
        "pve_quorum_up": ("cluster",),
        "pve_quorum_expected_votes": ("cluster",),
        "pve_quorum_total_votes": ("cluster",),
        "pve_quorum_quorum": ("cluster",),
        "pve_quorum_quorate": ("cluster",),
        "pve_quorum_qdevice_votes": ("cluster",),
        "pve_quorum_node_votes": ("cluster", "node"),
        "pve_quorum_textfile_last_run_timestamp": (),
    },
}


def kind_of_role(role):
    for k, v in KINDS.items():
        if role in v["roles"]:
            return k
    return None
