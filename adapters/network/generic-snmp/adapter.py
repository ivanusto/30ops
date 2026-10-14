"""Switches and access points that answer the standard MIBs. Collection
(interfaces, sensors, uptime) comes in v0.7; until then the adapter only
says what to prepare on the device."""


def manual_steps(site, h):
    col = next(x for x in site["hosts"] if x["name"] == site["collector"]["host"])["address"]
    return [f"SNMP v3, read-only, authPriv, UDP 161 reachable from {col} only",
            f"syslog to {col} port 514, if the device can send it",
            "30ops scrapes switches from v0.7"]
