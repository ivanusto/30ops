"""Switches and access points that answer the standard MIBs. The collector
scrapes them itself (the switch-snmp job, module if_mib); the adapter only
says what to prepare on the device."""


def manual_steps(site, h):
    col = next(x for x in site["hosts"] if x["name"] == site["collector"]["host"])["address"]
    steps = [f"SNMP v3, read-only, authPriv, UDP 161 reachable from {col} only",
             f"syslog to {col} port 514, if the device can send it (and give the host role syslog)"]
    if not h.get("snmp"):
        steps.append("then set snmp.auth for this host in site.yaml, or the collector does not scrape it")
    return steps
