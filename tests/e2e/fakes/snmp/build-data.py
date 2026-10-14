#!/usr/bin/env python3
"""Synthesise the QNAP OIDs of the snmp_exporter qnap module for the e2e
fake NAS: every walk OID below the QNAP enterprise gets a value, tables
get two rows, scalars get .0. Status strings and enums are the healthy
ones (adapters/nas/qnap/adapter.yaml status:), so the baseline raises no
alert. Nothing comes from a real NAS.

  build-data.py [SNMP_YML] > qnap.data     # OID <tab> type <tab> value, sorted

Types are the pass_persist ones: integer, gauge, counter64, string.
"""
import os
import sys

import yaml

ENTERPRISE = "1.3.6.1.4.1.55062"
ROWS = (1, 2)

# healthy values by metric name; anything else gets a default by type
VALUES = {
    "qnap_disk_status": "Good",
    "qnap_smart_attribute_status": "GOOD",
    "qnap_raid_status": "Ready",
    "qnap_folder_status": "Ready",
    "qnap_ups_status": "-1",
    "qnap_ups_load_percent": "-1",
    "qnap_ups_battery_percent": "-1",
    "qnap_disk_temperature_celsius": 35,
    "qnap_cpu_temperature_celsius": 45,
    "qnap_system_temperature_celsius": 30,
    "qnap_cpu_usage_percent": 7,
    "qnap_fan_speed_rpm": 900,
    "qnap_firmware_upgrade_available": 0,
    "qnap_firmware_info": "QuTS hero 6.0.2",
    "qnap_model_info": "TS-E2E",
    "qnap_uptime": 864000,
    "qnap_disk_count": 2,
    "qnap_pool_count": 2,
    "qnap_smart_attribute_current": 100,
    "qnap_smart_attribute_worst": 100,
    "qnap_smart_attribute_threshold": 10,
}


def columns(module):
    """{oid: (name, snmp_exporter type, indexed)} for every metric and lookup."""
    out = {}
    for m in module["metrics"]:
        out[m["oid"]] = (m["name"], m["type"], bool(m.get("indexes")))
        for lk in m.get("lookups") or []:
            out.setdefault(lk["oid"], (lk["labelname"], lk["type"], True))
    return out


def value(name, typ, oid, row):
    if name in VALUES:
        v = VALUES[name]
        return ("string", v) if isinstance(v, str) else ("integer", v)
    if typ in ("EnumAsInfo", "EnumAsStateSet"):
        return ("integer", 0)      # ready, ok, no: the healthy end of every QNAP enum
    if typ == "DisplayString":
        return ("string", f"e2e-{name}-{row}")
    if typ == "counter":
        big = 500_000_000_000 if any(w in name for w in ("free", "available", "used")) else 1_000_000_000_000
        return ("counter64", big)
    return ("gauge", row)


def build(snmp_yml):
    with open(snmp_yml, encoding="utf-8") as f:
        module = yaml.safe_load(f)["modules"]["qnap"]
    cols = columns(module)
    rows = []
    for w in module["walk"]:
        if not w.startswith(ENTERPRISE + "."):
            continue          # IF-MIB and sysName come from snmpd itself
        name, typ, indexed = cols.get(w, (f"oid{w.rsplit('.', 1)[1]}", "DisplayString", True))
        for r in (ROWS if indexed else (0,)):
            t, v = value(name, typ, w, r)
            rows.append((f"{w}.{r}", t, v))
    rows.sort(key=lambda x: tuple(int(p) for p in x[0].split(".")))
    return rows


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    snmp_yml = argv[1] if len(argv) > 1 else os.path.join(here, "../../../../collector/prometheus/snmp.yml")
    for oid, t, v in build(snmp_yml):
        print(f"{oid}\t{t}\t{v}")


if __name__ == "__main__":
    main(sys.argv)
