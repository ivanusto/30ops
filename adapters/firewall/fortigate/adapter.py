"""Fortinet FortiGate, REST API with a read-only token.

licences: every licence the device reports, from
/api/v2/monitor/license/status, as (component, status, expires).
eol-textfile.py turns them into asset_eol_timestamp_seconds and
asset_licence_status in eol.prom. The response shape is walked generically:
any object with a numeric `expires` is a licence and its key path is the
component, so a new licence type shows up by itself.

The token's admin profile needs nothing but read on the licence status
(sysgrp custom, upd read): sysgrp read would also show the policies and
system global.
"""
import json

PATH = "/api/v2/monitor/license/status"


def walk_licences(obj, path=(), parent_exp=None):
    """Yield (component, status, expires) for every object with a numeric expires.

    Skipped, as seen on a 60F with FortiOS 7.6.7: a free_license (the
    FortiCloud sandbox tier carries the contract's date but never lapses),
    and an object nested in a licence with the same expires
    (iot_detection.definitions repeats iot_detection)."""
    if isinstance(obj, dict):
        exp = obj.get("expires")
        own = None
        if isinstance(exp, (int, float)) and exp > 0:
            own = int(exp)
            status = str(obj.get("status", ""))
            if status != "free_license" and own != parent_exp:
                yield ".".join(path) or "licence", status, own
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield from walk_licences(v, path + (str(k),), own if own is not None else parent_exp)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_licences(v, path, parent_exp)


def from_doc(doc):
    return list(walk_licences(doc.get("results", doc) if isinstance(doc, dict) else doc))


def licences(transport, url, token, insecure=False):
    """[(component, status, expires)]; raises RuntimeError when the device
    does not answer with a licence document."""
    r = transport.get(url.rstrip("/") + PATH,
                      {"Authorization": f"Bearer {token}", "Accept": "application/json"}, insecure)
    if r.rc != 200:
        raise RuntimeError(f"{PATH}: HTTP {r.rc or 'error'} {r.err.decode(errors='replace')}".strip())
    try:
        return from_doc(json.loads(r.out))
    except ValueError as e:
        raise RuntimeError(f"{PATH}: not JSON ({e})") from None


def manual_steps(site, h):
    """What 30ops install node prints for a FortiGate. Back up the config
    first, and make each of these a change record."""
    col = next(x for x in site["hosts"] if x["name"] == site["collector"]["host"])["address"]
    out = []
    if h.get("api"):
        f = site["credentials"][h["api"]["token"]]["file"]
        out.append(f"an admin profile with sysgrp custom and only upd read, and a REST API user on it with "
                   f"trusthost {col}/32; its token in {f} (0400, install collector sets the owner)")
    if "syslog" in h["roles"] or "webfilter" in h["roles"]:
        out.append(f"log syslogd2: server {col}, port 514, mode reliable, format rfc5424, forward and local "
                   "traffic (logs/firewall/fortigate-webfilter.md)")
    if "audit-source" in h["roles"]:
        out.append(f"log syslogd3: server {col}, port 515, mode reliable, format rfc5424, event log only "
                   "(logs/audit/fortigate-syslogd3.md)")
    return out
