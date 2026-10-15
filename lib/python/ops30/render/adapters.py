"""30ops-adapters.prom: which adapter serves which host, as a textfile.

The metrics an adapter writes keep their v0.4 names and labels (TSDB
continuity), so they carry no vendor label. This file says it once per host
and kind instead, with the label the existing series use to name the host,
so a query can join on it:

  ops30_adapter_info{name, kind, vendor, version, <join>} 1

  nas         nas="<labels.nas or name>"     as nas.prom and the SNMP job
  hypervisor  cluster="<pve.cluster>"        as pve-quorum.prom
  firewall    host="<syslog.devname>"        as fw.prom
  os          instance="<address>:9100"      as the node and collector jobs

It also says which NAS the site runs without a UPS on purpose (site.yaml
ups: none), for NasUpsAbsent to leave alone:

  ops30_ups_none{nas} 1

It is static (it changes only with site.yaml), so install puts it in the
textfile directory and doctor does not check its age.
"""
from .. import site as S
from ..adapters import registry
from ..textfile import esc
from . import Output, header

HELP = "# HELP ops30_adapter_info The adapter that serves a host for one kind; join on the kind's host label\n" \
       "# TYPE ops30_adapter_info gauge\n"


def join(kind, h):
    if kind == "nas":
        return [("nas", h["labels"].get("nas", h["name"]))]
    if kind == "hypervisor" and h.get("pve"):
        return [("cluster", h["pve"]["cluster"])]
    if kind == "firewall" and h.get("syslog"):
        return [("host", h["syslog"]["devname"])]
    if kind == "os" and set(h["roles"]) & {"collector", "node"}:
        return [("instance", f"{h['address']}:9100")]
    return []


def lines(site):
    out = []
    for h in site["hosts"]:
        seen = []
        for r in h["roles"]:
            kv = registry.for_role(h.get("vendor"), r)
            if kv and kv not in seen:
                seen.append(kv)
        for kind, vendor in seen:
            labels = [("name", h["name"]), ("kind", kind), ("vendor", vendor),
                      ("version", str(registry.meta(kind, vendor)["version"]))] + join(kind, h)
            out.append("ops30_adapter_info{" + ",".join(f'{k}="{esc(v)}"' for k, v in labels) + "} 1\n")
    return out


UPS_HELP = "# HELP ops30_ups_none 1 for a NAS that site.yaml says runs without a UPS (ups: none)\n" \
           "# TYPE ops30_ups_none gauge\n"


def ups_none(site):
    return [f'ops30_ups_none{{nas="{esc(join("nas", h)[0][1])}"}} 1\n'
            for h in site["hosts"] if h.get("ups") == "none" and "nas" in h["roles"]]


def render(site, sha):
    ls, ups = lines(site), ups_none(site)
    if not ls and not ups:
        return {}
    path = site["collector"]["textfile_dir"].strip("/") + "/30ops-adapters.prom"
    return {path: Output(header(sha) + HELP + "".join(ls) + (UPS_HELP + "".join(ups) if ups else ""))}


