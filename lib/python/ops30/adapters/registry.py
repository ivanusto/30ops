"""Finds and loads the adapters in adapters/<kind>/<vendor>/.

module(kind, vendor) imports adapter.py with nothing but the standard
library, so the cron path (30ops textfile) works without PyYAML.
meta(kind, vendor) reads adapter.yaml and needs PyYAML; validate, render,
doctor and the tests use it.
"""
import importlib.util
from pathlib import Path

from . import schema

REPO = Path(__file__).resolve().parents[4]
ROOT = REPO / "adapters"
_MODULES = {}


def available():
    """[(kind, vendor)] for every adapter directory that has an adapter.yaml."""
    return sorted((p.parent.parent.name, p.parent.name) for p in ROOT.glob("*/*/adapter.yaml"))


def directory(kind, vendor):
    return ROOT / kind / vendor


def module(kind, vendor):
    key = (kind, vendor)
    if key not in _MODULES:
        path = directory(kind, vendor) / "adapter.py"
        if not path.exists():
            raise LookupError(f"no adapter.py for {kind}/{vendor}")
        spec = importlib.util.spec_from_file_location(f"ops30_adapter_{kind}_{vendor.replace('-', '_')}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _MODULES[key] = mod
    return _MODULES[key]


def meta(kind, vendor):
    from .. import yamlio
    return yamlio.load(directory(kind, vendor) / "adapter.yaml")


def for_role(vendor, role):
    """(kind, vendor) of the adapter that handles role on a host of vendor,
    or None. OS roles (journal, pcap, node) on an appliance that runs a
    general-purpose OS go to the adapter its adapter.yaml names under os."""
    kind = schema.kind_of_role(role)
    if kind is None or not vendor:
        return None
    have = set(available())
    if (kind, vendor) in have:
        return kind, vendor
    if kind == "os":
        for k, v in have:
            if v == vendor:
                os_ = (meta(k, v).get("os") or None)
                if os_ and ("os", os_) in have:
                    return "os", os_
    return None
