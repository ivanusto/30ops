"""Finds and reads the plugins in plugins/<name>/ (docs/plugins.md).

A plugin is a directory with a plugin.yaml. Everything 30ops does with a
plugin comes from that file: which hosts may list it (roles, vendors), what
the node bundle carries and runs (install), the textfiles it writes, the
scrape job that reads them, its rules, thresholds and dashboard rows, and
its readiness items. A site turns a plugin on by listing it in a host's
plugins; render then adds the plugin's job, rules and rows, and leaves them
out when no host lists it.

available() only globs, so site.py can build its enum without PyYAML.
"""
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
ROOT = REPO / "plugins"
HOOK = "install.sh"   # the one install hook name; node-install.sh runs plugins/<name>/install.sh
_META = {}


def available():
    """Names of the plugin directories that have a plugin.yaml, sorted."""
    return tuple(sorted(p.parent.name for p in ROOT.glob("*/plugin.yaml")))


def directory(name):
    return ROOT / name


def meta(name):
    if name not in _META:
        from . import yamlio
        _META[name] = yamlio.load(directory(name) / "plugin.yaml") or {}
    return _META[name]


def enabled(site):
    """Plugins any host of the (resolved or raw) site lists, sorted."""
    return sorted({p for h in site.get("hosts") or [] if isinstance(h, dict)
                   for p in h.get("plugins") or [] if p in available()})


def hosts(site, name):
    return [h for h in site["hosts"] if name in (h.get("plugins") or [])]


def rule_files(name):
    """Absolute paths of the plugin's rule files, in plugin.yaml order."""
    return [str(directory(name) / r) for r in meta(name).get("rules") or []]


def threshold_file(name):
    t = meta(name).get("thresholds")
    return str(directory(name) / t) if t else None


def threshold_order(name):
    return [tuple(p) for p in meta(name).get("threshold_order") or []]


def scrape(name):
    """The plugin's scrape entry ({job, port, replaces, config}) or None."""
    return meta(name).get("scrape")


def dashboard(name):
    d = meta(name).get("dashboard")
    return str(directory(name) / d) if d else None


def install_files(name):
    """Repo-relative paths the node bundle carries for the plugin."""
    return [os.path.join("plugins", name, f) for f in (meta(name).get("install") or {}).get("files") or []]


def textfiles(name):
    return list(meta(name).get("textfile") or [])


def readiness_items(name):
    return list(meta(name).get("readiness") or [])


def fits(name, h):
    """Why host h cannot carry the plugin, or None when it can."""
    m = meta(name)
    roles, vendors = m.get("roles") or [], m.get("vendors") or []
    if roles and not set(roles) & set(h.get("roles") or []):
        return f"plugin {name} needs one of roles {', '.join(roles)}"
    if vendors and h.get("vendor") not in vendors:
        return f"plugin {name} runs on vendor {', '.join(vendors)}"
    return None
