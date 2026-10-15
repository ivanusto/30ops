"""rules/status.yml: vendor status strings normalised to 1 (healthy) or 0.

Every adapter.yaml status entry becomes one recording rule. The result keeps
all labels of the source series, the status string included, so the alerts
that compare it with 0 keep their labels and annotations. The two sides of
`or` never overlap: the regex is anchored and one side is its negation.

  ok:   X{l=~"ok"} * 0 + 1 or X{l!~"ok"} * 0      a string not seen yet is 0
  bad:  X{l=~"bad"} * 0 or X{l!~"bad"} * 0 + 1    only the listed string is 0

A presence entry (adapter.yaml presence:) records whether the device is
there at all, 0 where the label matches `absent` and 1 otherwise:

  absent:  X{l=~"absent"} * 0 or X{l!~"absent"} * 0 + 1

Prometheus evaluates the status group on its own schedule, so an alert can
see the recorded value up to one evaluation interval late.
"""
from .. import yamlio
from ..adapters import registry
from . import Output, header

PATH = "etc/30ops/prometheus/rules/status.yml"
GROUP = "status"


def entries():
    """[(kind, vendor, entry)] for every status entry of every adapter."""
    out = []
    for kind, vendor in registry.available():
        for e in registry.meta(kind, vendor).get("status") or []:
            out.append((kind, vendor, e))
    return out


def presence():
    """[(kind, vendor, entry)] for every presence entry of every adapter."""
    out = []
    for kind, vendor in registry.available():
        for e in registry.meta(kind, vendor).get("presence") or []:
            out.append((kind, vendor, e))
    return out


def expr(e):
    m, lab = e["metric"], e["label"]
    if "absent" in e:
        rx = e["absent"]
        return f'{m}{{{lab}=~"{rx}"}} * 0 or {m}{{{lab}!~"{rx}"}} * 0 + 1'
    if "ok" in e:
        rx = e["ok"]
        return f'{m}{{{lab}=~"{rx}"}} * 0 + 1 or {m}{{{lab}!~"{rx}"}} * 0'
    rx = e["bad"]
    return f'{m}{{{lab}=~"{rx}"}} * 0 or {m}{{{lab}!~"{rx}"}} * 0 + 1'


def render(site, sha):
    rules = [{"record": e["record"], "expr": expr(e)} for _, _, e in entries() + presence()]
    if not rules:
        return {}
    doc = {"groups": [{"name": GROUP, "rules": rules}]}
    return {PATH: Output(header(sha) + yamlio.dumps(doc))}
