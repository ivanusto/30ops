"""Metric output shared by the adapters' collect capabilities.

A collect capability fills a Metrics with samples whose values are already
formatted (the text the old shell writers printed, "26" or "0.003369"), and
emits it in one of the two layouts the existing textfiles use:

  blocks()        HELP, TYPE and the samples of one family together, families
                  without samples left out (nas.prom)
  headers_first() HELP and TYPE of every family first, then the samples in
                  family order (pve-quorum.prom)

Either way every family is one contiguous block, which is what the text
format and node_exporter require.
"""
from dataclasses import dataclass, field

from ..textfile import esc


@dataclass(frozen=True)
class Target:
    """One cron argument LABEL=user@host[,user@host...]: a label and the ssh
    destinations to try in order."""
    label: str
    dests: tuple

    @classmethod
    def parse(cls, spec):
        label, sep, rest = spec.partition("=")
        dests = tuple(d for d in rest.split(",") if d)
        if not sep or not label or not dests or not all("@" in d for d in dests):
            raise ValueError(f"expected LABEL=user@host[,user@host...], got {spec}")
        return cls(label, dests)


@dataclass
class Metrics:
    """Families in declared order, each with its samples in insertion order."""
    families: list                      # [(name, help, type)]
    samples: dict = field(default_factory=dict)

    def add(self, name, labels, value):
        if name not in {f[0] for f in self.families}:
            raise KeyError(f"{name} is not a declared family")
        lab = ",".join(f'{k}="{esc(v)}"' for k, v in labels)
        self.samples.setdefault(name, []).append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

    def blocks(self):
        out = []
        for name, help_, type_ in self.families:
            if name in self.samples:
                out.append(f"# HELP {name} {help_}\n# TYPE {name} {type_}\n")
                out.extend(s + "\n" for s in self.samples[name])
        return "".join(out)

    def headers_first(self):
        out = [f"# HELP {n} {h}\n# TYPE {n} {t}\n" for n, h, t in self.families]
        for name, _, _ in self.families:
            out.extend(s + "\n" for s in self.samples.get(name, ()))
        return "".join(out)


def parse_textfile(text):
    """{family: [label-name tuples]} of a textfile, for the contract test."""
    import re
    fams = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})? \S+$", line)
        if not m:
            raise ValueError(f"not a sample line: {line!r}")
        names = tuple(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="(?:[^"\\]|\\.)*"', m.group(3) or ""))
        fams.setdefault(m.group(1), set()).add(names)
    return fams
