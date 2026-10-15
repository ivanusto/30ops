"""The alert rules: collector/prometheus/rules/*.yml with every ${key}
replaced by the site's threshold (site.yaml alerting.thresholds) or the
default in collector/prometheus/thresholds.yml. Only ${name} is a
placeholder; Prometheus' own $labels, $value and {{ }} pass through.

Each plugin a host lists adds its rule files (plugin.yaml rules:), filled
the same way, as rules/plugin-<name>.yml.
"""
import glob
import os
import re

from .. import plugins, site as S
from . import Output, header

P = "etc/30ops/prometheus/rules"
SRC = os.path.join(S.REPO, "collector", "prometheus", "rules")
PLACEHOLDER = re.compile(r"\$\{([a-z0-9_]+)\}")


def number(v):
    """80 -> "80", 0.5 -> "0.5": what a person would write in PromQL."""
    return str(int(v)) if float(v).is_integer() else repr(float(v))


def fill(text, values, name="rules"):
    def sub(m):
        if m.group(1) not in values:
            raise S.SiteError(f"{name}: ${{{m.group(1)}}} is not in thresholds.yml")
        return number(values[m.group(1)])
    out = PLACEHOLDER.sub(sub, text)
    if "${" in out:
        raise S.SiteError(f"{name}: a ${{ is left after filling the thresholds")
    return out


def sources():
    return sorted(glob.glob(os.path.join(SRC, "*.yml")))


def plugin_sources(names=None):
    """[(output file name, source path)] of the plugins' rules (all plugins by default)."""
    out = []
    for n in plugins.available() if names is None else names:
        files = plugins.rule_files(n)
        for i, src in enumerate(files):
            out.append((f"plugin-{n}.yml" if len(files) == 1 else f"plugin-{n}-{i + 1}.yml", src))
    return out


def render(site, sha):
    values = S.thresholds(site)
    out = {}
    srcs = [(os.path.basename(s), s) for s in sources()] + plugin_sources(plugins.enabled(site))
    for name, src in srcs:
        with open(src, encoding="utf-8") as f:
            out[f"{P}/{name}"] = Output(header(sha) + fill(f.read(), values, name))
    return out
