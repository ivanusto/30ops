"""The alert rules: collector/prometheus/rules/*.yml with every ${key}
replaced by the site's threshold (site.yaml alerting.thresholds) or the
default in collector/prometheus/thresholds.yml. Only ${name} is a
placeholder; Prometheus' own $labels, $value and {{ }} pass through.
"""
import glob
import os
import re

from .. import site as S
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


def render(site, sha):
    values = S.thresholds(site)
    out = {}
    for src in sources():
        name = os.path.basename(src)
        with open(src, encoding="utf-8") as f:
            out[f"{P}/{name}"] = Output(header(sha) + fill(f.read(), values, name))
    return out
