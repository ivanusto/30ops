"""/etc/30ops/readiness.json: the site's readiness plan (ops30.readiness).

The collector's cron runs `30ops readiness --plan` on it every 15 minutes
and writes readiness.prom; site.yaml is not on the collector, and the cron
path needs neither PyYAML nor the checklist file.
"""
import json

from .. import readiness
from . import Output

PATH = "etc/30ops/readiness.json"


def render(site, sha):
    p = readiness.plan(site)
    p["site_sha256"] = sha
    return {PATH: Output(json.dumps(p, ensure_ascii=False, indent=1, sort_keys=False) + "\n")}
