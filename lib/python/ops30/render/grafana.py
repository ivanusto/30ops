"""Grafana: datasource provisioning (Prometheus and Alertmanager always,
VictoriaLogs when the site collects logs) and the dashboard, drawn by
collector/grafana/build-dashboard.py with the site's thresholds and the
rows of the plugins its hosts list. The
dashboard provider (collector/grafana/provisioning/dashboards/) is product
and is mounted from the checkout."""
import os

from .. import plugins, site as S, yamlio
from . import Output, header
from .prometheus import logs_enabled

G = "etc/30ops/grafana"
SRC = os.path.join(S.REPO, "collector", "grafana")


def dashboard(site):
    mod = S._load_script(os.path.join(SRC, "build-dashboard.py"), "_ops30_dashboard")
    return mod.render(S.thresholds(site), plugins.enabled(site))


def render(site, sha):
    ds = os.path.join(SRC, "provisioning", "datasources")
    out = {f"{G}/datasources/prometheus.yml": Output(header(sha) + yamlio.dumps(yamlio.load(f"{ds}/prometheus.yml")))}
    if logs_enabled(site):
        out[f"{G}/datasources/victorialogs.yml"] = Output(
            header(sha) + yamlio.dumps(yamlio.load(f"{ds}/victorialogs.yml")))
    out[f"{G}/dashboards/onprem-overview.json"] = Output(dashboard(site))
    return out
