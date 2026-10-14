"""Grafana datasource provisioning: Prometheus and Alertmanager always,
VictoriaLogs when the site collects logs (it used to be dropped in by hand
from logs/grafana/)."""
from .. import site as S, yamlio
from . import Output, header
from .prometheus import logs_enabled

D = "etc/30ops/grafana/datasources"


def render(site, sha):
    out = {f"{D}/prometheus.yml": Output(header(sha) + yamlio.dumps(
        yamlio.load(f"{S.REPO}/collector/grafana/provisioning/datasources/prometheus.yml")))}
    if logs_enabled(site):
        out[f"{D}/victorialogs.yml"] = Output(header(sha) + yamlio.dumps(
            yamlio.load(f"{S.REPO}/logs/grafana/datasource-victorialogs.yml")))
    return out
