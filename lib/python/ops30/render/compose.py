"""compose.env: the site's half of collector/compose.yml. The compose file
is product (services, images by digest, mounts); this file names the
volumes, the retention, the time zone, the Grafana port, the secret files
and the profiles that run:
  pve    pve-exporter, when site.yaml has pve.exporter;
  snmp   snmp-exporter, when a NAS is scraped over SNMP;
  logs   VictoriaLogs, when the site collects logs.
"""
from .. import site as S
from . import Output, header
from .prometheus import logs_enabled, targets

P = "etc/30ops/compose.env"
GRAFANA_ADMIN = "/etc/30ops/secrets/grafana-admin.pass"


def profiles(site):
    jobs, _ = targets(site)
    out = []
    if (site.get("pve") or {}).get("exporter") and "pve" in jobs:
        out.append("pve")
    if "nas-snmp" in jobs:
        out.append("snmp")
    if logs_enabled(site):
        out.append("logs")
    return out


def env(site):
    col = site["collector"]
    smtp = (site["alerting"].get("smtp") or {}).get("password")
    return {
        "COMPOSE_PROJECT_NAME": "30ops",
        "COMPOSE_PROFILES": ",".join(profiles(site)),
        "OPS30_ETC": "/etc/30ops",
        "OPS30_TZ": site["site"]["timezone"],
        "OPS30_VOL_PROMETHEUS": col["volumes"]["prometheus"],
        "OPS30_VOL_ALERTMANAGER": col["volumes"]["alertmanager"],
        "OPS30_VOL_GRAFANA": col["volumes"]["grafana"],
        "OPS30_VOL_VICTORIALOGS": col["volumes"]["victorialogs"],
        "OPS30_RETENTION_METRICS": col["retention"]["metrics"],
        "OPS30_RETENTION_LOGS": col["retention"]["logs"],
        "OPS30_LOGS_MAX_DISK": col["retention"]["logs_max_disk"],
        "OPS30_GRAFANA_PORT": str(col["grafana_port"]),
        "OPS30_GRAFANA_ADMIN_FILE": GRAFANA_ADMIN,
        "OPS30_SMTP_PASSWORD_FILE": S.secret_file(site, smtp) if smtp else "/dev/null",
    }


def render(site, sha):
    text = header(sha) + "".join(f"{k}={v}\n" for k, v in env(site).items())
    return {P: Output(text)}
