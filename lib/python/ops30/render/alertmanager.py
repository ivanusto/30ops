"""alertmanager.yml: the route tree and inhibit rules of the repo's
collector/alertmanager/alertmanager.base.yml, with the site's SMTP
settings and receivers. The SMTP password is read by Alertmanager from the
credentials file, which collector/compose.yml mounts as the secret
/run/secrets/smtp (smtp_auth_password_file); render never sees it.

The deadman receiver gets the Watchdog alone (the first route of the base
file): a webhook to 30ops-deadman on alerting.deadman.host, and/or the
external check URL alerting.deadman.healthchecks, which Alertmanager reads
from the secret /run/secrets/deadman_url (url_file)."""
from .. import site as S, yamlio
from . import Output, header

BASE = f"{S.REPO}/collector/alertmanager/alertmanager.base.yml"
SMTP_SECRET = "/run/secrets/smtp"
DEADMAN_SECRET = "/run/secrets/deadman_url"


def deadman_receiver(site):
    x = {"name": "deadman"}
    dm = site["alerting"].get("deadman") or {}
    hooks = []
    h = S.deadman_host(site)
    if h:
        hooks.append({"url": f"http://{h['address']}:{dm['port']}/alertmanager", "send_resolved": False})
    if dm.get("healthchecks"):
        hooks.append({"url_file": DEADMAN_SECRET, "send_resolved": False})
    if hooks:
        x["webhook_configs"] = hooks
    return x


def alertmanager_yml(site):
    doc = yamlio.load(BASE)
    al = site["alerting"]
    g = {k: v for k, v in doc["global"].items() if not k.startswith("smtp_")}
    smtp = al.get("smtp")
    if smtp:
        g["smtp_smarthost"] = smtp["smarthost"]
        g["smtp_from"] = smtp["from"]
        if smtp.get("username"):
            g["smtp_auth_username"] = smtp["username"]
        if smtp.get("password"):
            g["smtp_auth_password_file"] = SMTP_SECRET
        g["smtp_require_tls"] = smtp.get("require_tls", True)
    doc["global"] = g
    recv = al.get("receivers") or {}
    order = [r for r in S.RECEIVERS if r in recv] + [r for r in recv if r not in S.RECEIVERS and r != "deadman"]
    out = []
    for name in order:
        r = recv[name] or {}
        sr = r.get("send_resolved", True)
        x = {"name": name}
        if r.get("email"):
            x["email_configs"] = [{"to": a, "send_resolved": sr} for a in r["email"]]
        if r.get("webhook"):
            x["webhook_configs"] = [{"url": u, "send_resolved": sr} for u in r["webhook"]]
        out.append(x)
    out.append(deadman_receiver(site))
    doc["receivers"] = out
    return doc


def render(site, sha):
    return {"etc/30ops/alertmanager/alertmanager.yml": Output(header(sha) + yamlio.dumps(alertmanager_yml(site)))}
