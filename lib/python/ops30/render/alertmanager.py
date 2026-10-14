"""alertmanager.yml: the route tree and inhibit rules of the repo's
collector/alertmanager/alertmanager.base.yml, with the site's SMTP
settings and receivers. The SMTP password is read by Alertmanager from the
credentials file, which collector/compose.yml mounts as the secret
/run/secrets/smtp (smtp_auth_password_file); render never sees it."""
from .. import site as S, yamlio
from . import Output, header

BASE = f"{S.REPO}/collector/alertmanager/alertmanager.base.yml"
SMTP_SECRET = "/run/secrets/smtp"


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
    order = [r for r in S.RECEIVERS if r in recv] + [r for r in recv if r not in S.RECEIVERS]
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
    doc["receivers"] = out
    return doc


def render(site, sha):
    return {"etc/30ops/alertmanager/alertmanager.yml": Output(header(sha) + yamlio.dumps(alertmanager_yml(site)))}
