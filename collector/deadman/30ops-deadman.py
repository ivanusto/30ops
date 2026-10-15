#!/usr/bin/env python3
"""30ops-deadman: alert when the collector goes quiet.

The collector's Prometheus fires Watchdog all the time and its Alertmanager
pushes it here every minute (the deadman receiver, a webhook to
POST /alertmanager). When no push has arrived for AFTER_S seconds the
collector, its rules or its alert path is down, and it cannot say so
itself: this process says it, by mail and/or webhook, then again every
REMIND_S, and once more when the pushes come back.

It runs on another host than the collector (site.yaml alerting.deadman.host),
installed by `30ops install node` (collector/deadman/install-deadman.sh)
with the settings render wrote to /etc/30ops-deadman/deadman.env:

  SITE            site id, in every message
  LISTEN          address:port to listen on (0.0.0.0:9095)
  COLLECTOR       addresses pushes may come from; others get 403
  AFTER_S         silence that counts as down (300)
  REMIND_S        repeat while down (21600)
  EMAIL_TO        recipients, space separated (needs SMTP_SMARTHOST, SMTP_FROM)
  SMTP_SMARTHOST  host:port; SMTP_USERNAME, SMTP_REQUIRE_TLS (STARTTLS, true)
  WEBHOOK         URLs, space separated; the body is Alertmanager's webhook format

The SMTP password is the systemd credential "smtp" ($CREDENTIALS_DIRECTORY/smtp,
LoadCredential in the unit); an empty file means no login.

GET /metrics serves deadman_last_push_timestamp_seconds, deadman_alerting
and deadman_notifications_total for the collector's deadman scrape job.

Standard library only, and it does not import ops30: the file is copied to
the deadman host and runs there on its own (docs/lib.md, node-side files).
"""
import json
import os
import smtplib
import sys
import threading
import time
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ALERT = "CollectorSilent"


def config(env):
    host, _, port = env.get("LISTEN", "0.0.0.0:9095").rpartition(":")
    smtp = env.get("SMTP_SMARTHOST", "")
    return {
        "site": env.get("SITE", ""),
        "listen": (host or "0.0.0.0", int(port)),
        "collector": set(env.get("COLLECTOR", "").split()),
        "after_s": int(env.get("AFTER_S", "300")),
        "remind_s": int(env.get("REMIND_S", "21600")),
        "email": env.get("EMAIL_TO", "").split(),
        "smtp": smtp,
        "smtp_from": env.get("SMTP_FROM", ""),
        "smtp_user": env.get("SMTP_USERNAME", ""),
        "smtp_tls": env.get("SMTP_REQUIRE_TLS", "true").lower() != "false",
        "webhook": env.get("WEBHOOK", "").split(),
    }


def smtp_password(env):
    d = env.get("CREDENTIALS_DIRECTORY")
    if not d:
        return ""
    try:
        with open(os.path.join(d, "smtp"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


class Deadman:
    """The state machine; the clock and the two senders are injectable."""

    def __init__(self, cfg, clock=time.time, mail=None, hook=None, log=None):
        self.cfg, self.clock = cfg, clock
        self.mail, self.hook = mail, hook
        self.log = log or (lambda m: print(m, file=sys.stderr, flush=True))
        self.lock = threading.Lock()
        self.started = clock()
        self.last_push = None       # never pushed since start
        self.alerting = False
        self.down_since = None
        self.last_sent = None
        self.sent = {}               # (channel, result) -> count

    # ----- input -----
    def push(self, peer, body):
        """A webhook from Alertmanager: (HTTP status, reason)."""
        if self.cfg["collector"] and peer not in self.cfg["collector"]:
            return 403, f"{peer} is not the collector"
        try:
            doc = json.loads(body or b"{}")
        except ValueError:
            return 400, "not JSON"
        alerts = doc.get("alerts") if isinstance(doc, dict) else None
        if not any(isinstance(a, dict) and a.get("status") == "firing"
                   and (a.get("labels") or {}).get("alertname") == "Watchdog" for a in alerts or []):
            return 400, "no firing Watchdog in the push"
        with self.lock:
            self.last_push = self.clock()
            if self.alerting:
                self.alerting = False
                self.notify(False)
                self.down_since = self.last_sent = None
        return 200, "ok"

    # ----- the watch -----
    def tick(self):
        now = self.clock()
        with self.lock:
            since = self.last_push if self.last_push is not None else self.started
            if now - since < self.cfg["after_s"]:
                return
            if not self.alerting:
                self.alerting, self.down_since = True, since
                self.notify(True)
                self.last_sent = now
            elif now - self.last_sent >= self.cfg["remind_s"]:
                self.notify(True)
                self.last_sent = now

    # ----- output -----
    def message(self, firing):
        site, now = self.cfg["site"], self.clock()
        if firing:
            last = iso(self.last_push) if self.last_push is not None else f"none since {iso(self.started)}"
            subject = f"[{site}] collector silent: no Watchdog for {int(now - self.down_since)} s"
            text = (f"The 30ops collector of site {site} has not pushed its Watchdog since {last}.\n"
                    "The collector host, Prometheus, its rules or Alertmanager is down, or the network\n"
                    "between it and this host is. Nothing on the collector can alert about this.\n")
        else:
            subject = f"[{site}] collector back: Watchdog pushes resumed"
            text = (f"The 30ops collector of site {site} pushes its Watchdog again (at {iso(now)}),\n"
                    f"after a silence that began at {iso(self.down_since)}.\n")
        return subject, text

    def payload(self, firing, subject):
        status = "firing" if firing else "resolved"
        alert = {"status": status,
                 "labels": {"alertname": ALERT, "severity": "critical", "site": self.cfg["site"]},
                 "annotations": {"summary": subject},
                 "startsAt": iso(self.down_since),
                 "endsAt": "0001-01-01T00:00:00Z" if firing else iso(self.clock())}
        return {"version": "4", "status": status, "receiver": "30ops-deadman",
                "groupLabels": {"alertname": ALERT}, "commonLabels": alert["labels"],
                "commonAnnotations": alert["annotations"], "alerts": [alert]}

    def notify(self, firing):
        subject, text = self.message(firing)
        self.log(subject)
        if self.cfg["email"] and self.mail:
            self.count("email", self.mail(self.cfg, subject, text))
        for url in self.cfg["webhook"]:
            if self.hook:
                self.count("webhook", self.hook(url, self.payload(firing, subject)))

    def count(self, channel, ok):
        k = (channel, "ok" if ok else "error")
        self.sent[k] = self.sent.get(k, 0) + 1

    def metrics(self):
        with self.lock:
            lines = ["# HELP deadman_last_push_timestamp_seconds When the collector last pushed its Watchdog (0: never since start).",
                     "# TYPE deadman_last_push_timestamp_seconds gauge",
                     f"deadman_last_push_timestamp_seconds {self.last_push or 0:.3f}",
                     "# HELP deadman_alerting 1 while the collector counts as silent.",
                     "# TYPE deadman_alerting gauge",
                     f"deadman_alerting {int(self.alerting)}",
                     "# HELP deadman_after_seconds The silence that counts as down.",
                     "# TYPE deadman_after_seconds gauge",
                     f"deadman_after_seconds {self.cfg['after_s']}",
                     "# HELP deadman_notifications_total Notifications sent, by channel and result.",
                     "# TYPE deadman_notifications_total counter"]
            for ch in ("email", "webhook"):
                for res in ("ok", "error"):
                    lines.append(f'deadman_notifications_total{{channel="{ch}",result="{res}"}} {self.sent.get((ch, res), 0)}')
        return "\n".join(lines) + "\n"


def send_mail(cfg, subject, text, password="", log=print):
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, cfg["smtp_from"], ", ".join(cfg["email"])
    msg["Date"] = formatdate(localtime=False)
    msg.set_content(text)
    host, _, port = cfg["smtp"].rpartition(":")
    try:
        with smtplib.SMTP(host or cfg["smtp"], int(port or 25), timeout=30) as s:
            if cfg["smtp_tls"]:
                s.starttls()
            if cfg["smtp_user"] and password:
                s.login(cfg["smtp_user"], password)
            s.send_message(msg)
        return True
    except (OSError, smtplib.SMTPException) as e:
        log(f"mail to {', '.join(cfg['email'])} failed: {e}")
        return False


def send_hook(url, payload, log=print):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= r.status < 300
    except OSError as e:
        log(f"webhook {url.split('?')[0]} failed: {e}")
        return False


def handler(dm):
    class H(BaseHTTPRequestHandler):
        def reply(self, code, text, ctype="text/plain; charset=utf-8"):
            data = text.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/metrics":
                self.reply(200, dm.metrics(), "text/plain; version=0.0.4")
            elif self.path == "/healthz":
                self.reply(200, "ok\n")
            else:
                self.reply(404, "not found\n")

        def do_POST(self):
            if self.path != "/alertmanager":
                self.reply(404, "not found\n")
                return
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(n, 1 << 20))
            code, why = dm.push(self.client_address[0], body)
            if code != 200:
                dm.log(f"refused a push from {self.client_address[0]}: {why}")
            self.reply(code, why + "\n")

        def log_message(self, *a):
            pass
    return H


def main(env=os.environ):
    cfg = config(env)
    pw = smtp_password(env)
    log = lambda m: print(m, file=sys.stderr, flush=True)   # noqa: E731
    dm = Deadman(cfg, mail=lambda c, s, t: send_mail(c, s, t, pw, log),
                 hook=lambda u, p: send_hook(u, p, log), log=log)
    srv = ThreadingHTTPServer(cfg["listen"], handler(dm))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log(f"30ops-deadman for {cfg['site']}: listening on {cfg['listen'][0]}:{cfg['listen'][1]}, "
        f"collector {' '.join(sorted(cfg['collector'])) or 'any'}, silent after {cfg['after_s']} s")
    try:
        while True:
            time.sleep(10)
            dm.tick()
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
