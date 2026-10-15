"""The collector deadman: 30ops-deadman itself, the Watchdog route, and
what render writes for alerting.deadman."""
import importlib.util
import json
import re
import sys
import threading
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import site, yamlio  # noqa: E402
from ops30.render import alertmanager, compose, nodes, prometheus  # noqa: E402

spec = importlib.util.spec_from_file_location("deadman", ROOT / "collector" / "deadman" / "30ops-deadman.py")
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)

SAMPLE = ROOT / "examples" / "sample-site"
WATCHDOG = json.dumps({"status": "firing", "alerts": [{"status": "firing", "labels": {"alertname": "Watchdog"}}]})


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def cfg(**kw):
    c = D.config({"SITE": "lab", "COLLECTOR": "192.0.2.49", "AFTER_S": "300", "REMIND_S": "3600",
                  "EMAIL_TO": "oncall@example.net", "SMTP_SMARTHOST": "smtp.example.net:587",
                  "SMTP_FROM": "alerts@example.net", "WEBHOOK": "http://192.0.2.9/hook"})
    c.update(kw)
    return c


class Machine(unittest.TestCase):
    def setUp(self):
        self.clock, self.mails, self.hooks = Clock(), [], []
        self.dm = D.Deadman(cfg(), self.clock, mail=lambda c, s, t: self.mails.append(s) or True,
                            hook=lambda u, p: self.hooks.append(p) or True, log=lambda m: None)

    def at(self, dt):
        self.clock.t += dt
        self.dm.tick()

    def test_quiet_while_pushed(self):
        for _ in range(20):
            self.assertEqual(self.dm.push("192.0.2.49", WATCHDOG.encode()), (200, "ok"))
            self.at(60)
        self.assertEqual((self.mails, self.hooks), ([], []))
        self.assertIn("deadman_alerting 0", self.dm.metrics())

    def test_grace_after_start(self):
        self.at(299)
        self.assertEqual(self.mails, [])
        self.at(1)
        self.assertEqual(len(self.mails), 1)
        self.assertIn("no Watchdog for 300 s", self.mails[0])

    def test_alert_remind_recover(self):
        self.dm.push("192.0.2.49", WATCHDOG.encode())
        self.at(301)
        self.assertEqual(len(self.mails), 1)
        self.assertEqual(self.hooks[0]["status"], "firing")
        self.assertEqual(self.hooks[0]["alerts"][0]["labels"],
                         {"alertname": "CollectorSilent", "severity": "critical", "site": "lab"})
        for _ in range(5):
            self.at(600)                      # 3000 s more, below the 3600 s reminder
        self.assertEqual(len(self.mails), 1)
        self.at(700)
        self.assertEqual(len(self.mails), 2)
        self.assertIn("deadman_alerting 1", self.dm.metrics())
        self.dm.push("192.0.2.49", WATCHDOG.encode())
        self.assertEqual(len(self.mails), 3)
        self.assertIn("collector back", self.mails[2])
        self.assertEqual(self.hooks[-1]["status"], "resolved")
        self.assertIn('deadman_notifications_total{channel="email",result="ok"} 3', self.dm.metrics())

    def test_refuses_strangers_and_other_alerts(self):
        self.assertEqual(self.dm.push("192.0.2.66", WATCHDOG.encode())[0], 403)
        other = json.dumps({"alerts": [{"status": "firing", "labels": {"alertname": "TargetDown"}}]})
        self.assertEqual(self.dm.push("192.0.2.49", other.encode())[0], 400)
        resolved = WATCHDOG.replace('"status": "firing", "labels"', '"status": "resolved", "labels"')
        self.assertEqual(self.dm.push("192.0.2.49", resolved.encode())[0], 400)
        self.assertEqual(self.dm.push("192.0.2.49", b"{not json")[0], 400)
        self.assertIn("deadman_last_push_timestamp_seconds 0.000", self.dm.metrics())

    def test_failed_sends_are_counted(self):
        dm = D.Deadman(cfg(), self.clock, mail=lambda c, s, t: False, hook=lambda u, p: False, log=lambda m: None)
        self.clock.t += 400
        dm.tick()
        m = dm.metrics()
        self.assertIn('deadman_notifications_total{channel="email",result="error"} 1', m)
        self.assertIn('deadman_notifications_total{channel="webhook",result="error"} 1', m)


class Http(unittest.TestCase):
    def test_push_and_metrics_over_http(self):
        dm = D.Deadman(cfg(collector={"127.0.0.1"}), log=lambda m: None)
        srv = D.ThreadingHTTPServer(("127.0.0.1", 0), D.handler(dm))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            req = urllib.request.Request(base + "/alertmanager", data=WATCHDOG.encode(), method="POST")
            with urllib.request.urlopen(req, timeout=5) as r:
                self.assertEqual(r.status, 200)
            with urllib.request.urlopen(base + "/metrics", timeout=5) as r:
                text = r.read().decode()
            self.assertRegex(text, r"deadman_last_push_timestamp_seconds [1-9]")
        finally:
            srv.shutdown()
            srv.server_close()


def without_deadman(doc):
    """The sample site with no deadman: neither the role nor alerting.deadman."""
    for h in doc["hosts"]:
        h["roles"] = [r for r in h["roles"] if r != "deadman"]
    doc["alerting"].pop("deadman", None)
    return doc


def resolved(**dm):
    doc = without_deadman(site.load(SAMPLE / "site.yaml"))
    doc["hosts"].append({"name": "watcher", "address": "192.0.2.150", "vendor": "linux", "roles": ["deadman"]})
    doc["alerting"]["deadman"] = {"host": "watcher", **dm}
    return doc, site.resolve(doc, str(SAMPLE))


def matches(matchers, labels):
    for m in matchers:
        k, op, v = re.fullmatch(r'(\w+)(=~|!=|=)"(.*)"', m).groups()
        val = labels.get(k, "")
        if (op == "=" and val != v) or (op == "!=" and val == v) or (op == "=~" and not re.fullmatch(v, val)):
            return False
    return True


def route(tree, labels):
    """The receivers Alertmanager sends an alert with these labels to."""
    out = []
    for r in tree.get("routes") or []:
        if matches(r.get("matchers") or [], labels):
            out += route(r, labels) or [r.get("receiver", tree["receiver"])]
            if not r.get("continue"):
                return out
    return out or [tree["receiver"]]


class Wiring(unittest.TestCase):
    def test_watchdog_goes_to_the_deadman_only(self):
        doc = alertmanager.alertmanager_yml(resolved()[1])
        self.assertEqual(route(doc["route"], {"alertname": "Watchdog", "severity": "none"}), ["deadman"])
        self.assertEqual(route(doc["route"], {"alertname": "NasPoolAbove90", "severity": "critical"}), ["ops-critical"])
        self.assertEqual(route(doc["route"], {"alertname": "TargetDown", "severity": "warning"}), ["ops-warning"])
        self.assertEqual(route(doc["route"], {"alertname": "DrillRtoOverTarget", "severity": "info"}), ["ops-digest"])
        first = doc["route"]["routes"][0]
        self.assertEqual((first["group_interval"], first["repeat_interval"]), ("1m", "1m"))

    def test_no_inhibit_rule_catches_the_watchdog(self):
        doc = alertmanager.alertmanager_yml(resolved()[1])
        for r in doc["inhibit_rules"]:
            self.assertFalse(matches(r["target_matchers"], {"alertname": "Watchdog", "severity": "none"}), r)

    def test_receiver_and_scrape_job(self):
        _, r = resolved()
        recv = {x["name"]: x for x in alertmanager.alertmanager_yml(r)["receivers"]}
        self.assertEqual(recv["deadman"]["webhook_configs"],
                         [{"url": "http://192.0.2.150:9095/alertmanager", "send_resolved": False}])
        jobs, _ = prometheus.targets(r)
        self.assertEqual(jobs["deadman"], ("deadman.yml", [{"targets": ["192.0.2.150:9095"]}]))
        self.assertEqual(compose.env(r)["OPS30_DEADMAN_URL_FILE"], "/dev/null")

    def test_no_deadman_no_webhook(self):
        r = site.resolve(without_deadman(site.load(SAMPLE / "site.yaml")), str(SAMPLE))
        recv = {x["name"]: x for x in alertmanager.alertmanager_yml(r)["receivers"]}
        self.assertEqual(recv["deadman"], {"name": "deadman"})
        self.assertNotIn("deadman", prometheus.targets(r)[0])

    def test_healthchecks(self):
        doc, _ = resolved(healthchecks="smtp")   # any credentials entry
        r = site.resolve(doc, str(SAMPLE))
        recv = {x["name"]: x for x in alertmanager.alertmanager_yml(r)["receivers"]}
        self.assertIn({"url_file": "/run/secrets/deadman_url", "send_resolved": False},
                      recv["deadman"]["webhook_configs"])
        self.assertEqual(compose.env(r)["OPS30_DEADMAN_URL_FILE"], site.secret_file(r, "smtp"))

    def test_deadman_env(self):
        _, r = resolved()
        env = nodes.deadman_env(r)
        self.assertEqual(env["LISTEN"], "0.0.0.0:9095")
        self.assertEqual(env["AFTER_S"], "300")
        self.assertEqual(env["COLLECTOR"], site.host(r, r["collector"]["host"])["address"])
        crit = r["alerting"]["receivers"]["ops-critical"]
        self.assertEqual(env.get("EMAIL_TO", ""), " ".join(crit.get("email") or []))
        tree = nodes.render(r, "x")
        self.assertIn("nodes/watcher/etc/30ops-deadman/deadman.env", tree)
        self.assertIn('ROLES="deadman journal"', tree["nodes/watcher/install.env"].text)   # journal by default

    def test_validate(self):
        doc, _ = resolved()
        self.assertEqual(site.validate(doc, str(SAMPLE)), ([], []))
        doc["alerting"]["deadman"] = {"host": "collector", "after_s": 60}
        errs, _ = site.validate(doc, str(SAMPLE))
        self.assertIn("alerting.deadman.host 'collector' does not have role deadman", errs)
        self.assertTrue(any("must not be the collector" in e for e in errs), errs)
        self.assertTrue(any("after_s must be at least 180" in e for e in errs), errs)
        doc["alerting"]["deadman"] = {}
        errs, warns = site.validate(doc, str(SAMPLE))
        self.assertTrue(any("needs a host" in e for e in errs), errs)
        self.assertIn("host watcher has role deadman but alerting.deadman.host does not name it", warns)
        doc["alerting"]["receivers"]["deadman"] = {"webhook": ["http://192.0.2.9/"]}
        errs, _ = site.validate(doc, str(SAMPLE))
        self.assertIn("alerting.receivers.deadman is reserved: set alerting.deadman instead", errs)


class Rule(unittest.TestCase):
    def test_watchdog_rule(self):
        doc = yamlio.load(ROOT / "collector" / "prometheus" / "rules" / "staleness.yml")
        meta = next(g for g in doc["groups"] if g["name"] == "meta")
        self.assertEqual(meta["rules"], [{"alert": "Watchdog", "expr": "vector(1)", "labels": {"severity": "none"},
                                          "annotations": meta["rules"][0]["annotations"]}])


if __name__ == "__main__":
    unittest.main()
