"""30ops readiness: the checklist contract, the plan, every kind of check,
accept and answers, the outputs and the exit code."""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import plugins, readiness as R, site  # noqa: E402

SAMPLE = ROOT / "examples" / "sample-site"


def resolved(edit=None):
    doc = site.load(SAMPLE / "site.yaml")
    if edit:
        edit(doc)
    return site.resolve(doc, str(SAMPLE))


def s(value, **labels):
    return {"metric": labels, "value": [0, str(value)]}


class Fake:
    """query(expr) from a table; an expression not in it returns no series,
    one mapped to None stands for a failed query."""

    def __init__(self, table=None):
        self.table, self.asked = dict(table or {}), []

    def __call__(self, expr):
        self.asked.append(expr)
        return self.table.get(expr, [])


def item(**kw):
    base = {"id": "x", "category": "node-guard", "question": {"zh-TW": "問", "en": "q"}}
    return {**base, **kw}


def one(check, query, **kw):
    p = {"facts": kw.pop("facts", {}), "items": [item(check=check, **kw)]}
    return R.evaluate(p, query, kw.pop("local", None))[0]


# metric names an expression may use: what collectors before v0.7 already had
# (the textfile goldens, snmp.yml, Prometheus' own) or what the item is about
def known_metrics():
    names = {"up", "ALERTS", "scrape_samples_scraped", "prometheus_notifications_alertmanagers_discovered"}
    for p in (ROOT / "tests" / "golden" / "textfile").glob("*.prom"):
        names |= set(re.findall(r"^# TYPE (\S+)", p.read_text(), re.M))
    names |= set(re.findall(r"^\s+- name: (\S+)$", (ROOT / "collector" / "prometheus" / "snmp.yml").read_text(), re.M))
    names |= {"gb10_textfile_last_run_timestamp", "deadman_alerting", "deadman_last_push_timestamp_seconds"}
    return names


PROMQL_WORDS = {"time", "max", "min", "count", "sum", "by", "on", "or", "and", "unless", "without", "absent",
                "max_over_time", "min_over_time"}


def metrics_in(expr):
    e = re.sub(r'"[^"]*"', "", expr)
    e = re.sub(r"\{[^}]*\}", "", e)
    e = re.sub(r"\b(by|on|without)\s*\([^)]*\)", "", e)
    return {w for w in re.findall(r"[A-Za-z_][A-Za-z0-9_:]*", e) if w not in PROMQL_WORDS}


class Checklist(unittest.TestCase):
    def test_contract(self):
        items = R.checklist()
        ids = [i["id"] for i in items]
        self.assertEqual(len(ids), len(set(ids)), "duplicate ids")
        thresholds = set(site.threshold_catalogue())
        known = known_metrics()
        for i in items:
            with self.subTest(item=i["id"]):
                self.assertRegex(i["id"], r"^([a-z0-9-]+:)?[a-z0-9-]+$")
                self.assertIn(i["category"], R.CATEGORIES)
                self.assertEqual(set(i["question"]), {"zh-TW", "en"})
                self.assertEqual(set(i) - {"id", "category", "question", "applies", "check", "plugin"}, set())
                self.assertEqual(set(i.get("applies") or {}) - {"role", "site"}, set())
                self.assertEqual(set((i.get("applies") or {}).get("role", [])) - set(site.ROLES), set())
                self.assertIn((i.get("applies") or {}).get("site", "worm"), ("worm", "gate"))
                c = i["check"]
                self.assertIn(c["type"], R.TYPES)
                if c["type"] == "promql":
                    self.assertTrue({"ok", "bad"} & set(c))
                    self.assertEqual(set(c) - {"type", "ok", "bad", "show"}, set())
                    for k in ("ok", "bad"):
                        if k in c:
                            self.assertEqual(set(re.findall(r"\$\{([a-z0-9_]+)\}", c[k])) - thresholds, set())
                            self.assertEqual(metrics_in(re.sub(r"\$\{[a-z0-9_]+\}", "1", c[k])) - known, set(), c[k])
                if c["type"] == "builtin":
                    self.assertIn(c["name"], R.BUILTINS)
                if c["type"] == "site":
                    self.assertIn(c["name"], R.SITE_CHECKS)
                if c["type"] == "manual":
                    self.assertTrue(c.get("hint"))
                if c["type"] == "local":
                    from ops30 import doctor
                    self.assertEqual(set(c["doctor"]) - set(doctor.Doctor.CHECKS), set())

    def test_plugin_items_carry_the_plugin_name(self):
        ids = R.item_ids()
        for name in plugins.available():
            for i in plugins.readiness_items(name):
                self.assertEqual(ids[f"{name}:{i['id']}"]["plugin"], name)


class Plan(unittest.TestCase):
    def test_applies(self):
        p = R.plan(resolved())
        ids = [i["id"] for i in p["items"]]
        self.assertIn("pve-quorum", ids)
        self.assertIn("gb10-ops:textfile-fresh", ids)
        self.assertIn("switch-in-assets", ids)                 # sw-core
        self.assertNotIn("spark-baseline:snapshot", ids)       # no host lists it

        def no_pve(d):
            d["hosts"] = [h for h in d["hosts"] if h.get("vendor") != "pve" and h["name"] != "qdevice"]
            d.pop("pve")
            d["alerting"].pop("deadman")
            for h in d["hosts"]:
                h.pop("plugins", None)
        ids = [i["id"] for i in R.plan(resolved(no_pve))["items"]]
        self.assertNotIn("pve-quorum", ids)
        self.assertNotIn("gb10-ops:textfile-fresh", ids)
        ids = [i["id"] for i in R.plan(resolved(lambda d: d.update(hosts=[h for h in d["hosts"]
                                                                          if h["name"] != "sw-core"])))["items"]]
        self.assertNotIn("switch-in-assets", ids)

    def test_thresholds_filled_and_json(self):
        r = resolved(lambda d: d["alerting"].setdefault("thresholds", {}).update(drill_max_age_days=45))
        p = R.plan(r)
        c = next(i for i in p["items"] if i["id"] == "restore-drill-pve")["check"]
        self.assertTrue(c["ok"].endswith("<= 45"))
        self.assertEqual(json.loads(json.dumps(p)), p)
        self.assertNotIn("readiness.prom", [t[0] for t in p["facts"]["textfiles"]])
        self.assertIn("nas.prom", [t[0] for t in p["facts"]["textfiles"]])

    def test_accept_answers_and_site_checks(self):
        def edit(d):
            d["readiness"] = {"accept": {"deadman": "v0.8"}, "answers": {"pkg-rollback": "tarball kept on the NAS"}}
            next(h for h in d["hosts"] if h["name"] == "qdevice")["journal"] = False
        p = R.plan(resolved(edit))
        by = {i["id"]: i for i in p["items"]}
        self.assertEqual(by["deadman"]["accept"], "v0.8")
        self.assertEqual(by["pkg-rollback"]["answer"], "tarball kept on the NAS")
        self.assertEqual(by["journald-coverage"]["static"], ["no", "no journal upload from qdevice"])


class Checks(unittest.TestCase):
    def test_promql(self):
        c = {"type": "promql", "ok": "a", "bad": "b", "show": "instance"}
        self.assertEqual(one(c, Fake({"a": [s(1)]}))["status"], R.YES)
        r = one(c, Fake({"a": [s(1)], "b": [s(0, instance="192.0.2.9:9100")]}))
        self.assertEqual((r["status"], r["evidence"]), (R.NO, "1 found: 192.0.2.9:9100"))
        self.assertEqual(one(c, Fake())["evidence"], "no data: a")
        self.assertEqual(one(c, Fake({"a": None}))["status"], R.UNKNOWN)

    def test_accept_and_manual(self):
        c = {"type": "promql", "ok": "a"}
        r = one(c, Fake(), accept="no switch on this site")
        self.assertEqual((r["status"], r["accept"]), (R.ACCEPTED, "no switch on this site"))
        self.assertEqual(one(c, Fake({"a": [s(1)]}), accept="x")["status"], R.YES)   # yes stays yes
        m = {"type": "manual", "hint": "look"}
        self.assertEqual(one(m, Fake())["status"], R.UNKNOWN)
        self.assertEqual(one(m, Fake(), answer="checked 10-15")["evidence"], "checked 10-15")

    def test_local(self):
        c = {"type": "local", "doctor": ["images"]}
        self.assertEqual(one(c, Fake())["status"], R.UNKNOWN)
        self.assertEqual(one(c, Fake(), local=lambda n: [("ok", "images: 6 services")])["status"], R.YES)
        self.assertEqual(one(c, Fake(), local=lambda n: [("fail", "images: grafana")])["status"], R.NO)

    def test_textfiles_fresh(self):
        f = {"textfiles": [["nas.prom", "nas_textfile", 600], ["eol.prom", "eol_textfile", 172800]]}
        q = Fake({"time() - nas_textfile_last_run_timestamp": [s(30)],
                  "time() - eol_textfile_last_run_timestamp": [s(200000)]})
        r = one({"type": "builtin", "name": "textfiles_fresh"}, q, facts=f)
        self.assertEqual((r["status"], r["evidence"]), (R.NO, "eol.prom 200000 s old (limit 172800)"))
        del q.table["time() - eol_textfile_last_run_timestamp"]
        self.assertIn("eol.prom never written", one({"type": "builtin", "name": "textfiles_fresh"}, q, facts=f)["evidence"])

    def test_deadman(self):
        c = {"type": "builtin", "name": "deadman"}
        self.assertEqual(one(c, Fake(), facts={"deadman": None})["status"], R.NO)
        f = {"deadman": {"host": "watcher", "address": "192.0.2.150", "port": 9095, "after_s": 300, "healthchecks": False}}
        ok = Fake({"deadman_alerting": [s(0)], "time() - deadman_last_push_timestamp_seconds": [s(45)]})
        self.assertEqual(one(c, ok, facts=f)["status"], R.YES)
        self.assertEqual(one(c, Fake(), facts=f)["evidence"], "30ops-deadman on watcher is not scraped (job deadman)")
        silent = Fake({"deadman_alerting": [s(1)], "time() - deadman_last_push_timestamp_seconds": [s(900)]})
        self.assertEqual(one(c, silent, facts=f)["status"], R.NO)
        f["deadman"].update(host=None, healthchecks=True)
        self.assertEqual(one(c, Fake({'ALERTS{alertname="Watchdog",alertstate="firing"}': [s(1)]}), facts=f)["status"],
                         R.YES)

    def test_switch_monitored(self):
        c = {"type": "builtin", "name": "switch_monitored"}
        self.assertEqual(one(c, Fake(), facts={"switches_all": [], "switches": []})["status"], R.NO)
        sw = [{"name": "sw1", "address": "192.0.2.40"}]
        f = {"switches_all": sw, "switches": sw}
        self.assertEqual(one(c, Fake({'up{job="switch-snmp"}': [s(1, instance="192.0.2.40")]}), facts=f)["status"], R.YES)
        self.assertEqual(one(c, Fake({'up{job="switch-snmp"}': [s(0, instance="192.0.2.40")]}), facts=f)["status"], R.NO)

    def test_ups_present(self):
        c = {"type": "builtin", "name": "ups_present"}
        f = {"nas": [{"name": "nas-primary", "nas": "primary", "ups_none": False},
                     {"name": "nas-secondary", "nas": "secondary", "ups_none": True}]}
        q = Fake({"qnap_ups_status": [s(1, nas="primary", qnap_ups_status="Online"),
                                      s(1, nas="secondary", qnap_ups_status="-1")]})
        r = one(c, q, facts=f)
        self.assertEqual((r["status"], r["evidence"]), (R.ACCEPTED, "no UPS, site.yaml ups: none: nas-secondary"))
        q.table["qnap_ups_status"][0] = s(1, nas="primary", qnap_ups_status="-1")
        self.assertEqual(one(c, q, facts=f)["evidence"], "no UPS: nas-primary")
        q.table["qnap_ups_status"] = [s(1, nas="primary", qnap_ups_status="Online"),
                                      s(1, nas="secondary", qnap_ups_status="Online")]
        self.assertEqual(one(c, q, facts=f)["status"], R.YES)

    def test_second_approver_and_effort(self):
        rec = 'change_record{status=~"approved|scheduled|in_progress|done|rolled_back"}'
        c = {"type": "builtin", "name": "second_approver"}
        self.assertEqual(one(c, Fake({rec: [s(1, id="CR-1", implementer="a", approver="b")]}))["status"], R.YES)
        r = one(c, Fake({rec: [s(1, id="CR-2", implementer="a", approver="a")]}))
        self.assertEqual((r["status"], r["evidence"]), (R.NO, "approved by their implementer: CR-2"))
        done = 'change_window_end_timestamp{status="done"} > time() - 90 * 86400'
        e = {"type": "builtin", "name": "change_effort"}
        self.assertEqual(one(e, Fake())["status"], R.UNKNOWN)
        q = Fake({done: [s(1, id="CR-1"), s(1, id="CR-2")], "change_effort_minutes": [s(90, id="CR-1")]})
        self.assertEqual(one(e, q)["evidence"], "no effort_min: CR-2")
        q.table["change_effort_minutes"].append(s(30, id="CR-2"))
        self.assertEqual(one(e, q)["evidence"], "2 changes, 120 staff minutes")


class Output(unittest.TestCase):
    def results(self):
        p = {"site": "lab", "tool": "30ops 0.7.0", "locale": "zh-TW", "facts": {},
             "items": [item(id="a", check={"type": "promql", "ok": "a"}),
                       item(id="b", category="packaging", check={"type": "local", "doctor": ["images"]}),
                       item(id="c", category="change-mgmt", check={"type": "manual", "hint": "h"}, accept="one person")]}
        return p, R.evaluate(p, Fake())

    def test_exit_codes(self):
        p, res = self.results()
        self.assertEqual(R.exit_code(res), 1)                       # a: no data
        self.assertEqual(R.exit_code([r for r in res if r["id"] != "a"]), 0)
        self.assertEqual(R.exit_code([r for r in res if r["id"] != "a"], strict=True), 1)   # b unknown

    def test_textfile_leaves_local_out(self):
        _, res = self.results()
        t = R.textfile(res, 1_800_000_000)
        self.assertIn('readiness_item{id="a",category="node-guard",status="no"} 1', t)
        self.assertIn('readiness_item{id="c",category="change-mgmt",status="accepted"} 1', t)
        self.assertNotIn('id="b"', t)
        self.assertIn('readiness_items{status="unknown"} 0', t)
        self.assertTrue(t.endswith("readiness_textfile_last_run_timestamp 1800000000\n"))

    def test_reports(self):
        p, res = self.results()
        md = R.report(p, res, "md", now=0)
        self.assertIn("## 封裝與版本", md)
        self.assertIn("| `c` | 問 | 明示接受 | manual: h (接受理由: one person) |", md)
        self.assertEqual(json.loads(R.report(p, res, "json"))["counts"], {"yes": 0, "no": 1, "unknown": 1, "accepted": 1})
        self.assertTrue(R.report(p, res).endswith("30ops readiness: 0 yes, 1 no, 1 unknown, 1 accepted\n"))


class Cli(unittest.TestCase):
    """bin/30ops readiness against a fake Prometheus over HTTP."""

    def setUp(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from urllib.parse import parse_qs, urlparse
        table = json.loads((ROOT / "tests" / "fixtures" / "readiness" / "prometheus.json").read_text())["queries"]
        table["vector(1)"] = [s(1)]

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                u = urlparse(self.path)
                q = parse_qs(u.query).get("query", [""])[0]
                body = json.dumps({"status": "success", "data": {"resultType": "vector",
                                                                 "result": table.get(q, [])}}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def run30(self, *args):
        import subprocess
        return subprocess.run([str(ROOT / "bin" / "30ops"), "readiness", *map(str, args)], capture_output=True, text=True)

    def test_site_and_plan(self):
        import tempfile
        r = self.run30("--site", SAMPLE / "site.yaml", "--prometheus", self.url, "--no-local", "--format", "json")
        self.assertEqual(r.returncode, 1, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["counts"]["no"], 5)
        with tempfile.TemporaryDirectory() as d:
            plan = Path(d) / "readiness.json"
            plan.write_text(json.dumps(R.plan(resolved())))
            tf = Path(d) / "readiness.prom"
            r = self.run30("--plan", plan, "--prometheus", self.url, "--no-local", "--textfile", tf)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn('readiness_items{status="no"} 5', tf.read_text())
            self.assertIn("30ops readiness: ", r.stdout.splitlines()[-1])

    def test_prometheus_down(self):
        r = self.run30("--site", SAMPLE / "site.yaml", "--prometheus", "http://127.0.0.1:9", "--no-local")
        self.assertEqual(r.returncode, 2)
        self.assertIn("did not answer", r.stderr)


class Validate(unittest.TestCase):
    def errs(self, rd):
        doc = site.load(SAMPLE / "site.yaml")
        doc["readiness"] = rd
        return site.validate(doc, str(SAMPLE))[0]

    def test_site_yaml(self):
        self.assertEqual(self.errs({"accept": {"deadman": "v0.8", "gb10-ops:host-guard": "later"},
                                    "answers": {"pkg-rollback": "kept"}}), [])
        e = self.errs({"accept": {"nope": "x", "deadman": " "}, "answers": {"targets-up": "all fine"}})
        self.assertTrue(any("readiness.accept.nope: not a readiness item" in x for x in e), e)
        self.assertTrue(any("readiness.accept.deadman: give the reason" in x for x in e), e)
        self.assertTrue(any("readiness.answers.targets-up: only a manual item takes an answer" in x for x in e), e)


if __name__ == "__main__":
    unittest.main()
