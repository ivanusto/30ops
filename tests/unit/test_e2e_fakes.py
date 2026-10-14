"""The e2e fakes (tests/e2e/fakes) answer what the collector asks."""
import importlib.util
import io
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
FAKES = ROOT / "tests" / "e2e" / "fakes"
SNMP_YML = ROOT / "collector" / "prometheus" / "snmp.yml"
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import site  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


build = load("e2e_build_data", FAKES / "snmp" / "build-data.py")
pp = load("e2e_pass_persist", FAKES / "snmp" / "pass-persist.py")
http = load("e2e_http", FAKES / "httpfakes.py")


class SnmpData(unittest.TestCase):
    def test_every_qnap_walk_oid_has_data(self):
        rows = build.build(SNMP_YML)
        oids = [r[0] for r in rows]
        walk = yaml.safe_load(SNMP_YML.read_text())["modules"]["qnap"]["walk"]
        for w in walk:
            if w.startswith(build.ENTERPRISE + "."):
                self.assertTrue(any(o.startswith(w + ".") for o in oids), w)
        self.assertEqual(len(oids), len(set(oids)))

    def test_healthy_values(self):
        rows = {o: (t, v) for o, t, v in build.build(SNMP_YML)}
        self.assertEqual(rows["1.3.6.1.4.1.55062.2.10.2.1.7.1"], ("string", "Good"))     # disk status
        self.assertEqual(rows["1.3.6.1.4.1.55062.2.10.7.1.5.1"], ("integer", 0))          # pool: ready
        self.assertEqual(rows["1.3.6.1.4.1.55062.2.14.8.0"], ("integer", 0))              # telnet: no
        self.assertEqual(rows["1.3.6.1.4.1.55062.2.13.1.0"], ("string", "-1"))            # no UPS
        self.assertEqual(rows["1.3.6.1.4.1.55062.2.10.2.1.9.1"][0], "counter64")          # bytes

    def test_status_strings_pass_the_adapter_rules(self):
        """The fake's strings are the ones adapter.yaml status: calls healthy."""
        import re
        status = yaml.safe_load((ROOT / "adapters/nas/qnap/adapter.yaml").read_text())["status"]
        ok = {s["metric"]: s["ok"] for s in status if "ok" in s}
        self.assertTrue(re.fullmatch(ok["qnap_disk_status"], build.VALUES["qnap_disk_status"]))
        self.assertTrue(re.fullmatch(ok["qnap_ups_status"], build.VALUES["qnap_ups_status"]))


class PassPersist(unittest.TestCase):
    def setUp(self):
        self.rows = [(pp.key(o), t, str(v)) for o, t, v in build.build(SNMP_YML)]
        self.rows.sort()

    def talk(self, text):
        out = io.StringIO()
        pp.serve(self.rows, io.StringIO(text), out)
        return out.getvalue().splitlines()

    def test_ping_get_getnext(self):
        out = self.talk("PING\nget\n.1.3.6.1.4.1.55062.2.10.1.0\ngetnext\n.1.3.6.1.4.1.55062\n")
        self.assertEqual(out[:4], ["PONG", ".1.3.6.1.4.1.55062.2.10.1.0", "integer", "2"])
        self.assertEqual(out[4], ".1.3.6.1.4.1.55062.2.10.1.0")

    def test_getnext_walks_in_numeric_order(self):
        """2.10.9 comes before 2.10.10 (numeric, not text, order)."""
        seen, oid = [], ".1.3.6.1.4.1.55062"
        while True:
            out = self.talk(f"getnext\n{oid}\n")
            if out == ["NONE"]:
                break
            seen.append(pp.key(out[0]))
            oid = out[0]
        self.assertEqual(seen, sorted(seen))
        self.assertEqual(len(seen), len(self.rows))

    def test_unknown_and_set(self):
        self.assertEqual(self.talk("get\n.1.3.6.1.4.1.55062.9.9.0\n"), ["NONE"])
        self.assertEqual(self.talk("set\n.1.3.6.1.4.1.55062.2.10.1.0\ninteger 3\n"), ["not-writable"])


class HttpFakes(unittest.TestCase):
    def serve(self, kind, cfg):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), http.handler(kind, {**cfg, "quiet": True}))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    def get(self, url, auth):
        req = urllib.request.Request(url, headers={"Authorization": auth})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, None

    def test_pve_api(self):
        nodes = [("pve1", "192.0.2.9"), ("pve2", "192.0.2.5")]
        base = self.serve("pve", {"token": "u@pve!t=s", "routes": http.pve_routes(nodes, "pve1", "lab")})
        code, body = self.get(base + "/api2/json/cluster/status", "PVEAPIToken=u@pve!t=s")
        self.assertEqual(code, 200)
        local = [x["name"] for x in body["data"] if x["type"] == "node" and x["local"]]
        self.assertEqual(local, ["pve1"])
        _, body = self.get(base + "/api2/json/cluster/resources?type=storage", "PVEAPIToken=u@pve!t=s")
        self.assertEqual({x["status"] for x in body["data"]}, {"available"})
        _, body = self.get(base + "/api2/json/cluster/resources?type=vm", "PVEAPIToken=u@pve!t=s")
        self.assertEqual(body["data"], [])
        self.assertEqual(self.get(base + "/api2/json/version", "PVEAPIToken=u@pve!t=wrong")[0], 401)

    def test_fortigate(self):
        raw = (ROOT / "tests/fixtures/adapters/fortigate/licences/license-status/001.out").read_bytes()
        base = self.serve("fortigate", {"token": "tok", "body": raw})
        code, body = self.get(base + "/api/v2/monitor/license/status", "Bearer tok")
        self.assertEqual((code, body), (200, json.loads(raw)))
        self.assertEqual(self.get(base + "/api/v2/monitor/license/status", "Bearer no")[0], 401)

    def test_sink_records_posts(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
        f = f"{d}/webhook.jsonl"
        base = self.serve("sink", {"file": f, "lock": threading.Lock()})
        req = urllib.request.Request(base + "/ops-critical", data=b'{"alerts":[{"status":"firing"}]}', method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read()
        with open(f) as fh:
            rec = json.loads(fh.read())
        self.assertEqual(rec["path"], "/ops-critical")
        self.assertEqual(rec["body"]["alerts"][0]["status"], "firing")


class E2eSite(unittest.TestCase):
    def test_site_is_valid_and_matches_the_fakes(self):
        doc = site.load(ROOT / "tests" / "e2e" / "site.yaml")
        self.assertEqual(site.validate(doc, str(ROOT / "tests" / "e2e"), strict=True), ([], []))
        addrs = {h["name"]: h["address"] for h in doc["hosts"]}
        conf = (FAKES / "sshd_config.in").read_text()
        for name in ("nas-primary", "pve1", "pve2"):
            self.assertIn(f"ListenAddress {addrs[name]}:22", conf)
        netns = (FAKES / "netns.sh").read_text()
        for a in addrs.values():
            self.assertIn(a, netns)


if __name__ == "__main__":
    unittest.main()
