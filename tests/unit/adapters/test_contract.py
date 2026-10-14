"""The adapter contract (docs/adapters.md), checked for every adapter.

Each adapters/<kind>/<vendor>/adapter.yaml must be well formed and only
declare capabilities of its kind. Every implemented capability is checked by
its face:
  collect     adapter.py has the function, and every recorded case under
              tests/fixtures/adapters/<vendor>/<capability>/ replays to
              exactly expected.prom, with only the families and labels that
              schema.FAMILIES allows
  data        adapter.py has the function, and every recorded case replays
              to exactly expected.json, or raises what case.json names (the
              textfile is written elsewhere, by the ref)
  snmp        the metrics it names are in collector/prometheus/snmp.yml
  render      adapter.py has the function
  descriptor, install
              the file it refers to exists
"""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import site  # noqa: E402
from ops30.adapters import base, registry, schema  # noqa: E402
from ops30.adapters.transport import Replay  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "adapters"
SNMP = (ROOT / "collector" / "prometheus" / "snmp.yml").read_text()
TOP = {"adapter", "kind", "vendor", "version", "tested", "capabilities", "os", "status", "manual"}
CAP = {"face", "status", "textfile", "via", "ref", "module", "metrics", "milestone", "note"}


def snmp_has(metric):
    names = set(re.findall(r"^\s+- name: (\S+)$", SNMP, re.M))
    return metric in names or (metric.endswith("_info") and metric[:-5] in names)


def cases(vendor, cap):
    d = FIX / vendor / cap
    return sorted(p for p in d.iterdir() if p.is_dir()) if d.is_dir() else []


def replay(kind, vendor, cap, case):
    c = json.loads((case / "case.json").read_text())
    t = Replay(case)
    fn = getattr(registry.module(kind, vendor), cap)
    out = fn([base.Target.parse(s) for s in c["targets"]], t, c.get("now", 0))
    t.done()
    return out


class Contract(unittest.TestCase):
    def test_registry_matches_vendors(self):
        self.assertEqual({v for _, v in registry.available()}, set(site.VENDORS))
        self.assertEqual({k for k, _ in registry.available()}, set(schema.KINDS))

    def test_adapter_yaml(self):
        for kind, vendor in registry.available():
            with self.subTest(adapter=f"{kind}/{vendor}"):
                m = registry.meta(kind, vendor)
                self.assertEqual(set(m) - TOP, set())
                self.assertEqual((m["adapter"], m["kind"], m["vendor"]), (1, kind, vendor))
                self.assertIsInstance(m["version"], int)
                self.assertIsInstance(m["tested"], list)
                if "os" in m:
                    self.assertIn(("os", m["os"]), registry.available())
                caps = m["capabilities"]
                self.assertEqual(set(caps) - set(schema.KINDS[kind]["capabilities"]), set(), "unknown capability")
                for name, c in caps.items():
                    self.assertEqual(set(c) - CAP, set(), name)
                    self.assertIn(c["status"], schema.STATUSES, name)
                    if c["status"] == "planned":
                        continue
                    self.assertIn(c.get("face"), schema.FACES, name)
                    if "ref" in c:
                        self.assertTrue((ROOT / c["ref"]).exists(), f"{name}: {c['ref']} does not exist")
                    if c["face"] in ("descriptor", "install"):
                        self.assertIn("ref", c, name)
                    if c["face"] == "snmp":
                        for metric in c.get("metrics", []):
                            self.assertTrue(snmp_has(metric), f"{name}: {metric} is not in snmp.yml")
                    if c["face"] == "render":
                        self.assertTrue(callable(getattr(registry.module(kind, vendor), "render", None)), name)
                    if c["face"] == "collect" and not c.get("via"):
                        self.assertTrue(callable(getattr(registry.module(kind, vendor), name, None)), name)
                        self.assertIn("textfile", c, name)
                        self.assertTrue(cases(vendor, name), f"{name}: no recorded case in {FIX / vendor / name}")
                    if c["face"] == "data":
                        self.assertTrue(callable(getattr(registry.module(kind, vendor), name, None)), name)
                        self.assertTrue(cases(vendor, name), f"{name}: no recorded case in {FIX / vendor / name}")
                    if c.get("via"):
                        self.assertEqual(caps[c["via"]]["status"], c["status"], f"{name} via {c['via']}")

    def test_status_maps(self):
        """Each status entry names an SNMP metric, the label holding the
        string, exactly one of ok or bad, and the alert that reads it."""
        rules_text = "".join(p.read_text() for p in (ROOT / "collector" / "prometheus" / "rules").glob("*.yml"))
        for kind, vendor in registry.available():
            for e in registry.meta(kind, vendor).get("status") or []:
                with self.subTest(adapter=f"{kind}/{vendor}", record=e.get("record")):
                    self.assertEqual(set(e) - {"record", "metric", "label", "ok", "bad", "alert"}, set())
                    self.assertEqual(len({"ok", "bad"} & set(e)), 1)
                    self.assertEqual(e["record"], f"{kind}:{e['metric']}:ok")
                    self.assertTrue(snmp_has(e["metric"]), e["metric"])
                    self.assertRegex(rules_text, rf"- alert: {e['alert']}\n\s+expr: {re.escape(e['record'])} == 0\n")

    def test_collect_cases(self):
        for kind, vendor in registry.available():
            caps = registry.meta(kind, vendor)["capabilities"]
            for name, c in caps.items():
                if c["status"] != "implemented" or c.get("face") != "collect" or c.get("via"):
                    continue
                allowed = schema.FAMILIES[(kind, name)]
                for case in cases(vendor, name):
                    with self.subTest(adapter=f"{kind}/{vendor}", capability=name, case=case.name):
                        got = replay(kind, vendor, name, case)
                        self.assertEqual(got, (case / "expected.prom").read_text())
                        for fam, labelsets in base.parse_textfile(got).items():
                            self.assertIn(fam, allowed)
                            self.assertEqual(labelsets, {allowed[fam]}, fam)

    def test_data_cases(self):
        for kind, vendor in registry.available():
            for name, c in registry.meta(kind, vendor)["capabilities"].items():
                if c["status"] != "implemented" or c.get("face") != "data":
                    continue
                for case in cases(vendor, name):
                    with self.subTest(adapter=f"{kind}/{vendor}", capability=name, case=case.name):
                        c = json.loads((case / "case.json").read_text())
                        t = Replay(case)
                        fn = getattr(registry.module(kind, vendor), name)
                        if "raises" in c:
                            with self.assertRaisesRegex(Exception, c["raises"]):
                                fn(t, **c["args"])
                        else:
                            got = fn(t, **c["args"])
                            self.assertEqual(json.loads(json.dumps(got)),
                                             json.loads((case / "expected.json").read_text()))
                        t.done()


if __name__ == "__main__":
    unittest.main()
