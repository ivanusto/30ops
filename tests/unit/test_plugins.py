"""The plugin contract (docs/plugins.md), checked for every plugin.

Each plugins/<name>/plugin.yaml must be well formed, name its own directory,
and refer only to files that exist. site.PLUGINS is what the directory holds.
"""
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import plugins, site, yamlio  # noqa: E402

TOP = {"plugin", "name", "version", "license", "summary", "roles", "vendors", "install", "textfile",
       "scrape", "rules", "thresholds", "threshold_order", "dashboard", "readiness"}
INSTALL = {"files"}
TEXTFILE = {"file", "prefix", "max_age_s"}
SCRAPE = {"job", "port", "replaces", "config"}


def host(**kw):
    return {"name": "n1", "address": "192.0.2.10", "vendor": "linux", "roles": ["node"], **kw}


class Contract(unittest.TestCase):
    def test_site_enum_is_the_directory(self):
        self.assertEqual(set(site.PLUGINS), set(plugins.available()))
        self.assertEqual(set(plugins.available()),
                         {p.name for p in (ROOT / "plugins").iterdir() if p.is_dir()})

    def test_plugin_yaml(self):
        for name in plugins.available():
            with self.subTest(plugin=name):
                m = plugins.meta(name)
                d = plugins.directory(name)
                self.assertEqual(set(m) - TOP, set())
                self.assertEqual((m["plugin"], m["name"]), (1, name))
                self.assertIsInstance(m["version"], int)
                self.assertEqual(m["license"], "Apache-2.0")
                self.assertTrue(m.get("summary"))
                self.assertEqual(set(m.get("roles") or []) - set(site.ROLES), set())
                self.assertEqual(set(m.get("vendors") or []) - set(site.VENDORS), set())
                inst = m.get("install")
                if inst:
                    self.assertEqual(set(inst) - INSTALL, set())
                    self.assertIn(plugins.HOOK, inst["files"], "install.files must carry install.sh")
                    for f in inst["files"]:
                        self.assertTrue((d / f).is_file(), f)
                        if f.endswith((".sh", ".py")):
                            self.assertTrue(os.access(d / f, os.X_OK), f"{f} is not executable")
                for t in m.get("textfile") or []:
                    self.assertEqual(set(t) - TEXTFILE, set())
                    self.assertRegex(t["file"], r"^[a-z0-9-]+\.prom$")
                    self.assertTrue(t["prefix"].endswith("_textfile"))
                    self.assertIsInstance(t["max_age_s"], int)
                sc = m.get("scrape")
                if sc:
                    self.assertEqual(set(sc) - SCRAPE, set())
                    self.assertRegex(sc["job"], r"^[a-z0-9-]+$")
                    self.assertIsInstance(sc["port"], int)
                    self.assertIn(sc.get("replaces"), (None, "node"))
                    self.assertNotIn("job_name", sc.get("config") or {})
                    self.assertNotIn("file_sd_configs", sc.get("config") or {})
                for r in m.get("rules") or []:
                    self.assertTrue((d / r).is_file(), r)
                if m.get("thresholds"):
                    cat = yamlio.load(d / m["thresholds"])
                    core = yamlio.load(site.THRESHOLDS)
                    self.assertEqual(set(cat) & set(core), set(), "a plugin threshold shadows a core one")
                    for lo, hi in m.get("threshold_order") or []:
                        self.assertIn(lo, cat)
                        self.assertIn(hi, cat)
                if m.get("dashboard"):
                    self.assertTrue((d / m["dashboard"]).is_file())

    def test_textfile_age_is_the_stale_alert(self):
        """A plugin textfile's max_age_s is the threshold of the stale alert
        on its *_last_run_timestamp, as for the collector's own textfiles."""
        for name in plugins.available():
            text = "".join(Path(p).read_text() for p in plugins.rule_files(name))
            for t in plugins.textfiles(name):
                with self.subTest(plugin=name, textfile=t["file"]):
                    m = re.search(rf"time\(\) - {t['prefix']}_last_run_timestamp > (\d+)", text)
                    self.assertTrue(m, f"no stale alert on {t['prefix']}_last_run_timestamp")
                    self.assertEqual(int(m.group(1)), t["max_age_s"])

    def test_fits(self):
        for name in plugins.available():
            self.assertIsNone(plugins.fits(name, host()))
        self.assertIn("roles", plugins.fits("gb10-ops", host(roles=["journal"])))
        self.assertIn("vendor", plugins.fits("gb10-ops", host(vendor="pve")))

    def test_validate_refuses_a_plugin_on_the_wrong_host(self):
        doc = {"version": 1, "site": {"id": "t", "timezone": "UTC"}, "collector": {"host": "c"},
               "hosts": [host(name="c", roles=["collector"]),
                         host(name="n1", address="192.0.2.11", roles=["journal"], plugins=["gb10-ops"])],
               "alerting": {"receivers": {r: {"webhook": ["http://192.0.2.9/"]} for r in site.RECEIVERS}}}
        errs, _ = site.validate(doc)
        self.assertIn("hosts[1].plugins[0]: plugin gb10-ops needs one of roles node", errs)


if __name__ == "__main__":
    unittest.main()
