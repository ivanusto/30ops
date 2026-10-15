import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import site, yamlio  # noqa: E402
from ops30.render import rules, status  # noqa: E402

SAMPLE = ROOT / "examples" / "sample-site"


def resolved(thresholds=None):
    doc = site.load(SAMPLE / "site.yaml")
    if thresholds is not None:
        doc.setdefault("alerting", {})["thresholds"] = thresholds
    return site.resolve(doc, str(SAMPLE))


def alerts(tree):
    """alert name -> (group, expr with whitespace collapsed, for, labels)."""
    out = {}
    for p, o in tree.items():
        for g in yamlio.loads(o.text, p)["groups"]:
            for r in g["rules"]:
                out[r["alert"]] = (g["name"], g.get("interval"), " ".join(r["expr"].split()),
                                   r.get("for"), r.get("labels"))
    return out


def all_sources():
    """The core rule files and every plugin's."""
    return rules.sources() + [src for _, src in rules.plugin_sources()]


# the alerts of the sample site: 62 core and 7 from gb10-ops
ALERTS = 69
# alerts that moved to another group since v0.3.0, with the same evaluation interval
REGROUPED = {"Gb10TextfileStale": ("pipeline", "gb10-pipeline")}


def git_show(rev, path):
    r = subprocess.run(["git", "-C", str(ROOT), "show", f"{rev}:{path}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


class Rules(unittest.TestCase):
    def test_catalogue_and_placeholders_agree(self):
        cat = site.threshold_catalogue()
        used = set()
        for src in all_sources():
            used |= set(rules.PLACEHOLDER.findall(Path(src).read_text()))
        self.assertEqual(used, set(cat))
        for k, v in cat.items():
            self.assertEqual(set(v), {"default", "unit", "alerts", "help"}, k)

    def test_catalogue_names_its_alerts(self):
        names = set(alerts(rules.render(resolved(), "x")))
        for k, v in site.threshold_catalogue().items():
            self.assertTrue(set(v["alerts"]) <= names, k)

    def test_alert_count(self):
        self.assertEqual(len(alerts(rules.render(resolved(), "x"))), ALERTS)

    def test_plugin_rules_follow_the_hosts(self):
        """A site whose hosts list no plugin gets no plugin rules."""
        r = resolved()
        for h in r["hosts"]:
            h["plugins"] = []
        tree = rules.render(r, "x")
        self.assertNotIn(f"{rules.P}/plugin-gb10-ops.yml", tree)
        self.assertFalse([a for a in alerts(tree) if a.startswith("Gb10")])
        self.assertIn(f"{rules.P}/plugin-gb10-ops.yml", rules.render(resolved(), "x"))

    def test_defaults_match_v030(self):
        """With no override the rules mean what v0.3.0 shipped (expr, for,
        labels); only the comments and the annotation text moved. The four
        status alerts compare a recording rule with 0 since v0.5; their
        status map must be exactly what the v0.3.0 matcher said."""
        if git_show("v0.3.0", "VERSION") is None:
            self.skipTest("tag v0.3.0 not in this clone")
        old = {}
        for src in rules.sources():
            name = os.path.basename(src)
            text = git_show("v0.3.0", f"collector/prometheus/rules/{name}")
            old[name] = rules.Output(text)
        new, was = alerts(rules.render(resolved(), "x")), alerts(old)
        for _, _, e in status.entries():
            name, m, lab = e["alert"], e["metric"], e["label"]
            g, iv, ex, f, labels = was[name]
            norm = re.sub(r'(\w+)="', r'\1=~"', re.sub(r'(\w+)!="', r'\1!~"', ex))
            want = f'{m}{{{lab}!~"{e["ok"]}"}} == 1' if "ok" in e else f'{m}{{{lab}=~"{e["bad"]}"}} == 1'
            self.assertEqual(norm, want, name)
            self.assertEqual(new[name][2], f'{e["record"]} == 0', name)
            new[name] = new[name][:2] + (ex,) + new[name][3:]
        for name, (g_old, g_new) in REGROUPED.items():
            self.assertEqual(new[name][0], g_new, name)
            self.assertIsNone(new[name][1], name)
            new[name] = (g_old,) + new[name][1:]
        self.assertEqual(new, was)

    def test_override_changes_only_its_alert(self):
        a = alerts(rules.render(resolved(), "x"))
        b = alerts(rules.render(resolved({"nas_pool_warn_pct": 85, "fw_burst_ufw": 150}), "x"))
        diff = {k for k in a if a[k] != b[k]}
        self.assertEqual(diff, {"NasPoolAbove80", "FwSourceBurst"})
        self.assertIn("nas_zpool_capacity_percent > 85", b["NasPoolAbove80"][2])
        self.assertIn('{source="ufw"} > 150', b["FwSourceBurst"][2])

    def test_status_rules(self):
        """One recording rule per status entry, both sides of `or` disjoint."""
        doc = yamlio.loads(status.render(resolved(), "x")[status.PATH].text)
        self.assertEqual([g["name"] for g in doc["groups"]], ["status"])
        recs = {r["record"]: r["expr"] for r in doc["groups"][0]["rules"]}
        self.assertEqual(recs["nas:qnap_disk_status:ok"],
                         'qnap_disk_status{qnap_disk_status=~"(?i)good"} * 0 + 1 or '
                         'qnap_disk_status{qnap_disk_status!~"(?i)good"} * 0')
        self.assertEqual(recs["nas:qnap_service_telnet_enabled_info:ok"],
                         'qnap_service_telnet_enabled_info{qnap_service_telnet_enabled=~"yes"} * 0 or '
                         'qnap_service_telnet_enabled_info{qnap_service_telnet_enabled!~"yes"} * 0 + 1')

    def test_number_format(self):
        self.assertEqual([rules.number(v) for v in (80, 80.0, 0.5, 1e3)], ["80", "80", "0.5", "1000"])

    def test_unknown_placeholder(self):
        with self.assertRaisesRegex(site.SiteError, r"\$\{nope\} is not in thresholds.yml"):
            rules.fill("expr: x > ${nope}", {}, "t.yml")

    def test_prometheus_templates_pass_through(self):
        t = 'summary: "{{ $labels.nas }} {{ $value }} ${a}"'
        self.assertEqual(rules.fill(t, {"a": 2}), 'summary: "{{ $labels.nas }} {{ $value }} 2"')

    def test_documented(self):
        doc = (ROOT / "docs" / "rules.md").read_text()
        for name in alerts(rules.render(resolved(), "x")):
            self.assertIn(f"| {name} |", doc)
        for k in site.threshold_catalogue():
            self.assertIn(f"| `{k}` |", doc)

    def test_alertmanager_base_names_real_alerts(self):
        """Every alertname="X" in alertmanager.base.yml (routes, inhibit
        rules; the gb10-ops ones among them) is an alert of the core rules
        or of a plugin, so a rename cannot leave a dead matcher behind."""
        names = set()
        for src in all_sources():
            names |= set(re.findall(r"- alert: (\S+)", Path(src).read_text()))
        base = (ROOT / "collector" / "alertmanager" / "alertmanager.base.yml").read_text()
        for name in re.findall(r'alertname="([^"]+)"', base):
            self.assertIn(name, names)

    def test_no_day_references(self):
        for src in all_sources():
            self.assertIsNone(re.search(r"\bDay \d+", Path(src).read_text()), src)


class Validate(unittest.TestCase):
    def check(self, th):
        doc = site.load(SAMPLE / "site.yaml")
        doc["alerting"]["thresholds"] = th
        return site.validate(doc, str(SAMPLE))

    def test_known_keys(self):
        self.assertEqual(self.check({"nas_pool_warn_pct": 85, "drill_rto_target_s": 1200.5}), ([], []))

    def test_unknown_key(self):
        errs, _ = self.check({"nas_pool_warn": 85})
        self.assertIn("alerting.thresholds.nas_pool_warn is not a threshold "
                      "(see collector/prometheus/thresholds.yml)", errs)

    def test_positive(self):
        errs, _ = self.check({"nas_disk_temp_c": 0})
        self.assertIn("alerting.thresholds.nas_disk_temp_c must be above 0", errs)

    def test_order(self):
        errs, _ = self.check({"nas_pool_warn_pct": 95})
        self.assertIn("alerting.thresholds: nas_pool_warn_pct (95) must be below nas_pool_crit_pct (90)", errs)
        errs, _ = self.check({"eol_crit_days": 90})
        self.assertIn("alerting.thresholds: eol_crit_days (90) must be below eol_warn_days (90)", errs)


if __name__ == "__main__":
    unittest.main()
