"""30ops render on the sample site, end to end.

- The whole tree is compared with tests/golden/render/sample-site/, file
  for file and byte for byte, with the 30ops version and the manifest's
  per-file sha256 masked.
- Two runs give the same bytes.
- The tree is semantically the same as tests/fixtures/legacy-root, the
  old layout put together from the repo's hand-written files (targets
  .example, the five cron fragments, allowlist, mount, gate config): that
  is what says render reproduces what those files did.
- import-legacy on that fixture gives a site.yaml that validates and
  renders to the same thing again.
- The fixture's copies are still the same as the repo files they came
  from, so a change to one of those shows up here.

Regenerate the golden tree after an intended change with:

    GOLDEN_UPDATE=1 python3 -m unittest tests/test_render.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import legacy, legacy_import, render, site  # noqa: E402

SAMPLE = ROOT / "examples" / "sample-site" / "site.yaml"
GOLDEN = ROOT / "tests" / "golden" / "render" / "sample-site"
LEGACY = ROOT / "tests" / "fixtures" / "legacy-root"
MASK = [(re.compile(r"30ops \d+\.\d+\.\d+"), "30ops X.Y.Z"),
        (re.compile(r'"sha256": "[0-9a-f]{64}"'), '"sha256": "X"')]
# fixture file -> the repo file(s) it is a copy of
COPIES = {
    "opt/onprem-metrics/prometheus/targets/collector.yml": ["collector/prometheus/targets/collector.yml.example"],
    "opt/onprem-metrics/prometheus/targets/gb10.yml": ["collector/prometheus/targets/gb10.yml.example"],
    "opt/onprem-metrics/prometheus/targets/nas-snmp.yml": ["collector/prometheus/targets/nas-snmp.yml.example"],
    "opt/onprem-metrics/prometheus/targets/pve.yml": ["collector/prometheus/targets/pve.yml.example"],
    "opt/onprem-metrics/prometheus/pve.yml": ["collector/prometheus/pve.yml.example"],
    "opt/onprem-metrics/prometheus/snmp-auth.yml": ["collector/prometheus/snmp-auth.yml.example"],
    "opt/onprem-metrics/alertmanager/alertmanager.yml": ["collector/alertmanager/alertmanager.yml.example"],
    "opt/onprem-metrics/grafana/provisioning/datasources/prometheus.yml": ["collector/grafana/provisioning/datasources/prometheus.yml"],
    "etc/cron.d/onprem-metrics": ["collector/systemd/collector.cron"],
    "etc/cron.d/onprem-logs": ["logs/collector.cron", "logs/firewall/collector.cron", "logs/audit/collector.cron",
                               "logs/pcap/collector.cron"],
    "etc/cron.d/onprem-changes": ["changes/collector.cron"],
    "etc/cron.d/onprem-agent-gate": ["gate/collector.cron"],
    "etc/default/onprem-logs-allowlist": ["logs/collector/onprem-logs-allowlist.default"],
    "etc/systemd/system/onprem-logs-allowlist.service": ["logs/collector/onprem-logs-allowlist.service"],
    "etc/systemd/system/mnt-worm.mount": ["logs/collector/mnt-worm.mount"],
    "etc/onprem-agent-gate/config.json": ["gate/config.json.example"],
    "etc/onprem-agent-gate/tools.json": ["gate/tools.json"],
    "etc/30ops/assets.tsv": ["examples/sample-site/assets.tsv"],
}


def masked(text):
    for rx, rep in MASK:
        text = rx.sub(rep, text)
    return text


def tree_of(path):
    s = site.resolve(site.load(path), str(Path(path).parent))
    return s, render.render(s, render.site_sha(path))


class Render(unittest.TestCase):
    def test_golden(self):
        _, tree = tree_of(SAMPLE)
        if os.environ.get("GOLDEN_UPDATE") == "1":
            shutil.rmtree(GOLDEN, ignore_errors=True)
            for p, o in tree.items():
                (GOLDEN / p).parent.mkdir(parents=True, exist_ok=True)
                (GOLDEN / p).write_text(masked(o.text))
            return
        have = sorted(str(p.relative_to(GOLDEN)) for p in GOLDEN.rglob("*") if p.is_file())
        self.assertEqual(have, sorted(tree), "the set of rendered files changed")
        for p, o in tree.items():
            with self.subTest(path=p):
                self.assertEqual(masked(o.text), (GOLDEN / p).read_text(), f"{p} differs from the golden copy")

    def test_deterministic(self):
        _, a = tree_of(SAMPLE)
        _, b = tree_of(SAMPLE)
        self.assertEqual({p: o.text for p, o in a.items()}, {p: o.text for p, o in b.items()})

    def test_same_as_legacy_layout(self):
        s, tree = tree_of(SAMPLE)
        self.assertEqual(legacy.compare(tree, str(LEGACY), s), [])

    def test_fixture_copies_match_repo(self):
        for fx, srcs in COPIES.items():
            got = (LEGACY / fx).read_text()
            if fx == "etc/cron.d/onprem-logs":
                want = "".join((ROOT / s).read_text() for s in srcs)
            else:
                want = (ROOT / srcs[0]).read_text()
            self.assertEqual(got, want, f"{fx} is no longer a copy of {', '.join(srcs)}")
        prom = (LEGACY / "opt/onprem-metrics/prometheus/prometheus.yml").read_text()
        self.assertTrue(prom.startswith((ROOT / "collector/prometheus/prometheus.yml").read_text()))

    def test_import_round_trip(self):
        tmp = tempfile.mkdtemp()
        try:
            doc, todo, assets = legacy_import.draft(str(LEGACY))
            self.assertEqual(assets, "etc/30ops/assets.tsv")
            shutil.copy(LEGACY / assets, os.path.join(tmp, "assets.tsv"))
            p = os.path.join(tmp, "site.yaml")
            Path(p).write_text(legacy_import.dumps(doc, todo, "fixture"))
            self.assertEqual(site.validate(site.load(p), tmp), ([], []))
            s, tree = tree_of(p)
            self.assertEqual(legacy.compare(tree, str(LEGACY), s), [])
            self.assertTrue(any("192.0.2.30" in t for t in todo), todo)
            names = [h["name"] for h in doc["hosts"]]
            for n in ("collector", "spark01", "pve2", "nas-primary", "fgt-edge", "admin1"):
                self.assertIn(n, names)
        finally:
            shutil.rmtree(tmp)


class Detects(unittest.TestCase):
    """compare() is only worth something if it notices a change."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "root")
        shutil.copytree(LEGACY, self.root)
        self.site, self.tree = tree_of(SAMPLE)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def edit(self, rel, old, new):
        p = Path(self.root) / rel
        text = p.read_text()
        self.assertIn(old, text)
        p.write_text(text.replace(old, new, 1))

    def diffs(self):
        return legacy.compare(self.tree, self.root, self.site)

    def test_target(self):
        self.edit("opt/onprem-metrics/prometheus/targets/gb10.yml", '"192.0.2.141:9100"', '"192.0.2.142:9100"')
        d = self.diffs()
        self.assertIn("targets/gb10.yml: 192.0.2.142:9100 {'hw': 'dgx-spark', 'role': 'gpu-node'} only in legacy", d)
        self.assertIn("targets/gb10.yml: 192.0.2.141:9100 {'hw': 'dgx-spark', 'role': 'gpu-node'} only in render", d)

    def test_cron_argument_and_file_variable(self):
        self.edit("etc/cron.d/onprem-logs", "--window 1h --baseline 7d", "--window 2h --baseline 7d")
        self.edit("etc/cron.d/onprem-logs", 'AUDIT_QUIET_FROM="192.0.2.10 192.0.2.11"', 'AUDIT_QUIET_FROM="192.0.2.10"')
        d = self.diffs()
        self.assertEqual(sum(1 for x in d if x.startswith("cron: only in legacy")), 3, d)
        self.assertTrue(any("--window 2h" in x for x in d))
        self.assertTrue(any("AUDIT_QUIET_FROM=192.0.2.10 CHANGES_DIR" in x for x in d))

    def test_allowlist_mount_receiver_gate(self):
        self.edit("etc/default/onprem-logs-allowlist", "192.0.2.22 ", "")
        self.edit("etc/systemd/system/mnt-worm.mount", "vers=4.1", "vers=4.2")
        self.edit("opt/onprem-metrics/alertmanager/alertmanager.yml", "oncall@example.net", "pager@example.net")
        self.edit("etc/onprem-agent-gate/config.json", '"approval_ttl_s": 600', '"approval_ttl_s": 900')
        d = self.diffs()
        self.assertIn("allowlist SYSLOG_FROM: only in legacy [], only in render ['192.0.2.22']", d)
        self.assertTrue(any(x.startswith("mount: /mnt/worm.Options") for x in d), d)
        self.assertTrue(any(x.startswith("alertmanager.yml: receivers") for x in d), d)
        self.assertIn("gate config.json: approval_ttl_s: legacy 900 != render 600", d)

    def test_secrets_are_not_compared(self):
        self.edit("opt/onprem-metrics/prometheus/pve.yml", "REPLACE-WITH-TOKEN", "MASKED")
        self.edit("etc/cron.d/onprem-metrics", "/etc/onprem-metrics/fgt.token", "/root/fgt.token")
        self.assertEqual(self.diffs(), [])

    def test_missing_file(self):
        os.unlink(os.path.join(self.root, "etc/cron.d/onprem-changes"))
        d = self.diffs()
        self.assertIn("cron: legacy has no /etc/cron.d/onprem-changes", d)


class Cli(unittest.TestCase):
    def run30(self, *args):
        return subprocess.run([str(ROOT / "bin" / "30ops"), *map(str, args)], capture_output=True, text=True)

    def test_validate_render_import(self):
        self.assertEqual(self.run30("validate", "--site", SAMPLE).returncode, 0)
        tmp = tempfile.mkdtemp()
        try:
            bad = Path(tmp) / "site.yaml"
            bad.write_text(SAMPLE.read_text().replace("password: smtp", "password: hunter2"))
            r = self.run30("validate", "--site", bad)
            self.assertEqual(r.returncode, 1)
            self.assertIn("alerting.smtp.password must name an entry in credentials", r.stderr)
            self.assertEqual(self.run30("render", "--site", bad, "--out", Path(tmp) / "x").returncode, 1)
            self.assertFalse((Path(tmp) / "x").exists())

            out = Path(tmp) / "out"
            r = self.run30("render", "--site", SAMPLE, "--out", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(oct((out / "etc/30ops/prometheus/pve.yml").stat().st_mode & 0o777), "0o640")
            self.assertEqual(self.run30("render", "--site", SAMPLE, "--diff", "--root", out).returncode, 0)
            with open(out / "etc/default/30ops-allowlist", "a") as f:
                f.write("# local edit\n")
            r = self.run30("render", "--site", SAMPLE, "--diff", "--root", out)
            self.assertEqual(r.returncode, 1)
            self.assertIn("-# local edit", r.stdout)
            r = self.run30("render", "--site", SAMPLE, "--compare-legacy", LEGACY)
            self.assertEqual((r.returncode, r.stdout), (0, ""), r.stderr)

            imp = Path(tmp) / "imp" / "site.yaml"
            r = self.run30("import-legacy", "--from", LEGACY, "-o", imp)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((imp.parent / "assets.tsv").exists())
            self.assertEqual(self.run30("import-legacy", "--from", LEGACY, "-o", imp).returncode, 2)
            r = self.run30("render", "--site", imp, "--compare-legacy", LEGACY)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
