import copy
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import site, yamlio  # noqa: E402

SAMPLE = ROOT / "examples" / "sample-site"


def sample():
    return site.load(SAMPLE / "site.yaml")


def check(doc, **kw):
    return site.validate(doc, str(SAMPLE), **kw)


class Yaml(unittest.TestCase):
    def test_dates_stay_strings(self):
        self.assertEqual(yamlio.loads("a: 2026-10-14\nb: 2026-10-14T01:02:03Z\n"),
                         {"a": "2026-10-14", "b": "2026-10-14T01:02:03Z"})

    def test_duplicate_key(self):
        with self.assertRaisesRegex(yamlio.YamlError, "duplicate key 'a'"):
            yamlio.loads("a: 1\nb: 2\na: 3\n")

    def test_dump_is_stable(self):
        obj = {"z": 1, "a": ["x", {"k": "多行\n文字"}], "m": "a: b"}
        self.assertEqual(yamlio.dumps(obj), yamlio.dumps(copy.deepcopy(obj)))
        self.assertEqual(yamlio.loads(yamlio.dumps(obj)), obj)
        self.assertTrue(yamlio.dumps(obj).startswith("z: 1\n"))


class Validate(unittest.TestCase):
    def test_sample_is_clean(self):
        self.assertEqual(check(sample()), ([], []))

    def assertErr(self, doc, text):
        errs, _ = check(doc)
        self.assertTrue(any(text in e for e in errs), errs)

    def test_schema(self):
        d = sample()
        d["hosts"][1]["vendor"] = "cisco"
        d["hosts"][2]["colour"] = "red"
        del d["site"]["timezone"]
        d["version"] = 2
        errs, _ = check(d)
        self.assertIn("hosts[1].vendor must be one of linux, pve, qnap, fortigate, generic-snmp (got 'cisco')", errs)
        self.assertIn("hosts[2].colour: unknown key", errs)
        self.assertIn("site.timezone is required", errs)
        self.assertIn("version must be 1", errs)

    def test_role_needs_an_adapter(self):
        d = sample()
        nas = next(i for i, h in enumerate(d["hosts"]) if h["name"] == "nas-secondary")
        d["hosts"][nas]["vendor"] = "linux"
        pve = next(i for i, h in enumerate(d["hosts"]) if h["name"] == "pve1")
        errs, _ = check(d)
        self.assertIn(f"hosts[{nas}]: no adapter serves role nas for vendor linux (adapters/nas/ has qnap)", errs)
        # journal and pcap on a PVE node go to os/linux through adapter.yaml os:
        self.assertFalse([e for e in errs if e.startswith(f"hosts[{pve}]")], errs)

    def test_types(self):
        d = sample()
        d["hosts"][0]["roles"] = "collector"
        d["logs"]["archive"]["skip"] = "x"
        self.assertErr(d, "hosts[0].roles must be a list")
        self.assertErr(d, "logs.archive.skip must be a list")

    def test_plain_text_secret(self):
        d = sample()
        d["alerting"]["smtp"]["password"] = "hunter2"
        d["snmp"]["auths"]["nas_v3"]["priv_password"] = "hunter3"
        errs, _ = check(d)
        self.assertIn("alerting.smtp.password must name an entry in credentials (plain-text secrets are not allowed)", errs)
        self.assertIn("snmp.auths.nas_v3.priv_password must name an entry in credentials (plain-text secrets are not allowed)", errs)
        self.assertNotIn("hunter2", " ".join(errs))

    def test_credentials_are_file_refs(self):
        d = sample()
        d["credentials"]["smtp"] = {"file": "secrets/smtp", "value": "x"}
        self.assertErr(d, "credentials.smtp.value: unknown key")
        self.assertErr(d, "credentials.smtp.file must be an absolute path")

    def test_references(self):
        d = sample()
        d["collector"]["host"] = "spark01"
        d["worm"]["host"] = "nas-third"
        d["logs"]["admin_from"] = ["nobody"]
        d["hosts"][7]["snmp"]["auth"] = "v2"
        errs, _ = check(d)
        self.assertIn("collector.host 'spark01' does not have role collector", errs)
        self.assertIn("worm.host 'nas-third' is not a host name", errs)
        self.assertIn("logs.admin_from[0] 'nobody' is not a host name", errs)
        self.assertIn("hosts[7].snmp.auth 'v2' is not in snmp.auths", errs)

    def test_duplicates(self):
        d = sample()
        d["hosts"][2]["name"] = "spark01"
        d["hosts"][3]["address"] = "192.0.2.30"
        errs, _ = check(d)
        self.assertIn("hosts[2].name 'spark01' is used twice", errs)
        self.assertIn("hosts[6].also[0] '192.0.2.30' is also the address of pve1", errs)

    def test_timezone_and_names(self):
        d = sample()
        d["site"]["timezone"] = "Mars/Olympus"
        d["site"]["id"] = "Lab 1"
        d["hosts"][0]["labels"]["bad-label"] = "x"
        self.assertErr(d, "site.timezone 'Mars/Olympus' is not in the zoneinfo database")
        self.assertErr(d, "site.id 'Lab 1' must be lower case")
        self.assertErr(d, "hosts[0].labels.bad-label is not a valid Prometheus label name")

    def test_receivers(self):
        d = sample()
        del d["alerting"]["receivers"]["ops-digest"]
        del d["alerting"]["smtp"]
        errs, _ = check(d)
        self.assertIn("alerting.receivers.ops-digest is required (the route tree sends to it)", errs)
        self.assertIn("alerting.smtp is required when a receiver has email", errs)

    def test_vendor_needed_for_managed_roles(self):
        d = sample()
        del d["hosts"][1]["vendor"]
        self.assertErr(d, "hosts[1].vendor is required for roles journal, node, pcap")

    def test_gate_assets_must_exist(self):
        d = sample()
        d["gate"]["targets"].append({"asset": "nas-primary/QTS", "ssh": "gate@nas"})
        self.assertErr(d, "gate.targets[3].asset 'nas-primary/QTS' is not a row of assets.tsv")

    def test_collector_volumes_and_retention(self):
        d = sample()
        d["collector"]["volumes"]["grafana"] = "onprem-metrics_prometheus-data"
        d["collector"]["volumes"]["alertmanager"] = "-bad"
        d["collector"]["retention"] = {"metrics": "90 days", "logs_max_disk": "12G"}
        d["collector"]["grafana_port"] = 70000
        errs, _ = check(d)
        for e in ("collector.volumes: onprem-metrics_prometheus-data is used twice",
                  "collector.volumes.alertmanager '-bad' is not a docker volume name",
                  "collector.retention.metrics '90 days' must be a number and h, d, w or y (90d)",
                  "collector.retention.logs_max_disk '12G' must be bytes or KiB, MiB, GiB, TiB (12GiB)",
                  "collector.grafana_port 70000 is not a port"):
            self.assertIn(e, errs)

    def test_warnings_and_strict(self):
        d = sample()
        d["alerting"]["thresholds"] = {"nas_pool_warn_pct": 85}
        d["credentials"]["spare"] = {"file": "/etc/30ops/secrets/spare"}
        errs, warns = check(d)
        self.assertEqual(errs, [])
        self.assertIn("credentials.spare is not used", warns)
        errs, warns = check(d, strict=True)
        self.assertEqual(warns, [])
        self.assertIn("credentials.spare is not used (--strict)", errs)


class SecretFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_mode(self):
        d = sample()
        ok = os.path.join(self.tmp, "ok")
        loose = os.path.join(self.tmp, "loose")
        for p, m in ((ok, 0o600), (loose, 0o644)):
            Path(p).write_text("x")
            os.chmod(p, m)
        d["credentials"] = {k: {"file": ok} for k in d["credentials"]}
        d["credentials"]["smtp"] = {"file": loose}
        d["credentials"]["pcap-pull"] = {"file": os.path.join(self.tmp, "missing")}
        errs, _ = check(d, secrets=True)
        self.assertEqual(len(errs), 2, errs)
        self.assertIn(f"credentials.smtp.file {loose} is mode 644, must be 0600 or 0400", errs)
        self.assertEqual(check(d)[0], [])


class Resolve(unittest.TestCase):
    def test_defaults(self):
        r = site.resolve(sample(), str(SAMPLE))
        self.assertEqual(r["collector"]["root"], "/opt/30ops")
        self.assertEqual(r["collector"]["drills"]["logs"], "/srv/drills/onprem-logs/drills.jsonl")
        self.assertEqual(r["changes"]["clone"], "/opt/onprem-changes")
        self.assertEqual(r["gate"]["approval_ttl_s"], 600)
        self.assertEqual(site.host(r, "spark01")["pcap"], {"user": "pcap"})
        self.assertEqual([h["name"] for h in site.with_role(r, "nas")], ["nas-primary", "nas-secondary"])


class JournalDefault(unittest.TestCase):
    def hosts(self, doc):
        return {h["name"]: h for h in site.resolve(doc, str(SAMPLE))["hosts"]}

    def test_linux_and_pve_hosts_ship_their_journal(self):
        h = self.hosts(sample())
        self.assertIn("journal", h["qdevice"]["roles"])
        self.assertTrue(h["qdevice"]["journal_default"])
        self.assertNotIn("journal_default", h["spark01"])           # listed it itself
        self.assertNotIn("journal", h["collector"]["roles"])        # where the journals go
        self.assertNotIn("journal", h["nas-primary"]["roles"])      # an appliance

    def test_opt_out(self):
        d = sample()
        q = next(x for x in d["hosts"] if x["name"] == "qdevice")
        q["journal"] = False
        self.assertEqual(check(d), ([], []))
        self.assertNotIn("journal", self.hosts(d)["qdevice"]["roles"])
        q["roles"] = ["qdevice", "journal"]
        errs, _ = check(d)
        self.assertTrue(any("journal: false and role journal contradict" in e for e in errs), errs)


if __name__ == "__main__":
    unittest.main()
