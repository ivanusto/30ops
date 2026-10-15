import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import legacy, site  # noqa: E402
from ops30.render import compose, cron, logs, prometheus  # noqa: E402

SAMPLE = ROOT / "examples" / "sample-site"


def sample(edit=None):
    doc = site.load(SAMPLE / "site.yaml")
    if edit:
        edit(doc)
    return site.resolve(doc, str(SAMPLE))


class Parts(unittest.TestCase):
    def test_compose_env(self):
        env = compose.env(sample())
        self.assertEqual(env["COMPOSE_PROFILES"], "pve,snmp,logs")
        self.assertEqual(env["OPS30_VOL_PROMETHEUS"], "onprem-metrics_prometheus-data")
        self.assertEqual(env["OPS30_SMTP_PASSWORD_FILE"], "/etc/30ops/secrets/smtp.pass")
        self.assertEqual(env["OPS30_TZ"], "Asia/Taipei")

    def test_compose_env_defaults_and_profiles(self):
        def edit(d):
            del d["collector"]["volumes"]
            del d["alerting"]["smtp"]
            for r in d["alerting"]["receivers"].values():
                r.pop("email", None)
            d.pop("pve")
            d["hosts"] = [h for h in d["hosts"] if "nas" not in h["roles"]]
        env = compose.env(sample(edit))
        self.assertEqual(env["OPS30_VOL_GRAFANA"], "30ops_grafana-data")
        self.assertEqual(env["OPS30_SMTP_PASSWORD_FILE"], "/dev/null")
        self.assertEqual(env["COMPOSE_PROFILES"], "logs")

    def test_switch_snmp(self):
        def edit(d):
            d["hosts"] = [h for h in d["hosts"] if "nas" not in h["roles"]]
            d["snmp"]["auths"]["sw_v3"] = dict(d["snmp"]["auths"]["nas_v3"])
            d["hosts"] += [{"name": "sw1", "address": "192.0.2.40", "vendor": "generic-snmp", "roles": ["switch"],
                            "snmp": {"auth": "sw_v3"}},
                           {"name": "ap1", "address": "192.0.2.41", "vendor": "generic-snmp", "roles": ["ap"],
                            "labels": {"switch": "lobby-ap"}, "snmp": {"auth": "nas_v3"}},
                           {"name": "sw2", "address": "192.0.2.42", "vendor": "generic-snmp", "roles": ["switch"]}]
        s = sample(edit)
        jobs, auth = prometheus.targets(s)
        self.assertEqual(jobs["switch-snmp"], ("switch-snmp.yml", [
            {"targets": ["192.0.2.40"], "labels": {"switch": "sw1"}},
            {"targets": ["192.0.2.41"], "labels": {"switch": "lobby-ap", "__param_auth": "nas_v3"}}]))
        self.assertEqual(auth["switch-snmp"], "sw_v3")
        self.assertNotIn("nas-snmp", jobs)
        job = next(j for j in prometheus.prometheus_yml(s, jobs, auth)["scrape_configs"] if j["job_name"] == "switch-snmp")
        self.assertEqual(job["params"], {"module": ["if_mib"], "auth": ["sw_v3"]})
        self.assertIn("snmp", compose.env(s)["COMPOSE_PROFILES"].split(","))
        from ops30.render import adapters
        self.assertTrue(any('kind="network",vendor="generic-snmp",version="1",switch="sw1"' in x
                            for x in adapters.lines(s)))
        errs, warns = site.validate(site.load(SAMPLE / "site.yaml"), str(SAMPLE))
        self.assertEqual((errs, warns), ([], []))

    def test_rendered_compose_settings(self):
        text = compose.render(sample(), "x")[compose.P].text
        s = legacy.rendered_compose_settings(text)
        self.assertEqual(s["services"], ["alertmanager", "grafana", "prometheus", "pve-exporter",
                                         "snmp-exporter", "victorialogs"])
        self.assertEqual(s["retention"], {"metrics": "90d", "logs": "90d", "logs_max_disk": "12GiB"})

    def test_escape_path(self):
        # the same answers as systemd-escape --path
        self.assertEqual(logs.escape_path("/mnt/worm"), "mnt-worm")
        self.assertEqual(logs.escape_path("/srv/log-archive/"), "srv-log\\x2darchive")
        self.assertEqual(logs.escape_path("/mnt/.hidden/a b"), "mnt-.hidden-a\\x20b")
        self.assertEqual(logs.escape_path("/"), "-")

    def test_cron_time_in_site_timezone(self):
        self.assertEqual(cron.at(cron.ARCHIVE, "Asia/Taipei"), "10 8 * * *")
        self.assertEqual(cron.at(cron.EOL, "Asia/Taipei"), "35 7 * * *")
        self.assertEqual(cron.at(cron.FW_WEEKLY, "Asia/Taipei"), "15 8 * * 1")
        self.assertEqual(cron.at(cron.FW_WEEKLY, "UTC"), "15 0 * * 1")
        # west of UTC the Monday 00:15 UTC job is Sunday evening; standard time, not DST
        self.assertEqual(cron.at(cron.FW_WEEKLY, "America/New_York"), "15 19 * * 0")
        self.assertEqual(cron.at(cron.ARCHIVE, "Asia/Kolkata"), "40 5 * * *")

    def test_groups(self):
        hs = [{"address": "a", "labels": {"x": "1"}}, {"address": "b", "labels": {}},
              {"address": "c", "labels": {"x": "1"}}]
        self.assertEqual(prometheus.groups(hs, 9100),
                         [{"targets": ["a:9100", "c:9100"], "labels": {"x": "1"}}, {"targets": ["b:9100"]}])

    def test_parse_cron(self):
        text = ('MAILTO=""\nFW_EXPECT=fortigate:fw1\n'
                '*/10 * * * *  metrics VL=http://x PCAP="a b" /opt/x/fw-report.py --window 1h\n'
                '@reboot root /bin/true\n')
        e, g = legacy.parse_cron(text)
        self.assertEqual(g, {"MAILTO": ""})
        self.assertEqual(e[0], ("*/10 * * * *", "metrics", {"VL": "http://x", "PCAP": "a b", "FW_EXPECT": "fortigate:fw1"},
                                "/opt/x/fw-report.py --window 1h"))
        self.assertEqual(e[1], ("@reboot", "root", {}, "/bin/true"))


if __name__ == "__main__":
    unittest.main()
