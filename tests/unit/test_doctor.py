"""30ops doctor on a fake collector that test_install's FakeOps installed."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib" / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ops30 import doctor, render  # noqa: E402
from ops30.install import collector  # noqa: E402
from ops30.render.cron import TEXTFILES  # noqa: E402
from test_install import FakeOps, host, site_for  # noqa: E402


class Fs:
    f_blocks, f_bavail, f_fsid = 100, 50, 1


class DoctorOps(FakeOps):
    def __init__(self, root):
        super().__init__(root)
        self.tz = "Asia/Taipei"
        self.grafana_pw = None
        self.down = []
        self.digest_override = {}

    def statvfs(self, p):
        return Fs()

    def http(self, url, method="GET", timeout=5, auth=None):
        if "/api/v1/targets" in url:
            ts = [{"labels": {"job": "node", "instance": "192.0.2.49:9100"}, "health": "up"}]
            ts += [{"labels": {"job": j, "instance": i}, "health": "down", "lastError": "refused"} for j, i in self.down]
            return 200, json.dumps({"data": {"activeTargets": ts}})
        if "/api/v1/query" in url:
            return 200, json.dumps({"data": {"result": [{"metric": {"instance": "192.0.2.49:9100"}, "value": [0, "0"]}]}})
        if url.endswith("/api/user"):
            pw = self.grafana_pw or (self.read("/etc/30ops/secrets/grafana-admin.pass") or b"").decode().strip()
            return (200, "{}") if auth == f"admin:{pw}" else (401, "")
        return super().http(url, method, timeout, auth)

    def run(self, argv, input=None, timeout=600, env=None):
        ok = lambda out="": subprocess.CompletedProcess(argv, 0, out, "")    # noqa: E731
        a = list(argv)
        if a[0] == "findmnt":
            return ok("nfs4 rw,relatime,vers=4.1\n")
        if a[0] == "timedatectl":
            return ok(f"NTPSynchronized=yes\nTimezone={self.tz}\n")
        if a[:2] == ["runuser", "-u"] and a[4:6] == ["test", "-w"]:
            return ok()
        if a[:2] == ["docker", "info"]:
            return ok("/var/lib/docker\n")
        if a[:2] == ["docker", "inspect"]:
            svc = next(s for s, i in self.containers.items() if i == a[-1])
            return ok(f"sha256:img-{svc}\n")
        if a[:3] == ["docker", "image", "inspect"] and a[-1].startswith("sha256:img-"):
            svc = a[-1][len("sha256:img-"):]
            img = self.want[svc]
            d = self.digest_override.get(svc, img.split("@")[1])
            return ok(json.dumps([img.split(":")[0] + "@" + d]))
        if a[0] == "systemctl" and a[1] == "is-active" and a[-1] in ("cron", "crond"):
            return ok() if a[-1] == "cron" else subprocess.CompletedProcess(argv, 3, "", "")
        return super().run(argv, input, timeout, env)


class Doctor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.site = site_for(self.tmp)
        self.tree = render.render(self.site, "x")
        base = host(self.tmp, self.site)
        self.ops = DoctorOps(self.tmp)
        self.ops.volumes, self.ops.want_services, self.ops.want_images = base.volumes, base.want_services, base.want_images
        self.ops.want = collector.Ctx(self.site, {}, self.ops, collector.Run(True, print)).services()
        rc = collector.install(self.site, self.tree, self.ops, out=lambda x: None)
        self.assertEqual(rc, 0)
        self.stamp_textfiles(time.time())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def stamp_textfiles(self, t, extra=""):
        tf = self.site["collector"]["textfile_dir"]
        for name, (prefix, _) in TEXTFILES.items():
            self.ops.write(f"{tf}/{name}", f"{prefix}_last_run_timestamp {int(t)}\n{extra}".encode(), 0o644, 0, 0)

    def results(self):
        return {r["check"]: r for r in doctor.Doctor(self.site, self.tree, self.ops).run()}

    def test_healthy(self):
        res = self.results()
        bad = {k: v for k, v in res.items() if v["status"] != "ok"}
        self.assertEqual(bad, {})

    def test_stale_and_down(self):
        self.stamp_textfiles(time.time() - 4000)
        tf = self.site["collector"]["textfile_dir"]
        self.ops.write(f"{tf}/nas.prom", f'nas_up{{nas="primary"}} 0\nnas_textfile_last_run_timestamp{{nas="secondary"}} {int(time.time())}\n'.encode(), 0o644, 0, 0)
        res = self.results()
        self.assertEqual(res["textfile changes.prom"]["status"], "fail")       # 3600 s
        self.assertEqual(res["textfile eol.prom"]["status"], "ok")             # 2 days
        self.assertEqual(res["textfile nas.prom"]["status"], "warn")
        self.assertIn('nas_up{nas="primary"}', res["textfile nas.prom"]["detail"])

    def test_targets_clock_grafana(self):
        self.ops.down = [("nas-snmp", "192.0.2.2")]
        self.ops.tz = "Etc/UTC"
        self.ops.grafana_pw = "admin"
        res = self.results()
        self.assertEqual(res["targets"]["status"], "fail")
        self.assertIn("nas-snmp/192.0.2.2: refused", res["targets"]["detail"])
        self.assertEqual(res["clock"]["status"], "fail")
        self.assertEqual(res["grafana"]["status"], "fail")
        self.assertIn("still 'admin'", res["grafana"]["detail"])

    def test_secret_mode_render_and_image(self):
        tok = self.site["credentials"]["fortigate-api"]["file"]
        os.chmod(self.ops.path(tok), 0o644)
        am = Path(self.ops.path("etc/30ops/alertmanager/alertmanager.yml"))
        am.write_text(am.read_text() + "# edit\n")
        self.ops.digest_override["grafana"] = "sha256:" + "0" * 64
        res = self.results()
        self.assertEqual(res["secrets"]["status"], "fail")
        self.assertIn(tok, res["secrets"]["detail"])
        self.assertEqual(res["render"]["status"], "fail")
        self.assertIn("/etc/30ops/alertmanager/alertmanager.yml: content", res["render"]["detail"])
        self.assertEqual(res["images"]["status"], "fail")
        self.assertIn("grafana runs sha256:000", res["images"]["detail"])

    def test_text_and_json(self):
        res = doctor.Doctor(self.site, self.tree, self.ops).run()
        self.assertTrue(doctor.report(res).endswith("0 warn, 0 fail\n"))
        self.assertEqual(json.loads(doctor.report(res, "json"))["fail"], 0)


class Thresholds(unittest.TestCase):
    def test_max_age_is_the_stale_alert(self):
        rules = "".join(p.read_text() for p in (ROOT / "collector" / "prometheus" / "rules").glob("*.yml"))
        for name, (prefix, max_age) in TEXTFILES.items():
            m = re.search(rf"expr: time\(\) - {prefix}_last_run_timestamp > ([0-9 *]+)\n", rules)
            self.assertIsNotNone(m, prefix)
            n = 1
            for x in m.group(1).split("*"):
                n *= int(x)
            self.assertEqual(n, max_age, name)


if __name__ == "__main__":
    unittest.main()
