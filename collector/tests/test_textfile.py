import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / "textfile" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


drills = load("drills-textfile")
PROMTOOL = shutil.which("promtool")


def promtool_ok(text):
    """promtool check metrics reads the exposition format from stdin."""
    if not PROMTOOL:
        return True, "promtool not installed, skipped"
    r = subprocess.run([PROMTOOL, "check", "metrics"], input=text, capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr


class Drills(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, name, recs):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as fh:
            for r in recs:
                fh.write(json.dumps(r) + "\n")
        return p

    def test_three_formats(self):
        # one line of each, copied from the drills.jsonl the three tools wrote
        pve = self.write("pve.jsonl", [
            {"t0": "2026-09-30T15:47:06Z", "label": "d3-full", "vmid": "104", "ip": "192.0.2.49", "restore_point": "2026-09-30T15:34:02Z", "t_exists": 23, "t_running": 557, "t_ping": 568, "t_ssh": 568, "rto_s": 569, "rpo_s": "784", "result": "OK", "host": "spark1"},
            {"t0": "2026-09-30T15:08:44Z", "label": "d1-instant", "vmid": "vs", "restore_point": "2026-09-30T15:05:02Z", "t_exists": None, "t_running": None, "t_ping": 0, "t_ssh": 0, "rto_s": 0, "rpo_s": "", "result": "FAIL", "host": "x"},
        ])
        nas = self.write("nas.jsonl", [
            {"t0": "2026-10-01T14:22:55Z", "label": "3. 從次要 NAS 還原回主 NAS", "path": "/mnt/drill/canary", "kind": "frozen", "restore_point": "2026-10-01T14:14:01Z", "appear": "68", "canary": "99", "manifest": "99", "rto": "-", "rpo": "534", "payload": "ok", "size_mb": 55, "rate_mbs": "-", "result": "FAIL", "code": 4},
            {"t0": "2026-10-01T13:30:25Z", "label": "2. 整個共享資料夾回復到快照", "rto": "1198", "rpo": "1799", "rate_mbs": "17", "result": "OK", "code": 0},
        ])
        cloud = self.write("cloud.jsonl", [
            {"t0": "2026-10-01T23:43:59Z", "label": "2. 還原 Music", "mib": 4808, "seconds": 92, "rate": "52 MiB/s", "rpo": "-", "result": "OK"},
            {"t0": "2026-10-01T17:38:09Z", "label": "2. 還原 Music", "mib": 100, "seconds": 500, "rate": "1 MiB/s", "result": "FAIL"},
        ])
        text = drills.render([("pve", pve), ("nas", nas), ("cloud", cloud)], 1_800_000_000)
        # pve-backup-drill writes rto_s / rpo_s
        self.assertIn('drill_last_rto_seconds{source="pve",label="d3-full"} 569', text)
        self.assertIn('drill_last_rpo_seconds{source="pve",label="d3-full"} 784', text)
        self.assertIn('drill_last_result{source="pve",label="d1-instant"} 0', text)
        self.assertNotIn('drill_last_success_timestamp{source="pve",label="d1-instant"}', text)
        # nas-backup-drill writes "-" for what it could not measure
        self.assertIn('drill_last_result{source="nas",label="3. 從次要 NAS 還原回主 NAS"} 0', text)
        self.assertNotIn('drill_last_rto_seconds{source="nas",label="3. 從次要 NAS 還原回主 NAS"}', text)
        self.assertIn('drill_last_rpo_seconds{source="nas",label="3. 從次要 NAS 還原回主 NAS"} 534', text)
        self.assertIn('drill_last_rate_mib_per_second{source="nas",label="2. 整個共享資料夾回復到快照"} 17', text)
        # cloud: latest record wins, seconds maps to rto, rate parsed from "52 MiB/s"
        self.assertIn('drill_last_rto_seconds{source="cloud",label="2. 還原 Music"} 92', text)
        self.assertIn('drill_last_rate_mib_per_second{source="cloud",label="2. 還原 Music"} 52', text)
        self.assertIn('drill_count_total{source="cloud",label="2. 還原 Music"} 2', text)
        self.assertIn('drill_last_success_timestamp{source="cloud",label="2. 還原 Music"} 1790898239', text)   # 2026-10-01T23:43:59Z
        ok, msg = promtool_ok(text)
        self.assertTrue(ok, msg)

    def test_missing_file_and_bad_lines(self):
        bad = self.write("bad.jsonl", [{"t0": "garbage"}])
        with open(bad, "a") as fh:
            fh.write("not json\n")
        text = drills.render([("x", bad), ("y", os.path.join(self.tmp, "none.jsonl"))], 5)
        self.assertIn("drills_textfile_last_run_timestamp 5", text)
        self.assertNotIn("drill_last_timestamp{", text)

    def test_out_is_world_readable(self):
        out = os.path.join(self.tmp, "d", "drills.prom")
        drills.main(["--out", out, "x=" + os.path.join(self.tmp, "none.jsonl")])
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o644)

    def test_v1_records_and_non_objects(self):
        # v1 (30ops v0.2) next to an old line in the same file; a JSON line that
        # is not an object used to raise AttributeError
        p = self.write("mixed.jsonl", [
            {"t0": "2026-10-01T23:43:59Z", "label": "2. 還原 Music", "mib": 4808, "seconds": 92, "rate": "52 MiB/s", "result": "OK"},
            {"v": 1, "t0": "2026-10-02T00:00:00Z", "kind": "cloud-offload", "label": "2. 還原 Music", "result": "pass",
             "rto_s": 80, "rate_bps": 47.5 * 1048576},
            [1, 2], 7,
        ])
        text = drills.render([("cloud", p)], 5)
        self.assertIn('drill_last_rto_seconds{source="cloud",label="2. 還原 Music"} 80', text)
        self.assertIn('drill_last_rate_mib_per_second{source="cloud",label="2. 還原 Music"} 47.5', text)
        self.assertIn('drill_count_total{source="cloud",label="2. 還原 Music"} 2', text)


if __name__ == "__main__":
    unittest.main()
