"""gb10-textfile.py on a fake DGX Spark (sysfs zones, nvidia-smi, meminfo, dmesg)."""
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gb10_textfile", HERE / "textfile" / "gb10-textfile.py")
gb10 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gb10)
PROMTOOL = shutil.which("promtool")


def promtool_ok(text):
    """promtool check metrics reads the exposition format from stdin."""
    if not PROMTOOL:
        return True, "promtool not installed, skipped"
    r = subprocess.run([PROMTOOL, "check", "metrics"], input=text, capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr


class FakeBox:
    """A fake DGX Spark: sysfs zones, nvidia-smi, meminfo, dmesg."""

    def __init__(self, tmp, zones=(70, 85), gpu="78, 55.2, 91", nv_errs=0):
        self.tmp = tmp
        self.sysfs = os.path.join(tmp, "thermal")
        for i, z in enumerate(zones):
            d = os.path.join(self.sysfs, f"thermal_zone{i}")
            os.makedirs(d)
            with open(os.path.join(d, "temp"), "w") as fh:
                fh.write(f"{z * 1000}\n")
        self.meminfo = os.path.join(tmp, "meminfo")
        with open(self.meminfo, "w") as fh:
            fh.write("MemTotal:       131072000 kB\nMemAvailable:    8388608 kB\n")
        self.smi = os.path.join(tmp, "nvidia-smi")
        with open(self.smi, "w") as fh:
            fh.write(f"#!/bin/sh\necho '{gpu}'\n")
        os.chmod(self.smi, 0o755)
        self.dmesg = os.path.join(tmp, "dmesg")
        with open(self.dmesg, "w") as fh:
            fh.write("#!/bin/sh\n")
            for _ in range(nv_errs):
                fh.write("echo '[123.4] NVRM: NV_ERR_NO_MEMORY'\n")
            fh.write("echo '[124.0] ok'\n")
        os.chmod(self.dmesg, 0o755)

    def set_zone(self, i, c):
        with open(os.path.join(self.sysfs, f"thermal_zone{i}", "temp"), "w") as fh:
            fh.write(f"{c * 1000}\n")

    def collect(self, now, state, **kw):
        return gb10.collect(now, state, sysfs=self.sysfs, nvidia_smi=self.smi,
                            meminfo=self.meminfo, dmesg=self.dmesg,
                            hot_flag=os.path.join(self.tmp, "HOT"), **kw)


class Gb10(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.box = FakeBox(self.tmp, nv_errs=3)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_values(self):
        text, state = self.box.collect(1000.0, {})
        self.assertIn("gb10_zone_temp_celsius 85", text)
        self.assertIn("gb10_gpu_temp_celsius 78.0", text)
        self.assertIn("gb10_gpu_power_watts 55.2", text)
        self.assertIn("gb10_mem_available_bytes 8589934592", text)
        self.assertIn("gb10_nv_err_no_memory_total 3", text)
        self.assertIn("gb10_soak_seconds 0", text)
        self.assertIn("gb10_hot 0", text)
        self.assertIn("gb10_textfile_errors 0", text)
        self.assertIsNone(state["hot_since"])
        ok, msg = promtool_ok(text)
        self.assertTrue(ok, msg)

    def test_soak_accumulates_and_resets(self):
        self.box.set_zone(1, 89)
        _, s = self.box.collect(1000.0, {})
        self.assertEqual(s["hot_since"], 1000.0)
        for t in (1050.0, 1100.0, 1150.0, 1200.0, 1250.0):
            text, s = self.box.collect(t, s)
        self.assertIn("gb10_soak_seconds 250", text)
        self.box.set_zone(1, 80)
        text, s = self.box.collect(1260.0, s)
        self.assertIn("gb10_soak_seconds 0", text)
        self.assertIsNone(s["hot_since"])

    def test_soak_resets_after_gap(self):
        self.box.set_zone(1, 90)
        _, s = self.box.collect(1000.0, {})
        text, s = self.box.collect(1200.0, s, max_gap=60)  # timer was dead for 200 s
        self.assertIn("gb10_soak_seconds 0", text)
        self.assertEqual(s["hot_since"], 1200.0)

    def test_missing_sources_counted_not_fatal(self):
        text, _ = gb10.collect(1.0, {}, sysfs=os.path.join(self.tmp, "nope"), nvidia_smi="/nonexistent",
                               meminfo="/nonexistent", dmesg="/nonexistent", hot_flag="/nonexistent")
        self.assertIn("gb10_textfile_errors 4", text)
        self.assertNotIn("gb10_gpu_temp_celsius", text)
        ok, msg = promtool_ok(text)
        self.assertTrue(ok, msg)

    def test_hot_flag(self):
        open(os.path.join(self.tmp, "HOT"), "w").close()
        text, _ = self.box.collect(1.0, {})
        self.assertIn("gb10_hot 1", text)

    def test_cli_writes_atomically(self):
        out = os.path.join(self.tmp, "x", "gb10.prom")
        st = os.path.join(self.tmp, "x", "state.json")
        rc = gb10.main(["--out", out, "--state", st, "--hot-flag", "/nonexistent"])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(out))
        self.assertTrue(os.path.exists(st))
        self.assertFalse([f for f in os.listdir(os.path.dirname(out)) if f.startswith(".prom.")])
        # node_exporter reads it as another user
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o644)


if __name__ == "__main__":
    unittest.main()
