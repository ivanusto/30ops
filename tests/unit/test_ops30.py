import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import drills, frontmatter, jsonl, rfc3339, textfile  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "drills"


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)


class FrontMatter(unittest.TestCase):
    def test_scalars_lists_and_body(self):
        meta, body, line = frontmatter.parse("---\nid: CR-2026-0001\nassets:\n  - nas1\n  - pve1\n---\n## 目的\nx\n")
        self.assertEqual(meta, {"id": "CR-2026-0001", "assets": ["nas1", "pve1"]})
        self.assertEqual(line, 7)
        self.assertEqual(frontmatter.sections(body), {"目的": "x"})

    def test_rejects(self):
        for bad in ("no front matter", "---\nid: 1\nid: 2\n---\n", "---\njunk line\n---\n", "---\nid: 1\n"):
            with self.assertRaises(frontmatter.FrontMatterError):
                frontmatter.parse(bad)


class Rfc3339(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(rfc3339.to_epoch("2026-10-13T12:30:00Z"), 1791894600)
        self.assertEqual(rfc3339.to_epoch(" 2026-10-13T20:30:00+08:00 "), 1791894600)
        self.assertEqual(rfc3339.parse("2026-10-13T20:30:00+08:00").utcoffset().total_seconds(), 0)
        for bad in ("2026-10-13T12:30:00", "", "junk", None, 5):
            self.assertIsNone(rfc3339.parse(bad), bad)

    def test_format(self):
        d = rfc3339.parse("2026-10-13T20:30:00+08:00")
        self.assertEqual(rfc3339.format(d), "2026-10-13T12:30:00Z")
        self.assertEqual(rfc3339.from_epoch(1791894600), "2026-10-13T12:30:00Z")


class Textfile(Tmp):
    def test_esc(self):
        self.assertEqual(textfile.esc('a\\b"c\nd'), 'a\\\\b\\"c\\nd')
        self.assertEqual(textfile.esc(5), "5")

    def test_family(self):
        L = []
        textfile.family(L, "x_total", "Things", "counter")
        self.assertEqual(L, ["# HELP x_total Things", "# TYPE x_total counter"])

    def test_write_mode_and_atomic(self):
        p = os.path.join(self.tmp, "sub", "x.prom")
        textfile.write(p, "a 1\n")
        self.assertEqual(Path(p).read_text(), "a 1\n")
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o644)
        self.assertEqual(os.listdir(os.path.dirname(p)), ["x.prom"])

    def test_write_cleans_up(self):
        p = os.path.join(self.tmp, "x.prom")

        class Boom:
            def __str__(self):
                raise RuntimeError("boom")
        with self.assertRaises(TypeError):
            textfile.write(p, Boom())
        self.assertEqual(os.listdir(self.tmp), [])


class Jsonl(Tmp):
    def test_append_read_skip(self):
        p = os.path.join(self.tmp, "d", "x.jsonl")
        jsonl.append(p, {"a": "é"})
        with open(p, "a") as f:
            f.write("\nnot json\n[1]\n5\n")
        jsonl.append(p, {"b": 2})
        self.assertIn('{"a":"é"}', Path(p).read_text(encoding="utf-8"))
        self.assertEqual(jsonl.read(p), ([{"a": "é"}, {"b": 2}], 3))
        self.assertEqual(jsonl.read(os.path.join(self.tmp, "missing")), ([], 0))

    def test_lock_serialises_writers(self):
        p = os.path.join(self.tmp, "x.jsonl")

        def work(n):
            for i in range(50):
                with jsonl.lock(p) as f:
                    recs, _ = jsonl.read(p)
                    jsonl.write_line(f, jsonl.dumps({"seq": len(recs) + 1, "w": n}))
        ts = [threading.Thread(target=work, args=(n,)) for n in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        recs, _ = jsonl.read(p)
        self.assertEqual([r["seq"] for r in recs], list(range(1, 201)))


class Drills(Tmp):
    def test_new_validate_append(self):
        r = drills.new("pve-backup", "d3-full", "2026-09-30T15:47:06Z", "pass", rto_s=569,
                       checks=[{"name": "ssh", "result": "pass"}])
        self.assertEqual(drills.validate(r), [])
        p = os.path.join(self.tmp, "drills.jsonl")
        drills.append(p, r)
        line = Path(p).read_text().strip()
        self.assertEqual(list(json.loads(line)), list(drills.KEYS))
        bad = dict(r, result="OK", rto_s="569", kind="x", cr="CR-1", t0="2026-09-30T15:47:06", junk=1)
        errs = " | ".join(drills.validate(bad))
        for want in ("unknown field junk", "t0 must", "kind must", "result must", "rto_s must", "cr must"):
            self.assertIn(want, errs)
        with self.assertRaises(drills.DrillError):
            drills.append(p, bad)
        self.assertEqual(len(Path(p).read_text().splitlines()), 1)

    def test_every_legacy_fixture_normalises_to_valid_v1(self):
        n = 0
        for f in sorted(FIX.glob("legacy-*.jsonl")):
            hint = f.stem.split("-", 1)[1]
            for guess in (hint, None):
                recs, skipped = drills.load(f, guess)
                self.assertEqual(skipped, 0, f)
                for r in recs:
                    self.assertEqual(drills.validate(r), [], (f.name, guess, r))
                    self.assertEqual(r["kind"], drills.HINTS[hint], (f.name, guess))
                    n += 1
        self.assertGreaterEqual(n, 24)

    def test_legacy_mapping(self):
        pve, _ = drills.load(FIX / "legacy-pve.jsonl", "pve")
        self.assertEqual((pve[1]["rto_s"], pve[1]["rpo_s"], pve[1]["result"]), (569, 784, "pass"))
        self.assertEqual((pve[0]["rpo_s"], pve[0]["extra"]["t_exists"]), (None, None))
        nas, _ = drills.load(FIX / "legacy-nas.jsonl", "nas")
        self.assertEqual((nas[0]["rate_bps"], nas[1]["rto_s"], nas[1]["extra"]["code"]), (17 * 1048576, None, 4))
        cloud, _ = drills.load(FIX / "legacy-cloud.jsonl", "cloud")
        self.assertEqual((cloud[2]["bytes"], cloud[2]["rto_s"], cloud[2]["rate_bps"]), (4808 * 1048576, 92, 52 * 1048576))
        self.assertEqual((cloud[1]["result"], cloud[1]["extra"]["result_raw"]), ("fail", "rclone rc=7"))
        ch, _ = drills.load(FIX / "legacy-changes.jsonl", "changes")
        self.assertEqual((ch[0]["cr"], ch[0]["rollback_of"], ch[0]["extra"]["checks"]), ("CR-2026-0011", "CR-2026-0001", 450))

    def test_v1_passes_through_and_junk_is_skipped(self):
        p = os.path.join(self.tmp, "d.jsonl")
        drills.append(p, drills.new("qdevice", "q", "2026-10-01T00:00:00Z", "partial"))
        with open(p, "a") as f:
            f.write('7\n{"label":"no t0"}\n{"v":1,"t0":"bad"}\n')
        recs, skipped = drills.load(p)
        self.assertEqual((len(recs), skipped, recs[0]["result"]), (1, 3, "partial"))


class Cli(Tmp):
    def run30(self, *args):
        return subprocess.run([str(ROOT / "bin" / "30ops"), *args], capture_output=True, text=True)

    def test_record_and_migrate(self):
        p = os.path.join(self.tmp, "drills.jsonl")
        r = self.run30("drill", "record", "--file", p, "--kind", "nas-backup", "--label", 'say "hi"\nthere',
                       "--t0", "2026-10-01T13:30:25Z", "--result", "pass", "--rto-s", "1198", "--rpo-s", "-",
                       "--rate-bps", "17825792", "--check", "canary=pass:99s", "--check", "manifest=fail",
                       "--extra", "code=0", "--extra", "path=/mnt/x", "--extra", "appear=-")
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = json.loads(Path(p).read_text())
        self.assertEqual(rec["label"], 'say "hi"\nthere')
        self.assertEqual((rec["rto_s"], rec["rpo_s"], rec["rate_bps"]), (1198, None, 17825792.0))
        self.assertEqual(rec["checks"], [{"name": "canary", "result": "pass", "detail": "99s"},
                                         {"name": "manifest", "result": "fail"}])
        self.assertEqual(rec["extra"], {"code": 0, "path": "/mnt/x", "appear": "-"})
        self.assertTrue(rec["tool"].startswith("30ops "))
        self.assertEqual(rec["t1"][-1], "Z")
        bad = self.run30("drill", "record", "--file", p, "--kind", "nas-backup", "--label", "x",
                         "--result", "pass", "--cr", "CR-1")
        self.assertEqual(bad.returncode, 2)
        self.assertIn("cr must", bad.stderr)
        m = self.run30("drill", "migrate", "--hint", "cloud", str(FIX / "legacy-cloud.jsonl"))
        self.assertEqual(m.returncode, 0, m.stderr)
        self.assertEqual(len(m.stdout.splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
