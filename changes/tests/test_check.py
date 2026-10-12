import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import check  # noqa: E402
import frontmatter  # noqa: E402
import render  # noqa: E402

# A frozen copy of the first record as it stood when scheduled. The live
# record moves through its statuses; the tests must not move with it.
FIX = ROOT / "tests" / "fixtures"
GOOD = FIX / "CR-2026-0001-qdevice-debian-13.md"
TSV = ("asset\tcomponent\tkind\tversion\tmilestone\tdate\tbasis\teol_ref\tsource\tnote\n"
       "qdevice\tDebian\tos\t12\tsecurity_support_end\t2026-07-11\tvendor\tdebian/12\thttp://x\t\n")


def variant(text, **changes):
    """Rewrite front matter scalars of a record text."""
    meta_lines, rest = text.split("\n---\n", 1)
    out = []
    for line in meta_lines.splitlines():
        k = line.split(":", 1)[0]
        if k in changes:
            if changes[k] is None:
                continue
            line = f"{k}: {changes[k]}"
            changes.pop(k)
        out.append(line)
    for k, v in changes.items():
        if v is not None:
            out.append(f"{k}: {v}")
    return "\n".join(out) + "\n---\n" + rest


class FrontMatter(unittest.TestCase):
    def test_parse_scalars_and_lists(self):
        meta, body, _ = frontmatter.parse("---\nid: X\nassets:\n  - a/b\n  - c/d\ntags: x, y\n---\n## 目的\nhi\n")
        self.assertEqual(meta["id"], "X")
        self.assertEqual(meta["assets"], ["a/b", "c/d"])
        self.assertEqual(meta["tags"], "x, y")
        self.assertEqual(frontmatter.sections(body), {"目的": "hi"})

    def test_rejects_junk(self):
        with self.assertRaises(frontmatter.FrontMatterError):
            frontmatter.parse("id: X\n---\n")
        with self.assertRaises(frontmatter.FrontMatterError):
            frontmatter.parse("---\nid: X\nnot a pair\n---\n")
        with self.assertRaises(frontmatter.FrontMatterError):
            frontmatter.parse("---\nid: X\n")


class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.text = GOOD.read_text(encoding="utf-8")
        self.tsv = os.path.join(self.tmp, "assets.tsv")
        Path(self.tsv).write_text(TSV, encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, name, text):
        p = os.path.join(self.tmp, name)
        Path(p).write_text(text, encoding="utf-8")
        return p

    def errs(self, name, text, assets=None):
        p = self.write(name, text)
        e, _ = check.check_file(p, check.load_assets(assets) if assets else None)
        return e

    def test_the_first_record_passes_with_assets(self):
        self.assertEqual(check.check_file(str(GOOD), check.load_assets(self.tsv))[0], [])

    def test_file_name_and_id(self):
        e = self.errs("CR-2026-0002-x.md", self.text)
        self.assertTrue(any("file name says CR-2026-0002, id says CR-2026-0001" in x for x in e))
        e = self.errs("cr-2026-0001-X.md", self.text)
        self.assertTrue(any("file name must be" in x for x in e))

    def test_same_person_needs_an_exception(self):
        t = variant(self.text, approval_exception=None)
        e = self.errs("CR-2026-0001-x.md", t)
        self.assertTrue(any("approver equals implementer" in x for x in e), e)
        t = variant(self.text, approval_exception=None, approver="helena")
        self.assertEqual(self.errs("CR-2026-0001-x.md", t), [])
        # a draft needs no approver at all
        t = variant(self.text, approval_exception=None, approver="", status="draft", window_start="", window_end="")
        self.assertEqual(self.errs("CR-2026-0001-x.md", t), [])

    def test_window_rules(self):
        t = variant(self.text, window_end="2026-10-11T21:00:00+08:00")
        self.assertTrue(any("window_end is not after" in x for x in self.errs("CR-2026-0001-x.md", t)))
        t = variant(self.text, window_start="2026-10-11 22:00")           # no offset
        self.assertTrue(any("RFC 3339 with an offset" in x for x in self.errs("CR-2026-0001-x.md", t)))
        t = variant(self.text, status="approved", window_start="", window_end="")   # approved needs no window yet
        self.assertEqual(self.errs("CR-2026-0001-x.md", t), [])

    def test_enums_and_assets(self):
        t = variant(self.text, status="pending", risk="meh", type="urgent")
        e = self.errs("CR-2026-0001-x.md", t)
        self.assertEqual(sum(1 for x in e if "status" in x or "risk" in x or "type" in x), 3, e)
        e = self.errs("CR-2026-0001-x.md", self.text.replace("  - qdevice/Debian", "  - qdevice/Ubuntu"), assets=self.tsv)
        self.assertTrue(any("not a row in the assets TSV" in x for x in e))
        e = self.errs("CR-2026-0001-x.md", self.text.replace("  - qdevice/Debian", "  - qdevice"))
        self.assertTrue(any("not asset/component" in x for x in e))

    def test_sections_and_rollback(self):
        t = self.text.replace("## 回退", "## 退回")
        e = self.errs("CR-2026-0001-x.md", t)
        self.assertTrue(any("section ## 回退 missing" in x for x in e))
        head, _, tail = self.text.partition("## 回退")
        body = tail.split("## 紀錄", 1)[1]
        t = head + "## 回退\n\n無，就地升級沒有回頭路\n\n## 紀錄" + body
        e = self.errs("CR-2026-0001-x.md", t)
        self.assertTrue(any("risk: high" in x for x in e), e)
        self.assertEqual(self.errs("CR-2026-0001-x.md", variant(t, risk="high")), [])

    def test_done_needs_the_record_filled(self):
        t = variant(self.text, status="done")
        e = self.errs("CR-2026-0001-x.md", t)
        self.assertEqual(sorted(x.split("'")[1] for x in e if "needs '" in x), ["- begin: ...", "- end: ...", "- result: ..."])
        t = t.replace("- begin: \n- end: \n- result: ", "- begin: 2026-10-11T22:03:00+08:00\n- end: 2026-10-11T22:41:00+08:00\n- result: ok, 13.1")
        self.assertEqual(self.errs("CR-2026-0001-x.md", t), [])

    def test_template_is_not_a_record(self):
        e = self.errs("CR-2026-0009-t.md", (ROOT / "changes" / "TEMPLATE.md").read_text(encoding="utf-8"))
        self.assertTrue(any("template placeholder" in x for x in e))

    def test_cli_duplicate_ids(self):
        d = os.path.join(self.tmp, "changes")
        os.makedirs(d)
        Path(d, "CR-2026-0001-a.md").write_text(self.text, encoding="utf-8")
        Path(d, "CR-2026-0001-b.md").write_text(self.text, encoding="utf-8")
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "check.py"), "--dir", d], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("already used by", r.stdout)


class Textfile(unittest.TestCase):
    def test_metrics(self):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "changes-textfile.py"), "--dir", str(FIX)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('change_record{id="CR-2026-0001",status="scheduled"', r.stdout)
        self.assertIn('change_records{status="cancelled"} 0', r.stdout)
        self.assertIn('change_window_start_timestamp{id="CR-2026-0001",status="scheduled"} 1791727200', r.stdout)
        # without a drills file: the families are declared, no rows
        self.assertIn("# TYPE change_rollback_last_drill_timestamp gauge", r.stdout)
        self.assertNotIn("change_rollback_last_drill_timestamp{", r.stdout)
        if shutil.which("promtool"):
            p = subprocess.run(["promtool", "check", "metrics"], input=r.stdout, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_rollback_drills(self):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "changes-textfile.py"), "--dir", str(FIX),
                            "--drills", str(FIX / "drills.jsonl")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        # the latest of two drills wins (OK at 06:20Z), both are counted
        self.assertIn('change_rollback_last_drill_timestamp{id="CR-2026-0001"} 1791786000', r.stdout)
        self.assertIn('change_rollback_last_drill_result{id="CR-2026-0001"} 1', r.stdout)
        self.assertIn('change_rollback_drills_total{id="CR-2026-0001"} 2', r.stdout)
        # a drill of a record that is not in changes/ is not exposed, junk lines are skipped
        self.assertNotIn("CR-2026-0099", r.stdout)
        if shutil.which("promtool"):
            p = subprocess.run(["promtool", "check", "metrics"], input=r.stdout, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()


class Index(unittest.TestCase):
    def test_rollback_drill_column(self):
        d = render.drills(str(FIX / "drills.jsonl"))
        self.assertEqual(set(d), {"CR-2026-0001", "CR-2026-0099"})
        self.assertEqual(d["CR-2026-0001"][1:], ("OK", "CR-2026-0011"))      # the later of the two drills
        rows = [{"id": "CR-2026-0001", "_file": "x.md", "title": "t", "status": "done", "risk": "medium",
                 "assets": ["a/b"], "window_start": "2026-10-10T22:45:00+08:00", "window_end": "2026-10-10T23:45:00+08:00",
                 "approver": "x"},
                {"id": "CR-2026-0002", "_file": "y.md", "title": "t", "status": "done", "risk": "low", "approver": "x"}]
        t = render.table(rows, "en", d)
        self.assertIn("| Rollback drill |", t)
        self.assertIn("| 2026-10-12 OK ([CR-2026-0011](drills/drills.md)) |", t)
        self.assertIn("| - | x | - |", t)        # no window, no drill
        self.assertEqual(render.drills(str(FIX / "nope.jsonl")), {})
