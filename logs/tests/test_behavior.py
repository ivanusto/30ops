"""Unit tests of the behaviour pipeline pieces: pseudonyms, the chain, the
metrics, the summary features, the loaders. python3 -m unittest tests/test_behavior.py (from logs/)."""
import importlib.util, json, os, random, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    p = os.path.join(HERE, "..", "behavior", name + ".py")
    spec = importlib.util.spec_from_file_location("behavior_" + name, p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


pseudonymize = load("pseudonymize")
detect = load("detect")
evaluate = load("evaluate")
summarize = load("summarize")
events = load("events")
KEY = b"0123456789abcdef0123456789abcdef"


class Pseudonyms(unittest.TestCase):
    def test_deterministic_and_keyed(self):
        a, b, c = (pseudonymize.Pseudonymizer(k, "standard") for k in (KEY, KEY, KEY[::-1]))
        self.assertEqual(a.name("user", "alice", "u"), b.name("user", "alice", "u"))
        self.assertNotEqual(a.name("user", "alice", "u"), c.name("user", "alice", "u"))
        self.assertNotEqual(a.name("user", "alice", "u"), a.name("host", "alice", "u"))

    def test_ip_prefix_preserving(self):
        p = pseudonymize.Pseudonymizer(KEY, "standard")
        x, y, z = p.ip("192.0.2.10"), p.ip("192.0.2.11"), p.ip("198.51.100.10")
        self.assertEqual(x.split(".")[:3], y.split(".")[:3])
        self.assertNotEqual(x, y)
        self.assertNotEqual(x.split(".")[:2], z.split(".")[:2])
        self.assertEqual(x.split(".")[0], p.ip("192.0.3.1").split(".")[0])

    def test_domain_path_file_bytes(self):
        s = pseudonymize.Pseudonymizer(KEY, "standard")
        self.assertEqual(s.domain("a.b.drive.example.net", "cloud_storage"), "example.net")
        self.assertEqual(s.domain("www.shop.example.com.tw", ""), "example.com.tw")
        self.assertEqual(s.path("hr/payroll/2026-09.xlsx", "s-1"), "hr/payroll/*.xlsx")
        self.assertEqual(s.filename("secret plan.docx"), "*.docx")
        self.assertEqual(s.bytes_(123456), 123456)
        t = pseudonymize.Pseudonymizer(KEY, "strict")
        self.assertEqual(t.domain("drive.example.net", "cloud_storage"), "[cloud_storage]")
        self.assertEqual(t.path("hr/payroll/2026-09.xlsx", "s-1"), "s-1")
        self.assertEqual(t.filename("x.pdf"), "")
        self.assertEqual(t.bytes_(123456), 120000)
        self.assertEqual(t.when("2026-09-30T15:33:10Z"), "2026-09-30T15:00:00Z")
        self.assertEqual(s.when("2026-09-30T15:33:10Z"), "2026-09-30T15:33:00Z")

    def test_event_allowlist(self):
        p = pseudonymize.Pseudonymizer(KEY, "minimal")
        e = p.event({"ts": "2026-09-30T15:33:10Z", "kind": "file.access", "user": "bob", "src_host": "ws-1", "source": "x",
                     "share": "hr", "path": "hr/a/b.txt", "action": "read", "bytes": 5, "note": "real name here", "subject": "x"})
        self.assertNotIn("note", e); self.assertNotIn("subject", e)
        self.assertTrue(e["user"].startswith("u-")); self.assertTrue(e["share"].startswith("s-"))
        self.assertEqual(p.dropped_keys, 2)


class Chain(unittest.TestCase):
    def test_verify_and_tamper(self):
        last = None
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "det.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                for i in range(5):
                    last = detect.chained({"user": f"u{i}", "final": {"verdict": "NORMAL", "risk": i}}, last)
                    f.write(detect.canonical(last) + "\n")
            self.assertTrue(detect.verify(path)[0])
            with open(path, encoding="utf-8") as f:
                lines = f.read().splitlines()
            lines[2] = lines[2].replace('"risk":2', '"risk":99')
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            ok, msg = detect.verify(path)
            self.assertFalse(ok); self.assertIn("line 3", msg)
            del lines[1]
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            self.assertFalse(detect.verify(path)[0])

    def test_rules_backend(self):
        class A: t1, t2 = 6.0, 9.0
        r = detect.Rules(A)
        s1 = r.stage1({"prescreen": 7, "guess": "S3"})
        self.assertTrue(s1["flag"]); self.assertEqual(s1["category"], "S3")
        self.assertEqual(r.stage2({"prescreen": 7, "guess": "S3"}, s1)["verdict"], "NORMAL")
        self.assertEqual(r.stage2({"prescreen": 12, "guess": "S3"}, s1)["verdict"], "THREAT")
        self.assertFalse(r.stage1({"prescreen": 2, "guess": "S1"})["flag"])

    def test_parse_json(self):
        self.assertEqual(detect.parse_json('noise {"flag": true, "category": "s2"} tail')["category"], "s2")
        self.assertEqual(detect.norm_cat("s2"), "S2"); self.assertEqual(detect.norm_cat("S9"), "NONE")


class Metrics(unittest.TestCase):
    def rows(self):
        return ([{"pos": True, "pred": True}] * 8 + [{"pos": True, "pred": False}] * 2 +
                [{"pos": False, "pred": True}] * 1 + [{"pos": False, "pred": False}] * 89)

    def test_counts(self):
        c = evaluate.counts(self.rows())
        self.assertEqual((c["tp"], c["fp"], c["fn"], c["tn"]), (8, 1, 2, 89))
        self.assertAlmostEqual(c["precision"], 8 / 9); self.assertAlmostEqual(c["recall"], 0.8)
        self.assertAlmostEqual(c["fpr"], 1 / 90)
        self.assertAlmostEqual(c["f1"], 2 * (8 / 9) * 0.8 / ((8 / 9) + 0.8))

    def test_bootstrap(self):
        ci = evaluate.bootstrap(self.rows(), 300, 1)
        for k in ("precision", "recall", "f1", "fpr"):
            lo, hi = ci[k]
            self.assertTrue(0 <= lo <= hi <= 1, (k, lo, hi))
        self.assertEqual(evaluate.bootstrap(self.rows(), 300, 1), ci)   # seeded
        self.assertLess(ci["f1"][0], 0.85); self.assertGreater(ci["f1"][1], 0.85)


class Features(unittest.TestCase):
    def test_burst_and_fail_then_success(self):
        D = summarize.Day()
        D.read_times = [1000 + i * 10 for i in range(50)] + [100000, 100001]
        D.logons = [(5, False), (6, False), (7, False), (8, True)]
        D.port_by_dst = {"h": set(range(30)), "g": {1}}
        D.finish()
        self.assertEqual(D.f["f_burst30"], 50); self.assertEqual(D.f["a_fail_then_success"], 1); self.assertEqual(D.f["n_scan_ports"], 30)
        E = summarize.Day(); E.logons = [(1, False), (2, True)]; E.finish()
        self.assertEqual(E.f["a_fail_then_success"], 0)

    def test_bucket_and_baseline(self):
        tz = summarize.parse_tz("+08:00")
        ev = []
        for day in range(1, 8):
            for i in range(10):
                ev.append({"ts": f"2026-09-{day:02d}T0{i}:00:00Z", "kind": "file.access", "user": "u1", "src_host": "h1", "share": "s1", "path": "a/b.txt", "action": "read", "bytes": 1, "role": "rd"})
        ev.append({"ts": "2026-09-08T03:00:00Z", "kind": "file.access", "user": "u1", "src_host": "h1", "share": "s9", "path": "a/b.txt", "action": "read", "bytes": 1})
        ev.append({"ts": "2026-09-08T03:00:00Z", "kind": "net.conn", "user": "", "src_host": "h1", "dst": "203.0.113.5", "dst_name": "x.example.net", "category": "cloud_storage", "bytes_out": 5_000_000_000, "dst_port": 443})
        ev.append({"ts": "2026-09-01T00:00:00Z", "kind": "auth.logon", "user": "u1", "src_host": "h1", "dst": "dc", "result": "success", "logon_type": 2})
        days, roles, dates = summarize.bucket(ev, tz)
        self.assertEqual(roles["u1"], "rd")
        import datetime as dt
        last = days[("u1", dt.date(2026, 9, 8))]
        self.assertEqual(last.f["n_personal_bytes"], 5_000_000_000)     # attributed through the logon host
        bl = summarize.build_baselines(days, roles, set(dates[:-1]), 3)
        src, b = bl["u1"]
        self.assertEqual(src, "self")
        self.assertIn("s9", last.sets["shares"] - b.sets["shares"])
        feat = dict({k: last.f[k] for k in summarize.COUNTS}, new_shares=1, new_domains=1, new_dst_int=0, new_logon_hosts=0, new_logon_dsts=0)
        z = {k: b.z(k, feat[k]) for k in summarize.COUNTS}
        pts, guess, signals = summarize.score(feat, z)
        self.assertGreaterEqual(pts, 7); self.assertEqual(guess, "S1"); self.assertTrue(any("S1" in x for x in signals))
        self.assertTrue(summarize.off_hours(dt.datetime(2026, 9, 5, 12, tzinfo=tz)))      # a Saturday
        self.assertFalse(summarize.off_hours(dt.datetime(2026, 9, 7, 12, tzinfo=tz)))


class Loaders(unittest.TestCase):
    def test_logfmt_and_fortigate(self):
        d = events.logfmt('type="traffic" srcip=192.0.2.1 user="a b" sentbyte=5 msg="x=1 y=2"')
        self.assertEqual(d["user"], "a b"); self.assertEqual(d["msg"], "x=1 y=2"); self.assertEqual(d["sentbyte"], "5")
        line = 'date=2026-09-30 time=23:33:10 tz="+0800" type="traffic" subtype="forward" srcip=192.0.2.21 user="sa" dstip=203.0.113.31 dstport=443 proto=6 action="accept" sentbyte=10 rcvdbyte=1 catdesc="Web-based Email" hostname="m.example.net"'
        e = list(events.from_fortigate_lines([line]))[0]
        self.assertEqual(e["ts"], "2026-09-30T15:33:10Z"); self.assertEqual(e["kind"], "net.conn"); self.assertEqual(e["proto"], "tcp")
        self.assertTrue(events.valid(e))

    def test_zeek_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "conn.log")
            with open(p, "w") as f:
                f.write(json.dumps({"ts": 1759000000.5, "id.orig_h": "192.0.2.21", "id.orig_p": 1, "id.resp_h": "198.51.100.11", "id.resp_p": 445,
                                    "proto": "tcp", "service": "smb", "duration": 3.2, "orig_bytes": 100, "resp_bytes": 50}) + "\n")
            e = list(events.from_zeek(p))[0]
            self.assertEqual(e["dst_port"], 445); self.assertEqual(e["duration_s"], 3); self.assertEqual(e["ts"], "2025-09-27T19:06:40Z")

    def test_winsec(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sec.jsonl")
            with open(p, "w") as f:
                f.write(json.dumps({"EventID": 4625, "TimeCreated": "2026-09-30T23:33:10+08:00", "Computer": "dc-01",
                                           "EventData": {"TargetUserName": "sa", "WorkstationName": "ws-7", "IpAddress": "192.0.2.7", "LogonType": "10"}}) + "\n")
            e = list(events.from_winsec(p))[0]
            self.assertEqual((e["kind"], e["result"], e["logon_type"], e["src_host"]), ("auth.logon", "failure", 10, "ws-7"))


if __name__ == "__main__":
    unittest.main()
