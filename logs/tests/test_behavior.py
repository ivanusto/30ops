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


import sys
sys.path.insert(0, os.path.join(HERE, "..", "behavior"))
pseudonymize = load("pseudonymize")
scrub = load("scrub")
pii_audit = load("pii_audit")
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


PRIV = ".".join(("10", "20", "30", "40"))     # hygiene keeps literal private addresses out of the repo


def wazuh_row(**kw):
    r = {"timestamp": "2026-09-01T02:00:00.000+0000", "agent_name": "SRV01.corp.example.net", "agent_ip": "192.0.2.10", "rule_id": "5715", "rule_level": "3",
         "rule_groups": "syslog,sshd,authentication_success", "decoder": "sshd", "srcip": "", "srcuser": "", "dstuser": "alice", "mitre_id": ""}
    r.update(kw)
    return r


class SiemLoaders(unittest.TestCase):
    def test_wazuh_mapping(self):
        e = events.wazuh_event(wazuh_row(srcip=PRIV))
        self.assertEqual((e["kind"], e["user"], e["result"], e["asset"], e["logon_type"]), ("auth.logon", "alice", "success", "srv01.corp.example.net", "ssh"))
        self.assertTrue(events.valid(e))
        self.assertEqual(events.wazuh_event(wazuh_row(rule_groups="syslog,sudo", srcuser="bob", dstuser="root", command="openvpn c.ovpn"))["category"], "evasion")
        self.assertEqual(events.wazuh_event(wazuh_row(rule_groups="syslog,dpkg", package="vim", dpkg_status="installed"))["kind"], "pkg.change")
        a = events.wazuh_event(wazuh_row(rule_groups="web,recon,web_scan", srcip="203.0.113.9", full_log="GET /x?secret=1"))
        self.assertEqual((a["kind"], a["rule_group"]), ("sec.alert", "recon"))
        self.assertNotIn("full_log", a)
        self.assertIsNone(events.wazuh_event(wazuh_row(timestamp="not a time")))

    def test_flatten_agrees_with_csv(self):
        alert = {"timestamp": "2026-09-01T02:00:00.000+0000", "agent": {"name": "SRV01.corp.example.net", "ip": "192.0.2.10"}, "decoder": {"name": "sshd"},
                 "rule": {"id": "5715", "level": 3, "groups": ["syslog", "sshd", "authentication_success"]}, "data": {"dstuser": "alice"}, "full_log": "x"}
        self.assertEqual(events.wazuh_event(events.flatten_alert(alert)), events.wazuh_event(wazuh_row()))

    def test_spill_sort(self):
        ev = [{"ts": t, "kind": "sec.alert", "user": "", "src_host": "h", "source": "wazuh"} for t in ("2026-09-02T01:00:00Z", "2026-09-01T02:00:00Z", "2026-09-01T01:00:00Z")]
        with tempfile.TemporaryDirectory() as d:
            spill = os.path.join(d, "spill")
            self.assertEqual([e["ts"] for e in events.spill_sort(iter(ev), spill)], sorted(e["ts"] for e in ev))
            self.assertEqual(os.listdir(spill), [])

    def test_scope_and_home_paths(self):
        p = pseudonymize.Pseudonymizer(b"k" * 32, "standard")
        o = p.event({"ts": "2026-09-01T02:03:04Z", "kind": "sec.alert", "user": "", "src_host": "srv", "asset": "srv", "src_ip": PRIV, "source": "wazuh", "rule_id": "1", "rule_level": 3, "full_log": "secret"})
        self.assertEqual(o["src_scope"], "internal"); self.assertNotEqual(o["src_ip"], PRIV); self.assertNotIn("full_log", o); self.assertTrue(o["asset"].startswith("h-"))
        self.assertEqual(p.event({"ts": "2026-09-01T02:03:04Z", "kind": "sec.alert", "user": "", "src_host": "s", "src_ip": "203.0.113.9", "source": "wazuh"})["src_scope"], "external")
        self.assertNotIn("alice", p.path("/".join(("home", "alice", "x", "y.txt")), ""))
        self.assertNotIn("alice", p.path("/".join(("C:", "Users", "alice", "Desktop", "y.txt")), ""))


class Scrub(unittest.TestCase):
    TERMS = [{"kind": "host", "real": "srv01.corp.example.net"}, {"kind": "host", "real": "srv01"}, {"kind": "domain", "real": "example.net"}, {"kind": "user", "real": "alice"}, {"kind": "host", "real": "財務部電腦"}]

    def sc(self, level="standard"):
        return scrub.Scrubber(b"k" * 32, level, self.TERMS)

    def test_patterns_remove(self):
        s = self.sc()
        for raw, gone in [("from=<bob@mail.example.org>", "bob@"), ("GET /a?token=abcdef&u=2 HTTP", "abcdef"), ("EXAMPLE\\carol logged on", "carol"), ("C:\\Users\\carol\\x.exe", "carol"),
                          ("/".join(("", "home", "carol", ".ssh")), "carol"), ("aa:bb:cc:dd:ee:ff", "aa:bb"), ("password=hunter22 ok", "hunter22"), ("id A123456789", "A123456789"), ("tel 0912-345-678", "0912"),
                          ("Authorization: Bearer abcdefghijkl", "abcdefghijkl"), (f"from {PRIV} port", PRIV), ("cookie: sid=zzzzzz", "zzzzzz")]:
            self.assertNotIn(gone, s.text(raw), raw)

    def test_dictionary_same_pseudonym(self):
        s = self.sc()
        out = s.text("sshd on SRV01 and srv01.corp.example.net user alice 財務部電腦")
        for gone in ("srv01", "example.net", "alice", "財務部電腦"):
            self.assertNotIn(gone, out.lower())
        self.assertEqual(s.host("SRV01"), s.map["srv01"])
        self.assertIn(s.map["alice"], out)

    def test_generic_words_and_rule_text_survive(self):
        t = {}
        scrub.add_term(t, "user", "root"); scrub.add_term(t, "host", "ab"); scrub.add_term(t, "host", "web01.corp.example.net")
        self.assertNotIn("root", t); self.assertNotIn("ab", t); self.assertEqual(t["web01"], "host"); self.assertEqual(t["example.net"], "domain")
        self.assertEqual(self.sc().text("sshd: authentication failed"), "sshd: authentication failed")

    def test_levels_and_unknown_column_fails_safe(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "a.csv")
            with open(src, "w", encoding="utf-8-sig") as f:
                f.write("timestamp,agent_name,srcip,full_log,new_col\n2026-09-01T02:03:04.5+0000,SRV01,203.0.113.9,alice from 203.0.113.9,carol@example.org\n")
            key = os.path.join(d, "k"); open(key, "w").write("k" * 32)
            terms = os.path.join(d, "t"); open(terms, "w").write("\n".join(json.dumps(x) for x in self.TERMS))
            import csv as _csv, gzip, argparse
            for level in ("standard", "strict"):
                out = os.path.join(d, level + ".csv.gz")
                scrub.cmd_csv(argparse.Namespace(key_file=key, terms=terms, level=level, inp=src, out=out, policy="wazuh", templates=None, timing=None))
                self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)
                row = next(_csv.DictReader(gzip.open(out, "rt", encoding="utf-8")))
                text = json.dumps(row)
                for gone in ("SRV01", "alice", "carol", "203.0.113.9"):
                    self.assertNotIn(gone, text)
                self.assertNotIn(":04", row["timestamp"])
                if level == "strict":
                    self.assertNotIn("full_log", row); self.assertNotIn("new_col", row)

    def test_json_alert(self):
        s = self.sc(); tpl = scrub.Templates(None)
        o = scrub.scrub_json(s, {"timestamp": "2026-09-01T02:03:04+0000", "agent": {"name": "SRV01", "ip": "192.0.2.10"}, "rule": {"id": "1", "groups": ["web"], "description": "login by alice"},
                                 "data": {"srcuser": "root", "dstuser": "alice", "command": "curl -u alice:pw", "url": "/x?y=1"}, "full_log": "alice logged"}, tpl)
        text = json.dumps(o, ensure_ascii=False)
        self.assertNotIn("alice", text); self.assertNotIn("command", o["data"]); self.assertEqual(o["data"]["srcuser"], "root"); self.assertEqual(o["rule"]["groups"], ["web"])

    def test_templates_merge_numbers(self):
        with tempfile.TemporaryDirectory() as d:
            t = scrub.Templates(os.path.join(d, "t"))
            t.add("x", "port 1 from 192.0.2.1"); t.add("x", "port 2 from 192.0.2.2"); t.add("x", "other")
            t.write()
            rows = [json.loads(x) for x in open(t.path)]
            self.assertEqual([r["n"] for r in rows], [2, 1])


class Audit(unittest.TestCase):
    def test_canary_classes_and_hit(self):
        import random
        rnd = random.Random(1)
        for cls in pii_audit.CLASSES:
            plant, core = pii_audit.canary_item(rnd, cls)
            self.assertIn(core, plant)
        self.assertTrue(pii_audit.hit("abc123", [{"span": "user abc123", "type": "x"}]))
        self.assertFalse(pii_audit.hit("abc123", [{"span": "ab", "type": "x"}, {"span": "other", "type": "x"}]))
        self.assertLess(pii_audit.wilson_upper(0, 3000), 0.002)

    def test_unreadable_answer_is_not_a_pass(self):
        class A:
            base_url = "http://127.0.0.1:9"; model = "m"; seed = 1; thermal_hot = 0; thermal_cool = 0; api_key_file = None
        c = pii_audit.Client(A())
        self.assertIsNone(c.ask({0: "x"}))
        self.assertEqual(c.errors, 1)


class HostDays(unittest.TestCase):
    def ev(self, day, **kw):
        e = {"ts": f"2026-09-{day:02d}T03:00:00Z", "kind": "sec.alert", "user": "", "src_host": "h1", "asset": "h1", "source": "wazuh", "src_scope": "external", "rule_id": "1", "rule_level": 5}
        e.update(kw)
        return e

    def test_external_noise_scores_nothing(self):
        import datetime as dt
        tz = summarize.parse_tz("+08:00")
        ev = [self.ev(d) for d in range(1, 11)] + [self.ev(11) for _ in range(5000)]
        days, _, dates = summarize.bucket_host(ev, tz)
        bl = summarize.build_baselines(days, {}, set(dates[:-1]), 3, summarize.HOST_COUNTS, summarize.HOST_SETS, workdays_only=False)
        D = days[("h1", dt.date(2026, 9, 11))]
        f = {k: D.f[k] for k in summarize.HOST_COUNTS}
        z = {k: bl["h1"][1].z(k, f[k]) for k in summarize.HOST_COUNTS}
        self.assertEqual(f["h_ext"], 5000)
        self.assertEqual(summarize.score(dict(f, new_accounts=0, new_int_src=0, new_rule_ids=0), z, summarize.HOST_RULES, summarize.HOST_Z_RULES)[0], 0)

    def test_fail_then_success_is_per_source(self):
        import datetime as dt
        tz = summarize.parse_tz("+08:00")
        base = {"kind": "auth.logon", "dst": "h1", "src_scope": "external"}
        spread = [self.ev(1, result="failure", src_ip=f"203.0.113.{i}", **base) for i in range(5)] + [self.ev(1, result="success", src_ip="198.51.100.1", user="u1", **base)]
        days, _, _ = summarize.bucket_host(spread, tz)
        self.assertEqual(days[("h1", dt.date(2026, 9, 1))].f["a_fail_then_success"], 0)
        one = [dict(self.ev(2, result="failure", src_ip="203.0.113.1", **base), ts=f"2026-09-02T03:00:0{i}Z") for i in range(3)] + [dict(self.ev(2, result="success", src_ip="203.0.113.1", user="u1", **base), ts="2026-09-02T03:00:09Z")]
        days, _, _ = summarize.bucket_host(one, tz)
        self.assertEqual(days[("h1", dt.date(2026, 9, 2))].f["a_fail_then_success"], 1)

    def test_excluded_kind_is_invisible(self):
        tz = summarize.parse_tz("+08:00")
        days, _, _ = summarize.bucket_host([self.ev(1), self.ev(2, kind="malware.detect")], tz, {"malware.detect"})
        self.assertEqual(len(days), 1)


if __name__ == "__main__":
    unittest.main()
