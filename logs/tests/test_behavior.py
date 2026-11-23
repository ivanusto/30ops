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
sys.path.insert(0, os.path.join(HERE, "..", "..", "lib", "python"))
from ops30 import rfc3339  # noqa: E402
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

    def test_siem_logon_keeps_rule_fields(self):
        e = events.wazuh_event(wazuh_row(srcip=PRIV))
        self.assertEqual(e["kind"], "auth.logon")
        self.assertIn("rule_id", e); self.assertIn("rule_level", e)
        for level in ("minimal", "standard", "strict"):
            out = pseudonymize.Pseudonymizer(KEY, level).event(dict(e, not_allowed="x"))
            self.assertEqual((out.get("rule_id"), out.get("rule_level")), (e["rule_id"], e["rule_level"]), level)
            self.assertNotIn("not_allowed", out, level)

    def fgt_alert(self, line, groups=("fortigate", "syslog")):
        return {"timestamp": "2026-11-23T10:00:01.000+0800", "agent": {"name": "SIEM-1"}, "decoder": {"name": "fortigate-firewall-v5"},
                "rule": {"id": "81618", "level": 3, "groups": list(groups)}, "data": {"srcip": "192.0.2.81"}, "full_log": line}

    def test_wazuh_fortigate_activity(self):
        head = 'date=2026-11-23 time=10:00:00 eventtime=1763863200000000000 tz="+0800" srcip=192.0.2.81 dstip=198.51.100.7 '
        e = events.wazuh_alert_event(self.fgt_alert(head + 'type="traffic" subtype="forward" dstport=443 proto=6 service="HTTPS" '
                                                    'sentbyte=1200 rcvdbyte=3400 duration=5 action="close" hostname="example.org"'))
        self.assertEqual((e["kind"], e["bytes_out"], e["dst_name"], e["asset"], e["rule_id"], e["rule_level"], e["source"]),
                         ("net.conn", 1200, "example.org", "siem-1", "81618", 3, "fortigate"))
        self.assertTrue(events.valid(e))
        u = events.wazuh_alert_event(self.fgt_alert(head + 'type="utm" subtype="webfilter" hostname="jobs.example.com" catdesc="Job Search" action="passthrough"'))
        self.assertEqual((u["kind"], u["category"], u["action"], u["asset"]), ("fw.utm", "Job Search", "allow", "siem-1"))
        for o in (pseudonymize.Pseudonymizer(KEY, lv).event(dict(x)) for lv in ("minimal", "standard", "strict") for x in (e, u)):
            self.assertEqual((o["rule_id"], o["rule_level"]), ("81618", 3))
        ips = events.wazuh_alert_event(self.fgt_alert(head + 'type="utm" subtype="ips" attack="x"', groups=("fortigate", "attack")))
        self.assertEqual(ips["kind"], "sec.alert")
        web_attack = events.wazuh_alert_event(self.fgt_alert(head + 'type="utm" subtype="webfilter" hostname="x.example"', groups=("fortigate", "web_scan")))
        self.assertEqual(web_attack["kind"], "sec.alert")
        self.assertEqual(events.wazuh_alert_event(self.fgt_alert(head + 'type="event" subtype="system" action="x"'))["kind"], "sec.alert")
        self.assertEqual(events.wazuh_alert_event(self.fgt_alert(head + 'type="utm" subtype="dns" qname="x.example"'))["kind"], "sec.alert")

    def test_fortigate_alerts_left_to_archives(self):
        head = 'eventtime=1763863200000000000 srcip=192.0.2.81 '
        alerts = [self.fgt_alert(head + 'type="utm" subtype="app-ctrl" app="SSH"'), self.fgt_alert(head + 'type="utm" subtype="ips"', groups=("fortigate", "attack"))]
        import gzip, tarfile
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "logs", "alerts", "2026", "Nov")
            os.makedirs(sub)
            with gzip.open(os.path.join(sub, "ossec-alerts-23.json.gz"), "wt") as f:
                f.write("\n".join(json.dumps(x) for x in alerts) + "\n")
            self.assertEqual([e["kind"] for e in events.from_wazuh_tar(d)], ["fw.utm", "sec.alert"])
            self.assertEqual([e["kind"] for e in events.from_wazuh_tar(d, archives_too=True)], ["sec.alert"])

    def test_fortigate_sessions(self):
        T0 = 1795249800                                          # 2026-11-21T08:30:00Z
        def win(t, eid, lid, user, lt=2, agent="WS-W1"):
            return {"timestamp": "2026-11-21T00:00:00.000+0000", "agent": {"name": agent},
                    "data": {"win": {"system": {"eventID": eid, "systemTime": events.epoch_to_ts(t).replace("Z", ".1234567Z")},
                                     "eventdata": {"targetLogonId": lid, "targetUserName": user, "logonType": str(lt)}}}}
        alerts = [win(T0, "4624", "0x1", "T_Delta"), win(T0 + 3600, "4634", "0x1", "t_delta"),          # 1 h, closed by logoff
                  win(T0 + 7200, "4624", "0x9", "t_delta", lt=3),                                         # network logon: not a session
                  win(T0 + 10000, "4624", "0x2", "t_delta", lt=10),                                       # RDP, no logoff: capped at 12 h
                  win(T0 + 1000, "4624", "0x3", "bob"), win(T0 + 1500, "4647", "0x3", "bob"),             # someone else: cut out
                  win(T0 + 100, "4624", "0x4", "DWM-1"), win(T0 + 200, "4624", "0x5", "WS-W1$"),          # system accounts: ignored
                  win(T0 + 300, "4624", "0x6", "t_delta", agent="WS-OTHER")]                             # another machine
        spec = events.parse_sessions_spec(["ws-w1=192.0.2.10:t_delta"])
        sessions, stats = events.build_sessions(events.windows_logon_events(alerts, spec), spec)
        self.assertEqual((stats[("ws-w1", "sessions")], stats[("ws-w1", "closed by logoff")], stats[("ws-w1", "capped at 12 h")],
                          stats[("ws-w1", "other accounts' sessions")]), (2, 1, 1, 1))
        def fgt(t, kind="fw.utm", ip="192.0.2.10", source="fortigate", **kw):
            return {"ts": events.epoch_to_ts(t), "kind": kind, "user": "", "src_host": ip, "src_ip": ip, "source": source, **kw}
        ev = [fgt(T0 - 4), fgt(T0 + 500), fgt(T0 + 1200), fgt(T0 + 3604, "net.conn", duration_s=10), fgt(T0 + 3604),
              fgt(T0 + 3606), fgt(T0 + 3700, "net.conn", duration_s=200), fgt(T0 + 10000 + 11 * 3600), fgt(T0 + 10000 + 13 * 3600),
              fgt(T0 + 1200, ip="192.0.2.81"), fgt(T0 + 1200, source="wazuh")]
        f = events.SessionFilter(spec, sessions, stats)
        import contextlib, io
        with contextlib.redirect_stderr(io.StringIO()) as err:
            kept = list(f(iter(ev)))
        self.assertEqual([round(rfc3339.parse(e["ts"]).timestamp() - T0) for e in kept if e["src_ip"] == "192.0.2.10" and e["source"] == "fortigate"],
                         [-4, 500, 3604, 3604, 3700, 10000 + 11 * 3600])
        self.assertEqual(len(kept), 8)                           # the other address and the non-FortiGate line pass untouched
        self.assertTrue(all(e["user"] == "t_delta" for e in kept[:6]) and kept[6]["user"] == "" and kept[7]["user"] == "")
        self.assertEqual((stats[("ws-w1", "fortigate kept")], stats[("ws-w1", "fortigate dropped outside sessions")]), (6, 3))
        self.assertIn("fortigate dropped outside sessions 3", err.getvalue())
        with self.assertRaises(SystemExit):
            events.parse_sessions_spec(["ws-w1:t_delta"])

    def test_windows_logon_account(self):
        a = {"timestamp": "2026-11-21T16:30:00.000+0800", "agent": {"name": "WS-W1"}, "decoder": {"name": "windows_eventchannel"},
             "rule": {"id": "60106", "level": 3, "groups": ["windows", "authentication_success"]},
             "data": {"win": {"system": {"eventID": "4624"}, "eventdata": {"targetUserName": "T_Delta", "logonType": "10"}}}}
        e = events.wazuh_alert_event(a)
        self.assertEqual((e["kind"], e["user"], e["logon_type"], e["dst"]), ("auth.logon", "t_delta", 10, "ws-w1"))
        a["data"]["win"]["eventdata"] = {}
        self.assertEqual((events.wazuh_alert_event(a)["user"], events.wazuh_alert_event(a)["logon_type"]), ("", "local"))

    def test_qulog_from_archives(self):
        def arch(t, line):
            return json.dumps({"timestamp": t, "predecoder": {"hostname": "NAS-1"}, "full_log": line})
        hdr = "Nov 21 16:41:41 NAS-1 qulogd[1]: "
        rows = [arch("2026-11-21T16:41:41.000+0800", hdr + "conn log: Users: WORKGROUP\\t_alpha, Source IP: 192.0.2.81, Computer name: ---, "
                     "Connection type: SAMBA, Accessed resources: ---, Action: Login Success"),
                arch("2026-11-21T16:41:48.000+0800", hdr + "conn log: Users: WORKGROUP\\t_alpha, Source IP: 192.0.2.81, Computer name: ---, "
                     "Connection type: SAMBA, Accessed resources: TestHR/q4, plan.txt, Action: Read"),
                arch("2026-11-21T16:42:00.000+0800", hdr + "conn log: Users: t_bravo, Source IP: 192.0.2.83, Computer name: WS-B, "
                     "Connection type: SAMBA, Accessed resources: TestFinance/new.txt, Action: Add"),
                arch("2026-11-21T16:43:00.000+0800", hdr + "conn log: Users: t_bravo, Action: Logout"),
                arch("2026-11-21T16:44:00.000+0800", "date=2026-11-21 type=\"traffic\""),
                json.dumps({"timestamp": "2026-11-21T16:45:00.000+0800", "agent": {"name": "SIEM-1"}, "decoder": {"name": "fortigate-firewall-v5"},
                            "full_log": 'devid="FG1" eventtime=1763714700000000000 srcip=192.0.2.81 type="utm" subtype="webfilter" hostname="jobs.example.com" catdesc="Job Search" action="passthrough"'}),
                "not json"]
        import gzip, io, tarfile
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "logs", "archives", "2026", "Nov")
            os.makedirs(sub)
            with gzip.open(os.path.join(sub, "ossec-archive-21.json.gz"), "wt") as f:
                f.write("\n".join(rows) + "\n")
            got = list(events.from_wazuh_archives(d))
            tar = os.path.join(d, "m.tar.gz")
            with tarfile.open(tar, "w:gz") as t:
                t.add(os.path.join(d, "logs"), arcname="logs")
            self.assertEqual(list(events.from_wazuh_archives(tar)), got)
        self.assertEqual([(e["kind"], e["user"], e.get("share"), e.get("path"), e.get("action")) for e in got],
                         [("auth.logon", "t_alpha", None, None, None), ("file.access", "t_alpha", "TestHR", "q4, plan.txt", "read"),
                          ("file.access", "t_bravo", "TestFinance", "new.txt", "write"), ("fw.utm", "", None, None, "allow")])
        self.assertEqual((got[3]["dst_name"], got[3]["asset"], got[3]["rule_id"]), ("jobs.example.com", "siem-1", ""))
        self.assertTrue(all(events.valid(e) for e in got))
        self.assertEqual((got[0]["src_ip"], got[0]["dst"], got[0]["asset"], got[0]["logon_type"], got[0]["source"]), ("192.0.2.81", "nas-1", "nas-1", "samba", "qulog"))
        kept = list(events.only_users(iter(got + [{"user": "", "kind": "sec.alert"}]), {"t_bravo"}))
        self.assertEqual([e["user"] for e in kept], ["t_bravo", "", ""])

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

    def test_terms_need_letters_and_time_is_not_ipv6(self):
        t = {}
        scrub.add_term(t, "host", "203.0.113.9:443"); scrub.add_term(t, "host", "12345")
        self.assertEqual(t, {})
        s = self.sc()
        self.assertEqual(s.text("at 13:55:36 ok"), "at 13:55:36 ok")
        self.assertNotIn("2001:db8", s.text("from 2001:db8::1 ok"))
        out = s.text("srv01-backup srv01_db x.srv01.example.org")
        self.assertNotIn("srv01", out)
        self.assertNotIn("abc", s.text('referer "/a/b.php?x=abc"'))

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


class ScrubDictTerms(unittest.TestCase):
    """The dictionary must not learn our own pseudonyms or bare numbers."""

    def test_pseudonym_is_not_a_term(self):
        out = {}
        scrub.add_term(out, "host", "h-0123456789")
        scrub.add_term(out, "user", "u-abcdef0123")
        self.assertEqual(out, {})

    def test_numeric_label_is_not_a_term(self):
        out = {}
        scrub.add_term(out, "host", "203.web01.example.local")
        self.assertNotIn("203", out)
        self.assertIn("203.web01.example.local", out)

    def test_span_with_pseudonym_is_not_a_term(self):
        out = {}
        scrub.add_term(out, "host", "portal.h-0123456789")
        self.assertEqual(out, {})

    def test_residual_names(self):
        self.assertEqual(scrub.residual_names("203.10-h-0123456789-h-abcdef0123"), [])
        self.assertEqual(scrub.residual_names("portal7.h-0123456789"), ["portal7"])
        self.assertEqual(scrub.residual_names("h-0123456789->abc"), ["abc"])

    def test_kept_path_segment_uses_dictionary(self):
        terms = [{"kind": "user", "real": "alice"}, {"kind": "host", "real": "srv01"}]
        p = pseudonymize.Pseudonymizer(KEY, "standard")
        p.set_terms(terms, scrub.term_regex({t["real"]: t["kind"] for t in terms}))
        out = p.path("/srv01-data/alice/report.pdf", "")
        self.assertNotIn("alice", out); self.assertNotIn("srv01", out)
        self.assertEqual(out.split("/")[0], scrub.Scrubber(KEY, "standard", terms).map["srv01"] + "-data")

    def test_syslog_header_host(self):
        sc = scrub.Scrubber(KEY, "standard", [])
        out = sc.text("Nov 15 12:00:01 wazuh sshd[42]: Accepted publickey for root")
        self.assertNotIn(" wazuh ", out)
        self.assertIn(" sshd[42]: ", out)
        self.assertEqual(out.split()[3], sc.host("wazuh"))
        iso = sc.text("2026-11-15T12:00:01+08:00 nas205 kernel: x")
        self.assertEqual(iso.split()[1], sc.host("nas205"))
        ip = sc.text("Nov 15 12:00:01 192.0.2.5 sshd[1]: x")
        self.assertEqual(ip.split()[3], sc.ip("192.0.2.5"))
        self.assertEqual(sc.text("rule wazuh fired"), "rule wazuh fired")

    def test_extra_reject(self):
        self.assertEqual(scrub.extra_reject("domain", "openai"), "domain_shape")
        self.assertIsNone(scrub.extra_reject("domain", "example.inc"))
        self.assertEqual(scrub.extra_reject("host", "haproxy"), "generic_or_no_letters")
        self.assertEqual(scrub.extra_reject("host", "203.0.113.9:9090"), "generic_or_no_letters")
        self.assertEqual(scrub.extra_reject("color", "blue"), "kind")
        self.assertIsNone(scrub.extra_reject("file", "a1b2c3.php"))

    def test_new_kinds_get_their_prefix(self):
        sc = scrub.Scrubber(KEY, "standard", [{"kind": "file", "real": "a1b2c3.php"}, {"kind": "hash", "real": "sha256:abcdef"}])
        out = sc.text("GET /a1b2c3.php key SHA256:abcdef")
        self.assertRegex(out, r"/f-[0-9a-f]{10} key x-[0-9a-f]{10}$")

    def test_name_with_digits_is_kept(self):
        out = {}
        scrub.add_term(out, "host", "srv01.corp.local")
        self.assertIn("srv01", out)


class ScrubJsonDepth(unittest.TestCase):
    """Bitdefender incidents arrive as a list of objects under data.nodes."""
    TERMS = [{"kind": "user", "real": "alice"}, {"kind": "host", "real": "srv01"}]

    def run_json(self, level, obj):
        return scrub.scrub_json(scrub.Scrubber(b"k" * 32, level, self.TERMS), obj, scrub.Templates(None))

    def line(self):
        return {"data": {
            "nodes": [{"name": "SRV01", "type": "endpoint", "details": {"ips": ["192.0.2.10"], "macs": ["00:11:22:33:44:55"],
                       "process": {"command_line": "run.exe -u alice", "user": {"user_name": "CORP\\\\carol", "user_sid": "S-1-5-21-1-2-3-1104"}},
                       "file": {"path": "C:\\\\Users\\\\carol\\\\a.exe"}}}],
            "alice": "field named after an account",
            "user": {"name": "\u738b\u5c0f\u660e"},
            "vulnerability": {"cve": "CVE-2026-1", "severity": "High", "reference": "https://srv01.example.org/x", "package": {"name": "alice-tools", "architecture": "amd64"}},
            "matrix": [[{"who": "alice"}]]}}

    def test_nothing_real_survives(self):
        text = json.dumps(self.run_json("standard", self.line()), ensure_ascii=False)
        for real in ("alice", "SRV01", "srv01", "carol", "192.0.2.10", "00:11:22:33:44:55", "run.exe", "S-1-5-21", "\u738b\u5c0f\u660e"):
            self.assertNotIn(real, text)

    def test_catalogue_words_stay(self):
        v = self.run_json("standard", self.line())["data"]["vulnerability"]
        self.assertEqual((v["cve"], v["severity"], v["package"]["architecture"]), ("CVE-2026-1", "High", "amd64"))

    def test_strict_keeps_structure_only(self):
        text = json.dumps(self.run_json("strict", self.line()), ensure_ascii=False)
        for real in ("alice", "SRV01", "carol", "Users", "00:11:22:33:44:55"):
            self.assertNotIn(real, text)
        self.assertIn("CVE-2026-1", text)

    def test_account_term_drops_the_domain(self):
        out = {}
        scrub.add_user(out, "CORP\\\\carol")
        self.assertEqual(out, {"carol": "user"})


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


cert = load("cert")


def cert_release(d, release):
    """a few rows of each CERT file, in the column order of the release"""
    def w(name, head, rows):
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            f.write(",".join(head) + "\n")
            for r in rows:
                f.write(",".join(f'"{x}"' for x in r) + "\n")
    six = release == "r6.2"
    w("logon.csv", ["id", "date", "user", "pc", "activity"],
      [["{L1}", "01/04/2010 08:01:00", "AAA0001", "PC-1", "Logon"], ["{L2}", "01/04/2010 17:00:00", "AAA0001", "PC-1", "Logoff"],
       ["{L3}", "01/05/2010 23:10:00", "BBB0002", "PC-2", "Logon"], ["{L4}", "bad", "BBB0002", "PC-2", "Logon"]])
    w("device.csv", ["id", "date", "user", "pc"] + (["file_tree"] if six else []) + ["activity"],
      [["{D1}", "01/05/2010 23:20:00", "BBB0002", "PC-2"] + (["R:\\"] if six else []) + ["Connect"],
       ["{D2}", "01/05/2010 23:40:00", "BBB0002", "PC-2"] + (["R:\\"] if six else []) + ["Disconnect"]])
    if six:
        w("file.csv", ["id", "date", "user", "pc", "filename", "activity", "to_removable_media", "from_removable_media", "content"],
          [["{F1}", "01/05/2010 23:30:00", "BBB0002", "PC-2", "R:\\x\\a.zip", "File Copy", "True", "False", "secret words"],
           ["{F2}", "01/04/2010 09:00:00", "AAA0001", "PC-1", "C:\\d\\b.doc", "File Open", "False", "False", "x"]])
    else:
        w("file.csv", ["id", "date", "user", "pc", "filename", "content"], [["{F1}", "01/05/2010 23:30:00", "BBB0002", "PC-2", "R:\\x\\a.zip", "secret words"]])
    w("http.csv", ["id", "date", "user", "pc", "url"] + (["activity"] if six else []) + ["content"],
      [["{H1}", "01/05/2010 23:35:00", "BBB0002", "PC-2", "http://wikileaks.org/a/b.php"] + (["WWW Upload"] if six else []) + ["words"],
       ["{H2}", "01/04/2010 10:00:00", "AAA0001", "PC-1", "https://www.example.com/q?x=1"] + (["WWW Visit"] if six else []) + ["words"]])
    w("email.csv", ["id", "date", "user", "pc", "to", "cc", "bcc", "from"] + (["activity"] if six else []) + ["size", "attachments", "content"],
      [["{E1}", "01/04/2010 11:00:00", "AAA0001", "PC-1", "x@dtaa.com", "", "", "aaa@dtaa.com"] + (["Send"] if six else []) + ["1000", "0", "hi"],
       ["{E2}", "01/05/2010 23:50:00", "BBB0002", "PC-2", "y@dtaa.com;me@hotmail.com", "", "", "bbb@dtaa.com"] + (["Send"] if six else []) + ["250000", "1", "hi"]])
    os.makedirs(os.path.join(d, "LDAP"))
    w(os.path.join("LDAP", "2010-01.csv"), ["employee_name", "user_id", "email", "role"], [["A A", "AAA0001", "a@dtaa.com", "Salesman"], ["B B", "BBB0002", "b@dtaa.com", "ITAdmin"]])


def cert_answers(d, release):
    os.makedirs(d)
    with open(os.path.join(d, "insiders.csv"), "w", encoding="utf-8") as f:
        f.write("dataset,scenario,details,user,start,end\n")
        f.write(f"{release.lstrip('r')},1,{release}-1-BBB0002.csv,BBB0002,01/05/2010 23:10:00,01/05/2010 23:50:00\n")
        f.write("9.9,1,other.csv,ZZZ0009,01/05/2010 23:10:00,01/05/2010 23:50:00\n")
    sub = os.path.join(d, f"{release}-1") if release == "r4.2" else d
    os.makedirs(sub, exist_ok=True)
    with open(os.path.join(sub, f"{release}-1-BBB0002.csv"), "w", encoding="utf-8") as f:
        f.write("logon,{L3},01/05/2010 23:10:00,BBB0002,PC-2,Logon\n")
        f.write("device,{D1},01/05/2010 23:20:00,BBB0002,PC-2,Connect\n")
        f.write("http,{H1},01/05/2010 23:35:00,BBB0002,PC-2,http://wikileaks.org/a/b.php,words\n")
        f.write("device,{D2},01/05/2010 23:40:00,BBB0002,PC-2,Disconnect\n")


class Cert(unittest.TestCase):
    def run_load(self, release, shards=1):
        t = tempfile.mkdtemp()
        os.makedirs(os.path.join(t, "data"))
        cert_release(os.path.join(t, "data"), release)
        cert_answers(os.path.join(t, "answers"), release)
        a = type("A", (), dict(dir=os.path.join(t, "data"), release=release, out=os.path.join(t, "ev.jsonl"), shards=shards,
                               answers=os.path.join(t, "answers"), stats=os.path.join(t, "stats.json")))
        cert.load(a)
        return t, json.load(open(a.stats))

    def events(self, t):
        out = []
        for p in sorted(os.listdir(t)):
            if p.startswith("ev") and p.endswith(".jsonl"):
                out += [json.loads(x) for x in open(os.path.join(t, p))]
        return out

    def test_rows_balance_and_mapping(self):
        for rel in cert.RELEASES:
            t, st = self.run_load(rel)
            for k, v in st["files"].items():
                self.assertTrue(v["balanced"], (rel, k))
            ev = self.events(t)
            kinds = collections_counter(e["kind"] for e in ev)
            self.assertEqual(kinds["auth.logon"], 2)                       # logoff and the bad time dropped
            self.assertEqual(kinds["usb.attach"], 1)
            self.assertEqual(kinds["net.file"], 1)                         # internal-only mail dropped
            mail = next(e for e in ev if e["kind"] == "net.file")
            self.assertEqual((mail["dst_name"], mail["bytes"], mail["direction"]), ("hotmail.com", 250000, "up"))
            web = next(e for e in ev if e["kind"] == "net.conn" and e["user"] == "AAA0001")
            self.assertEqual((web["dst_name"], web["dst_port"]), ("www.example.com", 443))
            self.assertTrue(all(e["ts"].endswith("Z") and e["source"] == "cert" for e in ev))
            self.assertTrue(all(events.valid(e) for e in ev))
            self.assertEqual({e["role"] for e in ev if e["user"] == "BBB0002"}, {"ITAdmin"})
            self.assertNotIn("secret", json.dumps(ev))                     # content never read into an event
            self.assertNotIn("q?x", json.dumps(ev))                        # nor the url beyond the host
            usb = next(e for e in ev if e["kind"] == "file.access" and e["user"] == "BBB0002")
            self.assertEqual((usb["share"], usb["action"]), ("removable", "write" if rel == "r4.2" else "copy"))
            self.assertEqual(st["answers"], {"ids": 4, "kept": 3, "dropped": 1, "not_found": 0, "insiders": 1})

    def test_shards_split_users_whole(self):
        t, _ = self.run_load("r4.2", shards=4)
        by = {}
        for p in os.listdir(t):
            if p.startswith("ev.s"):
                for x in open(os.path.join(t, p)):
                    by.setdefault(json.loads(x)["user"], set()).add(p)
        self.assertTrue(all(len(v) == 1 for v in by.values()))
        self.assertEqual(cert.shard_of("AAA0001", 4), cert.shard_of("AAA0001", 4))

    def test_labels_one_row_per_insider_day(self):
        for rel in cert.RELEASES:
            t = tempfile.mkdtemp()
            cert_answers(os.path.join(t, "answers"), rel)
            out = os.path.join(t, "s.tsv")
            cert.labels(type("A", (), dict(answers=os.path.join(t, "answers"), release=rel, out=out)))
            rows = [l.rstrip("\n").split("\t") for l in open(out)][1:]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][:5], ["2010-01-05T23:10:00Z", "2010-01-05T23:40:00Z", "BBB0002", "PC-2", "S1"])
            self.assertEqual(set(evaluate.labels(out)), {("BBB0002", "2010-01-05")})

    def test_sample_keeps_insiders_and_is_seeded(self):
        t = tempfile.mkdtemp()
        s, sch = os.path.join(t, "s.jsonl"), os.path.join(t, "sch.tsv")
        with open(s, "w") as f:
            for i in range(50):
                f.write(json.dumps({"user": f"u{i}", "date": "2010-02-01"}) + "\n")
        with open(sch, "w") as f:
            f.write("start\tend\tuser\thost\tscenario\tnote\n2010-02-01T01:00:00Z\t2010-02-01T02:00:00Z\tu3\th\tS1\tx\n")
        got = []
        for _ in range(2):
            out = os.path.join(t, "o.jsonl")
            cert.sample(type("A", (), dict(summaries=s, schedule=sch, normal=5, negatives=None, seed=7, out=out, users_out=None)))
            got.append({json.loads(x)["user"] for x in open(out)})
        self.assertEqual(got[0], got[1])
        self.assertIn("u3", got[0])
        self.assertEqual(len(got[0]), 6)

    def test_case_control_and_weigh(self):
        t = tempfile.mkdtemp()
        s, sch, out, fr = (os.path.join(t, x) for x in ("s.jsonl", "sch.tsv", "o.jsonl", "f.json"))
        with open(s, "w") as f:
            for u in range(4):
                for d in range(1, 26 if u else 6):
                    f.write(json.dumps({"user": f"u{u}", "date": f"2010-03-{d:02d}"}) + "\n")
        with open(sch, "w") as f:
            f.write("start\tend\tuser\thost\tscenario\tnote\n2010-03-02T01:00:00Z\t2010-03-02T02:00:00Z\tu0\th\tS1\tx\n")
        a = type("A", (), dict(summaries=s, schedule=sch, normal=None, negatives=20, seed=7, out=out, frac_out=fr, users_out=None))
        cert.sample(a)
        rows = [json.loads(x) for x in open(out)]
        fj = json.load(open(fr))
        self.assertIn({"user": "u0", "date": "2010-03-02"}, rows)
        self.assertEqual((fj["positives"], fj["negatives_total"], fj["negatives_sampled"]), (1, 79, 20))
        per = collections_counter(r["user"] for r in rows)
        self.assertEqual(per["u0"], 2)                                   # 4/79 of 20 rounds to 1, plus the positive
        first = rows
        cert.sample(a)
        self.assertEqual([json.loads(x) for x in open(out)], first)
        det = os.path.join(t, "d.jsonl")
        with open(det, "w") as f:
            for r in rows:
                pred = r["user"] == "u0" or r == rows[-1]
                f.write(json.dumps(dict(r, final={"verdict": "THREAT" if pred else "NORMAL"})) + "\n")
        w = os.path.join(t, "w.json")
        cert.weigh(type("A", (), dict(detections=det, schedule=sch, frac=fr, bootstrap=50, seed=1, out=w)))
        o = json.load(open(w))["overall"]
        self.assertEqual((o["tp"], o["fp"], o["fn"]), (1, 2, 0))
        self.assertAlmostEqual(o["fp_population_est"], 2 / (20 / 79))
        self.assertAlmostEqual(o["precision_weighted"], 1 / (1 + 2 * 79 / 20))


def collections_counter(it):
    import collections
    return collections.Counter(it)


if __name__ == "__main__":
    unittest.main()
