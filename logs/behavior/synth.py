#!/usr/bin/env python3
"""synth: a synthetic site for the behaviour pipeline, so the whole path
(events, pseudonymize, summarize, detect, evaluate) runs with no site data
at all, in CI and on a laptop, and so the six injection scenarios have a
known ground truth to score against.

    synth.py --out DIR [--users 40] [--days 35] [--baseline-days 21] [--seed 7] [--scenarios S1,S2,S3,S4,S5,S6]

Writes to DIR:
    events.jsonl   every event of the period, the schema of events.py, real (synthetic) names
    schedule.tsv   the injection schedule, the ground truth: start, end, user, host, scenario, note
    site.json      users, roles, hosts, shares, the parameters; for the researcher, not for the models

Background: each user has a role (sales, rd, hr, finance, it, ops, mgmt), a
workstation, the shares of the role, office hours around 09:00 to 18:00
local time, a daily volume of file reads, external connections, logons and
the odd print job, drawn from per-user rates fixed by the seed. IT
accounts log on to servers and a service account runs a nightly backup.
Hard negatives in the test period: a weekend crunch upload to an approved
vendor, a new hire's first week, a payroll run in HR's own share, a patch
window that touches every server. None of those is in schedule.tsv.

Injections follow the thesis plan (the six scenarios S1 to S6), each a
few times in the test period, on four test accounts and one admin
account that behave normally otherwise. S6 is spread over five
consecutive workdays and is mild on every single day.

Addresses are documentation ranges (192.0.2.0/24 workstations,
198.51.100.0/24 servers, 203.0.113.0/24 the internet) and names end in
example.net, so the output can live in a public repository.

Standard library only.
"""
import argparse, datetime as dt, json, os, random, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "lib", "python"))
from ops30 import rfc3339  # noqa: E402

TZ = dt.timezone(dt.timedelta(hours=8))
ROLES = {  # share of users, shares, daily rates (file reads, external conns, prints per day)
    "sales":   {"w": 8,  "shares": ["sales", "public"],        "files": 25, "conns": 70, "prints": 0.4},
    "rd":      {"w": 10, "shares": ["eng", "public"],          "files": 45, "conns": 50, "prints": 0.1},
    "hr":      {"w": 3,  "shares": ["hr", "public"],           "files": 35, "conns": 40, "prints": 0.8},
    "finance": {"w": 4,  "shares": ["fin", "public"],          "files": 40, "conns": 40, "prints": 1.0},
    "it":      {"w": 4,  "shares": ["it", "eng", "public"],    "files": 20, "conns": 60, "prints": 0.05},
    "ops":     {"w": 6,  "shares": ["ops", "public"],          "files": 15, "conns": 30, "prints": 0.3},
    "mgmt":    {"w": 3,  "shares": ["sales", "fin", "hr", "public"], "files": 20, "conns": 50, "prints": 0.5},
}
SERVERS = {"fs-01": "198.51.100.11", "dc-01": "198.51.100.12", "prn-01": "198.51.100.13", "mail-01": "198.51.100.14",
           "bk-01": "198.51.100.15", "nas-01": "198.51.100.16", "app-01": "198.51.100.21", "app-02": "198.51.100.22",
           "app-03": "198.51.100.23", "db-01": "198.51.100.24", "web-01": "198.51.100.25", "vpn-gw": "198.51.100.1"}
EXTERNAL = {  # name: (address, category, weight for background traffic, typical bytes out)
    "mail.example.net":            ("203.113.0.10", "business", 30, 60_000),
    "office.example.net":          ("203.113.0.11", "business", 25, 120_000),
    "cdn.example.net":             ("203.113.0.12", "web", 20, 4_000),
    "update.example.net":          ("203.113.0.13", "software_update", 5, 2_000),
    "vendor-portal.example.net":   ("203.113.0.14", "business", 6, 300_000),
    "news.example.net":            ("203.113.0.15", "news", 8, 3_000),
    "video.example.net":           ("203.113.0.16", "streaming", 3, 8_000),
    "search.example.net":          ("203.113.0.17", "search", 15, 2_000),
    "drive-personal.example.net":  ("203.113.0.30", "cloud_storage", 0, 0),
    "webmail-personal.example.net": ("203.113.0.31", "webmail", 0, 0),
    "doh.example.net":             ("203.113.0.40", "doh", 0, 0),
    "vpn-free.example.net":        ("203.113.0.41", "proxy_avoidance", 0, 0),
}
for k, v in list(EXTERNAL.items()):   # 203.0.113.0/24 is the documentation range; fix the typo above in one place
    EXTERNAL[k] = ("203.0.113." + v[0].split(".")[-1],) + v[1:]
EXT_NAMES = [n for n, v in EXTERNAL.items() if v[2] > 0]
EXT_W = [EXTERNAL[n][2] for n in EXT_NAMES]
SHARE_DIRS = {"sales": ["accounts", "quotes", "pipeline"], "eng": ["projects", "firmware", "specs"], "hr": ["payroll", "personnel", "policies"],
              "fin": ["ledger", "invoices", "budget"], "it": ["inventory", "runbooks"], "ops": ["shifts", "tickets"], "public": ["forms", "templates"]}
EXTS = [".docx", ".xlsx", ".pdf", ".pptx", ".txt", ".csv"]


class Site:
    def __init__(self, a):
        self.r = random.Random(a.seed)
        self.a = a
        self.start = dt.datetime.strptime(a.start, "%Y-%m-%d").replace(tzinfo=TZ)
        self.users = []
        weights = [(k, v["w"]) for k, v in ROLES.items()]
        tot = sum(w for _, w in weights)
        i = 0
        for role, w in weights:
            for _ in range(max(1, round(a.users * w / tot))):
                i += 1
                self.users.append(self.user(f"{role[:2]}-{i:03d}", role, i))
        # the actors: three test accounts and one admin, normal otherwise
        self.actors = {"tA": self.pick("sales"), "tB": self.pick("rd"), "tC": self.pick("finance"), "tD": self.pick("ops"), "adm": self.pick("it")}
        for u in self.users:
            u["test"] = u["name"] in {v["name"] for v in self.actors.values()}
        self.newhire = self.user(f"rd-{i + 1:03d}", "rd", i + 1)
        self.newhire["joins"] = a.baseline_days  # first day index of the test period
        self.users.append(self.newhire)
        self.svc = {"name": "svc-backup", "role": "it", "ws": "bk-01", "ip": SERVERS["bk-01"], "shares": [], "files": 0, "conns": 0, "prints": 0}
        self.roles = {u["name"]: u["role"] for u in self.users} | {"svc-backup": "service"}
        self.events = []
        self.schedule = []

    def user(self, name, role, i):
        r = self.r
        spec = ROLES[role]
        return {"name": name, "role": role, "ws": f"ws-{i:03d}", "ip": f"192.0.2.{10 + i}", "shares": list(spec["shares"]),
                "files": max(3, int(r.gauss(spec["files"], spec["files"] * 0.3))),
                "conns": max(5, int(r.gauss(spec["conns"], spec["conns"] * 0.3))),
                "prints": spec["prints"] * r.uniform(0.5, 1.5),
                "in": r.uniform(8.3, 9.6), "out": r.uniform(17.5, 19.2),
                "ext_bias": r.sample(EXT_NAMES, 3)}

    def pick(self, role):
        c = [u for u in self.users if u["role"] == role and not u.get("test")]
        return self.r.choice(c)

    # ------------------------------------------------------------ emit
    def t(self, day, hour):
        """day index and fractional local hour -> RFC 3339 UTC"""
        return rfc3339.format(self.start + dt.timedelta(days=day, hours=hour))

    def emit(self, **e):
        e.setdefault("source", "synth")
        e.setdefault("role", self.roles.get(e.get("user", ""), ""))
        self.events.append(e)

    def conn(self, day, hour, u, name, bytes_out=None, bytes_in=None, port=443, service="ssl", host=None, ip=None, dur=None, action="allow"):
        addr, cat, _, typ = EXTERNAL[name] if name in EXTERNAL else (SERVERS.get(name, name), "internal", 0, 2000)
        bo = bytes_out if bytes_out is not None else max(200, int(self.r.lognormvariate(10.5, 1.0) * typ / 30000)) if typ else 500
        self.emit(ts=self.t(day, hour), kind="net.conn", user=u["name"], src_host=host or u["ws"], src_ip=ip or u["ip"], dst=addr,
                  dst_name=name if name in EXTERNAL else "", dst_port=port, proto="tcp", service=service,
                  bytes_out=bo, bytes_in=bytes_in if bytes_in is not None else int(bo * self.r.uniform(1, 8)),
                  duration_s=dur if dur is not None else max(1, int(self.r.expovariate(1 / 20))), category=cat, action=action)

    def logon(self, day, hour, u, dst, result="success", logon_type=2, host=None, ip=None):
        self.emit(ts=self.t(day, hour), kind="auth.logon", user=u["name"], src_host=host or u["ws"], src_ip=ip or u["ip"], dst=dst,
                  logon_type=logon_type, result=result, method="Kerberos" if result == "success" else "NTLM")

    def file(self, day, hour, u, share, action="read", ext=None, dir_=None, host=None, ip=None, size=None):
        d = dir_ or self.r.choice(SHARE_DIRS[share])
        self.emit(ts=self.t(day, hour), kind="file.access", user=u["name"], src_host=host or u["ws"], src_ip=ip or u["ip"], dst="fs-01",
                  share=share, path=f"{share}/{d}/{self.r.randint(1, 400):04d}{ext or self.r.choice(EXTS)}", action=action,
                  bytes=size if size is not None else int(self.r.lognormvariate(12, 1.2)))

    def print_(self, day, hour, u, pages=None):
        self.emit(ts=self.t(day, hour), kind="print.job", user=u["name"], src_host=u["ws"], src_ip=u["ip"], dst="prn-01",
                  pages=pages or self.r.randint(1, 20), filename=f"doc{self.r.randint(1, 999)}.pdf")

    def utm(self, day, hour, u, name, action, app="", host=None, ip=None):
        addr, cat, _, _ = EXTERNAL[name]
        self.emit(ts=self.t(day, hour), kind="fw.utm", user=u["name"], src_host=host or u["ws"], src_ip=ip or u["ip"], dst=addr,
                  dst_name=name, category=cat, app=app, action=action)

    def workday(self, day):
        return (self.start + dt.timedelta(days=day)).weekday() < 5

    def hours(self, u, n, lo=None, hi=None):
        lo = u["in"] if lo is None else lo
        hi = u["out"] if hi is None else hi
        return sorted(self.r.uniform(lo, hi) for _ in range(n))

    # ------------------------------------------------------------ background
    def background_day(self, day, u):
        r = self.r
        if u.get("joins") is not None and day < u["joins"]:
            return
        if not self.workday(day):
            if r.random() > 0.06:
                return
            scale = 0.25
        else:
            scale = r.uniform(0.6, 1.4)
        if r.random() < 0.03:                               # one typo before the morning logon
            self.logon(day, u["in"] - 0.02, u, u["ws"], "failure")
        self.logon(day, u["in"] + r.gauss(0, 0.2), u, u["ws"])
        nf = int(r.gauss(u["files"] * scale, u["files"] * 0.25))
        for h in self.hours(u, max(0, nf)):
            share = r.choice(u["shares"]) if r.random() < 0.85 else "public"
            self.file(day, h, u, share, "write" if r.random() < 0.08 else "read")
        nc = int(r.gauss(u["conns"] * scale, u["conns"] * 0.25))
        for h in self.hours(u, max(0, nc), u["in"] - 0.1, u["out"] + 0.3):
            name = r.choice(u["ext_bias"]) if r.random() < 0.4 else r.choices(EXT_NAMES, EXT_W)[0]
            self.conn(day, h, u, name)
        for h in self.hours(u, 2):                           # mail and the file server, internal
            self.conn(day, h, u, "mail-01", port=993, service="imap")
        if r.random() < u["prints"]:
            self.print_(day, r.uniform(u["in"], u["out"]), u)
        if u["role"] == "it":                                # admins touch servers every day
            for s in r.sample(list(SERVERS), r.randint(1, 4)):
                h = r.uniform(u["in"], u["out"])
                self.logon(day, h, u, s, logon_type=10 if r.random() < 0.6 else 3)
                self.conn(day, h + 0.001, u, s, port=3389 if r.random() < 0.6 else 445, service="rdp", dur=r.randint(60, 1800))

    def backup_night(self, day):
        """svc-backup moves a lot of bytes to the NAS at 01:00; large, off hours, every night, a normal thing"""
        u = self.svc
        self.logon(day, 1.0, u, "nas-01", logon_type=3)
        for i in range(6):
            self.conn(day, 1.05 + i * 0.3, u, "nas-01", bytes_out=int(self.r.gauss(9e9, 1.5e9)), bytes_in=2_000_000, port=445, service="smb", dur=900)

    def hard_negatives(self):
        """legitimate but odd-looking, in the test period, not in the schedule"""
        a, r = self.a, self.r
        test_days = range(a.baseline_days, a.days)
        sat = next(d for d in test_days if (self.start + dt.timedelta(days=d)).weekday() == 5)
        rd = self.pick("rd")
        self.logon(sat, 10.0, rd, rd["ws"])                   # weekend crunch: 1.5 GB to the approved vendor
        for i in range(8):
            self.file(sat, 10.2 + i * 0.4, rd, "eng")
        self.conn(sat, 14.0, rd, "vendor-portal.example.net", bytes_out=1_500_000_000, bytes_in=5_000_000, dur=2400)
        hr = self.pick("hr")                                  # payroll run: 220 reads in HR's own share in two hours
        pay = a.baseline_days + 2
        for h in self.hours(hr, 220, 9.5, 11.5):
            self.file(pay, h, hr, "hr", dir_="payroll", ext=".xlsx")
        adm = self.actors["adm"]                              # patch window on a Tuesday: every server, RDP, in office hours
        tue = next(d for d in test_days if (self.start + dt.timedelta(days=d)).weekday() == 1)
        for i, s in enumerate(SERVERS):
            self.logon(tue, 14.0 + i * 0.12, adm, s, logon_type=10)
            self.conn(tue, 14.0 + i * 0.12 + 0.001, adm, s, port=3389, service="rdp", dur=400)
        self.notes = {"weekend_crunch": (rd["name"], sat), "payroll_run": (hr["name"], pay), "patch_window": (adm["name"], tue),
                      "new_hire": (self.newhire["name"], a.baseline_days)}

    # ------------------------------------------------------------ injections
    def sched(self, day, h0, h1, u, host, sc, note):
        s = self.start + dt.timedelta(days=day, hours=h0)
        e = self.start + dt.timedelta(days=day, hours=h1)
        self.schedule.append((s.isoformat(timespec="minutes"), e.isoformat(timespec="minutes"), u["name"], host, sc, note))

    def test_days(self, n, workdays=True, exclude=()):
        a = self.a
        pool = [d for d in range(a.baseline_days, a.days) if (self.workday(d) == workdays) and d not in exclude]
        return sorted(self.r.sample(pool, min(n, len(pool))))

    def inject_S1(self, n):
        u, r = self.actors["tA"], self.r
        days = self.test_days(3) + self.test_days(2, workdays=False)
        for d in days:
            h = r.uniform(22.0, 25.5) if self.workday(d) else r.uniform(10, 20)
            name = r.choice(["drive-personal.example.net", "webmail-personal.example.net"])
            size = r.randint(600, 2500) * 1_000_000
            self.logon(d, h - 0.05, u, u["ws"])
            self.utm(d, h, u, name, "allow", app="Personal-Storage")
            for i in range(3):
                self.conn(d, h + i * 0.1, u, name, bytes_out=size // 3, bytes_in=2_000_000, dur=600)
            self.emit(ts=self.t(d, h + 0.05), kind="net.file", user=u["name"], src_host=u["ws"], src_ip=u["ip"], dst=EXTERNAL[name][0],
                      dst_name=name, filename="export.7z", bytes=size, direction="up")
            self.sched(d, h - 0.1, h + 0.4, u, u["ws"], "S1", f"{size // 1_000_000} MB to {EXTERNAL[name][1]} at {h % 24:04.1f}h")

    def inject_S2(self, n):
        u, r = self.actors["tB"], self.r
        for d in self.test_days(n, exclude=()):
            share = r.choice(["hr", "fin"])
            h0 = r.uniform(10, 16)
            k = r.randint(40, 120)
            for h in self.hours(u, k, h0, h0 + r.uniform(0.25, 0.5)):
                self.file(d, h, u, share)
            self.sched(d, h0, h0 + 0.5, u, u["ws"], "S2", f"{k} reads in {share}, first time")

    def inject_S3(self, n):
        u, r = self.actors["adm"], self.r
        ws = [x["ws"] for x in self.users if x is not u]
        for d in self.test_days(n, exclude=(self.notes["patch_window"][1],)):
            h0 = r.uniform(9.5, 17)
            targets = r.sample(ws, r.randint(8, 15)) + r.sample(list(SERVERS), 2)
            for i, tgt in enumerate(targets):
                h = h0 + i * 0.01
                self.logon(d, h, u, tgt, logon_type=10 if r.random() < 0.5 else 3)
                self.conn(d, h + 0.0005, u, tgt, port=r.choice([3389, 445]), service=r.choice(["rdp", "smb"]), dur=r.randint(2, 20), bytes_out=3000)
            scan = r.choice(list(SERVERS))
            for p in r.sample(range(1, 1024), r.randint(25, 40)):
                self.conn(d, h0 + 0.3 + p * 1e-5, u, scan, port=p, service="", dur=0, bytes_out=60, bytes_in=0)
            self.sched(d, h0, h0 + 0.5, u, u["ws"], "S3", f"{len(targets)} hosts rdp/smb, port scan on {scan}")

    def inject_S4(self, n):
        u, r = self.actors["tA"], self.r
        others = [x for x in self.users if x is not u and x["role"] != "it"]
        for d in self.test_days(n):
            src = r.choice(others)
            h0 = r.choice([r.uniform(23.0, 24.5), r.uniform(5.5, 7.0)])
            k = r.randint(6, 12)
            for i in range(k):
                self.logon(d, h0 + i * 0.01, u, "dc-01", "failure", logon_type=10 if r.random() < 0.5 else 3, host=src["ws"], ip=src["ip"])
            self.logon(d, h0 + k * 0.01 + 0.01, u, "dc-01", "success", logon_type=10, host=src["ws"], ip=src["ip"])
            self.conn(d, h0 + k * 0.01 + 0.02, u, "fs-01", port=445, service="smb", host=src["ws"], ip=src["ip"], dur=300)
            self.sched(d, h0, h0 + 0.3, u, src["ws"], "S4", f"{k} failures then success from {src['ws']} at {h0 % 24:04.1f}h")

    def inject_S5(self, n):
        u, r = self.actors["tD"], self.r
        for d in self.test_days(n):
            h0 = r.uniform(9.5, 17)
            for i in range(r.randint(25, 45)):
                self.conn(d, h0 + i * 0.01, u, "doh.example.net", bytes_out=r.randint(300, 900), bytes_in=r.randint(400, 1500), dur=1)
            self.utm(d, h0 + 0.2, u, "vpn-free.example.net", "block", app="Proxy.Avoidance")
            self.conn(d, h0 + 0.2, u, "vpn-free.example.net", bytes_out=1200, bytes_in=0, dur=0, action="deny")
            self.emit(ts=self.t(d, h0 + 0.3), kind="usb.attach", user=u["name"], src_host=u["ws"], src_ip=u["ip"], device="USB Mass Storage")
            self.sched(d, h0, h0 + 0.5, u, u["ws"], "S5", "DoH, blocked proxy, USB storage")

    def inject_S6(self, n):
        u, r = self.actors["tC"], self.r
        wd = [d for d in range(self.a.baseline_days, self.a.days) if self.workday(d)]
        start = r.randint(0, max(0, len(wd) - 5))
        for d in wd[start:start + 5]:
            k = int(u["files"] * r.uniform(1.8, 2.6))
            for h in self.hours(u, k):
                self.file(d, h, u, r.choice(u["shares"]))
            for _ in range(r.randint(1, 3)):
                self.file(d, r.uniform(u["in"], u["out"]), u, "fin", action="write", ext=".zip", size=r.randint(50, 400) * 1_000_000)
            self.print_(d, r.uniform(u["in"], u["out"]), u, pages=r.randint(30, 60))
            self.sched(d, u["in"], u["out"], u, u["ws"], "S6", f"day {wd.index(d) - start + 1}/5: {k} reads, zip writes, print")

    # ------------------------------------------------------------ run
    def build(self):
        a = self.a
        for d in range(a.days):
            for u in self.users:
                self.background_day(d, u)
            self.backup_night(d)
        self.hard_negatives()
        want = set(a.scenarios.split(","))
        for sc in ("S1", "S2", "S3", "S4", "S5", "S6"):
            if sc in want:
                getattr(self, f"inject_{sc}")(a.per_scenario)
        self.events.sort(key=lambda e: e["ts"])
        self.schedule.sort()

    def write(self):
        a = self.a
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "events.jsonl"), "w", encoding="utf-8") as f:
            for e in self.events:
                f.write(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n")
        with open(os.path.join(a.out, "schedule.tsv"), "w", encoding="utf-8") as f:
            f.write("start\tend\tuser\thost\tscenario\tnote\n")
            for row in self.schedule:
                f.write("\t".join(row) + "\n")
        site = {"start": a.start, "days": a.days, "baseline_days": a.baseline_days, "seed": a.seed, "tz": "+08:00",
                "users": [{k: u[k] for k in ("name", "role", "ws", "ip", "shares")} | ({"test": True} if u.get("test") else {}) | ({"joins_day": u["joins"]} if u.get("joins") is not None else {}) for u in self.users],
                "actors": {k: v["name"] for k, v in self.actors.items()}, "servers": SERVERS,
                "external": {k: {"ip": v[0], "category": v[1]} for k, v in EXTERNAL.items()},
                "hard_negatives": {k: {"user": v[0], "day": v[1]} for k, v in self.notes.items()},
                "events": len(self.events), "injections": len(self.schedule)}
        with open(os.path.join(a.out, "site.json"), "w", encoding="utf-8") as f:
            json.dump(site, f, ensure_ascii=False, indent=1)
        print(f"synth: {len(self.users)} users, {a.days} days ({a.baseline_days} baseline), {len(self.events)} events, {len(self.schedule)} injected user-days -> {a.out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--users", type=int, default=40)
    ap.add_argument("--days", type=int, default=35)
    ap.add_argument("--baseline-days", type=int, default=21)
    ap.add_argument("--start", default="2026-09-07", help="a Monday, local date")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--scenarios", default="S1,S2,S3,S4,S5,S6")
    ap.add_argument("--per-scenario", type=int, default=5)
    a = ap.parse_args()
    if a.baseline_days >= a.days:
        sys.exit("synth: --baseline-days must be smaller than --days")
    s = Site(a)
    s.build()
    s.write()


if __name__ == "__main__":
    main()
