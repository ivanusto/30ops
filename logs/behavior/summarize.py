#!/usr/bin/env python3
"""summarize: pseudonymized events in, one summary per user and day out,
with the user's own baseline next to every number. This is the layer the
models read; nothing they say can be more than what is written here.

    summarize.py --in events.p.jsonl --out summaries.jsonl --baseline-days 21 [--tz +08:00] [--timing timing.jsonl]
    summarize.py ... --baseline-until 2026-09-28        # local date, first day of the test period
    summarize.py ... --entity host [--exclude-kinds malware.detect]   # one summary per monitored host and day

Baseline: the days before the test period. For every user, per workday
means and standard deviations of each count, and the sets of shares,
domains, internal destinations, logon hosts and logon targets seen. A
user with fewer than --min-baseline-days days (a new hire) gets the
baseline of the role (events may carry `role`), else the whole site.

Per user-day the features below, each with its z against the baseline
(cap 9.9), the entities not seen in the baseline, a transparent rule
score (`prescreen`, what the rules backend of detect.py uses and what the
report explains false positives with), a scenario the rules would guess,
and `text`: the summary in Traditional Chinese that goes to the models,
its second line the rules that fired, written out (`signals`).

    files    f_reads f_writes f_bytes f_archive_writes f_archive_bytes f_burst30 (reads in the busiest 30 min)
    net      n_ext_conns n_ext_bytes n_ext_bytes_off n_personal_bytes n_denied n_doh n_dst_int n_rdp_smb_short n_scan_ports
    auth     a_success a_fail a_fail_then_success a_remote a_off
    other    p_pages u_usb
    rolling  r5_reads r5_pages r5_archive (this day and the four before, the signal a slow S6 leaves)
    new      new_shares new_domains new_dst_int new_logon_hosts new_logon_dsts (counts; the lists in `new`)

Events without a user are attributed to the account that logs on most
from that source host (the DHCP and logon join a site would do).

--entity host is for a site whose logs say which machine and rarely which
person (a SIEM's server alerts): the unit is the event's `asset`, the features
are HOST_COUNTS, every day of the baseline counts (servers have no weekend),
and alerts from public addresses are counted apart and score nothing, because
an internet-facing service being scanned says nothing about an insider.

Standard library only.
"""
import argparse, collections, datetime as dt, json, math, os, statistics, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "lib", "python"))
from ops30 import rfc3339  # noqa: E402

COUNTS = ["f_reads", "f_writes", "f_bytes", "f_archive_writes", "f_archive_bytes", "f_burst30",
          "n_ext_conns", "n_ext_bytes", "n_ext_bytes_off", "n_personal_bytes", "n_denied", "n_doh", "n_dst_int", "n_rdp_smb_short", "n_scan_ports",
          "a_success", "a_fail", "a_fail_then_success", "a_remote", "a_off", "p_pages", "u_usb",
          "r5_reads", "r5_pages", "r5_archive"]
SETS = {"shares": "share", "domains": "dst_name", "dst_int": "dst", "logon_hosts": "src_host", "logon_dsts": "dst"}
PERSONAL = {"cloud_storage", "webmail", "personal_storage", "file_sharing"}
EVASION = {"doh", "proxy_avoidance", "proxy", "vpn", "anonymizer", "tor"}
ARCHIVE = (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz")
BYTES = {"f_bytes", "f_archive_bytes", "n_ext_bytes", "n_ext_bytes_off", "n_personal_bytes"}
WEEKDAYS = "一二三四五六日"
HOST_COUNTS = ["h_alerts", "h_ext", "h_int", "h_high", "h_recon_int", "h_int_src_n", "h_fim", "h_fim_off", "h_pkg", "h_pkg_evasion",
               "h_priv", "h_priv_off", "h_priv_evasion", "h_malware", "a_success", "a_fail", "a_fail_then_success", "a_ext_success", "a_off", "u_usb"]
HOST_SETS = {"accounts": "user", "int_src": "src_host", "rule_ids": "rule_id"}


class JsonlFile:
    """Read twice without being held in memory; `lines` is the last full pass."""
    def __init__(self, path):
        self.path, self.lines = path, 0

    def __iter__(self):
        n = 0
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    n += 1
                    yield e
        self.lines = n


def parse_tz(s):
    sign = -1 if s.startswith("-") else 1
    h, m = s.lstrip("+-").split(":")
    return dt.timezone(sign * dt.timedelta(hours=int(h), minutes=int(m)))


def off_hours(local):
    return local.weekday() >= 5 or local.hour < 8 or local.hour >= 20


def mb(n):
    return f"{n / 1e6:.0f} MB" if n >= 1e6 else f"{n / 1e3:.0f} KB"


class Day:
    def __init__(self, sets=SETS):
        self.f = collections.Counter()
        self.sets = {k: set() for k in sets}
        self.read_times, self.logons, self.port_by_dst, self.events = [], [], collections.defaultdict(set), 0

    def finish(self):
        f = self.f
        if self.read_times:
            ts = sorted(self.read_times); j = 0; best = 0
            for i, t in enumerate(ts):
                while ts[j] < t - 1800:
                    j += 1
                best = max(best, i - j + 1)
            f["f_burst30"] = best
        if self.port_by_dst:
            f["n_scan_ports"] = max(len(v) for v in self.port_by_dst.values())
        self.logons.sort()
        fails = 0
        for t, ok in self.logons:
            if ok:
                if fails >= 3:
                    f["a_fail_then_success"] = 1
                fails = 0
            else:
                fails += 1


def host_users(events):
    c = collections.defaultdict(collections.Counter)
    for e in events:
        if e.get("kind") == "auth.logon" and e.get("result") == "success" and e.get("user") and e.get("src_host"):
            c[e["src_host"]][e["user"]] += 1
    return {h: u.most_common(1)[0][0] for h, u in c.items()}


def bucket(events, tz):
    """-> {(user, date): Day}, roles, the ordered list of dates"""
    days, roles = {}, {}
    hu = host_users(events)
    for e in events:
        d = rfc3339.parse(e.get("ts", ""))
        if d is None:
            continue
        user = e.get("user") or hu.get(e.get("src_host", ""), "")
        if not user:
            continue
        if e.get("role"):
            roles[user] = e["role"]
        local = d.astimezone(tz)
        key = (user, local.date())
        D = days.get(key)
        if D is None:
            D = days[key] = Day()
        D.events += 1
        f, kind, off = D.f, e.get("kind"), off_hours(local)
        if kind == "file.access":
            act = e.get("action", "read")
            if e.get("share"):
                D.sets["shares"].add(e["share"])
            if act == "read":
                f["f_reads"] += 1; D.read_times.append(d.timestamp())
            else:
                f["f_writes"] += 1
                if str(e.get("path", "")).lower().endswith(ARCHIVE):
                    f["f_archive_writes"] += 1; f["f_archive_bytes"] += int(e.get("bytes") or 0)
            f["f_bytes"] += int(e.get("bytes") or 0)
        elif kind == "net.conn":
            cat = (e.get("category") or "").lower()
            if e.get("action") in ("deny", "block", "blocked"):
                f["n_denied"] += 1
            if cat in EVASION:
                f["n_doh"] += 1
            if cat == "internal" or (not e.get("dst_name") and cat in ("", "internal")):
                if e.get("dst"):
                    D.sets["dst_int"].add(e["dst"])
                    f["n_dst_int"] = len(D.sets["dst_int"])
                    D.port_by_dst[e["dst"]].add(e.get("dst_port"))
                if e.get("dst_port") in (3389, 445, 22, 5985, 5986) and int(e.get("duration_s") or 0) < 30:
                    f["n_rdp_smb_short"] += 1
            else:
                bo = int(e.get("bytes_out") or 0)
                f["n_ext_conns"] += 1; f["n_ext_bytes"] += bo
                if off:
                    f["n_ext_bytes_off"] += bo
                if cat in PERSONAL:
                    f["n_personal_bytes"] += bo
                if e.get("dst_name"):
                    D.sets["domains"].add(e["dst_name"])
        elif kind == "net.file":
            if e.get("direction") == "up":
                f["n_personal_bytes"] += int(e.get("bytes") or 0)
        elif kind == "fw.utm":
            cat = (e.get("category") or "").lower()
            if e.get("action") == "block":
                f["n_denied"] += 1
            if cat in EVASION:
                f["n_doh"] += 1
            if cat in PERSONAL and e.get("dst_name"):
                D.sets["domains"].add(e["dst_name"])
        elif kind == "auth.logon":
            ok = e.get("result") == "success"
            f["a_success" if ok else "a_fail"] += 1
            D.logons.append((d.timestamp(), ok))
            if e.get("src_host"):
                D.sets["logon_hosts"].add(e["src_host"])
            if e.get("dst"):
                D.sets["logon_dsts"].add(e["dst"])
            if str(e.get("logon_type")) in ("10", "vpn", "ssh") or e.get("method") == "vpn":
                f["a_remote"] += 1
            if off:
                f["a_off"] += 1
        elif kind == "print.job":
            f["p_pages"] += int(e.get("pages") or 0)
        elif kind == "usb.attach":
            f["u_usb"] += 1
    for D in days.values():
        D.finish()
    # rolling five days per user
    by_user = collections.defaultdict(list)
    for (u, date), D in days.items():
        by_user[u].append((date, D))
    for u, lst in by_user.items():
        lst.sort(key=lambda x: x[0])
        for i, (date, D) in enumerate(lst):
            win = [x for x in lst[max(0, i - 6):i + 1] if (date - x[0]).days <= 4]
            D.f["r5_reads"] = sum(x[1].f["f_reads"] for x in win)
            D.f["r5_pages"] = sum(x[1].f["p_pages"] for x in win)
            D.f["r5_archive"] = sum(x[1].f["f_archive_writes"] for x in win)
    return days, roles, sorted({k[1] for k in days})


class Baseline:
    def __init__(self, rows, counts=COUNTS, sets=SETS):
        """rows: list of (Day) from the baseline period"""
        self.n = len(rows)
        self.mean, self.std = {}, {}
        for k in counts:
            xs = [r.f[k] for r in rows]
            self.mean[k] = statistics.fmean(xs) if xs else 0.0
            self.std[k] = statistics.pstdev(xs) if len(xs) > 1 else 0.0
        self.sets = {k: set() for k in sets}
        for r in rows:
            for k in sets:
                self.sets[k] |= r.sets[k]

    def z(self, k, x):
        m, s = self.mean[k], self.std[k]
        floor = max(1e6, 0.2 * m) if k in BYTES else max(1.0, 0.1 * m)
        return max(-9.9, min(9.9, (x - m) / max(s, floor)))


def build_baselines(days, roles, dates_base, min_days, counts=COUNTS, sets=SETS, workdays_only=True):
    per_user, per_role, everyone = collections.defaultdict(list), collections.defaultdict(list), []
    for (u, date), D in days.items():
        if date in dates_base and (date.weekday() < 5 or not workdays_only):
            per_user[u].append(D); per_role[roles.get(u, "")].append(D); everyone.append(D)
    site = Baseline(everyone, counts, sets)
    role_b = {r: Baseline(v, counts, sets) for r, v in per_role.items()}
    out = {}
    for u in {k[0] for k in days}:
        rows = per_user.get(u, [])
        if len(rows) >= min_days:
            out[u] = ("self", Baseline(rows, counts, sets))
        elif roles.get(u) in role_b and role_b[roles[u]].n >= min_days:
            out[u] = ("role", role_b[roles[u]])
        else:
            out[u] = ("site", site)
    return out


RULES = [  # (feature, threshold, points, scenario) the transparent part of the detector
    ("n_personal_bytes", 100e6, 4, "S1"), ("n_ext_bytes_off", 300e6, 3, "S1"),
    ("new_shares", 1, 3, "S2"), ("f_burst30", 30, 2, "S2"),
    ("new_dst_int", 5, 3, "S3"), ("n_rdp_smb_short", 5, 2, "S3"), ("n_scan_ports", 15, 4, "S3"),
    ("a_fail_then_success", 1, 4, "S4"), ("new_logon_hosts", 1, 2, "S4"), ("a_off", 1, 1, "S4"),
    ("n_doh", 10, 3, "S5"), ("n_denied", 1, 1, "S5"), ("u_usb", 1, 2, "S5"),
    ("r5_pages", 100, 2, "S6"), ("r5_archive", 3, 2, "S6"),
]
Z_RULES = [("f_reads", "S2"), ("p_pages", "S6"), ("r5_reads", "S6"), ("n_ext_bytes", "S1"), ("n_dst_int", "S3"), ("a_fail", "S4")]
LABEL = {"n_personal_bytes": "個人儲存或網頁郵件傳輸 {mb}", "n_ext_bytes_off": "非工作時段對外傳輸 {mb}", "new_shares": "首次存取共享區 {v} 個",
         "f_burst30": "30 分鐘內讀取 {v} 次", "new_dst_int": "新的內部目的主機 {v} 台", "n_rdp_smb_short": "短連線 RDP/SMB {v} 次",
         "n_scan_ports": "單一主機 {v} 個埠", "a_fail_then_success": "多次失敗後登入成功", "new_logon_hosts": "新的登入來源主機 {v} 台",
         "a_off": "非工作時段登入 {v} 次", "n_doh": "DoH/代理/VPN 類連線 {v} 次", "n_denied": "被阻擋 {v} 次", "u_usb": "USB 儲存裝置 {v} 次",
         "r5_pages": "五日列印 {v} 頁", "r5_archive": "五日壓縮檔 {v} 個", "f_reads": "讀取 {v}（{z:+.1f}σ）", "p_pages": "列印 {v} 頁（{z:+.1f}σ）",
         "r5_reads": "五日累積讀取 {v}（{z:+.1f}σ）", "n_ext_bytes": "對外傳輸 {mb}（{z:+.1f}σ）", "n_dst_int": "內部目的主機 {v} 台（{z:+.1f}σ）",
         "a_fail": "登入失敗 {v} 次（{z:+.1f}σ）"}


HOST_RULES = [
    ("new_int_src", 1, 3, "S3"), ("h_recon_int", 1, 3, "S3"), ("h_int_src_n", 3, 2, "S3"), ("h_priv_off", 1, 1, "S3"),
    ("a_fail_then_success", 1, 4, "S4"), ("new_accounts", 1, 3, "S4"), ("a_ext_success", 1, 3, "S4"), ("a_off", 1, 1, "S4"),
    ("h_priv_evasion", 1, 4, "S5"), ("h_pkg_evasion", 1, 4, "S5"), ("u_usb", 1, 2, "S5"), ("h_fim_off", 5, 1, "S5"),
]
HOST_Z_RULES = [("h_int", "S3"), ("h_priv", "S3"), ("a_fail", "S4"), ("h_fim", "S5"), ("h_pkg", "S5")]
LABEL.update({"new_int_src": "新的內部來源 {v} 個", "h_recon_int": "內部來源的偵察告警 {v} 筆", "h_int_src_n": "單日內部來源 {v} 個", "h_priv_off": "非工作時段權限操作 {v} 次",
              "new_accounts": "基線未見的帳號登入 {v} 個", "a_ext_success": "公網來源登入成功 {v} 次", "h_priv_evasion": "權限操作涉及 VPN、代理或通道工具 {v} 次",
              "h_pkg_evasion": "安裝 VPN、代理或通道類套件 {v} 個", "h_fim_off": "非工作時段受監控檔案變更 {v} 筆", "h_int": "內部來源告警 {v} 筆（{z:+.1f}σ）",
              "h_priv": "權限操作 {v} 次（{z:+.1f}σ）", "h_fim": "受監控檔案變更 {v} 筆（{z:+.1f}σ）", "h_pkg": "套件變更 {v} 筆（{z:+.1f}σ）"})


def bucket_host(events, tz, exclude=()):
    """-> {(asset, date): Day}, {}, the ordered list of dates"""
    days = {}
    for e in events:
        kind = e.get("kind")
        if kind in exclude:
            continue
        d = rfc3339.parse(e.get("ts", ""))
        asset = e.get("asset") or e.get("src_host")
        if d is None or not asset:
            continue
        local = d.astimezone(tz)
        key = (asset, local.date())
        D = days.get(key)
        if D is None:
            D = days[key] = Day(HOST_SETS)
        D.events += 1
        f, off = D.f, off_hours(local)
        scope = e.get("src_scope", "")
        f["h_alerts"] += 1
        if int(e.get("rule_level") or 0) >= 10:
            f["h_high"] += 1
        if e.get("rule_id"):
            D.sets["rule_ids"].add(str(e["rule_id"]))
        if scope == "external":
            f["h_ext"] += 1
        elif scope == "internal":
            f["h_int"] += 1
            src = e.get("src_ip") or e.get("src_host")
            if src:
                D.sets["int_src"].add(src)
        if kind == "sec.alert" and scope == "internal" and e.get("rule_group") in ("recon", "web_scan"):
            f["h_recon_int"] += 1
        elif kind == "auth.logon":
            ok = e.get("result") == "success"
            f["a_success" if ok else "a_fail"] += 1
            D.logons.append((d.timestamp(), ok, e.get("src_ip") or e.get("src_host") or ""))
            if ok:
                if e.get("user"):
                    D.sets["accounts"].add(e["user"])
                if scope == "external":
                    f["a_ext_success"] += 1
                if off:
                    f["a_off"] += 1
        elif kind == "priv.exec":
            f["h_priv"] += 1
            if off:
                f["h_priv_off"] += 1
            if e.get("category") == "evasion":
                f["h_priv_evasion"] += 1
        elif kind == "file.integrity":
            f["h_fim"] += 1
            if off:
                f["h_fim_off"] += 1
        elif kind == "pkg.change":
            f["h_pkg"] += 1
            if e.get("category") == "evasion":
                f["h_pkg_evasion"] += 1
        elif kind == "malware.detect":
            f["h_malware"] += 1
        elif kind == "usb.attach":
            f["u_usb"] += 1
    for D in days.values():
        D.f["h_int_src_n"] = len(D.sets["int_src"])
        by_src = collections.defaultdict(list)        # one source's failures, not the internet's
        for t, ok, src in D.logons:
            by_src[src].append((t, ok))
        for rows in by_src.values():
            rows.sort(); fails = 0
            for t, ok in rows:
                if ok:
                    if fails >= 3:
                        D.f["a_fail_then_success"] = 1
                    fails = 0
                else:
                    fails += 1
    return days, {}, sorted({k[1] for k in days})


def score(feat, z, rules=None, z_rules=None):
    """-> (points, guessed scenario, signals). The signals are the rules that
    fired, written out, so the models read them in the first line of the
    summary instead of finding them among twenty numbers."""
    rules = RULES if rules is None else rules
    z_rules = Z_RULES if z_rules is None else z_rules
    pts, by, sig = 0.0, collections.Counter(), []
    for k, thr, p, sc in rules:
        v = feat.get(k, 0)
        if v >= thr:
            pts += p; by[sc] += p
            sig.append((sc, LABEL[k].format(v=v, mb=mb(v), z=z.get(k, 0))))
    for k, sc in z_rules:
        if z.get(k, 0) > 3:
            p = min(5.0, z[k] - 2); pts += p; by[sc] += p
            sig.append((sc, LABEL[k].format(v=feat.get(k, 0), mb=mb(feat.get(k, 0)), z=z[k])))
    guess = by.most_common(1)[0][0] if by else "NONE"
    return round(pts, 1), guess, [f"{t}（{sc} 類）" for sc, t in sig]


def text(u, date, role, src, b, f, z, new, signals):
    L = [f"使用者 {u}（角色 {role or '未知'}，基線來源 {dict(self='本人', role='同職務', site='全站')[src]}，{b.n} 個工作日）{date}（週{WEEKDAYS[date.weekday()]}）。",
         "觸發訊號：" + ("；".join(signals) if signals else "無") + "。"]
    def zs(k):
        return f"{z[k]:+.1f}σ"
    L.append(f"檔案：讀取 {f['f_reads']}（基線 {b.mean['f_reads']:.0f}±{b.std['f_reads']:.0f}，{zs('f_reads')}），寫入 {f['f_writes']}"
             + (f"，其中壓縮檔 {f['f_archive_writes']} 個共 {mb(f['f_archive_bytes'])}" if f['f_archive_writes'] else "")
             + f"，30 分鐘內最多 {f['f_burst30']} 次；"
             + (f"首次存取共享區 {len(new['shares'])} 個" if new['shares'] else "共享區皆為慣用") + "。")
    L.append(f"網路：對外連線 {f['n_ext_conns']} 次 {mb(f['n_ext_bytes'])}（基線 {mb(b.mean['n_ext_bytes'])}，{zs('n_ext_bytes')}），"
             + f"非工作時段對外 {mb(f['n_ext_bytes_off'])}，個人儲存或網頁郵件 {mb(f['n_personal_bytes'])}，新網域 {len(new['domains'])} 個；"
             + f"內部目的主機 {f['n_dst_int']} 台（新 {len(new['dst_int'])} 台），短連線 RDP/SMB {f['n_rdp_smb_short']} 次，單一主機最多 {f['n_scan_ports']} 個埠；"
             + f"被阻擋 {f['n_denied']} 次，DoH/代理/VPN 類 {f['n_doh']} 次。")
    L.append(f"登入：成功 {f['a_success']} 失敗 {f['a_fail']}" + ("，多次失敗後成功" if f['a_fail_then_success'] else "")
             + f"，遠端或 VPN {f['a_remote']}，非工作時段 {f['a_off']}；來源主機新 {len(new['logon_hosts'])} 台，登入目標新 {len(new['logon_dsts'])} 台。")
    L.append(f"列印 {f['p_pages']} 頁（基線 {b.mean['p_pages']:.1f}，{zs('p_pages')}），USB 儲存裝置 {f['u_usb']} 次。")
    L.append(f"五日累積：讀取 {f['r5_reads']}（基線 {b.mean['r5_reads']:.0f}，{zs('r5_reads')}），列印 {f['r5_pages']} 頁，壓縮檔 {f['r5_archive']} 個。")
    return "\n".join(L)


def host_text(u, date, src, b, f, z, new, signals):
    def zs(k):
        return f"{z[k]:+.1f}σ"
    return "\n".join([
        f"主機 {u}（基線來源 {dict(self='本機', role='同類', site='全站')[src]}，{b.n} 天）{date}（週{WEEKDAYS[date.weekday()]}）。",
        "觸發訊號：" + ("；".join(signals) if signals else "無") + "。",
        f"告警：共 {f['h_alerts']} 筆，公網來源 {f['h_ext']}（基線 {b.mean['h_ext']:.0f}，外部噪音不計分），內部來源 {f['h_int']}（基線 {b.mean['h_int']:.0f}，{zs('h_int')}），高嚴重度 {f['h_high']}（{zs('h_high')}）。",
        f"內部來源 {f['h_int_src_n']} 個（新 {len(new['int_src'])} 個），內部來源的偵察告警 {f['h_recon_int']} 筆。",
        f"登入：成功 {f['a_success']} 失敗 {f['a_fail']}（{zs('a_fail')}）" + ("，同來源多次失敗後成功" if f['a_fail_then_success'] else "")
        + f"，公網來源成功 {f['a_ext_success']}，非工作時段成功 {f['a_off']}；基線未見的帳號 {len(new['accounts'])} 個。",
        f"權限操作 {f['h_priv']}（基線 {b.mean['h_priv']:.1f}，{zs('h_priv')}），非工作時段 {f['h_priv_off']}，涉及 VPN、代理或通道工具 {f['h_priv_evasion']}。",
        f"受監控檔案變更 {f['h_fim']}（{zs('h_fim')}），非工作時段 {f['h_fim_off']}；套件變更 {f['h_pkg']}（{zs('h_pkg')}），其中 VPN、代理或通道類 {f['h_pkg_evasion']}；USB 儲存裝置 {f['u_usb']} 次。",
        f"基線未見的告警規則 {len(new['rule_ids'])} 種。"])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--entity", choices=("user", "host"), default="user")
    ap.add_argument("--exclude-kinds", default="", help="comma separated event kinds the summaries must not see (a blind backtest)")
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tz", default="+08:00")
    ap.add_argument("--baseline-days", type=int); ap.add_argument("--baseline-until", help="local date, first day of the test period")
    ap.add_argument("--min-baseline-days", type=int, default=5)
    ap.add_argument("--all-days", action="store_true", help="also write the baseline days (scored against the baseline they are part of)")
    ap.add_argument("--baseline-out", help="write the per-user baseline statistics (json)")
    ap.add_argument("--timing")
    a = ap.parse_args()
    if not a.baseline_days and not a.baseline_until:
        sys.exit("summarize: --baseline-days or --baseline-until is required")
    tz = parse_tz(a.tz)
    t0 = time.perf_counter()
    events = JsonlFile(a.inp)
    exclude = {x for x in a.exclude_kinds.split(",") if x}
    host = a.entity == "host"
    counts, sets = (HOST_COUNTS, HOST_SETS) if host else (COUNTS, SETS)
    if host:
        days, roles, dates = bucket_host(events, tz, exclude)
    else:
        days, roles, dates = bucket((e for e in events if e.get("kind") not in exclude) if exclude else events, tz)
    if not dates:
        sys.exit("summarize: no events")
    if a.baseline_until:
        cut = dt.date(*[int(x) for x in a.baseline_until.split("-")])
    else:
        cut = dates[0] + dt.timedelta(days=a.baseline_days)
    dates_base = {d for d in dates if d < cut}
    bl = build_baselines(days, roles, dates_base, a.min_baseline_days, counts, sets, workdays_only=not host)
    n = 0
    with open(a.out, "w", encoding="utf-8") as fo:
        for (u, date), D in sorted(days.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            if date < cut and not a.all_days:
                continue
            src, b = bl[u]
            f = {k: D.f[k] for k in counts}
            z = {k: round(b.z(k, f[k]), 2) for k in counts}
            new = {k: sorted(D.sets[k] - b.sets[k]) for k in sets}
            feat = dict(f, **{f"new_{k}": len(v) for k, v in new.items()})
            pre, guess, signals = score(feat, z, HOST_RULES, HOST_Z_RULES) if host else score(feat, z)
            rec = {"user": u, "date": date.isoformat(), "weekday": date.weekday(), "role": roles.get(u, ""), "baseline": src, "baseline_days": b.n,
                   "entity": a.entity, "events": D.events, "features": feat, "z": z, "new": new, "prescreen": pre, "guess": guess, "signals": signals,
                   "text": host_text(u, date, src, b, f, z, new, signals) if host else text(u, date, roles.get(u, ""), src, b, f, z, new, signals)}
            fo.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
            n += 1
    ms = (time.perf_counter() - t0) * 1000
    if a.baseline_out:
        with open(a.baseline_out, "w", encoding="utf-8") as f:
            json.dump({u: {"source": s, "days": b.n, "mean": b.mean, "std": b.std, "sets": {k: len(v) for k, v in b.sets.items()}} for u, (s, b) in sorted(bl.items())}, f, ensure_ascii=False, indent=1)
    if a.timing:
        with open(a.timing, "a", encoding="utf-8") as f:
            f.write(json.dumps({"stage": "summarize", "events": events.lines, "user_days": n, "ms": round(ms, 1), "ts": rfc3339.format(rfc3339.now())}) + "\n")
    print(f"summarize: {events.lines} events, {len(days)} {a.entity}-days ({len(dates_base)} baseline dates before {cut}), wrote {n}, {ms:.0f} ms")


if __name__ == "__main__":
    main()
