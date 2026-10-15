"""30ops readiness: the checklist (checks/readiness/checklist.yaml and the
plugins' items) answered for one site, each item yes, no, unknown or
accepted, with the evidence. docs/readiness.md.

Two steps, so the collector's cron needs neither site.yaml nor PyYAML:

  plan(site)        render time: the items that apply to the site, their
                    PromQL with the site's thresholds filled in, the answers
                    that come from site.yaml alone, readiness.accept and
                    readiness.answers, and the facts the built-in checks
                    need (hosts, textfiles). render writes it as
                    /etc/30ops/readiness.json.
  evaluate(plan, query, local)
                    run time: ask Prometheus (query(expr) -> result list or
                    None) and, on the collector, the doctor checks.

Statuses: yes; no; unknown (no data, a manual item without an answer, a
local check not run); accepted (not yes, and site.yaml says why that is
fine). An accepted item is still listed with its evidence.
"""
import json
import os
import re
import time

YES, NO, UNKNOWN, ACCEPTED = "yes", "no", "unknown", "accepted"
STATUSES = (YES, NO, UNKNOWN, ACCEPTED)
CATEGORIES = ("packaging", "node-guard", "storage-backup", "change-mgmt")
TYPES = ("promql", "builtin", "site", "local", "manual")
REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
CHECKLIST = os.path.join(REPO, "checks", "readiness", "checklist.yaml")
PLAN_VERSION = 1


# ---------- the checklist ----------

def checklist():
    """Core items, then every plugin's (ids prefixed), with "plugin" set."""
    from . import plugins, yamlio
    items = [dict(i) for i in yamlio.load(CHECKLIST)["items"]]
    for name in plugins.available():
        for i in plugins.readiness_items(name):
            items.append({**i, "id": f"{name}:{i['id']}", "plugin": name})
    return items


def item_ids():
    return {i["id"]: i for i in checklist()}


# ---------- plan (render time, needs the resolved site) ----------

def _site_has(site, what):
    if what == "worm":
        return bool(site.get("worm"))
    if what == "gate":
        return bool((site.get("gate") or {}).get("targets"))
    raise ValueError(f"unknown applies.site {what!r}")


def applies(site, item, enabled):
    if item.get("plugin") and item["plugin"] not in enabled:
        return False
    a = item.get("applies") or {}
    if "role" in a and not any(set(a["role"]) & set(h["roles"]) for h in site["hosts"]):
        return False
    if "site" in a and not _site_has(site, a["site"]):
        return False
    return True


def _journald_coverage(site, facts):
    col = site["collector"]["host"]
    miss = [h["name"] for h in site["hosts"]
            if h.get("vendor") in ("linux", "pve") and h["name"] != col and "journal" not in h["roles"]]
    if miss:
        return NO, f"no journal upload from {', '.join(miss)}"
    n = sum(1 for h in site["hosts"] if "journal" in h["roles"])
    return YES, f"{n} hosts ship their journal"


def _switch_in_assets(site, facts):
    from . import site as S
    names = [s["name"] for s in facts["switches_all"]]
    if not site.get("assets"):
        return NO, "site.yaml has no assets file"
    try:
        rows = S.read_assets(os.path.join(site["base"], site["assets"]))
    except (S.SiteError, OSError) as e:
        return UNKNOWN, str(e)
    have = {r["asset"] for r in rows}
    miss = [n for n in names if n not in have]
    if miss:
        return NO, f"not in {site['assets']}: {', '.join(miss)}"
    return YES, f"{len(names)} in {site['assets']}"


SITE_CHECKS = {"journald_coverage": _journald_coverage, "switch_in_assets": _switch_in_assets}


def facts(site):
    """What the built-in checks need to know about the site, as plain data."""
    from . import site as S
    from .render import cron
    dm = site["alerting"].get("deadman")
    dh = S.deadman_host(site)
    cron_text = "\n".join(cron.lines(site))
    tfs = [[name, p, age] for name, (p, age) in cron.TEXTFILES.items()
           if re.search(rf"[ /]{re.escape(name)}\b", cron_text) and name != "readiness.prom"]
    al = site["alerting"]
    receivers = {n: bool(r and (r.get("email") or r.get("webhook"))) for n, r in (al.get("receivers") or {}).items()}
    sw = [h for h in site["hosts"] if set(h["roles"]) & {"switch", "ap"}]
    return {
        "textfiles": tfs,
        "receivers": receivers,
        "deadman": None if not dm else {
            "host": dh["name"] if dh else None, "address": dh["address"] if dh else None,
            "port": dm["port"], "after_s": dm["after_s"], "healthchecks": bool(dm.get("healthchecks"))},
        "switches_all": [{"name": h["name"], "address": h["address"]} for h in sw],
        "switches": [{"name": h["name"], "address": h["address"]} for h in sw if h.get("snmp")],
        "nas": [{"name": h["name"], "nas": h["labels"].get("nas", h["name"]), "ups_none": h.get("ups") == "none"}
                for h in site["hosts"] if "nas" in h["roles"]],
    }


def plan(site):
    """The site's readiness plan (JSON-serialisable)."""
    from . import plugins, site as S, version
    from .render import rules
    values = S.thresholds(site)
    enabled = plugins.enabled(site)
    rd = site.get("readiness") or {}
    accept, answers = rd.get("accept") or {}, rd.get("answers") or {}
    f = facts(site)
    items = []
    for it in checklist():
        if not applies(site, it, enabled):
            continue
        c = dict(it["check"])
        for k in ("ok", "bad"):
            if k in c:
                c[k] = rules.fill(c[k], values, f"readiness {it['id']}")
        x = {"id": it["id"], "category": it["category"], "question": it["question"], "check": c}
        if c["type"] == "site":
            x["static"] = list(SITE_CHECKS[c["name"]](site, f))
        if it["id"] in accept:
            x["accept"] = accept[it["id"]]
        if it["id"] in answers:
            x["answer"] = answers[it["id"]]
        items.append(x)
    return {"plan": PLAN_VERSION, "site": site["site"]["id"], "locale": site["site"]["locale"],
            "tool": f"30ops {version()}", "facts": f, "items": items}


# ---------- evaluate (run time) ----------

def _labels(series, show=None):
    m = series.get("metric") or {}
    if show and show in m:
        return m[show]
    return ",".join(f"{k}={v}" for k, v in sorted(m.items()) if k not in ("__name__", "job"))


def _few(names, n=5):
    names = sorted(set(names))
    return ", ".join(names[:n]) + (f" and {len(names) - n} more" if len(names) > n else "")


def _value(series):
    try:
        return float(series["value"][1])
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def check_promql(c, query):
    res = {}
    for k in ("ok", "bad"):
        if k in c:
            res[k] = query(c[k])
            if res[k] is None:
                return UNKNOWN, f"query failed or Prometheus did not answer: {c[k]}"
    if "ok" in c and not res["ok"]:
        return NO, f"no data: {c['ok']}"
    if res.get("bad"):
        return NO, f"{len(res['bad'])} found: {_few(_labels(s, c.get('show')) for s in res['bad'])}"
    n = len(res.get("ok") or [])
    return YES, f"{n} series" if "ok" in c else "none found"


def b_textfiles_fresh(f, query):
    stale, seen = [], 0
    for name, prefix, age in f["textfiles"]:
        r = query(f"time() - {prefix}_last_run_timestamp")
        if r is None:
            return UNKNOWN, "Prometheus did not answer"
        if not r:
            stale.append(f"{name} never written")
            continue
        seen += 1
        old = [s for s in r if (_value(s) or 0) > age]
        if old:
            stale.append(f"{name} {int(max(_value(s) for s in old))} s old (limit {age})")
    if stale:
        return NO, "; ".join(stale)
    return YES, f"{seen} textfiles within their limits"


def b_alert_path(f, query):
    r = query("max(prometheus_notifications_alertmanagers_discovered)")
    if r is None:
        return UNKNOWN, "Prometheus did not answer"
    if not r or (_value(r[0]) or 0) < 1:
        return NO, "Prometheus has no Alertmanager"
    empty = [n for n, ok in f["receivers"].items() if not ok]
    if empty:
        return NO, f"receivers with no email and no webhook: {', '.join(sorted(empty))}"
    return YES, f"Alertmanager reached; {len(f['receivers'])} receivers send somewhere"


def b_deadman(f, query):
    d = f["deadman"]
    if not d:
        return NO, "site.yaml alerting.deadman is not set"
    if d["host"]:
        a = query("deadman_alerting")
        t = query("time() - deadman_last_push_timestamp_seconds")
        if a is None or t is None:
            return UNKNOWN, "Prometheus did not answer"
        if not a or not t:
            return NO, f"30ops-deadman on {d['host']} is not scraped (job deadman)"
        if any((_value(s) or 0) >= 1 for s in a):
            return NO, f"30ops-deadman on {d['host']} reports the collector silent"
        age = min(_value(s) or 0 for s in t)
        if age > d["after_s"]:
            return NO, f"last push {int(age)} s ago (limit {d['after_s']})"
        return YES, f"30ops-deadman on {d['host']} got a push {int(age)} s ago"
    w = query('ALERTS{alertname="Watchdog",alertstate="firing"}')
    if w is None:
        return UNKNOWN, "Prometheus did not answer"
    if not w:
        return NO, "Watchdog is not firing"
    return YES, "Watchdog fires and goes to the external check URL (its delivery is seen there, not here)"


def b_switch_monitored(f, query):
    if not f["switches_all"]:
        return NO, "site.yaml lists no switch or access point"
    no_snmp = sorted({s["name"] for s in f["switches_all"]} - {s["name"] for s in f["switches"]})
    if no_snmp:
        return NO, f"no snmp.auth: {', '.join(no_snmp)}"
    r = query('up{job="switch-snmp"}')
    if r is None:
        return UNKNOWN, "Prometheus did not answer"
    up = {s["metric"].get("instance"): _value(s) for s in r}
    bad = [s["name"] for s in f["switches"] if up.get(s["address"]) != 1]
    if bad:
        return NO, f"not answering: {', '.join(bad)}"
    return YES, f"{len(f['switches'])} answering SNMP"


def b_ups_present(f, query):
    r = query("qnap_ups_status")
    if r is None:
        return UNKNOWN, "Prometheus did not answer"
    state = {}
    for s in r:
        m = s.get("metric") or {}
        state[m.get("nas")] = m.get("qnap_ups_status")
    absent, accepted, nodata = [], [], []
    for n in f["nas"]:
        st = state.get(n["nas"])
        if st is None:
            nodata.append(n["name"])
        elif st == "-1":
            (accepted if n["ups_none"] else absent).append(n["name"])
    if absent:
        return NO, f"no UPS: {', '.join(absent)}"
    if nodata and not accepted:
        return UNKNOWN, f"no SNMP data: {', '.join(nodata)}"
    if accepted:
        return ACCEPTED, f"no UPS, site.yaml ups: none: {', '.join(accepted)}" + (
            f"; no SNMP data: {', '.join(nodata)}" if nodata else "")
    return YES, f"{len(f['nas'])} NAS report a UPS"


def b_second_approver(f, query):
    r = query('change_record{status=~"approved|scheduled|in_progress|done|rolled_back"}')
    if r is None:
        return UNKNOWN, "Prometheus did not answer"
    if not r:
        return UNKNOWN, "no approved change record"
    same = [s["metric"].get("id", "?") for s in r if s["metric"].get("approver") == s["metric"].get("implementer")]
    if same:
        return NO, f"approved by their implementer: {_few(same)}"
    return YES, f"{len(r)} records, each approved by someone else"


def b_change_effort(f, query):
    done = query('change_window_end_timestamp{status="done"} > time() - 90 * 86400')
    eff = query("change_effort_minutes")
    if done is None or eff is None:
        return UNKNOWN, "Prometheus did not answer"
    if not done:
        return UNKNOWN, "no change done in the last 90 days"
    have = {s["metric"].get("id") for s in eff}
    miss = [s["metric"].get("id", "?") for s in done if s["metric"].get("id") not in have]
    if miss:
        return NO, f"no effort_min: {_few(miss)}"
    total = sum(_value(s) or 0 for s in eff if s["metric"].get("id") in {x["metric"].get("id") for x in done})
    return YES, f"{len(done)} changes, {int(total)} staff minutes"


BUILTINS = {"textfiles_fresh": b_textfiles_fresh, "alert_path": b_alert_path, "deadman": b_deadman,
            "switch_monitored": b_switch_monitored, "ups_present": b_ups_present,
            "second_approver": b_second_approver, "change_effort": b_change_effort}


def evaluate(p, query, local=None):
    """[{id, category, question, status, evidence, accept?}] in plan order.
    local(names) -> [(status, detail)] runs doctor checks, or None to skip."""
    out = []
    for it in p["items"]:
        c = it["check"]
        t = c["type"]
        if t == "promql":
            st, ev = check_promql(c, query)
        elif t == "builtin":
            st, ev = BUILTINS[c["name"]](p["facts"], query)
        elif t == "site":
            st, ev = it["static"]
        elif t == "local":
            if local is None:
                st, ev = UNKNOWN, "not checked here (run 30ops readiness --site on the collector, as root)"
            else:
                res = local(c["doctor"])
                bad = [d for s, d in res if s != "ok"]
                st = YES if not bad else (NO if any(s == "fail" for s, _ in res) else UNKNOWN)
                ev = "; ".join(bad) if bad else "; ".join(d for _, d in res)
        elif t == "manual":
            if it.get("answer"):
                st, ev = YES, it["answer"]
            else:
                st, ev = UNKNOWN, f"manual: {c['hint']}"
        else:
            raise ValueError(f"{it['id']}: unknown check type {t}")
        r = {"id": it["id"], "category": it["category"], "question": it["question"], "type": t,
             "status": st, "evidence": ev}
        if it.get("accept"):
            r["accept"] = it["accept"]
            if st in (NO, UNKNOWN):
                r["status"] = ACCEPTED
        out.append(r)
    return out


def counts(results):
    return {s: sum(1 for r in results if r["status"] == s) for s in STATUSES}


def exit_code(results, strict=False):
    bad = {NO, UNKNOWN} if strict else {NO}
    return 1 if any(r["status"] in bad for r in results) else 0


# ---------- output ----------

LABEL = {"zh-TW": {"packaging": "封裝與版本", "node-guard": "監控與告警路徑", "storage-backup": "儲存與備份",
                   "change-mgmt": "變更、日誌與稽核", YES: "是", NO: "否", UNKNOWN: "未知", ACCEPTED: "明示接受",
                   "item": "項目", "question": "問題", "status": "結果", "evidence": "證據", "accepted_because": "接受理由"},
         "en": {"packaging": "Packaging", "node-guard": "Monitoring and alert path", "storage-backup": "Storage and backup",
                "change-mgmt": "Changes, logs and audit", YES: "yes", NO: "no", UNKNOWN: "unknown", ACCEPTED: "accepted",
                "item": "Item", "question": "Question", "status": "Result", "evidence": "Evidence",
                "accepted_because": "accepted because"}}


def _md_cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def report(p, results, fmt="text", now=None):
    n = counts(results)
    if fmt == "json":
        return json.dumps({"site": p["site"], "tool": p["tool"], "results": results, "counts": n},
                          ensure_ascii=False, indent=2) + "\n"
    if fmt == "md":
        loc = p.get("locale") if p.get("locale") in LABEL else "en"
        lb = LABEL[loc]
        t = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(now if now is not None else time.time()))
        out = [f"# 30ops readiness: {p['site']}", "",
               f"{p['tool']}, {t}. " + ", ".join(f"{lb[s]} {n[s]}" for s in STATUSES), ""]
        for cat in CATEGORIES:
            rows = [r for r in results if r["category"] == cat]
            if not rows:
                continue
            out += [f"## {lb[cat]}", "", f"| {lb['item']} | {lb['question']} | {lb['status']} | {lb['evidence']} |",
                    "|---|---|---|---|"]
            for r in rows:
                ev = r["evidence"] + (f" ({lb['accepted_because']}: {r['accept']})" if r.get("accept") else "")
                out.append(f"| `{r['id']}` | {_md_cell(r['question'].get(loc, r['question'].get('en', '')))} | "
                           f"{lb[r['status']]} | {_md_cell(ev)} |")
            out.append("")
        return "\n".join(out)
    lines = [f"{r['status']:<8} {r['id']}: {r['evidence']}" + (f" (accepted: {r['accept']})" if r.get("accept") else "")
             for r in results]
    lines.append("30ops readiness: " + ", ".join(f"{n[s]} {s}" for s in STATUSES))
    return "\n".join(lines) + "\n"


def textfile(results, now):
    """readiness.prom: one readiness_item per item (local ones left out:
    the cron job cannot run them), the count per status, the run time."""
    from .textfile import esc, family
    rs = [r for r in results if r["type"] != "local"]
    L = []
    family(L, "readiness_item", "One per readiness item: its id, category and status (docs/readiness.md)")
    for r in rs:
        L.append(f'readiness_item{{id="{esc(r["id"])}",category="{esc(r["category"])}",status="{r["status"]}"}} 1')
    family(L, "readiness_items", "Number of readiness items per status (every status is written, 0 included)")
    for s, k in counts(rs).items():
        L.append(f'readiness_items{{status="{s}"}} {k}')
    family(L, "readiness_textfile_last_run_timestamp", "Unix time of the last readiness run")
    L.append(f"readiness_textfile_last_run_timestamp {int(now)}")
    return "\n".join(L) + "\n"


# ---------- site.yaml readiness: validation ----------

def validate_site(doc, errs, warns):
    rd = doc.get("readiness")
    if not isinstance(rd, dict):
        return
    try:
        known = item_ids()
    except Exception as e:   # noqa: BLE001  (a broken checklist must not hide the site's own errors)
        errs.append(f"readiness: cannot read the checklist: {e}")
        return
    for k in ("accept", "answers"):
        for i, v in (rd.get(k) or {}).items() if isinstance(rd.get(k), dict) else ():
            if i not in known:
                errs.append(f"readiness.{k}.{i}: not a readiness item (checks/readiness/checklist.yaml, plugin.yaml)")
            elif not isinstance(v, str) or not v.strip():
                errs.append(f"readiness.{k}.{i}: give the reason or the evidence as text")
            elif k == "answers" and known[i]["check"]["type"] != "manual":
                errs.append(f"readiness.answers.{i}: only a manual item takes an answer; "
                            f"this one is checked ({known[i]['check']['type']})")
