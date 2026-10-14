#!/usr/bin/env python3
"""check.py: the assertions of tests/e2e/run.sh, against the running stack.

  check.py baseline --rules DIR --expected FILE
  check.py alert    --sink FILE [--alert NasPoolNotOnline] [--timeout 300]
  check.py logs     --token T --kernel-log FILE
  check.py archive  --mount DIR --day-dir DIR --drills FILE [--source NAME ...]
  check.py doctor   --json FILE --allowed FILE

Every mode prints one "ok" or "FAIL" line per check and exits 1 when any
check failed. Waits poll every 3 s up to the timeout given; the run is
over as soon as everything holds.
"""
import argparse
import glob
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

PROM = os.environ.get("PROM", "http://127.0.0.1:9090")
AM = os.environ.get("AM", "http://127.0.0.1:9093")
VL = os.environ.get("VL", "http://127.0.0.1:9428")
failed = []


def ok(cond, what, detail=""):
    print(("ok   " if cond else "FAIL ") + what + (f": {detail}" if detail and not cond else ""))
    if not cond:
        failed.append(what)
    return cond


def get(url, data=None, timeout=10):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode() if data else None)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode()


def prom(path, **q):
    return json.loads(get(f"{PROM}{path}?{urllib.parse.urlencode(q)}"))["data"]


def wait(fn, timeout, interval=3):
    """fn() -> (done, detail); returns the last (done, detail)."""
    end = time.monotonic() + timeout
    while True:
        try:
            r = fn()
        except OSError as e:
            r = (False, str(e))
        if r[0] or time.monotonic() >= end:
            return r
        time.sleep(interval)


def vl_query(q, limit=100):
    raw = get(f"{VL}/select/logsql/query", {"query": q, "limit": str(limit)})
    return [json.loads(x) for x in raw.splitlines() if x.strip()]


def baseline(a):
    def targets():
        t = prom("/api/v1/targets", state="active")["activeTargets"]
        bad = [f"{x['labels'].get('job')}/{x['labels'].get('instance')}={x['health']}"
               for x in t if x["health"] != "up"]
        return (bool(t) and not bad, ", ".join(bad) or "no targets")
    done, detail = wait(targets, a.timeout)
    ok(done, "every target up", detail)
    jobs = {x["labels"]["job"] for x in prom("/api/v1/targets", state="active")["activeTargets"]}
    print(f"     jobs: {', '.join(sorted(jobs))}")

    names = [x.split("#")[0].strip() for x in open(a.expected, encoding="utf-8")]
    names = [x for x in names if x]

    def present():
        miss = [n for n in names if not prom("/api/v1/query", query=f"count({{__name__=~\"{n}\"}})")["result"]]
        return (not miss, "missing " + ", ".join(miss))
    done, detail = wait(present, a.timeout)
    ok(done, f"{len(names)} expected metric names present", detail)

    want = sum(len(re.findall(r"^\s*- alert:", open(f, encoding="utf-8").read(), re.M))
               for f in glob.glob(os.path.join(a.rules, "*.yml")))
    got = sum(1 for g in prom("/api/v1/rules", type="alert")["groups"] for _ in g["rules"])
    ok(got == want and want > 0, f"{got} alerting rules loaded", f"rendered rules have {want}")

    firing = sorted({x["labels"]["alertname"] for x in prom("/api/v1/alerts")["alerts"] if x["state"] == "firing"})
    print(f"     firing now: {', '.join(firing) or 'none'}")
    ok(a.alert not in firing, f"{a.alert} not firing before the fault")


def alert(a):
    def am():
        al = json.loads(get(f"{AM}/api/v2/alerts?active=true"))
        hit = [x for x in al if x["labels"].get("alertname") == a.alert]
        return (bool(hit), f"{len(al)} active, none named {a.alert}")
    done, detail = wait(am, a.timeout)
    ok(done, f"Alertmanager has {a.alert} active", detail)

    def sink():
        if not os.path.exists(a.sink):
            return (False, "no POST yet")
        for line in open(a.sink, encoding="utf-8"):
            rec = json.loads(line)
            body = rec["body"] if isinstance(rec["body"], dict) else {}
            for x in body.get("alerts", []):
                if x.get("labels", {}).get("alertname") == a.alert and x.get("status") == "firing":
                    return (True, rec["path"])
        return (False, "POSTs, none firing " + a.alert)
    done, detail = wait(sink, 120)
    ok(done, f"the webhook receiver got {a.alert} firing", detail)
    if done:
        print(f"     delivered to {detail}")


def logs(a):
    t = a.token

    def found(q, what):
        def fn():
            rows = vl_query(q)
            return (bool(rows), f"0 rows for {q}")
        done, detail = wait(fn, a.timeout)
        ok(done, what, detail)

    found(f'"{t}-nas" hostname:nas-primary', "syslog from nas-primary (514/tcp, allowlisted) is in VictoriaLogs")
    found(f'"{t}-audit" audit:fortigate', "the FortiGate event log on 515 carries audit=fortigate")
    found(f'"{t}-journal" SYSLOG_IDENTIFIER:ops30-e2e', "the collector's own journal arrives through journal-upload")
    rows = vl_query(f'"{t}-blocked"')
    ok(not rows, "syslog from 192.0.2.66 (not allowlisted) is not in VictoriaLogs", f"{len(rows)} rows")
    klog = open(a.kernel_log, encoding="utf-8", errors="replace").read()
    ok(re.search(r"\[DOCKER-USER DROP\] .*SRC=192\.0\.2\.66 .*DPT=514", klog) is not None,
       "the drop of 192.0.2.66 is in the kernel log")


def archive(a):
    files = set(os.listdir(a.day_dir)) if os.path.isdir(a.day_dir) else set()
    ok({"MANIFEST.tsv", "SHA256SUMS"} <= files, f"archive day {a.day_dir} is complete", ", ".join(sorted(files)))
    manifest = open(os.path.join(a.day_dir, "MANIFEST.tsv"), encoding="utf-8").read() if "MANIFEST.tsv" in files else ""
    srcs = {line.split("\t")[0] for line in manifest.splitlines() if line and not line.startswith("#")}
    want = set(a.sources)
    ok(want <= srcs, f"the archive has {', '.join(sorted(want))}", f"MANIFEST.tsv lists {', '.join(sorted(srcs))}")
    mounts = open("/proc/mounts", encoding="utf-8").read()
    ok(re.search(rf"^\S+ {re.escape(a.mount)} nfs4 ", mounts, re.M) is not None, f"the WORM share at {a.mount} is an nfs4 mount")
    recs = [json.loads(x) for x in open(a.drills, encoding="utf-8") if x.strip()] if os.path.exists(a.drills) else []
    last = recs[-1] if recs else {}
    ok(last.get("v") == 1 and last.get("kind") == "logs-restore" and last.get("result") == "pass",
       "verify-archive wrote a passing drills v1 record", json.dumps(last)[:200])


def doctor(a):
    doc = json.load(open(a.json, encoding="utf-8"))
    allowed = {x.split("#")[0].strip() for x in open(a.allowed, encoding="utf-8")} - {""}
    fails = [f"{r['check']}: {r['detail']}" for r in doc["results"] if r["status"] == "fail"]
    warns = [r for r in doc["results"] if r["status"] == "warn"]
    ok(not fails, "doctor: no failure", "; ".join(fails))
    extra = [f"{r['check']}: {r['detail']}" for r in warns if r["check"] not in allowed]
    ok(not extra, "doctor: warnings only where tests/e2e/allowed-warn.txt allows", "; ".join(extra))
    print(f"     doctor: {len(doc['results']) - len(warns) - len(fails)} ok, {len(warns)} warn, {len(fails)} fail")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    b = sub.add_parser("baseline")
    b.add_argument("--rules", required=True)
    b.add_argument("--expected", required=True)
    b.add_argument("--alert", default="NasPoolNotOnline")
    b.add_argument("--timeout", type=int, default=240)
    al = sub.add_parser("alert")
    al.add_argument("--sink", required=True)
    al.add_argument("--alert", default="NasPoolNotOnline")
    al.add_argument("--timeout", type=int, default=300)
    lg = sub.add_parser("logs")
    lg.add_argument("--token", required=True)
    lg.add_argument("--kernel-log", required=True)
    lg.add_argument("--timeout", type=int, default=120)
    ar = sub.add_parser("archive")
    ar.add_argument("--mount", required=True)
    ar.add_argument("--day-dir", required=True)
    ar.add_argument("--drills", required=True)
    ar.add_argument("--source", dest="sources", action="append", default=[])
    d = sub.add_parser("doctor")
    d.add_argument("--json", required=True)
    d.add_argument("--allowed", required=True)
    a = ap.parse_args(argv)
    {"baseline": baseline, "alert": alert, "logs": logs, "archive": archive, "doctor": doctor}[a.mode](a)
    print(f"check.py {a.mode}: {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
