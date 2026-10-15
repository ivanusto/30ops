#!/usr/bin/env python3
"""check.py: the assertions of tests/e2e/run.sh, against the running stack.

  check.py baseline --rules DIR --expected FILE
  check.py alert    --sink FILE [--alert NasPoolNotOnline] [--timeout 300]
  check.py logs     --token T --kernel-log FILE
  check.py archive  --mount DIR --day-dir DIR --drills FILE [--source NAME ...]
  check.py doctor   --json FILE --allowed FILE
  check.py deadman  --sink FILE [--timeout 240]
  check.py silence  --id-file FILE            silence the Watchdog in Alertmanager
  check.py deadman-alert --sink FILE --id-file FILE [--timeout 300]
                    the deadman reports the collector silent; then the
                    silence is expired and it reports it back
  check.py readiness --ops30 BIN --site FILE --out FILE [--timeout 240]

Every mode prints one "ok" or "FAIL" line per check and exits 1 when any
check failed. Waits poll every 3 s up to the timeout given; the run is
over as soon as everything holds.
"""
import argparse
import glob
import subprocess
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


def deadman(a):
    """30ops-deadman got a push and counts the collector alive; the
    Watchdog went to no ordinary receiver, and the deadman sent nothing."""
    def pushed():
        r = prom("/api/v1/query", query="deadman_last_push_timestamp_seconds > 0 and on () deadman_alerting == 0")["result"]
        return (bool(r), "no push seen by the deadman job yet")
    done, detail = wait(pushed, a.timeout)
    ok(done, "30ops-deadman got the Watchdog (deadman_last_push_timestamp_seconds, deadman_alerting 0)", detail)
    hits, silent = [], []
    if os.path.exists(a.sink):
        for line in open(a.sink, encoding="utf-8"):
            rec = json.loads(line)
            body = rec["body"] if isinstance(rec["body"], dict) else {}
            names = {x.get("labels", {}).get("alertname") for x in body.get("alerts", [])}
            if "Watchdog" in names:
                hits.append(rec["path"])
            if "CollectorSilent" in names:
                silent.append(rec["path"])
    ok(not hits, "no ordinary receiver got the Watchdog", ", ".join(hits))
    ok(not silent, "the deadman did not report the collector silent", ", ".join(silent))
    up = prom("/api/v1/query", query='up{job="switch-snmp"} == 1 and on (instance) sysUpTime')["result"]
    ok(bool(up), "the switch answers SNMP (switch-snmp up, sysUpTime present)")


def silence(a):
    """Silence the Watchdog: Alertmanager stops pushing it, as when someone
    silences everything or Alertmanager stops, while Prometheus keeps
    scraping the deadman (the target stays up)."""
    now = time.time()
    body = json.dumps({"matchers": [{"name": "alertname", "value": "Watchdog", "isRegex": False, "isEqual": True}],
                       "startsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                       "endsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 1800)),
                       "createdBy": "e2e", "comment": "stop the deadman pushes"}).encode()
    req = urllib.request.Request(f"{AM}/api/v2/silences", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        sid = json.loads(r.read())["silenceID"]
    with open(a.id_file, "w", encoding="utf-8") as f:
        f.write(sid)
    ok(bool(sid), f"the Watchdog is silenced ({sid})")


def _deadman_posts(sink, status):
    if not os.path.exists(sink):
        return []
    out = []
    for line in open(sink, encoding="utf-8"):
        rec = json.loads(line)
        body = rec["body"] if isinstance(rec["body"], dict) else {}
        for x in body.get("alerts", []):
            if x.get("labels", {}).get("alertname") == "CollectorSilent" and x.get("status") == status:
                out.append(rec["path"])
    return out


def deadman_alert(a):
    done, detail = wait(lambda: (bool(_deadman_posts(a.sink, "firing")), "no CollectorSilent yet"), a.timeout)
    ok(done, "30ops-deadman reported the collector silent (CollectorSilent firing)", detail)
    if done:
        print(f"     delivered to {', '.join(sorted(set(_deadman_posts(a.sink, 'firing'))))}")
    sid = open(a.id_file, encoding="utf-8").read().strip()
    req = urllib.request.Request(f"{AM}/api/v2/silence/{sid}", method="DELETE")
    urllib.request.urlopen(req, timeout=10).close()
    done, detail = wait(lambda: (bool(_deadman_posts(a.sink, "resolved")), "no CollectorSilent resolved yet"), a.timeout)
    ok(done, "after the silence expired, 30ops-deadman reported the collector back", detail)

    def alive():
        r = prom("/api/v1/query", query='deadman_alerting == 0 and on () up{job="deadman"} == 1')["result"]
        return (bool(r), "deadman_alerting not back to 0")
    done, detail = wait(alive, a.timeout)
    ok(done, "deadman_alerting is 0 again and the deadman target is up", detail)


# check.py readiness: the status each item of tests/e2e/site.yaml must have.
# Two statuses where the fake LAN's timing decides (an alert that fires or
# not before the item is asked); site.yaml accepts those, with the reason.
READINESS = {
    "pkg-images-pinned": {"yes"}, "pkg-render-clean": {"yes"}, "pkg-release-verified": {"yes"},
    "pkg-rollback": {"accepted"},
    "targets-up": {"yes"}, "textfiles-fresh": {"yes"}, "alert-path": {"yes"}, "deadman": {"yes"},
    "journald-coverage": {"yes"}, "switch-monitored": {"yes"}, "switch-in-assets": {"yes"},
    "pve-quorum": {"yes"}, "restore-drill-pve": {"accepted"}, "restore-drill-nas": {"accepted"},
    "offsite-copy": {"accepted"}, "nas-snapshots": {"yes"}, "ups-present": {"accepted"},
    "backup-of-backup": {"accepted"},
    "logs-worm": {"yes"}, "fw-reviewed": {"yes"}, "eol": {"yes", "accepted"}, "change-records": {"accepted"},
    "audit-attributed": {"yes", "accepted"}, "rollback-drilled": {"yes", "accepted"},
    "second-approver": {"accepted"}, "change-effort": {"accepted"},
}


def readiness(a):
    last = {}

    def run():
        nonlocal last
        p = subprocess.run([a.ops30, "readiness", "--site", a.site, "--format", "json"], capture_output=True, text=True)
        if p.returncode not in (0, 1):
            return (False, f"exit {p.returncode}: {p.stderr.strip()[-300:]}")
        last = json.loads(p.stdout)
        got = {r["id"]: r["status"] for r in last["results"]}
        bad = [f"{i}={got.get(i)}" for i, want in READINESS.items() if got.get(i) not in want]
        extra = sorted(set(got) - set(READINESS))
        if extra:
            bad.append(f"unexpected items {', '.join(extra)}")
        return (not bad and p.returncode == 0, "; ".join(bad) or f"exit {p.returncode}")
    done, detail = wait(run, a.timeout, interval=10)
    if last:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(last, f, ensure_ascii=False, indent=2)
        for r in last["results"]:
            print(f"     {r['status']:<8} {r['id']}: {r['evidence']}")
    ok(done, f"readiness: {len(READINESS)} items as expected, no unaccepted no", detail)


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
    dm = sub.add_parser("deadman")
    dm.add_argument("--sink", required=True)
    dm.add_argument("--timeout", type=int, default=240)
    si = sub.add_parser("silence")
    si.add_argument("--id-file", required=True)
    da = sub.add_parser("deadman-alert")
    da.add_argument("--sink", required=True)
    da.add_argument("--id-file", required=True)
    da.add_argument("--timeout", type=int, default=300)
    rd = sub.add_parser("readiness")
    rd.add_argument("--ops30", required=True)
    rd.add_argument("--site", required=True)
    rd.add_argument("--out", required=True)
    rd.add_argument("--timeout", type=int, default=240)
    a = ap.parse_args(argv)
    {"baseline": baseline, "alert": alert, "logs": logs, "archive": archive, "doctor": doctor,
     "deadman": deadman, "silence": silence, "deadman-alert": deadman_alert, "readiness": readiness}[a.mode](a)
    print(f"check.py {a.mode}: {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
