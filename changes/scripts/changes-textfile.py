#!/usr/bin/env python3
"""changes-textfile: the change records as metrics, so the dashboard can
say "a change window is open on qdevice right now" and a rule can say "a
window closed an hour ago and nobody marked the record done".

    scripts/changes-textfile.py --out /var/lib/node_exporter/textfile/changes.prom

The collector keeps a clone of this repository (cron pulls it, see
collector.cron); the metrics are read from that clone's changes/*.md.

Metrics
    change_record{id,status,type,risk,implementer,approver} 1    one per record
    change_window_start_timestamp{id}                             records with a window
    change_window_end_timestamp{id}
    change_records{status}                                       count per status (0 rows for every status)
    changes_textfile_last_run_timestamp
"""
import argparse
import glob
import os
import sys
import tempfile
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from frontmatter import parse  # noqa: E402
from check import STATUSES  # noqa: E402


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def ts(s):
    try:
        d = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
        return int(d.timestamp()) if d.tzinfo else None
    except (ValueError, AttributeError):
        return None


def render(files, now):
    L = []
    def fam(n, h): L.extend([f"# HELP {n} {h}", f"# TYPE {n} gauge"])
    recs = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            meta, _, _ = parse(fh.read())
        recs.append(meta)
    fam("change_record", "One per change record in changes/, with its status")
    for m in recs:
        L.append('change_record{id="%s",status="%s",type="%s",risk="%s",implementer="%s",approver="%s"} 1'
                 % tuple(esc(m.get(k, "")) for k in ("id", "status", "type", "risk", "implementer", "approver")))
    fam("change_window_start_timestamp", "Unix time the change window opens")
    for m in recs:
        t = ts(m.get("window_start", ""))
        if t is not None:
            L.append(f'change_window_start_timestamp{{id="{esc(m["id"])}",status="{esc(m["status"])}"}} {t}')
    fam("change_window_end_timestamp", "Unix time the change window closes")
    for m in recs:
        t = ts(m.get("window_end", ""))
        if t is not None:
            L.append(f'change_window_end_timestamp{{id="{esc(m["id"])}",status="{esc(m["status"])}"}} {t}')
    fam("change_records", "Number of records per status (every status is written, 0 included)")
    for s in STATUSES:
        L.append(f'change_records{{status="{s}"}} {sum(1 for m in recs if m.get("status") == s)}')
    fam("changes_textfile_last_run_timestamp", "Unix time of the last changes-textfile run")
    L.append(f"changes_textfile_last_run_timestamp {int(now)}")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "changes"))
    ap.add_argument("--out")
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.dir, "CR-*.md")))
    body = render(files, time.time())
    if a.out:
        d = os.path.dirname(os.path.abspath(a.out))
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".changes.")
        with os.fdopen(fd, "w") as f:
            f.write(body)
        os.chmod(tmp, 0o644)
        os.replace(tmp, a.out)
    else:
        sys.stdout.write(body)


if __name__ == "__main__":
    main()
