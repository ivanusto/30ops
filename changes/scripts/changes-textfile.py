#!/usr/bin/env python3
"""changes-textfile: the change records as metrics, so the dashboard can
say "a change window is open on qdevice right now" and a rule can say "a
window closed an hour ago and nobody marked the record done".

    scripts/changes-textfile.py --out /var/lib/node_exporter/textfile/changes.prom

The collector keeps a clone of this repository (cron pulls it; the line is
in the cron file 30ops render writes); the metrics are read from that clone's changes/*.md.

Day 28 adds drills/drills.jsonl (what drills/drill.sh appends, committed
with the drill record): for every record that a drill rolled back
(rollback_of), the most recent drill's time and result, so a rule can say
"a high-risk change is done and its rollback has never been tried".

Metrics
    change_record{id,status,type,risk,implementer,approver} 1    one per record
    change_window_start_timestamp{id}                             records with a window
    change_window_end_timestamp{id}
    change_records{status}                                       count per status (0 rows for every status)
    change_rollback_last_drill_timestamp{id}                      unix time of the last rollback drill of this record
    change_rollback_last_drill_result{id}                         1 OK, 0 FAIL
    change_rollback_drills_total{id}                              rollback drills recorded for this record
    change_effort_minutes{id}                                     staff minutes, for records with effort_min (v0.7)
    changes_textfile_last_run_timestamp
"""
import argparse
import glob
import os
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "lib", "python"))
sys.path.insert(0, HERE)
from ops30 import drills as ops30_drills, rfc3339, textfile  # noqa: E402
from ops30.frontmatter import parse  # noqa: E402
from ops30.textfile import esc  # noqa: E402
from check import STATUSES  # noqa: E402


def read_drills(path):
    """drills.jsonl (any version) -> {rollback_of: (t0, ok, count)} for the latest drill per record."""
    out = {}
    recs, _ = ops30_drills.load(path, "changes")
    for r in recs:
        of = r["rollback_of"]
        if not of:
            continue
        t0, ok = ops30_drills.epoch(r), 1 if r["result"] == "pass" else 0
        prev = out.get(of)
        n = (prev[2] if prev else 0) + 1
        if prev is None or t0 >= prev[0]:
            out[of] = (t0, ok, n)
        else:
            out[of] = (prev[0], prev[1], n)
    return out


def render(files, now, drills=None):
    drills = drills or {}
    L = []
    recs = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            meta, _, _ = parse(fh.read())
        recs.append(meta)
    textfile.family(L, "change_record", "One per change record in changes/, with its status")
    for m in recs:
        L.append('change_record{id="%s",status="%s",type="%s",risk="%s",implementer="%s",approver="%s"} 1'
                 % tuple(esc(m.get(k, "")) for k in ("id", "status", "type", "risk", "implementer", "approver")))
    textfile.family(L, "change_window_start_timestamp", "Unix time the change window opens")
    for m in recs:
        t = rfc3339.to_epoch(m.get("window_start", ""))
        if t is not None:
            L.append(f'change_window_start_timestamp{{id="{esc(m["id"])}",status="{esc(m["status"])}"}} {t}')
    textfile.family(L, "change_window_end_timestamp", "Unix time the change window closes")
    for m in recs:
        t = rfc3339.to_epoch(m.get("window_end", ""))
        if t is not None:
            L.append(f'change_window_end_timestamp{{id="{esc(m["id"])}",status="{esc(m["status"])}"}} {t}')
    textfile.family(L, "change_records", "Number of records per status (every status is written, 0 included)")
    for s in STATUSES:
        L.append(f'change_records{{status="{s}"}} {sum(1 for m in recs if m.get("status") == s)}')
    ids = {m.get("id") for m in recs}
    textfile.family(L, "change_rollback_last_drill_timestamp", "Unix time of the last drill that rolled this record back (drills/drills.jsonl)")
    for of, (t0, _, _) in sorted(drills.items()):
        if of in ids:
            L.append(f'change_rollback_last_drill_timestamp{{id="{esc(of)}"}} {t0}')
    textfile.family(L, "change_rollback_last_drill_result", "1 when the last rollback drill of this record passed")
    for of, (_, ok, _) in sorted(drills.items()):
        if of in ids:
            L.append(f'change_rollback_last_drill_result{{id="{esc(of)}"}} {ok}')
    textfile.family(L, "change_rollback_drills_total", "Rollback drills recorded for this record", "counter")
    for of, (_, _, n) in sorted(drills.items()):
        if of in ids:
            L.append(f'change_rollback_drills_total{{id="{esc(of)}"}} {n}')
    textfile.family(L, "change_effort_minutes", "Staff minutes recorded in the change record (effort_min)")
    for m in recs:
        e = str(m.get("effort_min", "")).strip()
        if e.isdigit():
            L.append(f'change_effort_minutes{{id="{esc(m["id"])}"}} {int(e)}')
    textfile.family(L, "changes_textfile_last_run_timestamp", "Unix time of the last changes-textfile run")
    L.append(f"changes_textfile_last_run_timestamp {int(now)}")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "changes"))
    ap.add_argument("--drills", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "drills", "drills.jsonl"),
                    help="drills.jsonl written by drills/drill.sh (missing file: no rollback metrics)")
    ap.add_argument("--out")
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.dir, "CR-*.md")))
    body = render(files, time.time(), read_drills(a.drills))
    if a.out:
        textfile.write(a.out, body)
    else:
        sys.stdout.write(body)


if __name__ == "__main__":
    main()
