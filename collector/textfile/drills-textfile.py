#!/usr/bin/env python3
"""Turn the drills.jsonl files from Day 16, 17 and 18 into textfile metrics.
onprem-logs (Day 21) adds a fourth, the daily archive verify, as source=logs;
a source whose file does not exist yet is skipped.

Every drill tool appends one JSON object per drill. Since 30ops v0.2 they
write drills.jsonl v1 (docs/drills-jsonl.md); files written before that
keep their old per-tool fields and are read through ops30.drills.normalise,
so old and new lines can sit in the same file. The source name is also the
hint for which tool wrote an old line.

The JSONL is what the tool printed at the time. Corrections made by hand
later in a drill log do not flow back here.

For every (source, label) it exposes the most recent drill only. A
dashboard then shows "last successful restore N days ago" per drill and
alerts when that passes the policy (Day 16: monthly; Day 18: monthly).

    drills-textfile.py --out /var/lib/node_exporter/textfile/drills.prom \
        pve=/srv/drills/pve-backup-drill/drills.jsonl \
        nas=/srv/drills/nas-backup-drill/drills.jsonl \
        cloud=/srv/drills/cloud-offload-drill/drills.jsonl \
        logs=/srv/drills/onprem-logs/drills.jsonl

Metrics
    drill_last_timestamp{source,label}        unix time of the last drill
    drill_last_result{source,label}           1 OK, 0 FAIL
    drill_last_rto_seconds{source,label}
    drill_last_rpo_seconds{source,label}
    drill_last_rate_mib_per_second{source,label}
    drill_last_success_timestamp{source,label} unix time of the last OK drill
    drill_count_total{source,label}           drills recorded (counter)
    drills_textfile_last_run_timestamp
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "lib", "python"))
from ops30 import drills, textfile  # noqa: E402
from ops30.textfile import esc  # noqa: E402

MIB = drills.MIB


def normalise(rec):
    """A v1 record (ops30.drills.normalise) -> the fields this script exposes."""
    rate = rec.get("rate_bps")
    return {
        "label": rec["label"],
        "t0": drills.epoch(rec),
        "ok": 1 if rec["result"] == "pass" else 0,
        "rto": float(rec["rto_s"]) if rec.get("rto_s") is not None else None,
        "rpo": float(rec["rpo_s"]) if rec.get("rpo_s") is not None else None,
        "rate": rate / MIB if rate is not None else None,
    }


def read_jsonl(path, source=None):
    """Any drills.jsonl version; lines that are not JSON objects or have no
    usable t0 are skipped. A missing file is no records."""
    recs, _ = drills.load(path, source)
    return [normalise(r) for r in recs]


def latest_per_label(recs):
    last, last_ok, count = {}, {}, {}
    for r in sorted(recs, key=lambda r: r["t0"]):
        last[r["label"]] = r
        count[r["label"]] = count.get(r["label"], 0) + 1
        if r["ok"]:
            last_ok[r["label"]] = r["t0"]
    return last, last_ok, count


HELP = [
    ("drill_last_timestamp", "Unix time of the last drill", "gauge"),
    ("drill_last_result", "1 when the last drill passed", "gauge"),
    ("drill_last_rto_seconds", "RTO of the last drill", "gauge"),
    ("drill_last_rpo_seconds", "RPO of the last drill", "gauge"),
    ("drill_last_rate_mib_per_second", "Transfer rate of the last drill", "gauge"),
    ("drill_last_success_timestamp", "Unix time of the last passing drill", "gauge"),
    ("drill_count_total", "Drills recorded", "counter"),
]


def render(sources, now):
    rows = {name: [] for name, _, _ in HELP}
    for source, path in sources:
        try:
            recs = read_jsonl(path, source)
        except OSError:
            continue
        last, last_ok, count = latest_per_label(recs)
        for label, r in sorted(last.items()):
            lab = f'{{source="{esc(source)}",label="{esc(label)}"}}'
            rows["drill_last_timestamp"].append(f"drill_last_timestamp{lab} {r['t0']}")
            rows["drill_last_result"].append(f"drill_last_result{lab} {r['ok']}")
            if r["rto"] is not None:
                rows["drill_last_rto_seconds"].append(f"drill_last_rto_seconds{lab} {r['rto']:g}")
            if r["rpo"] is not None:
                rows["drill_last_rpo_seconds"].append(f"drill_last_rpo_seconds{lab} {r['rpo']:g}")
            if r["rate"] is not None:
                rows["drill_last_rate_mib_per_second"].append(f"drill_last_rate_mib_per_second{lab} {r['rate']:g}")
            if label in last_ok:
                rows["drill_last_success_timestamp"].append(f"drill_last_success_timestamp{lab} {last_ok[label]}")
            rows["drill_count_total"].append(f"drill_count_total{lab} {count[label]}")
    lines = []
    for name, hlp, typ in HELP:
        if rows[name]:
            textfile.family(lines, name, hlp, typ)
            lines += rows[name]
    textfile.family(lines, "drills_textfile_last_run_timestamp", "Unix time of the last run")
    lines.append(f"drills_textfile_last_run_timestamp {int(now)}")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="+", help="name=path/to/drills.jsonl")
    ap.add_argument("--out", help="write here atomically; default stdout")
    a = ap.parse_args(argv)
    sources = []
    for s in a.sources:
        if "=" not in s:
            ap.error(f"expected name=path, got {s}")
        sources.append(tuple(s.split("=", 1)))
    text = render(sources, time.time())
    if a.out:
        textfile.write(a.out, text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
