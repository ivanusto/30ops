#!/usr/bin/env python3
"""Reduce a hw-sample.py JSONL to one row of numbers.

Why this exists: power and temperature cannot be reported as a peak alone, and
cannot be reported as a mean alone either. The head and tail of a long job are
transitional (the model is still loading, the queue is not yet full), and
counting them dilutes the steady state. So the head and tail are trimmed by
default, and p10 and p90 are printed alongside the mean so you can see for
yourself whether that mean is stable.

    summarize-samples.py pwr.jsonl --skip-head 60 --skip-tail 15
    summarize-samples.py pwr.jsonl --from "2026-09-09 00:00:14" --to "2026-09-09 00:10:59"
"""
import argparse, json, statistics, sys, time


def parse_when(text):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(time.strptime(text[:19], fmt))
        except ValueError:
            continue
    raise SystemExit(f"unrecognised time format: {text}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--from", dest="t_from", help="start time, defaults to the first row")
    ap.add_argument("--to", dest="t_to", help="end time, defaults to the last row")
    ap.add_argument("--skip-head", type=float, default=0,
                    help="seconds to skip at the start of the window")
    ap.add_argument("--skip-tail", type=float, default=0,
                    help="seconds to skip at the end of the window")
    ap.add_argument("--soak-zone", type=int, default=88,
                    help="threshold for the continuous soak calculation")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of a human readable table")
    a = ap.parse_args()

    rows = [json.loads(l) for l in open(a.jsonl) if l.strip()]
    if not rows:
        raise SystemExit("empty file")
    lo = parse_when(a.t_from) if a.t_from else rows[0]["t"]
    hi = parse_when(a.t_to) if a.t_to else rows[-1]["t"]
    lo, hi = lo + a.skip_head, hi - a.skip_tail
    w = [r for r in rows if lo <= r["t"] <= hi]
    if not w:
        raise SystemExit("no samples inside the window, check the time range")

    def col(key):
        return [r[key] for r in w if r.get(key) is not None]

    power, gpu, zone, util = col("power_w"), col("gpu_c"), col("zone_c"), col("util")
    avail = col("avail_gib")

    # The soak has to be continuous. Dropping back below the threshold means the
    # cooling caught up, and that is the state that survived, so a running total
    # would mislead. What matters is the longest unbroken stretch.
    interval = statistics.median(
        [b["t"] - c["t"] for c, b in zip(w, w[1:])]) if len(w) > 1 else 0
    longest = cur = 0.0
    for r in w:
        if (r.get("zone_c") or 0) >= a.soak_zone:
            cur += interval
            longest = max(longest, cur)
        else:
            cur = 0.0

    out = {
        "samples": len(w),
        "span_s": round(w[-1]["t"] - w[0]["t"], 1),
        "interval_s": round(interval, 2),
        "power_w": {"avg": round(statistics.fmean(power), 2),
                    "p10": round(statistics.quantiles(power, n=10)[0], 2),
                    "p90": round(statistics.quantiles(power, n=10)[8], 2),
                    "max": round(max(power), 2)} if len(power) > 9 else None,
        "gpu_c_max": max(gpu) if gpu else None,
        "zone_c_max": max(zone) if zone else None,
        "util_avg": round(statistics.fmean(util)) if util else None,
        "avail_gib_min": round(min(avail), 2) if avail else None,
        f"longest_soak_s_at_{a.soak_zone}c": round(longest),
    }
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        for k, v in out.items():
            print(f"{k:28s} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
