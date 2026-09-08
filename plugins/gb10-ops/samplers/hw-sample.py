#!/usr/bin/env python3
"""Sample this box's temperature, power and memory while a render runs.

Two jobs. It writes an evidence trail a report can cite, and it watches for the
soak that precedes a hard power cut on this hardware. The cut is not triggered
by a peak: the fatal run on 2026-09-01 reached its plateau in four minutes and
then sat at roughly GPU 82 to 86 C and zone 91 to 94 C for seven more before the
box died with nothing in the kernel log. So what is measured is time spent hot,
continuously, and the budget here is the same 240 s that thermal_guard.py uses.

Neither video server can be interrupted once a generation is launched, so this
cannot stop a clip in flight. What it does instead is drop a HOT file. The
driver checks for it between clips and stops there. Losing the rest of a run
beats losing the box.

Memory is sampled from /proc/meminfo, not nvidia-smi, which reports N/A for
memory on the GB10 because the pool is unified.
"""
import argparse
import glob
import json
import os
import subprocess
import sys
import time

SOAK_ZONE = 88
SOAK_BUDGET = 240


def gpu():
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=temperature.gpu,power.draw,utilization.gpu",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10).stdout.strip().splitlines()[0]
        temp, power, util = (part.strip() for part in out.split(","))
        return int(float(temp)), float(power), int(float(util))
    except Exception:
        return None, None, None


def zone():
    hottest = 0
    for path in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        try:
            with open(path) as fh:
                hottest = max(hottest, int(fh.read().strip()) // 1000)
        except Exception:
            continue
    return hottest or None


def memory():
    """MemAvailable and swap used, in GiB. The used figure on a unified memory
    box conflates CPU, GPU and page cache, so available is the honest one."""
    fields = {}
    with open("/proc/meminfo") as fh:
        for line in fh:
            key, _, rest = line.partition(":")
            fields[key] = int(rest.split()[0])
    return (round(fields["MemAvailable"] / 1048576, 2),
            round((fields["SwapTotal"] - fields["SwapFree"]) / 1048576, 2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--hot-flag", required=True)
    ap.add_argument("--interval", type=float, default=3.0)
    a = ap.parse_args()

    soak = 0.0
    peak = {"gpu": 0, "zone": 0, "power": 0.0, "mem_low": 999.0, "swap": 0.0}
    with open(a.out, "a", buffering=1) as fh:
        while True:
            g, p, u = gpu()
            z = zone()
            avail, swap = memory()
            row = {"t": round(time.time(), 1), "gpu_c": g, "zone_c": z,
                   "power_w": p, "util": u, "avail_gib": avail, "swap_gib": swap}
            fh.write(json.dumps(row) + "\n")
            os.fsync(fh.fileno())

            if g:
                peak["gpu"] = max(peak["gpu"], g)
            if z:
                peak["zone"] = max(peak["zone"], z)
            if p:
                peak["power"] = max(peak["power"], p)
            peak["mem_low"] = min(peak["mem_low"], avail)
            peak["swap"] = max(peak["swap"], swap)

            # The soak has to be unbroken. Dropping below the threshold means
            # the cooling caught up, and that is the state that survived.
            soak = soak + a.interval if (z and z >= SOAK_ZONE) else 0.0
            if soak >= SOAK_BUDGET and not os.path.exists(a.hot_flag):
                with open(a.hot_flag, "w") as flag:
                    flag.write(json.dumps(
                        {"soaked_seconds": soak, "zone_c": z, "gpu_c": g,
                         "at": time.strftime("%F %T")}) + "\n")
                print(f"HOT: soaked {soak:.0f}s at zone >= {SOAK_ZONE} C", flush=True)
            time.sleep(a.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
