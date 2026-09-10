#!/usr/bin/env python3
"""Wrap any long running command in a cooling gate plus a thermal watchdog.

Why it exists: while measuring power on 2026-09-09 it turned out that a LoRA
fine-tune pushes the chassis to zone 94 C and draws 80 W, the same class of load
as video generation, while the gate and the watchdog were only attached to the
video chain. Fine-tuning was running completely unguarded. That run was stopped
by hand because someone happened to be watching. This is that judgement written
down as code.

Division of labour with thermal-guard-http.py: that one is for ComfyUI and
vLLM-Omni, which cannot be interrupted mid job, so it can only go through an
HTTP endpoint or drop a flag file. A local process can be signalled directly, so
this one raises its own child: a new process group via setsid, and the whole
group is taken down together on a violation.

Same measured thresholds as the rest of the repo:
    the hard power cut on 2026-09-01 followed 417 unbroken seconds of soak, so
    the budget is 240 s, which fires three minutes before that point
    zone is the maximum over the seven /sys/class/thermal/thermal_zone*/temp
    entries, because this platform has no GPU hwmon
    the start gate reads GPU temperature because it is the easiest proxy to
    read, though the chassis is the variable that actually matters
"""
import argparse, glob, json, os, signal, subprocess, sys, time


def zone_c():
    hottest = 0
    for path in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        try:
            with open(path) as fh:
                hottest = max(hottest, int(fh.read().strip()) // 1000)
        except Exception:
            continue
    return hottest or None


def gpu_c():
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=temperature.gpu",
                              "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        return int(float(out.splitlines()[0]))
    except Exception:
        return None


def emit(fh, event, **kw):
    row = {"t": time.strftime("%FT%T%z"), "event": event, **kw}
    line = json.dumps(row, ensure_ascii=False)
    print(line, flush=True)
    if fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def gate(fh, cool, timeout, interval):
    """Wait for the chassis to come down before starting. On timeout, go ahead
    and say so: never block silently for a whole night."""
    start = time.time()
    while True:
        g, z = gpu_c(), zone_c()
        waited = time.time() - start
        if g is None or g <= cool:
            emit(fh, "gate_pass", gpu_c=g, zone_c=z, waited_s=round(waited, 1))
            return
        if waited >= timeout:
            emit(fh, "gate_timeout", gpu_c=g, zone_c=z, waited_s=round(waited, 1),
                 note="timed out, running anyway")
            return
        emit(fh, "gate_wait", gpu_c=g, zone_c=z, waited_s=round(waited, 1), target=cool)
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(usage="thermal-run.py [options] -- command [args...]")
    ap.add_argument("--cool", type=int, default=55,
                    help="GPU must be at or below this before starting")
    ap.add_argument("--gate-timeout", type=float, default=300)
    ap.add_argument("--soak-zone", type=int, default=88)
    ap.add_argument("--soak-seconds", type=float, default=240)
    ap.add_argument("--zone-ceiling", type=int, default=96,
                    help="instantaneous ceiling, abort immediately above it")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--log", default=None)
    ap.add_argument("--no-gate", action="store_true")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()

    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        ap.error("a command is required, for example: "
                 "thermal-run.py --cool 55 -- python3 train.py run 4 1536 2")

    fh = open(os.path.expanduser(a.log), "a", buffering=1) if a.log else None
    emit(fh, "start", cmd=cmd, cool=a.cool, soak_zone=a.soak_zone,
         soak_seconds=a.soak_seconds, zone_ceiling=a.zone_ceiling)

    if not a.no_gate:
        gate(fh, a.cool, a.gate_timeout, a.interval)

    # Raise the child in its own process group so the whole group can be taken
    # down together. Never pkill by pattern: that kills your own shell too.
    proc = subprocess.Popen(cmd, start_new_session=True)
    pgid = os.getpgid(proc.pid)
    emit(fh, "launched", pid=proc.pid, pgid=pgid)

    soak = 0.0
    longest_soak = 0.0
    peak_zone = 0
    aborted = None
    try:
        while proc.poll() is None:
            z = zone_c()
            if z:
                peak_zone = max(peak_zone, z)
                # The soak has to be unbroken: dropping back below the threshold
                # means the cooling caught up, and that is the state that survived.
                soak = soak + a.interval if z >= a.soak_zone else 0.0
                longest_soak = max(longest_soak, soak)
                if z >= a.zone_ceiling:
                    aborted = f"zone {z} C above the instantaneous ceiling {a.zone_ceiling} C"
                elif soak >= a.soak_seconds:
                    aborted = (f"zone at or above {a.soak_zone} C for {soak:.0f}s "
                               f"continuously, over the {a.soak_seconds:.0f}s budget")
                if aborted:
                    emit(fh, "abort", reason=aborted, zone_c=z, gpu_c=gpu_c(),
                         soak_s=soak, peak_zone_c=peak_zone)
                    os.killpg(pgid, signal.SIGTERM)
                    for _ in range(30):
                        if proc.poll() is not None:
                            break
                        time.sleep(1)
                    if proc.poll() is None:
                        emit(fh, "sigkill", pgid=pgid)
                        os.killpg(pgid, signal.SIGKILL)
                    break
            time.sleep(a.interval)
    except KeyboardInterrupt:
        emit(fh, "interrupted", note="user interrupt, taking the child group with it")
        os.killpg(pgid, signal.SIGTERM)

    rc = proc.wait()
    # longest_soak, not soak: soak is reset to zero every time the zone drops
    # back below the threshold, so a job that soaked and then cooled would
    # otherwise report zero.
    emit(fh, "done", returncode=rc, aborted=aborted, peak_zone_c=peak_zone,
         longest_soak_s=round(longest_soak, 1))
    return 75 if aborted else rc


if __name__ == "__main__":
    sys.exit(main())
