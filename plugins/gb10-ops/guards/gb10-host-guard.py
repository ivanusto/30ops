#!/usr/bin/env python3
"""Host level memory guard for the GB10: act before the whole box stops responding.

Why this is not a container memory limit (measured 2026-09-09, which overturned
the original plan):
    With a model resident, the container's cgroup memory.current read 11 GiB and
    the sum of RSS for every process inside it was 4 GiB, while the host was
    using 113 GiB at the same moment. The missing 100 GiB is unified memory
    allocated through the NVIDIA driver, and **neither the memory cgroup nor RSS
    can see it**. So `docker run --memory` is useless for GPU work on this
    platform: it limits something that is not the thing that fills the machine.

    Exactly one source sees that memory:
    `nvidia-smi --query-compute-apps=pid,used_memory`, which honestly reports
    102843 MiB. So the guard has to run at the host level, use MemAvailable to
    decide that things are going wrong, and use compute-apps to pick the target.

Where the thresholds came from (calibrated against a full night of samples on
2026-09-09, not picked as round numbers):
    In normal two node service MemAvailable sits at just 7.85 GiB, and a 46
    minute cluster recovery never went below 6.91 GiB. So the warning line is
    6 GiB (zero false positives overnight) and the action line is 3 GiB.
    Against the two real incidents: the livelock on 2026-09-06 reached 0.20 GiB
    and an earlier near miss reached 2 GiB. Both would fire. The 8 GiB figure
    from the original write up was wrong; that line is red continuously during
    normal service on this machine.

Triggers (two of them; either one needs several consecutive samples before the
guard acts, so that a momentary spike does not kill a healthy job):
    1. MemAvailable below ACT_GIB for SUSTAIN consecutive samples
    2. NVRM emitting NVRM_RATE or more NV_ERR_NO_MEMORY lines within 60 seconds
       while MemAvailable is below WARN_GIB. The night of the 2026-09-06
       livelock that was 24 lines in 21 seconds, and it arrived 43 minutes
       before the machine was gone. A single line is far too noisy to use: this
       box has logged 6,697 of them since July.

Action: write the scene to the log first (who is holding GPU memory and how
much), then SIGTERM the largest unprotected process, and SIGKILL it if it is
still there 20 seconds later. **Processes matching the protect pattern are never
touched**; the default protects a serving vLLM worker. Use --dry-run to log
without acting.

Deliberately no pkill/pgrep pattern matching: those match the full command line,
which includes the shell that invoked them, and that is a good way to kill your
own session. Only explicit pids from nvidia-smi are ever signalled.
"""
import argparse, collections, json, os, re, signal, subprocess, sys, time

GIB = 1024 ** 3
LOG = os.path.expanduser("~/gb10-host-guard.log")


def log(fh, event, **kw):
    row = {"t": time.strftime("%FT%T%z"), "event": event, **kw}
    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    fh.flush()
    os.fsync(fh.fileno())          # one of this box's failure modes is a hard
                                   # power cut, so unflushed is the same as unwritten
    if event != "sample":
        print(json.dumps(row, ensure_ascii=False), flush=True)


def mem_available_gib():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1048576
    return None


def gpu_consumers():
    """[(pid, name, mib)], largest first. The only source that sees unified memory."""
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return []
    rows = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3 and parts[0].isdigit():
            try:
                rows.append((int(parts[0]), parts[1], int(float(parts[2]))))
            except ValueError:
                continue
    return sorted(rows, key=lambda r: -r[2])


def start_journal_follower():
    """Follow the kernel log. Only the timestamps of NVRM memory errors are kept."""
    p = subprocess.Popen(["journalctl", "-k", "-f", "-n", "0", "-o", "cat"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    os.set_blocking(p.stdout.fileno(), False)
    return p


def drain(proc, stamps, carry):
    """Read whatever is available without blocking; return the unfinished tail.

    A non-blocking readline can hand back a partial line with no trailing
    newline, and the rest of it arrives on the next call. Carrying that tail
    over matters because NV_ERR_NO_MEMORY can be split across the boundary,
    which would silently undercount the exact burst this guard triggers on.
    """
    if proc.stdout is None:
        return carry
    while True:
        chunk = proc.stdout.readline()
        if not chunk:
            return carry
        carry += chunk
        if not carry.endswith("\n"):
            return carry               # incomplete, wait for the remainder
        if "NV_ERR_NO_MEMORY" in carry:
            stamps.append(time.time())
        carry = ""


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def act(fh, consumers, protect, dry_run, reason):
    ranked = [{"pid": p, "name": n, "gib": round(m / 1024, 2)} for p, n, m in consumers]
    log(fh, "trigger", reason=reason, consumers=ranked)
    target = next((c for c in consumers
                   if not re.search(protect, c[1]) and c[0] != os.getpid()), None)
    if target is None:
        log(fh, "no_target", note="every GPU process is protected, logging only")
        return
    pid, name, mib = target
    if dry_run:
        log(fh, "would_kill", pid=pid, name=name, gib=round(mib / 1024, 2))
        return
    log(fh, "sigterm", pid=pid, name=name, gib=round(mib / 1024, 2))
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        log(fh, "kill_failed", pid=pid, error=str(e))
        return
    for _ in range(20):
        if not alive(pid):
            log(fh, "terminated", pid=pid)
            return
        time.sleep(1)
    log(fh, "sigkill", pid=pid, name=name)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--warn-gib", type=float, default=6.0)
    ap.add_argument("--act-gib", type=float, default=3.0)
    ap.add_argument("--sustain", type=int, default=3,
                    help="consecutive samples before it counts")
    ap.add_argument("--nvrm-rate", type=int, default=5,
                    help="lines within 60 seconds that count as a burst")
    ap.add_argument("--protect", default=r"VLLM::",
                    help="process names matching this are never terminated")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--log", default=LOG)
    a = ap.parse_args()

    stamps = collections.deque(maxlen=4096)
    jr = start_journal_follower()
    carry = ""
    low_streak = 0
    last_state = None
    with open(a.log, "a", buffering=1) as fh:
        log(fh, "start", pid=os.getpid(), warn_gib=a.warn_gib, act_gib=a.act_gib,
            sustain=a.sustain, nvrm_rate=a.nvrm_rate, protect=a.protect,
            dry_run=a.dry_run, interval=a.interval)
        while True:
            # If the follower dies, every later read returns empty and trigger 2
            # is silently gone while the guard still reports state "ok". That is
            # the worst way for a watchdog to fail, so check and restart it.
            if jr.poll() is not None:
                log(fh, "journal_restart", returncode=jr.returncode,
                    note="journalctl follower exited, NVRM detection was blind")
                jr = start_journal_follower()
                carry = ""
            carry = drain(jr, stamps, carry)
            now = time.time()
            while stamps and now - stamps[0] > 60:
                stamps.popleft()
            avail = mem_available_gib()
            rate = len(stamps)
            # 0.0 GiB is a real and very bad reading, so never let it fall
            # through a truthiness test and get logged as null.
            avail_out = round(avail, 2) if avail is not None else None

            state = "ok"
            if avail is not None and avail < a.act_gib:
                low_streak += 1
                state = "critical"
            else:
                low_streak = 0
                if avail is not None and avail < a.warn_gib:
                    state = "warn"
            if rate >= a.nvrm_rate and avail is not None and avail < a.warn_gib:
                state = "critical" if low_streak else "warn"

            log(fh, "sample", avail_gib=avail_out, nvrm_60s=rate,
                state=state, streak=low_streak)
            if state != last_state:
                log(fh, "state_change", frm=last_state, to=state,
                    avail_gib=avail_out, nvrm_60s=rate)
                last_state = state

            fire = low_streak >= a.sustain or (
                rate >= a.nvrm_rate and avail is not None and avail < a.warn_gib
                and low_streak >= 1)
            if fire:
                act(fh, gpu_consumers(), a.protect, a.dry_run,
                    reason=f"MemAvailable {avail:.2f} GiB for {low_streak} samples; "
                           f"NVRM {rate} lines in 60 s")
                low_streak = 0
                stamps.clear()
                time.sleep(60)     # let the system settle, do not fire repeatedly
            time.sleep(a.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
