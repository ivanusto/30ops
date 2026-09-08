#!/usr/bin/env python3
"""GB10 主機層記憶體守護：在整台停擺之前先動手。

為什麼不是容器記憶體上限（0909 實測推翻了原本的計畫）：
    容器 cgroup 的 memory.current 是 11 GiB，容器內所有行程的 RSS 加總是 4 GiB，
    而同一時刻主機用掉 113 GiB。差的那 100 GiB 是 NVIDIA 驅動的統一記憶體配置，
    **memory cgroup 與 RSS 都看不到它**。所以 `docker run --memory` 這條路
    對這台的 GPU 工作負載完全無效，限制得到的東西不是會撐爆機器的那一塊。

    唯一看得到那塊的是 `nvidia-smi --query-compute-apps=pid,used_memory`，
    它會誠實回報 102843 MiB。所以守護程式要跑在主機層，用 MemAvailable 判斷危險，
    用 compute-apps 找兇手。

門檻怎麼定的（0909 用整晚的實測資料校準，不是憑感覺挑整數）：
    正常雙機服務時 MemAvailable 就只有 7.85 GiB，而 46 分鐘的叢集復原全程最低
    6.91 GiB。所以警戒線放 6 GiB（整晚零誤報），動手線放 3 GiB。
    對照兩次真實事故：0906 停擺當晚掉到 0.20 GiB，Day 26 那次掉到 2 GiB，
    兩次都會觸發。原本文章裡寫的 8 GiB 是錯的，那條線在正常服務時就一直亮紅燈。

觸發條件（兩條，任一成立都要連續數次才動手，避免瞬間尖峰誤殺）：
    1. MemAvailable 低於 ACT_GIB，連續 SUSTAIN 次取樣
    2. 60 秒內 NVRM 噴出 NVRM_RATE 行以上 NV_ERR_NO_MEMORY，且 MemAvailable 低於 WARN_GIB
       （0906 停擺那晚是 21 秒內 24 行，而它比停擺早了 43 分鐘）

動作：先把現場寫進日誌（誰在吃 GPU 記憶體、吃多少），再 SIGTERM 最大的那個
非保護行程，20 秒後還在就 SIGKILL。**保護名單裡的行程永遠不動**，預設保護
正在服務的 vLLM worker。用 --dry-run 只記錄不動手。

刻意不用 pkill/pgrep 的樣式比對：那會連自己的 shell 一起殺掉（踩過）。
一律用 nvidia-smi 給的明確 pid。
"""
import argparse, collections, json, os, re, signal, subprocess, sys, time

GIB = 1024 ** 3
LOG = os.path.expanduser("~/gb10-host-guard.log")


def log(fh, event, **kw):
    row = {"t": time.strftime("%FT%T%z"), "event": event, **kw}
    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    fh.flush()
    os.fsync(fh.fileno())          # 這台的死法之一是硬斷電，沒 flush 就等於沒寫
    if event != "sample":
        print(json.dumps(row, ensure_ascii=False), flush=True)


def mem_available_gib():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1048576
    return None


def gpu_consumers():
    """[(pid, name, mib)]，由大到小。這是唯一看得到統一記憶體配置的來源。"""
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
    """跟著核心日誌，只留 NVRM 記憶體錯誤的時間戳。"""
    p = subprocess.Popen(["journalctl", "-k", "-f", "-n", "0", "-o", "cat"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    os.set_blocking(p.stdout.fileno(), False)
    return p


def drain(proc, stamps):
    if proc.stdout is None:
        return
    while True:
        line = proc.stdout.readline()
        if not line:
            return
        if "NV_ERR_NO_MEMORY" in line:
            stamps.append(time.time())


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
        log(fh, "no_target", note="所有 GPU 行程都在保護名單內，只記錄不動手")
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
    ap.add_argument("--sustain", type=int, default=3, help="連續幾次取樣才算數")
    ap.add_argument("--nvrm-rate", type=int, default=5, help="60 秒內幾行才算暴衝")
    ap.add_argument("--protect", default=r"VLLM::", help="行程名符合就永不中止")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--log", default=LOG)
    a = ap.parse_args()

    stamps = collections.deque(maxlen=4096)
    jr = start_journal_follower()
    low_streak = 0
    last_state = None
    with open(a.log, "a", buffering=1) as fh:
        log(fh, "start", pid=os.getpid(), warn_gib=a.warn_gib, act_gib=a.act_gib,
            sustain=a.sustain, nvrm_rate=a.nvrm_rate, protect=a.protect,
            dry_run=a.dry_run, interval=a.interval)
        while True:
            drain(jr, stamps)
            now = time.time()
            while stamps and now - stamps[0] > 60:
                stamps.popleft()
            avail = mem_available_gib()
            rate = len(stamps)

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

            log(fh, "sample", avail_gib=round(avail, 2) if avail else None,
                nvrm_60s=rate, state=state, streak=low_streak)
            if state != last_state:
                log(fh, "state_change", frm=last_state, to=state,
                    avail_gib=round(avail, 2) if avail else None, nvrm_60s=rate)
                last_state = state

            fire = low_streak >= a.sustain or (
                rate >= a.nvrm_rate and avail is not None and avail < a.warn_gib
                and low_streak >= 1)
            if fire:
                act(fh, gpu_consumers(), a.protect, a.dry_run,
                    reason=f"MemAvailable {avail:.2f} GiB 連續 {low_streak} 次；"
                           f"60 秒內 NVRM {rate} 行")
                low_streak = 0
                stamps.clear()
                time.sleep(60)     # 動手之後給系統時間回穩，不要連環開火
            time.sleep(a.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
