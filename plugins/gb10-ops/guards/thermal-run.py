#!/usr/bin/env python3
"""把冷卻閘門與熱看門狗包在任何一個長時間指令外面。

存在的理由：0909 量功耗時才發現，LoRA 微調會把機殼推到 zone 94 度、吃 80 W，
跟影片生成同一個等級，而閘門與看門狗當時只掛在影片鏈上，微調完全裸奔。
那次是我人在看著才手動停下來的，這支就是把那個判斷寫成程式。

跟 ltx25-h3-bench/thermal_guard.py 的分工：那支是給 ComfyUI 與 vLLM-Omni 用的，
它們不能中途插斷，所以只能走 HTTP 的 /interrupt 或丟旗標檔。本機行程可以直接
收訊號，所以這支自己帶小孩：用 setsid 開新的行程群組，中止時整組一起收。

門檻沿用同一組實測值（見 gb10-hard-poweroff-heat-soak 的軌跡）：
    0901 那次整台斷電是連續浸透 417 秒 → 預算 240 秒，會在斷電前三分鐘開火
    zone 是 /sys/class/thermal/thermal_zone*/temp 七個取最大，這台沒有 GPU 的 hwmon
    起跑閘門看 GPU 溫度，因為它是最容易讀到的代理指標（機殼才是真正的變數）
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
    """開跑前先等機殼降下來。逾時就放行並且說清楚，不要靜默地擋住整晚。"""
    start = time.time()
    while True:
        g, z = gpu_c(), zone_c()
        waited = time.time() - start
        if g is None or g <= cool:
            emit(fh, "gate_pass", gpu_c=g, zone_c=z, waited_s=round(waited, 1))
            return
        if waited >= timeout:
            emit(fh, "gate_timeout", gpu_c=g, zone_c=z, waited_s=round(waited, 1),
                 note="逾時，照跑")
            return
        emit(fh, "gate_wait", gpu_c=g, zone_c=z, waited_s=round(waited, 1), target=cool)
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(usage="thermal-run.py [選項] -- 指令 [參數...]")
    ap.add_argument("--cool", type=int, default=55, help="開跑前 GPU 要降到幾度")
    ap.add_argument("--gate-timeout", type=float, default=300)
    ap.add_argument("--soak-zone", type=int, default=88)
    ap.add_argument("--soak-seconds", type=float, default=240)
    ap.add_argument("--zone-ceiling", type=int, default=96, help="瞬時上限，超過立刻中止")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--log", default=None)
    ap.add_argument("--no-gate", action="store_true")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()

    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        ap.error("要有指令，例如：thermal-run.py --cool 55 -- python3 train.py run 4 1536 2")

    fh = open(os.path.expanduser(a.log), "a", buffering=1) if a.log else None
    emit(fh, "start", cmd=cmd, cool=a.cool, soak_zone=a.soak_zone,
         soak_seconds=a.soak_seconds, zone_ceiling=a.zone_ceiling)

    if not a.no_gate:
        gate(fh, a.cool, a.gate_timeout, a.interval)

    # 自己開一個行程群組，中止時整組一起收。絕不用 pkill 的樣式比對，那會誤殺自己的 shell。
    proc = subprocess.Popen(cmd, start_new_session=True)
    pgid = os.getpgid(proc.pid)
    emit(fh, "launched", pid=proc.pid, pgid=pgid)

    soak = 0.0
    peak_zone = 0
    aborted = None
    try:
        while proc.poll() is None:
            z = zone_c()
            if z:
                peak_zone = max(peak_zone, z)
                # 浸透必須是連續的：掉下門檻代表冷卻追上了，而那正是活下來的那種狀態
                soak = soak + a.interval if z >= a.soak_zone else 0.0
                if z >= a.zone_ceiling:
                    aborted = f"zone {z} 度超過瞬時上限 {a.zone_ceiling}"
                elif soak >= a.soak_seconds:
                    aborted = f"zone 連續 {soak:.0f} 秒 >= {a.soak_zone} 度，超過 {a.soak_seconds:.0f} 秒預算"
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
        emit(fh, "interrupted", note="使用者中斷，連同子行程一起收")
        os.killpg(pgid, signal.SIGTERM)

    rc = proc.wait()
    emit(fh, "done", returncode=rc, aborted=aborted, peak_zone_c=peak_zone,
         longest_soak_s=soak)
    return 75 if aborted else rc


if __name__ == "__main__":
    sys.exit(main())
