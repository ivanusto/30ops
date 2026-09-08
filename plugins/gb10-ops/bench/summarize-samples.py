#!/usr/bin/env python3
"""把 hw-sample.py 產生的 JSONL 收成一格數字。

為什麼要有這支：功耗與溫度不能只報峰值，也不能只報平均。長任務的頭尾都是過渡狀態
（模型還在載、請求還沒填滿佇列），把它們算進去會讓穩態被稀釋。所以預設掐頭去尾，
而且把 p10 與 p90 一起印出來，讓你自己看得出那個平均值穩不穩。

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
    raise SystemExit(f"看不懂的時間格式：{text}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--from", dest="t_from", help="起始時間，預設是檔案第一筆")
    ap.add_argument("--to", dest="t_to", help="結束時間，預設是檔案最後一筆")
    ap.add_argument("--skip-head", type=float, default=0, help="視窗開頭跳過幾秒")
    ap.add_argument("--skip-tail", type=float, default=0, help="視窗結尾跳過幾秒")
    ap.add_argument("--soak-zone", type=int, default=88, help="算連續浸透的門檻")
    ap.add_argument("--json", action="store_true", help="輸出 JSON 而不是給人看的表")
    a = ap.parse_args()

    rows = [json.loads(l) for l in open(a.jsonl) if l.strip()]
    if not rows:
        raise SystemExit("空檔案")
    lo = parse_when(a.t_from) if a.t_from else rows[0]["t"]
    hi = parse_when(a.t_to) if a.t_to else rows[-1]["t"]
    lo, hi = lo + a.skip_head, hi - a.skip_tail
    w = [r for r in rows if lo <= r["t"] <= hi]
    if not w:
        raise SystemExit("視窗內沒有樣本，檢查時間範圍")

    def col(key):
        return [r[key] for r in w if r.get(key) is not None]

    power, gpu, zone, util = col("power_w"), col("gpu_c"), col("zone_c"), col("util")
    avail = col("avail_gib")

    # 浸透必須是連續的。掉回門檻以下代表冷卻追上了，而那正是活下來的那種狀態，
    # 所以累計秒數會誤導，要看的是最長的那一段。
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
