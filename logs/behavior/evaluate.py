#!/usr/bin/env python3
"""evaluate: detections against the injection schedule. Precision, recall,
F1 and the false positive rate per user-day, overall and per scenario,
with bootstrap confidence intervals; what each stage let through; the
latency of each layer; the misses and the false alarms with the reason
the model gave. Markdown for people, a json for the validation step, and
behavior.prom for the collector.

    evaluate.py --detections detections.jsonl --schedule schedule.p.tsv [--summaries summaries.jsonl] \
        [--timing timing.jsonl] [--manifest run-manifest.json] --out report.md [--json metrics.json] [--textfile behavior.prom]
        [--bootstrap 1000] [--seed 1]

A user-day is positive when the schedule has an injection for that user
starting on that local date; everything else in the test period is a
negative, the hard cases included. A detection is positive when the final
verdict is THREAT. The scenario is right when the final category is one
the schedule lists for that user-day.

Standard library only.
"""
import argparse, collections, json, os, random, statistics, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "lib", "python"))
from ops30 import rfc3339, textfile  # noqa: E402
from ops30.textfile import esc  # noqa: E402

SCENARIOS = ("S1", "S2", "S3", "S4", "S5", "S6")
NAMES = {"S1": "資料外傳", "S2": "越權目錄", "S3": "橫向移動", "S4": "憑證異常", "S5": "規避控管", "S6": "離職徵兆"}


def read_jsonl(path):
    out = []
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    out.append(json.loads(line))
    return out


def labels(path):
    lab = collections.defaultdict(set)
    with open(path, encoding="utf-8") as f:
        header = None
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            if header is None:
                header = cols
                continue
            row = dict(zip(header, cols))
            lab[(row["user"], row["start"][:10])].add(row["scenario"])
    return lab


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def counts(rows):
    tp = sum(1 for r in rows if r["pos"] and r["pred"])
    fp = sum(1 for r in rows if not r["pos"] and r["pred"])
    fn = sum(1 for r in rows if r["pos"] and not r["pred"])
    tn = sum(1 for r in rows if not r["pos"] and not r["pred"])
    p, r, f = prf(tp, fp, fn)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": r, "f1": f, "fpr": fp / (fp + tn) if fp + tn else 0.0}


def bootstrap(rows, B, seed):
    rnd = random.Random(seed)
    stats = collections.defaultdict(list)
    n = len(rows)
    for _ in range(B):
        sample = [rows[rnd.randrange(n)] for _ in range(n)]
        c = counts(sample)
        for k in ("precision", "recall", "f1", "fpr"):
            stats[k].append(c[k])
    out = {}
    for k, xs in stats.items():
        xs.sort()
        out[k] = (xs[int(0.025 * (B - 1))], xs[int(0.975 * (B - 1))])
    return out


def pct(x):
    return f"{100 * x:.1f}%"


def q(xs, p):
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))]


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(str(x).replace("|", "\\|") for x in r) + " |" for r in rows]
    return "\n".join(out) if rows else "_無_"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--detections", required=True); ap.add_argument("--schedule", required=True)
    ap.add_argument("--summaries"); ap.add_argument("--timing"); ap.add_argument("--manifest")
    ap.add_argument("--out", required=True); ap.add_argument("--json"); ap.add_argument("--textfile")
    ap.add_argument("--bootstrap", type=int, default=1000); ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--top", type=int, default=15)
    a = ap.parse_args()
    now = rfc3339.now()
    det = read_jsonl(a.detections)
    lab = labels(a.schedule)
    man = json.load(open(a.manifest, encoding="utf-8")) if a.manifest and os.path.exists(a.manifest) else {}
    rows = []
    for d in det:
        key = (d["user"], d["date"])
        rows.append({"user": d["user"], "date": d["date"], "role": d.get("role", ""), "pos": key in lab, "truth": sorted(lab.get(key, ())),
                     "pred": d["final"]["verdict"] == "THREAT", "cat": d["final"]["category"], "risk": d["final"].get("risk", 0),
                     "reason": d["final"].get("reason", ""), "flag": bool(d["stage1"].get("flag")), "s1cat": d["stage1"].get("category"),
                     "s1ms": d["stage1"].get("ms", 0) or 0, "s2ms": (d["stage2"] or {}).get("ms", 0) or 0, "s2": d["stage2"] is not None,
                     "prescreen": d.get("prescreen", 0), "error": bool(d["stage1"].get("error") or (d["stage2"] or {}).get("error"))})
    if not rows:
        sys.exit("evaluate: no detections")
    missing = [k for k in lab if k not in {(r["user"], r["date"]) for r in rows}]
    overall = counts(rows)
    ci = bootstrap(rows, a.bootstrap, a.seed) if a.bootstrap else {}
    pos = [r for r in rows if r["pos"]]
    per = {}
    for s in SCENARIOS:
        mine = [r for r in pos if s in r["truth"]]
        per[s] = {"n": len(mine), "detected": sum(1 for r in mine if r["pred"]), "flagged": sum(1 for r in mine if r["flag"]),
                  "category_ok": sum(1 for r in mine if r["pred"] and r["cat"] == s),
                  "predicted": sum(1 for r in rows if r["pred"] and r["cat"] == s),
                  "predicted_ok": sum(1 for r in rows if r["pred"] and r["cat"] == s and s in r["truth"])}
    stage1 = {"calls": sum(1 for r in rows if r["s1ms"] or r["flag"] or True), "flagged": sum(1 for r in rows if r["flag"]),
              "recall": (sum(1 for r in pos if r["flag"]) / len(pos)) if pos else 0.0}
    s2rows = [r for r in rows if r["s2"]]
    stage2 = {"calls": len(s2rows), "threats": sum(1 for r in s2rows if r["pred"]),
              "precision": (sum(1 for r in s2rows if r["pred"] and r["pos"]) / sum(1 for r in s2rows if r["pred"])) if any(r["pred"] for r in s2rows) else 0.0}
    # latency
    timing = read_jsonl(a.timing)
    l1 = {t["stage"]: t for t in timing if t.get("stage") in ("pseudonymize", "summarize")}
    l1_ms = sum(t["ms"] for t in l1.values())
    l1_per_ud = l1_ms / len(rows) if rows else 0.0
    s1ms = [r["s1ms"] for r in rows if r["s1ms"]]
    s2ms = [r["s2ms"] for r in rows if r["s2ms"]]
    s1_mean = statistics.fmean(s1ms) if s1ms else 0.0
    s2_mean = statistics.fmean(s2ms) if s2ms else 0.0
    share_s2 = (len(s2rows) / len(rows)) if rows else 0.0
    e2e_mean = l1_per_ud + s1_mean + s2_mean * share_s2          # expected per user-day
    e2e_flagged = l1_per_ud + s1_mean + s2_mean                    # a user-day that goes all the way
    lat = {"layer1_ms_total": l1_ms, "layer1_ms_per_user_day": l1_per_ud, "events": max((t.get("events", 0) for t in l1.values()), default=0),
           "stage1_ms": {"n": len(s1ms), "mean": s1_mean, "median": q(s1ms, 0.5), "p95": q(s1ms, 0.95)},
           "stage2_ms": {"n": len(s2ms), "mean": s2_mean, "median": q(s2ms, 0.5), "p95": q(s2ms, 0.95)},
           "end_to_end_ms_expected": e2e_mean, "end_to_end_ms_flagged": e2e_flagged,
           "share_flagged": {"layer1": l1_per_ud / e2e_flagged if e2e_flagged else 0, "slm": s1_mean / e2e_flagged if e2e_flagged else 0, "llm": s2_mean / e2e_flagged if e2e_flagged else 0}}

    # ---------------------------------------------------------------- markdown
    L = [f"# 行為偵測評估  產生於 {now:%Y-%m-%d %H:%M} UTC", ""]
    if man:
        L += [f"模型：初篩 `{man.get('slm')}`，判讀 `{man.get('llm')}`（backend {man.get('backend')}，提示版本 {man.get('prompt_version')}，輸入 sha256 `{str(man.get('input_sha256', ''))[:12]}`，30ops {man.get('ops30_version')}）", ""]
    L += [f"使用者日 {len(rows)}，其中注入 {len(pos)}（排程 {len(lab)} 筆" + (f"，{len(missing)} 筆沒有對應的使用者日" if missing else "") + f"），判為 THREAT {sum(1 for r in rows if r['pred'])}" + (f"，模型呼叫錯誤 {sum(1 for r in rows if r['error'])} 筆" if any(r["error"] for r in rows) else ""), ""]
    L += ["## 整體", "", md_table(["指標", "值", "95% 信賴區間（bootstrap）"], [
        ("Precision", pct(overall["precision"]), f"{pct(ci['precision'][0])} 到 {pct(ci['precision'][1])}" if ci else ""),
        ("Recall", pct(overall["recall"]), f"{pct(ci['recall'][0])} 到 {pct(ci['recall'][1])}" if ci else ""),
        ("F1", pct(overall["f1"]), f"{pct(ci['f1'][0])} 到 {pct(ci['f1'][1])}" if ci else ""),
        ("每使用者日偽陽性率", pct(overall["fpr"]), f"{pct(ci['fpr'][0])} 到 {pct(ci['fpr'][1])}" if ci else ""),
        ("TP / FP / FN / TN", f"{overall['tp']} / {overall['fp']} / {overall['fn']} / {overall['tn']}", "")]), ""]
    L += ["## 六類情境", "", md_table(["代碼", "情境", "注入使用者日", "初篩標記", "判為威脅（召回）", "類別正確", "被判為此類", "其中正確（精確）"],
          [(s, NAMES[s], per[s]["n"], per[s]["flagged"], f"{per[s]['detected']} ({pct(per[s]['detected'] / per[s]['n']) if per[s]['n'] else '-'})", per[s]["category_ok"],
            per[s]["predicted"], f"{per[s]['predicted_ok']} ({pct(per[s]['predicted_ok'] / per[s]['predicted']) if per[s]['predicted'] else '-'})") for s in SCENARIOS]), ""]
    L += ["## 二段式", "", md_table(["階段", "呼叫", "放行或判定", "說明"], [
        ("初篩（小模型）", len(rows), f"{stage1['flagged']} 標記（{pct(stage1['flagged'] / len(rows))}）", f"注入使用者日被標記 {pct(stage1['recall'])}；只有被標記的進入第二段"),
        ("判讀（大模型）", stage2["calls"], f"{stage2['threats']} THREAT", f"第二段的精確率 {pct(stage2['precision'])}")]), ""]
    L += ["## 延遲", "", f"第一層（假名化＋彙整）整批 {l1_ms:.0f} ms，攤到每個使用者日 {l1_per_ud:.1f} ms（事件 {lat['events']}）。", "",
          md_table(["階段", "筆數", "平均 ms", "中位數 ms", "p95 ms"], [
              ("初篩（小模型）", len(s1ms), f"{s1_mean:.0f}", f"{q(s1ms, 0.5):.0f}", f"{q(s1ms, 0.95):.0f}"),
              ("判讀（大模型）", len(s2ms), f"{s2_mean:.0f}", f"{q(s2ms, 0.5):.0f}", f"{q(s2ms, 0.95):.0f}")]), "",
          f"走完兩段的使用者日端對端 {e2e_flagged:.0f} ms：第一層 {pct(lat['share_flagged']['layer1'])}、小模型 {pct(lat['share_flagged']['slm'])}、大模型 {pct(lat['share_flagged']['llm'])}。平均每個使用者日（含未進第二段者）{e2e_mean:.0f} ms。"
          + ("（rules backend：模型時間為 0，此段只在模型執行時有意義。）" if not s1ms else ""), ""]
    fns = sorted([r for r in rows if r["pos"] and not r["pred"]], key=lambda r: r["prescreen"])
    L += ["## 漏報（注入但未判為威脅）", "", md_table(["日期", "使用者", "角色", "情境", "規則分數", "初篩", "最終", "理由"],
          [(r["date"], r["user"], r["role"], "/".join(r["truth"]), r["prescreen"], "標記" if r["flag"] else "未標記", f"{r['cat']} {r['risk']}", r["reason"][:60]) for r in fns]), ""]
    fps = sorted([r for r in rows if not r["pos"] and r["pred"]], key=lambda r: -r["risk"])[: a.top]
    L += ["## 誤報（未注入但判為威脅）", "", md_table(["日期", "使用者", "角色", "判定", "風險", "規則分數", "理由"],
          [(r["date"], r["user"], r["role"], r["cat"], r["risk"], r["prescreen"], r["reason"][:60]) for r in fps]), ""]
    L += ["## 類別混淆（注入使用者日）", "", md_table(["注入情境", *SCENARIOS, "NONE/未判為威脅"],
          [(s, *[sum(1 for r in pos if s in r["truth"] and r["pred"] and r["cat"] == c) for c in SCENARIOS], sum(1 for r in pos if s in r["truth"] and (not r["pred"] or r["cat"] == "NONE"))) for s in SCENARIOS]), ""]
    md = "\n".join(L)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(md)
    metrics = {"generated": rfc3339.format(now), "user_days": len(rows), "positives": len(pos), "overall": overall,
               "ci95": {k: list(v) for k, v in ci.items()}, "per_scenario": per, "stage1": stage1, "stage2": stage2, "latency": lat,
               "manifest": man, "false_negatives": [{k: r[k] for k in ("date", "user", "truth", "prescreen", "flag", "cat", "risk", "reason")} for r in fns],
               "false_positives": [{k: r[k] for k in ("date", "user", "role", "cat", "risk", "prescreen", "reason")} for r in fps]}
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(metrics, f, ensure_ascii=False, indent=1)
    if a.textfile:
        T = []
        textfile.family(T, "behavior_user_days", "User-days evaluated in the last run")
        T.append(f"behavior_user_days {len(rows)}")
        textfile.family(T, "behavior_positives", "User-days with an injected scenario")
        T.append(f"behavior_positives {len(pos)}")
        textfile.family(T, "behavior_confusion", "TP, FP, FN, TN of the last run")
        for k in ("tp", "fp", "fn", "tn"):
            T.append(f'behavior_confusion{{cell="{k}"}} {overall[k]}')
        for k in ("precision", "recall", "f1", "fpr"):
            textfile.family(T, f"behavior_{k}", f"{k} of the last run, 0 to 1")
            T.append(f"behavior_{k} {overall[k]:.4f}")
            if ci:
                textfile.family(T, f"behavior_{k}_ci", f"bootstrap 95% interval of {k}")
                T.append(f'behavior_{k}_ci{{bound="low"}} {ci[k][0]:.4f}')
                T.append(f'behavior_{k}_ci{{bound="high"}} {ci[k][1]:.4f}')
        textfile.family(T, "behavior_scenario_recall", "Injected user-days judged THREAT, per scenario, 0 to 1")
        for s in SCENARIOS:
            T.append(f'behavior_scenario_recall{{scenario="{esc(s)}"}} {(per[s]["detected"] / per[s]["n"]) if per[s]["n"] else 0:.4f}')
        textfile.family(T, "behavior_stage_calls", "Model calls per stage")
        T.append(f'behavior_stage_calls{{stage="slm"}} {len(rows)}')
        T.append(f'behavior_stage_calls{{stage="llm"}} {stage2["calls"]}')
        textfile.family(T, "behavior_latency_ms", "Latency per stage: layer1 per user-day, slm and llm per call")
        T.append(f'behavior_latency_ms{{stage="layer1",stat="mean"}} {l1_per_ud:.1f}')
        for name, xs in (("slm", s1ms), ("llm", s2ms)):
            T.append(f'behavior_latency_ms{{stage="{name}",stat="mean"}} {(statistics.fmean(xs) if xs else 0):.1f}')
            T.append(f'behavior_latency_ms{{stage="{name}",stat="p95"}} {q(xs, 0.95):.1f}')
        textfile.family(T, "behavior_eval_last_run_timestamp", "Unix time of the last evaluate run")
        T.append(f"behavior_eval_last_run_timestamp {int(now.timestamp())}")
        textfile.write(a.textfile, "\n".join(T) + "\n")
    print(f"evaluate: {len(rows)} user-days, {len(pos)} positives, P {pct(overall['precision'])} R {pct(overall['recall'])} F1 {pct(overall['f1'])} FPR/user-day {pct(overall['fpr'])} -> {a.out}")


if __name__ == "__main__":
    main()
