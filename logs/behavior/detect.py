#!/usr/bin/env python3
"""detect: the two-stage inference. A small model reads every user-day
summary and flags the ones worth a second look; a larger model reads only
those and gives a verdict, a scenario, a risk score and a reason. Every
decision is appended to a hash-chained file, the way the agent gate keeps
its audit, so a record cannot be changed or removed without the chain
saying so.

    detect.py run --in summaries.jsonl --out detections.jsonl --backend ollama \
        --slm gemma4:e4b-mlx --llm gemma4:26b-nvfp4 [--ollama http://127.0.0.1:11434] [--manifest run-manifest.json]
    detect.py run --in summaries.jsonl --out detections.jsonl --backend openai \
        --base-url http://inference-node:8000 --slm dsv41-flash-exl3 --llm dsv41-flash-exl3   # vLLM or any OpenAI-compatible server
    detect.py run ... --slm-backend ollama --slm gemma4:e4b-mlx --llm-backend openai --llm dsv41-flash-exl3   # a stage on each
    detect.py run --in summaries.jsonl --out detections.jsonl --backend rules     # deterministic, no model, CI
    detect.py verify --in detections.jsonl

Backends (--backend sets both stages, --slm-backend and --llm-backend one each)
    ollama   chat calls to Ollama (think off, JSON output, temperature 0);
             the time of each call is recorded
    openai   chat completions on an OpenAI-compatible server (vLLM, SGLang,
             llama.cpp): temperature 0, JSON object response format,
             `chat_template_kwargs` thinking off; --api-key if the server wants one
    rules    stage 1 flags prescreen >= --t1, stage 2 says THREAT at
             prescreen >= --t2; the same thresholds the report explains
             the rule score with. The chain, the manifest and the output
             shape are identical, so the whole pipeline is tested without
             a model and a model run is compared against the rules.

--prescreen-min skips stage 1 for user-days under that rule score (a cost
mode; the default 0 sends every summary to the small model, as the
design says). --limit stops after N user-days (a dry run).

The manifest records the models, the sha256 of both prompts and of the
input, the thresholds and the versions, the "fixed seed and recorded
versions" of the reproducibility plan.

Standard library only.
"""
import argparse, glob, hashlib, json, os, platform, re, sys, time, urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "lib", "python"))
import ops30  # noqa: E402
from ops30 import rfc3339  # noqa: E402

PROMPT_VERSION = "2026-11-02.1"
SCENARIOS = ("S1", "S2", "S3", "S4", "S5", "S6")

STAGE1 = """你是企業內部威脅初篩器。輸入是一位使用者一天行為的彙整摘要，第二行「觸發訊號」列出已超過門檻的項目與它們指向的情境，其後每個數字旁附有該使用者自己的基線與偏離量（σ）。你的工作是判斷這一天是否值得交給資深分析師複核，寧可多送，不可漏掉：只要有任何觸發訊號，除非其餘內容明確顯示是例行工作，就應標記。
六類情境：
S1 資料外傳：對外或個人儲存、網頁郵件的大量傳輸，尤其在非工作時段
S2 越權目錄：首次存取非職務的共享區、短時間內大量讀取
S3 橫向移動：對多台內部主機的短連線 RDP/SMB、單一主機多埠（掃描）、多個新的登入目標
S4 憑證異常：多次失敗後成功、來自新的來源主機、非工作時段登入
S5 規避控管：DoH、代理或 VPN 類連線、被阻擋的連線、USB 儲存裝置
S6 離職徵兆：五日累積的讀取、壓縮檔與列印緩步上升，單日不突出
判斷原則：IT 與服務帳號本來就接觸多台主機；偏離量小於 2σ 且沒有任何新實體，通常是正常；新進人員以同職務基線比較，首週會有新共享區。
只輸出 JSON：{"flag":true或false,"category":"S1"到"S6"或"NONE","confidence":0到1之間的數字}"""

STAGE2 = """你是企業資安團隊的資深分析師，負責內部威脅研判。輸入是一位使用者一天行為的彙整摘要（帳號與主機已假名化），第二行「觸發訊號」列出已超過門檻的項目，其後每個數字旁附有該使用者自己的基線與偏離量（σ），最後是初篩器的意見。訊號是線索不是結論，請以整段摘要判斷。請判斷這一天是否為內部威脅事件，並說明依據。
六類情境：
S1 資料外傳：對外或個人儲存、網頁郵件的大量傳輸，尤其在非工作時段；核准的業務網域與平日相近的量不算
S2 越權目錄：首次存取非職務的共享區且短時間內大量讀取；在本職共享區內的大量作業（例如薪資結算）不算
S3 橫向移動：對多台內部主機的短連線 RDP/SMB、單一主機多埠（掃描）、多個新的登入目標；IT 人員在工作時段對伺服器的例行維護，若沒有掃描與新目標，不算
S4 憑證異常：多次失敗後成功、來自新的來源主機、非工作時段登入
S5 規避控管：DoH、代理或 VPN 類連線、被阻擋的連線、USB 儲存裝置
S6 離職徵兆：五日累積的讀取、壓縮檔與列印相對基線明顯上升
風險分數 0 到 100：0 到 39 正常、40 到 69 需要人工確認、70 以上高度可疑。verdict 為 THREAT 時 risk 至少 40。
只輸出 JSON：{"verdict":"THREAT"或"NORMAL","category":"S1"到"S6"或"NONE","risk":0到100的整數,"reason":"40字以內的中文依據"}"""


STAGE1_HOST = """你是資安監控的初篩器。輸入是一台主機一天的告警彙整（主機與帳號已假名化），第二行「觸發訊號」列出已超過門檻的項目，其後每個數字旁附有這台主機自己的基線與偏離量（σ）。你的工作是判斷這一天是否值得交給資深分析師複核，寧可多送，不可漏掉：只要有內部行為的觸發訊號，除非其餘內容明確顯示是例行工作，就應標記。
對外服務本來就持續收到來自公網的掃描與垃圾信，這些外部噪音本身不算內部威脅。
三類情境（本資料的來源只能觀察這三類）：
S3 橫向移動：來自新的內部來源的登入或偵察告警、單日多個內部來源、內部來源的權限操作
S4 憑證異常：多次失敗後成功、新的帳號或來源、非工作時段登入
S5 規避控管：安裝或執行 VPN、代理、通道類工具，USB 儲存裝置，非工作時段修改受監控檔案
判斷原則：服務帳號與排程作業每天相同的行為通常正常；偏離量小於 2σ 且沒有任何新實體，通常是正常。
只輸出 JSON：{"flag":true或false,"category":"S3"、"S4"、"S5"或"NONE","confidence":0到1之間的數字}"""

STAGE2_HOST = """你是企業資安團隊的資深分析師，負責內部威脅研判。輸入是一台主機一天的告警彙整（主機與帳號已假名化），第二行「觸發訊號」列出已超過門檻的項目，其後每個數字旁附有這台主機自己的基線與偏離量（σ），最後是初篩器的意見。訊號是線索不是結論，請以整段摘要判斷。公網來源的掃描、暴力嘗試與垃圾信若沒有成功登入，不算內部威脅。
三類情境：
S3 橫向移動：來自新的內部來源的登入或偵察告警、單日多個內部來源、內部來源的權限操作；維運帳號在工作時段的例行作業若沒有新來源，不算
S4 憑證異常：多次失敗後成功、新的帳號或來源、非工作時段登入
S5 規避控管：安裝或執行 VPN、代理、通道類工具，USB 儲存裝置，非工作時段修改受監控檔案；例行更新不算
風險分數 0 到 100：0 到 39 正常、40 到 69 需要人工確認、70 以上高度可疑。verdict 為 THREAT 時 risk 至少 40。
只輸出 JSON：{"verdict":"THREAT"或"NORMAL","category":"S3"、"S4"、"S5"或"NONE","risk":0到100的整數,"reason":"40字以內的中文依據"}"""

PROMPTS = {"user": (STAGE1, STAGE2), "host": (STAGE1_HOST, STAGE2_HOST)}


def sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def thermal_gate(hot, cool, zones="/sys/class/thermal/thermal_zone*/temp"):
    """Stop sending while the box is hot; a host without the sensor just goes on."""
    if not hot:
        return 0.0
    def zone():
        vals = []
        for p in glob.glob(zones):
            try:
                with open(p) as f:
                    vals.append(int(f.read()) // 1000)
            except (OSError, ValueError):
                pass
        return max(vals) if vals else 0
    if zone() < hot:
        return 0.0
    t0 = time.monotonic()
    while zone() > cool:
        time.sleep(5)
    return time.monotonic() - t0


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_json(txt):
    try:
        return json.loads(txt, strict=False)
    except ValueError:
        m = re.search(r"\{.*\}", txt or "", re.S)
        if m:
            try:
                return json.loads(m.group(0), strict=False)
            except ValueError:
                pass
    return {}


def norm_cat(c):
    c = str(c or "").upper().strip()
    return c if c in SCENARIOS else "NONE"


# ------------------------------------------------------------------ backends

class Ollama:
    def __init__(self, a):
        self.url, self.slm, self.llm, self.think = a.ollama.rstrip("/"), a.slm, a.llm, a.think
        self.keep = a.keep_alive
        self.setup(a)

    def setup(self, a):
        self.p1, self.p2 = PROMPTS[a.entity]
        self.hot, self.cool, self.paused = a.thermal_hot, a.thermal_cool, 0.0

    def chat(self, model, system, user, num_predict):
        body = {"model": model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "stream": False, "think": self.think, "format": "json", "keep_alive": self.keep,
                "options": {"temperature": 0, "num_predict": num_predict}}
        req = urllib.request.Request(self.url + "/api/chat", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=900) as r:
            res = json.loads(r.read().decode("utf-8", "replace"), strict=False)
        ms = (time.perf_counter() - t0) * 1000
        return parse_json(res.get("message", {}).get("content", "")), ms, {k: res.get(k) for k in ("prompt_eval_count", "eval_count", "total_duration")}

    def stage1(self, rec):
        try:
            self.paused += thermal_gate(self.hot, self.cool)
            j, ms, usage = self.chat(self.slm, self.p1, rec["text"], 200)
            if "flag" not in j:      # an answer that cannot be read must not read as "not flagged"
                return {"model": self.slm, "flag": True, "category": "NONE", "confidence": 0, "ms": round(ms), "usage": usage, "parse_error": True}
            return {"model": self.slm, "flag": bool(j.get("flag")), "category": norm_cat(j.get("category")),
                    "confidence": float(j.get("confidence") or 0), "ms": round(ms), "usage": usage}
        except Exception as e:  # noqa: BLE001  a failed call is a record too
            return {"model": self.slm, "flag": True, "category": "NONE", "confidence": 0, "ms": 0, "error": str(e)[:200]}

    def stage2(self, rec, s1):
        user = rec["text"] + f"\n\n初篩器意見：{'可疑' if s1.get('flag') else '正常'}，情境 {s1.get('category')}，信心 {s1.get('confidence', 0):.2f}。"
        try:
            self.paused += thermal_gate(self.hot, self.cool)
            j, ms, usage = self.chat(self.llm, self.p2, user, 400)
            if "verdict" not in j:
                return {"model": self.llm, "verdict": "ERROR", "category": "NONE", "risk": 0, "reason": "", "ms": round(ms), "usage": usage, "parse_error": True}
            v = str(j.get("verdict", "")).upper()
            risk = int(float(j.get("risk") or 0))
            return {"model": self.llm, "verdict": "THREAT" if v == "THREAT" else "NORMAL", "category": norm_cat(j.get("category")),
                    "risk": max(0, min(100, risk)), "reason": str(j.get("reason", ""))[:120], "ms": round(ms), "usage": usage}
        except Exception as e:  # noqa: BLE001
            return {"model": self.llm, "verdict": "ERROR", "category": "NONE", "risk": 0, "reason": "", "ms": 0, "error": str(e)[:200]}


class OpenAI(Ollama):
    """Chat completions on an OpenAI-compatible server. Same prompts, same
    parsing; only the wire format differs."""
    def __init__(self, a):
        self.url, self.slm, self.llm, self.think = a.base_url.rstrip("/"), a.slm, a.llm, a.think
        self.key = a.api_key or os.environ.get("OPENAI_API_KEY", "")
        if a.api_key_file:
            with open(a.api_key_file, encoding="utf-8") as f:
                self.key = f.read().strip()
        self.seed = a.seed
        self.setup(a)

    def chat(self, model, system, user, num_predict):
        body = {"model": model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": 0, "seed": self.seed, "max_tokens": num_predict if not self.think else num_predict + 2000,
                "response_format": {"type": "json_object"}, "chat_template_kwargs": {"thinking": self.think, "enable_thinking": self.think}}
        hdr = {"Content-Type": "application/json"}
        if self.key:
            hdr["Authorization"] = "Bearer " + self.key
        req = urllib.request.Request(self.url + "/v1/chat/completions", data=json.dumps(body).encode(), headers=hdr)
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=900) as r:
            res = json.loads(r.read().decode("utf-8", "replace"), strict=False)
        ms = (time.perf_counter() - t0) * 1000
        msg = (res.get("choices") or [{}])[0].get("message", {})
        u = res.get("usage") or {}
        return parse_json(msg.get("content", "")), ms, {"prompt_eval_count": u.get("prompt_tokens"), "eval_count": u.get("completion_tokens")}


class Mixed:
    """stage 1 on one backend, stage 2 on another"""
    def __init__(self, s1, s2):
        self.stage1, self.stage2 = s1.stage1, s2.stage2


def make(kind, a):
    return {"ollama": Ollama, "openai": OpenAI, "rules": Rules}[kind](a)


class Rules:
    def __init__(self, a):
        self.t1, self.t2 = a.t1, a.t2

    def stage1(self, rec):
        p = rec.get("prescreen", 0)
        return {"model": "rules", "flag": p >= self.t1, "category": rec.get("guess", "NONE") if p >= self.t1 else "NONE",
                "confidence": round(min(1.0, p / 20), 2), "ms": 0}

    def stage2(self, rec, s1):
        p = rec.get("prescreen", 0)
        threat = p >= self.t2
        return {"model": "rules", "verdict": "THREAT" if threat else "NORMAL", "category": rec.get("guess", "NONE") if threat else "NONE",
                "risk": int(min(100, p * 5)), "reason": f"規則分數 {p}（門檻 {self.t2}），主要訊號 {rec.get('guess')}", "ms": 0}


# ------------------------------------------------------------------ chain

def last_record(path):
    last = None
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)
    return last


def chained(rec, last):
    rec = dict(rec, seq=(last["seq"] + 1) if last else 1, prev=last["hash"] if last else "0" * 64)
    rec["hash"] = sha256(rec["prev"] + "\n" + canonical({k: v for k, v in rec.items() if k != "hash"}))
    return rec


def verify(path):
    prev, n = "0" * 64, 0
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            r = json.loads(line)
            body = {k: v for k, v in r.items() if k != "hash"}
            if r.get("prev") != prev or sha256(prev + "\n" + canonical(body)) != r.get("hash") or r.get("seq") != n + 1:
                return False, f"chain broken at line {i} (seq {r.get('seq')})"
            prev, n = r["hash"], n + 1
    return True, f"{n} records, chain intact"


# ------------------------------------------------------------------ run

def run(a):
    a.slm_backend = a.slm_backend or a.backend
    a.llm_backend = a.llm_backend or a.backend
    be = make(a.slm_backend, a) if a.slm_backend == a.llm_backend else Mixed(make(a.slm_backend, a), make(a.llm_backend, a))
    models = a.slm_backend != "rules" or a.llm_backend != "rules"
    recs = []
    with open(a.inp, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                recs.append(json.loads(line))
    if a.limit:
        recs = recs[: a.limit]
    last = last_record(a.out)
    if last and not a.append:
        sys.exit(f"detect: {a.out} exists; use --append to continue the chain or choose another file")
    started = rfc3339.format(rfc3339.now())
    # two passes: every summary through the small model first, then the
    # flagged ones through the large one. On a host that cannot hold both
    # models at once this is the difference between two loads and hundreds.
    s1s, n1 = [], 0
    for i, rec in enumerate(recs, 1):
        if rec.get("prescreen", 0) < a.prescreen_min:
            s1s.append({"model": "skipped", "flag": False, "category": "NONE", "confidence": 0, "ms": 0, "skipped": True})
        else:
            s1s.append(be.stage1(rec)); n1 += 1
        if models and (i % 25 == 0 or i == len(recs)):
            print(f"detect: stage 1 {i}/{len(recs)}, {sum(1 for x in s1s if x['flag'])} flagged", file=sys.stderr, flush=True)
    s2s, n2 = [None] * len(recs), 0
    todo = [i for i, x in enumerate(s1s) if x["flag"]]
    for j, i in enumerate(todo, 1):
        s2s[i] = be.stage2(recs[i], s1s[i]); n2 += 1
        if models and (j % 10 == 0 or j == len(todo)):
            print(f"detect: stage 2 {j}/{len(todo)}, {sum(1 for x in s2s if x and x['verdict'] == 'THREAT')} THREAT", file=sys.stderr, flush=True)
    flagged, threats = len(todo), 0
    with open(a.out, "a", encoding="utf-8") as fo:
        for rec, s1, s2 in zip(recs, s1s, s2s):
            final = ({"verdict": s2["verdict"], "category": s2["category"], "risk": s2["risk"], "reason": s2["reason"]} if s2
                     else {"verdict": "NORMAL", "category": "NONE", "risk": int(min(39, s1.get("confidence", 0) * 39)), "reason": "初篩未標記"})
            threats += final["verdict"] == "THREAT"
            out = {"ts": rfc3339.format(rfc3339.now()), "user": rec["user"], "date": rec["date"], "role": rec.get("role", ""),
                   "prescreen": rec.get("prescreen"), "guess": rec.get("guess"), "summary_sha256": sha256(rec["text"]),
                   "stage1": s1, "stage2": s2, "final": final}
            last = chained(out, last)
            fo.write(canonical(last) + "\n")
    finished = rfc3339.format(rfc3339.now())
    if a.manifest:
        man = {"started": started, "finished": finished, "backend": a.backend, "slm_backend": a.slm_backend, "llm_backend": a.llm_backend,
               "slm": a.slm if a.slm_backend != "rules" else "rules", "llm": a.llm if a.llm_backend != "rules" else "rules",
               "think": a.think, "prompt_version": PROMPT_VERSION,
               "entity": a.entity, "seed": a.seed, "engine": a.engine,
               "prompt1_sha256": sha256(PROMPTS[a.entity][0]), "prompt2_sha256": sha256(PROMPTS[a.entity][1]), "input": os.path.basename(a.inp),
               "input_sha256": file_sha256(a.inp), "user_days": len(recs), "stage1_calls": n1, "stage2_calls": n2,
               "flagged": flagged, "threats": threats, "t1": a.t1, "t2": a.t2, "prescreen_min": a.prescreen_min,
               "parse_errors": sum(1 for x in s1s if x.get("parse_error")) + sum(1 for x in s2s if x and x.get("parse_error")),
               "call_errors": sum(1 for x in s1s if x.get("error")) + sum(1 for x in s2s if x and x.get("error")),
               "ops30_version": ops30.version(), "python": platform.python_version(),
               "ollama": a.ollama if "ollama" in (a.slm_backend, a.llm_backend) else None,
               "base_url": a.base_url if "openai" in (a.slm_backend, a.llm_backend) else None}
        if "openai" in (a.slm_backend, a.llm_backend):
            try:
                with urllib.request.urlopen(a.base_url.rstrip("/") + "/version", timeout=10) as r:
                    man["server_version"] = json.loads(r.read().decode()).get("version")
            except Exception:  # noqa: BLE001
                pass
        if "ollama" in (a.slm_backend, a.llm_backend):
            try:
                with urllib.request.urlopen(a.ollama.rstrip("/") + "/api/version", timeout=10) as r:
                    man["ollama_version"] = json.loads(r.read().decode()).get("version")
            except Exception:  # noqa: BLE001
                pass
        with open(a.manifest, "w", encoding="utf-8") as f:
            json.dump(man, f, ensure_ascii=False, indent=1)
    print(f"detect: {len(recs)} user-days, stage1 {n1} calls, {flagged} flagged, stage2 {n2} calls, {threats} THREAT -> {a.out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--in", dest="inp", required=True); r.add_argument("--out", required=True)
    r.add_argument("--backend", choices=("ollama", "openai", "rules"), default="rules")
    r.add_argument("--slm-backend", choices=("ollama", "openai", "rules")); r.add_argument("--llm-backend", choices=("ollama", "openai", "rules"))
    r.add_argument("--ollama", default=os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"))
    r.add_argument("--base-url", default=os.environ.get("OPENAI_BASE_URL", "http://127.0.0.1:8000"), help="OpenAI-compatible server for --backend openai")
    r.add_argument("--api-key"); r.add_argument("--api-key-file", help="read the key from a file, so it is not in the process list")
    r.add_argument("--entity", choices=("user", "host"), default="user", help="what one summary is about; picks the prompts")
    r.add_argument("--seed", type=int, default=7, help="sent on every call and recorded; some servers otherwise use a hidden default")
    r.add_argument("--engine", default="", help="engine image or version, recorded in the manifest")
    r.add_argument("--thermal-hot", type=int, default=0, help="stop sending at this zone temperature (C); 0 is off")
    r.add_argument("--thermal-cool", type=int, default=74)
    r.add_argument("--slm", default="gemma4:e4b-mlx"); r.add_argument("--llm", default="gemma4:26b-nvfp4")
    r.add_argument("--think", action="store_true", help="let the models think (slower, not better on this task in the lab)")
    r.add_argument("--keep-alive", default="10m")
    r.add_argument("--t1", type=float, default=6.0); r.add_argument("--t2", type=float, default=9.0)
    r.add_argument("--prescreen-min", type=float, default=0.0)
    r.add_argument("--limit", type=int, default=0)
    r.add_argument("--append", action="store_true")
    r.add_argument("--manifest")
    v = sub.add_parser("verify")
    v.add_argument("--in", dest="inp", required=True)
    a = ap.parse_args()
    if a.cmd == "verify":
        ok, msg = verify(a.inp)
        print(msg)
        sys.exit(0 if ok else 1)
    run(a)


if __name__ == "__main__":
    main()
