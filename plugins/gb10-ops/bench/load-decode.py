#!/usr/bin/env python3
"""Drive sustained decode against an OpenAI-compatible endpoint.

For a power measurement the thing that must stay true is that the GPU is
decoding for the whole window. Two traps this avoids: prefix caching, which
turns a repeated prompt into a cheap prefill and shrinks the work (so every
worker gets its own random prefix), and short generations, which spend the
window on prefill and scheduling instead of decode (so max_tokens is long).

The default prompt is Traditional Chinese, which is what the numbers on this box
were collected with. Changing it with --prompt changes how many tokens the same
text becomes, and different engines disagree about that for the same string, so
do not compare token counts across prompts or across engines without checking
that first.
"""
import argparse, json, random, string, sys, threading, time
import urllib.request

DEFAULT_PROMPT = ("請用繁體中文寫一段技術說明，主題是統一記憶體架構下的推論排程，"
                  "內容要具體、不要條列、不要開場白，長度不限。")

def rand_tag(n=48):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def one(base, model, key, max_tokens, prompt_text, stats, lock):
    prompt = f"[{rand_tag()}] {prompt_text}"
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.9,
        "stream": False,
    }).encode()
    req = urllib.request.Request(f"{base}/v1/chat/completions", data=body,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {key}"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=900) as r:
        d = json.loads(r.read())
    u = d.get("usage") or {}
    with lock:
        stats["reqs"] += 1
        stats["out_tokens"] += u.get("completion_tokens", 0)
        stats["in_tokens"] += u.get("prompt_tokens", 0)
        stats["wall"] += time.time() - t0

def worker(args, deadline, stats, lock):
    while time.time() < deadline:
        try:
            one(args.base, args.model, args.key, args.max_tokens, args.prompt,
                stats, lock)
        except Exception as e:
            with lock:
                stats["errors"] += 1
                stats.setdefault("last_error", str(e)[:200])
            time.sleep(2)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8008")
    ap.add_argument("--model", required=True)
    ap.add_argument("--key", default="dummy")
    ap.add_argument("--concurrency", type=int, default=12)
    ap.add_argument("--seconds", type=float, default=600)
    ap.add_argument("--max-tokens", type=int, default=512)
    ap.add_argument("--prompt", default=DEFAULT_PROMPT,
                    help="prompt body; a random prefix is prepended per request")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    stats = {"reqs": 0, "out_tokens": 0, "in_tokens": 0, "wall": 0.0, "errors": 0}
    lock = threading.Lock()
    start = time.time()
    deadline = start + a.seconds
    threads = [threading.Thread(target=worker, args=(a, deadline, stats, lock), daemon=True)
               for _ in range(a.concurrency)]
    print(f"load: {a.concurrency} concurrent, {a.seconds:.0f}s, max_tokens={a.max_tokens}", flush=True)
    for t in threads:
        t.start()
    while any(t.is_alive() for t in threads):
        time.sleep(15)
        el = time.time() - start
        with lock:
            print(f"  {el:6.0f}s  reqs={stats['reqs']:4d}  out_tok={stats['out_tokens']:7d}  "
                  f"{stats['out_tokens']/max(el,1):6.1f} tok/s  err={stats['errors']}", flush=True)
    el = time.time() - start
    stats["elapsed_s"] = round(el, 1)
    stats["decode_tok_s"] = round(stats["out_tokens"] / el, 2)
    stats["started_at"] = time.strftime("%FT%T%z", time.localtime(start))
    stats["ended_at"] = time.strftime("%FT%T%z")
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    if a.out:
        with open(a.out, "w") as fh:
            json.dump(stats, fh, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    sys.exit(main())
