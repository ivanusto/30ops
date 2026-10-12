#!/usr/bin/env python3
"""render: rebuild the change index in README.md and README.zh-TW.md from
the front matter of changes/*.md, between the INDEX markers.

    scripts/render.py            # rewrite both READMEs
    scripts/render.py --check    # exit 1 if either README is stale (CI)

Newest id first. The table is the only thing people read day to day; the
records themselves are the evidence. Day 28 adds a rollback-drill column
from drills/drills.jsonl: the date and result of the last drill that ran
this record's rollback section, "-" when none has.
"""
import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from frontmatter import parse  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
START, END = "<!-- INDEX:START -->", "<!-- INDEX:END -->"


def records():
    out = []
    for f in sorted(glob.glob(os.path.join(ROOT, "changes", "CR-*.md")), reverse=True):
        with open(f, encoding="utf-8") as fh:
            meta, _, _ = parse(fh.read())
        meta["_file"] = os.path.relpath(f, ROOT)
        out.append(meta)
    return out


def drills(path=os.path.join(ROOT, "drills", "drills.jsonl")):
    """{rollback_of: (t0 datetime, result, drill cr)} for the latest drill per record."""
    out = {}
    try:
        fh = open(path, encoding="utf-8")
    except OSError:
        return out
    with fh:
        for line in fh:
            try:
                r = json.loads(line)
                t0 = datetime.strptime(r["t0"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                of = str(r["rollback_of"])
            except (ValueError, KeyError, TypeError):
                continue
            if of not in out or t0 >= out[of][0]:
                out[of] = (t0, str(r.get("result", "")).upper(), str(r.get("cr", "")))
    return out


def table(rows, lang, drilled=None):
    drilled = drilled if drilled is not None else drills()
    if lang == "zh":
        h = ["| 編號 | 標題 | 狀態 | 風險 | 資產 | 窗 | 核准 | 回退演練 |", "|---|---|---|---|---|---|---|---|"]
    else:
        h = ["| Id | Title | Status | Risk | Assets | Window | Approver | Rollback drill |", "|---|---|---|---|---|---|---|---|"]
    for m in rows:
        assets = ", ".join(m.get("assets", [])) if isinstance(m.get("assets"), list) else m.get("assets", "")
        win = f"{m.get('window_start', '')[:16]} to {m.get('window_end', '')[11:16]}" if m.get("window_start") else "-"
        appr = m.get("approver", "") + (" (exception)" if m.get("approval_exception") else "")
        d = drilled.get(m["id"])
        drill = f"{d[0].strftime('%Y-%m-%d')} {d[1]} ([{d[2]}](drills/drills.md))" if d else "-"
        h.append(f"| [{m['id']}]({m['_file']}) | {m['title']} | `{m['status']}` | {m['risk']} | {assets} | {win} | {appr} | {drill} |")
    return "\n".join(h)


def splice(text, block):
    i, j = text.find(START), text.find(END)
    if i < 0 or j < 0 or j < i:
        sys.exit("README lacks the INDEX markers")
    return text[: i + len(START)] + "\n" + block + "\n" + text[j:]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    rows = records()
    stale = []
    for name, lang in (("README.md", "en"), ("README.zh-TW.md", "zh")):
        p = os.path.join(ROOT, name)
        with open(p, encoding="utf-8") as f:
            cur = f.read()
        new = splice(cur, table(rows, lang))
        if new != cur:
            if a.check:
                stale.append(name)
            else:
                with open(p, "w", encoding="utf-8") as f:
                    f.write(new)
                print(f"wrote {name} ({len(rows)} records)")
    if a.check:
        if stale:
            sys.exit(f"stale: {', '.join(stale)}; run scripts/render.py")
        print("index up to date")


if __name__ == "__main__":
    main()
