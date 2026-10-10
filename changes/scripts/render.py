#!/usr/bin/env python3
"""render: rebuild the change index in README.md and README.zh-TW.md from
the front matter of changes/*.md, between the INDEX markers.

    scripts/render.py            # rewrite both READMEs
    scripts/render.py --check    # exit 1 if either README is stale (CI)

Newest id first. The table is the only thing people read day to day; the
records themselves are the evidence.
"""
import argparse
import glob
import os
import sys

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


def table(rows, lang):
    if lang == "zh":
        h = ["| 編號 | 標題 | 狀態 | 風險 | 資產 | 窗 | 核准 |", "|---|---|---|---|---|---|---|"]
    else:
        h = ["| Id | Title | Status | Risk | Assets | Window | Approver |", "|---|---|---|---|---|---|---|"]
    for m in rows:
        assets = ", ".join(m.get("assets", [])) if isinstance(m.get("assets"), list) else m.get("assets", "")
        win = f"{m.get('window_start', '')[:16]} to {m.get('window_end', '')[11:16]}" if m.get("window_start") else "-"
        appr = m.get("approver", "") + (" (exception)" if m.get("approval_exception") else "")
        h.append(f"| [{m['id']}]({m['_file']}) | {m['title']} | `{m['status']}` | {m['risk']} | {assets} | {win} | {appr} |")
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
