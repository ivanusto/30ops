#!/usr/bin/env python3
"""check: every change record in changes/ is complete enough for its status.

    scripts/check.py                          # all of changes/*.md
    scripts/check.py changes/CR-2026-0001-*.md
    scripts/check.py --assets ../onprem-metrics/eol/assets.tsv   # assets must exist there

Rules, in the order they are reported
  file      name is CR-YYYY-NNNN-<slug>.md and matches `id`; ids are unique
  fields    id, title, status, type, risk, requester, implementer, assets (a
            non-empty list of asset/component); approver from `approved` on
  enums     status draft|approved|scheduled|in_progress|done|rolled_back|cancelled
            type standard|emergency   risk low|medium|high
  approval  from `approved` on, approver is set and differs from implementer;
            the same person needs `approval_exception:` with a reason (a
            one-person site says so in writing instead of pretending)
  window    from `scheduled` on, window_start and window_end are RFC 3339
            with an offset and end is after start
  sections  ## 目的 影響 步驟 驗證 回退 紀錄 all present; 回退 is not empty;
            a high-risk change with no rollback has to say 無 and why
  record    done and rolled_back carry begin:, end: and result: in 紀錄
  assets    with --assets, every asset/component is a row in that TSV
  agent     optional (Day 29): the agents that may work under this record
            through onprem-agent-gate, each `agent:<name>`; the gate denies
            any call whose record does not name its principal here

Exit 0 when every file passes, 1 otherwise. The CI runs it on every push;
the GitHub branch protection (one review, not by the author) is what makes
`approver` mean something, this script only checks that it is written down.
"""
import argparse
import csv
import glob
import os
import re
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from frontmatter import FrontMatterError, parse, sections  # noqa: E402

STATUSES = ["draft", "approved", "scheduled", "in_progress", "done", "rolled_back", "cancelled"]
NEEDS_APPROVAL = {"approved", "scheduled", "in_progress", "done", "rolled_back"}
NEEDS_WINDOW = {"scheduled", "in_progress", "done", "rolled_back"}
NEEDS_RECORD = {"done", "rolled_back"}
REQUIRED = ["id", "title", "status", "type", "risk", "requester", "implementer", "assets"]   # approver: from approved on
SECTIONS = ["目的", "影響", "步驟", "驗證", "回退", "紀錄"]
ID_RE = re.compile(r"^CR-(\d{4})-(\d{4})$")
AGENT_RE = re.compile(r"^agent:[a-z0-9][a-z0-9_-]*$")
FILE_RE = re.compile(r"^(CR-\d{4}-\d{4})-[a-z0-9][a-z0-9-]*\.md$")
TEMPLATE_PLACEHOLDERS = ("CR-YYYY-NNNN",)


def rfc3339(s):
    try:
        d = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return d if d.tzinfo is not None else None


def load_assets(path):
    rows = set()
    with open(path, encoding="utf-8", newline="") as f:
        lines = [l for l in f if l.strip() and not l.lstrip().startswith("#")]
    for r in csv.DictReader(lines, delimiter="\t"):
        rows.add((r["asset"].strip(), r["component"].strip()))
    return rows


def check_file(path, assets=None):
    errs = []
    name = os.path.basename(path)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        meta, body, _ = parse(text)
    except FrontMatterError as e:
        return [f"{name}: {e}"], None
    m = FILE_RE.match(name)
    if not m:
        errs.append(f"{name}: file name must be CR-YYYY-NNNN-<slug>.md")
    for k in REQUIRED:
        if k not in meta or meta[k] in ("", []):
            errs.append(f"{name}: missing {k}")
    cid = meta.get("id", "")
    if cid and not ID_RE.match(cid):
        errs.append(f"{name}: id {cid!r} is not CR-YYYY-NNNN")
    if m and cid and m.group(1) != cid:
        errs.append(f"{name}: file name says {m.group(1)}, id says {cid}")
    status = meta.get("status", "")
    if status not in STATUSES:
        errs.append(f"{name}: status {status!r} not in {', '.join(STATUSES)}")
    if meta.get("type", "") not in ("standard", "emergency"):
        errs.append(f"{name}: type must be standard or emergency")
    if meta.get("risk", "") not in ("low", "medium", "high"):
        errs.append(f"{name}: risk must be low, medium or high")
    a = meta.get("assets", [])
    if isinstance(a, str):
        errs.append(f"{name}: assets must be a list ('  - asset/component')")
        a = []
    for item in a:
        if "/" not in item:
            errs.append(f"{name}: asset {item!r} is not asset/component")
        elif assets is not None and tuple(item.split("/", 1)) not in assets:
            errs.append(f"{name}: asset {item!r} is not a row in the assets TSV")

    if status in NEEDS_APPROVAL:
        appr, impl = meta.get("approver", ""), meta.get("implementer", "")
        if not appr:
            errs.append(f"{name}: status {status} needs an approver")
        elif appr == impl and not meta.get("approval_exception", "").strip():
            errs.append(f"{name}: approver equals implementer; add approval_exception with the reason or get another approver")
    if status in NEEDS_WINDOW:
        ws, we = rfc3339(meta.get("window_start", "")), rfc3339(meta.get("window_end", ""))
        if ws is None or we is None:
            errs.append(f"{name}: status {status} needs window_start and window_end as RFC 3339 with an offset")
        elif we <= ws:
            errs.append(f"{name}: window_end is not after window_start")
    agents = meta.get("agent", "")
    agents = agents if isinstance(agents, list) else [a.strip() for a in str(agents).split(",") if a.strip()]
    for a in agents:
        if not AGENT_RE.match(a):
            errs.append(f"{name}: agent {a!r} is not agent:<name> (lowercase, digits, - _)")

    sec = sections(body)
    for s in SECTIONS:
        if s not in sec:
            errs.append(f"{name}: section ## {s} missing")
    rb = sec.get("回退", "")
    if "回退" in sec and not rb:
        errs.append(f"{name}: ## 回退 is empty")
    if rb and re.search(r"^\s*無", rb, re.M) and meta.get("risk") != "high":
        errs.append(f"{name}: a change without a rollback is risk: high")
    if status in NEEDS_RECORD:
        rec = sec.get("紀錄", "")
        for k in ("begin", "end", "result"):
            if not re.search(rf"^- {k}:[ \t]*\S", rec, re.M):
                errs.append(f"{name}: status {status} needs '- {k}: ...' in ## 紀錄")
    for ph in TEMPLATE_PLACEHOLDERS:
        if ph in text:
            errs.append(f"{name}: template placeholder {ph} left in")
    return errs, cid


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("files", nargs="*")
    ap.add_argument("--assets", help="onprem-metrics eol/assets.tsv; every asset/component must be a row")
    ap.add_argument("--dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "changes"))
    a = ap.parse_args()
    files = a.files or sorted(f for f in glob.glob(os.path.join(a.dir, "*.md")) if os.path.basename(f) != "TEMPLATE.md")
    assets = load_assets(a.assets) if a.assets else None
    all_errs, seen = [], {}
    for f in files:
        errs, cid = check_file(f, assets)
        all_errs += errs
        if cid:
            if cid in seen:
                all_errs.append(f"{os.path.basename(f)}: id {cid} already used by {seen[cid]}")
            seen[cid] = os.path.basename(f)
    for e in all_errs:
        print(e)
    print(f"check: {len(files)} record(s), {len(all_errs)} problem(s)")
    return 1 if all_errs else 0


if __name__ == "__main__":
    sys.exit(main())
