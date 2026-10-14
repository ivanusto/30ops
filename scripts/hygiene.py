#!/usr/bin/env python3
"""發布衛生檢查：掃 git 追蹤的文字檔，擋下不該出現在公開 repo 的內容。

錯誤（結束碼 1）：破折號、私有 IP、家目錄路徑，
                  以及 .pii-patterns（不進版控，一行一個 regex）列出的個人字串。
警告（不影響結束碼）：系列文章的天數引用（Day N），產品文件應改引 docs/。

範例與測試只能用文件保留位址：192.0.2.0/24、198.51.100.0/24、203.0.113.0/24、example.net。
原始版本見 ivanusto/onprem-ops-30days 的 scripts/check.py。
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEXT_SUFFIXES = {
    ".md", ".yaml", ".yml", ".py", ".txt", ".sh", ".json", ".jsonl", ".tsv", ".cron",
    ".env", ".service", ".timer", ".mount", ".conf", ".default", ".example", ".j2", ".tmpl",
}
ERRORS = [
    ("破折號", re.compile(chr(0x2014))),
    ("私有 IP", re.compile(r"(?<![\d.])(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d]|\.\d)")),
    ("家目錄路徑", re.compile(r"/(home|Users)/[A-Za-z0-9_.-]+/")),
]
WARNINGS = [
    ("系列天數引用", re.compile(r"\bDay ?\d{1,2}\b")),
]


def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    for name in out.stdout.decode().split("\0"):
        if not name:
            continue
        path = ROOT / name
        if path.is_file() and (path.suffix in TEXT_SUFFIXES or text_without_suffix(path)):
            yield path


def text_without_suffix(path):
    if path.suffix:
        return False
    try:
        return path.read_bytes()[:2] == b"#!"
    except OSError:
        return False


def scan(patterns, paths):
    hits = []
    for path in paths:
        rel = path.relative_to(ROOT)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(lines, 1):
            for label, rx in patterns:
                if rx.search(line):
                    hits.append((str(rel), n, label))
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--summary", action="store_true", help="只印每個檔案的命中數")
    ap.add_argument("--no-warnings", action="store_true")
    a = ap.parse_args()

    errors = list(ERRORS)
    extra = ROOT / ".pii-patterns"
    if extra.exists():
        for line in extra.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                errors.append(("個人字串", re.compile(line, re.I)))

    paths = list(tracked())
    err = scan(errors, paths)
    warn = [] if a.no_warnings else scan(WARNINGS, paths)
    for kind, hits in (("錯誤", err), ("警告", warn)):
        if a.summary:
            counts = {}
            for rel, _, label in hits:
                counts[(rel, label)] = counts.get((rel, label), 0) + 1
            for (rel, label), c in sorted(counts.items()):
                print(f"{kind} {rel} {label} x{c}")
        else:
            for rel, n, label in hits:
                print(f"{kind} {rel}:{n} 含{label}")
    print(f"{len(paths)} 個檔案，{len(err)} 個錯誤，{len(warn)} 個警告")
    return 1 if err else 0


if __name__ == "__main__":
    sys.exit(main())
