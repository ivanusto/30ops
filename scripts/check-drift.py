#!/usr/bin/env python3
"""check-drift: code that lib/ already has must not be written again.

Duplicates (v0.2): the helpers that used to exist in four to eight copies
(label escaping, HELP/TYPE writers, atomic textfile writes, RFC 3339
parsing, front matter, the sh epoch-to-ISO helper, drill records built
with printf) may appear in lib/ and nowhere else.

Site files (v0.3): targets, Alertmanager config, cron files, allowlists,
mount units, compose.env and the like come from site.yaml through
`30ops render`; a hand-written one in the repo is a finding.

One source (v0.4):
- alert rules live in collector/prometheus/rules/ only, every threshold
  placeholder there is a key of collector/prometheus/thresholds.yml and
  every key is used, and the rules cite docs/rules.md, not the series;
- every datasource uid a dashboard uses is provisioned, and every job the
  rules and dashboards name is a scrape job;
- no instruction to copy a file by hand is left ("merge by hand",
  "change both together", "Copy into", "Drop into", "Append under");
- every compose image is pinned by digest (as scripts/check-ci-pins.sh).

Exempt: node-side scripts that are copied to another host and run there on
their own (docs/lib.md), source-specific parsers, tests and documentation.

    python3 scripts/check-drift.py      # exit 1 on any finding
"""
import fnmatch
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NODE_SIDE = [
    "collector/textfile/gb10-textfile.py",      # copied to /usr/local/bin on the GB10 hosts
    "collector/textfile/nas-textfile.sh",       # runs over ssh against the NAS
    "drills/pve-backup/canary.sh",              # installed in the guest as /usr/local/bin/canary.sh
    "drills/nas-backup/share-canary.sh",        # runs on the NAS (cron) and reads the share
    "drills/nas-backup/nas-audit.sh",           # runs on the NAS
    "drills/nas-backup/replica-verify.sh",      # runs on the NAS or the replica host
    "plugins/*",                                # node plugins ship on their own
]
SOURCE_SPECIFIC = [
    "logs/firewall/fortigate-export-load.py",   # FortiGate date= time= tz= fields, not RFC 3339
    "logs/firewall/aup-compare.sh",             # one-off comparison helper, inline python
]
EXEMPT = ["lib/*", "tests/*", "*/tests/*", "docs/*", "*.md", "scripts/check-drift.py"] + NODE_SIDE + SOURCE_SPECIFIC

SITE_GLOBS = ["*/targets/*.yml", "*alertmanager.yml", "*.mount", "*allowlist.default", "*.cron",
              "*/pve.yml", "*/snmp-auth.yml", "*/config.json", "*/cron.d/*", "*compose.env",
              "*docker-compose*.yml"]

RULES_DIR = "collector/prometheus/rules/"
THRESHOLDS = "collector/prometheus/thresholds.yml"
PROMETHEUS = "collector/prometheus/prometheus.yml"
DATASOURCES = "collector/grafana/provisioning/datasources/"
DASHBOARDS = "collector/grafana/dashboards/"
RENDER_JOBS = {"node"}                      # added by render/prometheus.py
BUILTIN_UIDS = {"-- Grafana --"}            # Grafana's own annotation source
HAND_COPY = re.compile(r"merge by hand|change both together|Copy into|Drop into|Append under")
PLACEHOLDER = re.compile(r"\$\{([a-z0-9_]+)\}")
JOB = re.compile(r'\bjob(=~?)\\?"([^"\\]+)\\?"')

PY_RULES = [
    (re.compile(r"^\s*def esc\("), "label escaping: use ops30.textfile.esc"),
    (re.compile(r"^\s*def fam\("), "HELP/TYPE writer: use ops30.textfile.family"),
    (re.compile(r"mkstemp\("), "atomic write: use ops30.textfile.write"),
    (re.compile(r"fromisoformat\("), "RFC 3339 parsing: use ops30.rfc3339"),
    (re.compile(r"strptime\([^)]*%Y-%m-%dT%H:%M:%SZ"), "RFC 3339 parsing: use ops30.rfc3339"),
    (re.compile(r"^\s*def parse_t0\("), "drill t0 parsing: use ops30.drills"),
]
SH_RULES = [
    (re.compile(r'date -u -d "@[^"]*" \+%Y-%m-%dT%H:%M:%SZ'), "epoch to ISO: use ops30_iso from lib/sh/ops30.sh"),
    (re.compile(r"^\s*iso_of\(\)"), "epoch to ISO: use ops30_iso from lib/sh/ops30.sh"),
    (re.compile(r"""printf '\{"t0"""), "drill record built with printf: use ops30_drill (drills.jsonl v1)"),
]


def exempt(path):
    return any(fnmatch.fnmatch(path, g) for g in EXEMPT)


def kind(path):
    if path.endswith(".py"):
        return "py"
    if path.endswith(".sh"):
        return "sh"
    try:
        with open(os.path.join(ROOT, path), "rb") as f:
            first = f.readline()
    except OSError:
        return None
    if first.startswith(b"#!") and b"python" in first:
        return "py"
    if first.startswith(b"#!") and first.rstrip().endswith((b"/sh", b" sh", b"/bash")):
        return "sh"
    return None


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8", errors="replace") as f:
        return f.read()


def one_source(files):
    """The v0.4 checks: rules, thresholds, dashboards, jobs, hand copies, images."""
    errors = []
    rules = [f for f in files if f.startswith(RULES_DIR) and f.endswith(".yml")]
    for path in files:
        if path.endswith((".yml", ".yaml")) and not path.startswith(RULES_DIR) and not exempt(path):
            text = read(path)
            if re.search(r"^groups:", text, re.M) and re.search(r"^\s*-?\s*alert:", text, re.M):
                errors.append(f"{path}: alert rules outside {RULES_DIR}")
        if not exempt(path) and (kind(path) or path.endswith((".yml", ".yaml", ".json", ".service", ".mount"))):
            for n, line in enumerate(read(path).splitlines(), 1):
                if HAND_COPY.search(line):
                    errors.append(f"{path}:{n}: an instruction to copy by hand; render or a single source does it")
        if fnmatch.fnmatch(os.path.basename(path), "*compose*.yml"):
            for n, line in enumerate(read(path).splitlines(), 1):
                if re.match(r"\s*image:", line) and not re.search(r"@sha256:[0-9a-f]{64}", line):
                    errors.append(f"{path}:{n}: image not pinned by digest")

    keys = set(re.findall(r"^([a-z0-9_]+):\s*$", read(THRESHOLDS), re.M))
    used = set()
    for path in rules:
        text = read(path)
        for n, line in enumerate(text.splitlines(), 1):
            for k in PLACEHOLDER.findall(line):
                used.add(k)
                if k not in keys:
                    errors.append(f"{path}:{n}: ${{{k}}} is not a key of {THRESHOLDS}")
            if re.search(r"\bDay \d+", line):
                errors.append(f"{path}:{n}: cite docs/rules.md, not the series")
    for k in sorted(keys - used):
        errors.append(f"{THRESHOLDS}: {k} is not used by any rule")

    jobs = set(re.findall(r"job_name:\s*(\S+)", read(PROMETHEUS))) | RENDER_JOBS
    uids = {u.strip("\"'") for f in files if f.startswith(DATASOURCES)
            for u in re.findall(r"^\s*uid:\s*(\S+)", read(f), re.M)} | BUILTIN_UIDS
    dashboards = [f for f in files if f.startswith(DASHBOARDS) and f.endswith(".json")]
    for path in dashboards:
        def walk(v):
            if isinstance(v, dict):
                ds = v.get("datasource")
                if isinstance(ds, dict) and ds.get("uid") and ds["uid"] not in uids:
                    errors.append(f"{path}: datasource uid {ds['uid']} is not provisioned in {DATASOURCES}")
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)
        walk(json.loads(read(path)))
    for path in rules + dashboards:
        for op, val in JOB.findall(read(path)):
            names = val.split("|") if op == "=~" else [val]
            for name in names:
                if re.fullmatch(r"[A-Za-z0-9_-]+", name) and name not in jobs:
                    errors.append(f"{path}: job \"{name}\" is not a scrape job in {PROMETHEUS}")
    return errors


def main():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    files = [f for f in files if os.path.isfile(os.path.join(ROOT, f))]
    errors = one_source(files)
    for path in files:
        if os.path.basename(path) == "frontmatter.py" and not path.startswith("lib/"):
            errors.append(f"{path}: a second front matter reader; use lib/python/ops30/frontmatter.py")
        if exempt(path):
            continue
        if any(fnmatch.fnmatch(path, g) for g in SITE_GLOBS):
            errors.append(f"{path}: a site-specific file outside site.yaml; 30ops render writes it (docs/render.md)")
            continue
        k = kind(path)
        if k is None:
            continue
        rules = PY_RULES if k == "py" else SH_RULES
        with open(os.path.join(ROOT, path), encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, 1):
                for rx, why in rules:
                    if rx.search(line):
                        errors.append(f"{path}:{n}: {why}")
    for e in errors:
        print(e, file=sys.stderr)
    print(f"check-drift: {len(files)} files, {len(errors)} finding(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
