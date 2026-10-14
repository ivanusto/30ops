#!/usr/bin/env python3
"""check-drift: code that lib/ already has must not be written again.

Duplicates (v0.2): the helpers that used to exist in four to eight copies
(label escaping, HELP/TYPE writers, atomic textfile writes, RFC 3339
parsing, front matter, the sh epoch-to-ISO helper, drill records built
with printf) may appear in lib/ and nowhere else.

Site files (v0.3): targets, Alertmanager config, cron files, allowlists,
mount units and the like come from site.yaml through `30ops render`. The
hand-written ones that predate it are listed in LEGACY_SITE and go with
the compose merge in v0.4; a new one anywhere else is a finding.

Rules, dashboards and compose drift join in v0.4.

Exempt: node-side scripts that are copied to another host and run there on
their own (docs/lib.md), source-specific parsers, tests and documentation.

    python3 scripts/check-drift.py      # exit 1 on any finding
"""
import fnmatch
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
              "*/pve.yml", "*/snmp-auth.yml", "*/config.json", "*/cron.d/*"]
LEGACY_SITE = [
    "collector/systemd/collector.cron", "logs/collector.cron", "logs/audit/collector.cron",
    "logs/firewall/collector.cron", "logs/pcap/collector.cron", "changes/collector.cron", "gate/collector.cron",
    "logs/collector/onprem-logs-allowlist.default", "logs/collector/mnt-worm.mount",
]

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


def main():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    errors = []
    for path in files:
        if os.path.basename(path) == "frontmatter.py" and not path.startswith("lib/"):
            errors.append(f"{path}: a second front matter reader; use lib/python/ops30/frontmatter.py")
        if exempt(path):
            continue
        if any(fnmatch.fnmatch(path, g) for g in SITE_GLOBS) and path not in LEGACY_SITE:
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
