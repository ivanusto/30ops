"""The agent gate's config.json and tools.json, plus the assets.tsv that
eol-textfile.py, check.py and the gate read. tools.json is the repo's
gate/tools.json for now; its assets have to be rows of assets.tsv."""
import json

from .. import site as S
from . import Output, header

G = "etc/30ops/gate"


def config(site):
    g = site["gate"]
    home, clone = g["home"], site["changes"]["clone"]
    return {
        "principal": g["principal"],
        "changes_dir": f"{clone}/changes",
        "state_dir": site["changes"]["state_dir"],
        "tools": f"/{G}/tools.json",
        "audit": f"{home}/audit.jsonl",
        "approvals_dir": f"{home}/approvals",
        "stop_file": f"{home}/STOP",
        "ssh": ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes",
                "-i", f"{home}/.ssh/id_gate"],
        "targets": {t["asset"]: t["ssh"] for t in g["targets"]},
        "approval_ttl_s": g["approval_ttl_s"],
        "approvers": g["approvers"],
        "logger": "logger",
        "stdout_limit": 65536,
    }


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2) + "\n"


def render(site, sha):
    out = {}
    if site.get("assets"):
        with open(f"{site['base']}/{site['assets']}", encoding="utf-8") as f:
            out["etc/30ops/assets.tsv"] = Output(header(sha) + f.read())
    if site["gate"]["targets"]:
        with open(f"{S.REPO}/gate/tools.json", encoding="utf-8") as f:
            tools = json.load(f)
        out[f"{G}/config.json"] = Output(dumps(config(site)), 0o640, "root:agent-gate")
        out[f"{G}/tools.json"] = Output(dumps(tools))
    return out
