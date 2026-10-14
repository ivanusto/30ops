"""agent-gate.prom for node_exporter (cron every 5 min on the collector).

    agent_gate_decisions_total{tool,level,decision}   records in audit.jsonl
    agent_gate_pending_approvals                       PENDING requests without an approval
    agent_gate_stopped                                 1 when the STOP file is present
    agent_gate_chain_length                            records in the chain
    agent_gate_chain_ok                                1 when the chain verifies
    agent_gate_last_decision_timestamp                 unix time of the last record
    agent_gate_textfile_last_run_timestamp
"""
import os
import time

from core import parse_time  # noqa: E402  (core puts lib/python on sys.path)
from ops30 import textfile  # noqa: E402
from ops30.textfile import esc  # noqa: E402


def render(gate, now_ts):
    recs = gate.records()
    counts = {}
    for r in recs:
        k = (r.get("tool", ""), r.get("level", ""), r.get("decision", ""))
        counts[k] = counts.get(k, 0) + 1
    ok, n, _ = gate.verify()
    L = ["# HELP agent_gate_decisions_total Gate decisions recorded in audit.jsonl",
         "# TYPE agent_gate_decisions_total counter"]
    for (tool, level, dec), c in sorted(counts.items()):
        L.append(f'agent_gate_decisions_total{{tool="{esc(tool)}",level="{esc(level)}",decision="{esc(dec)}"}} {c}')
    L += ["# HELP agent_gate_pending_approvals L3 requests waiting for a human",
          "# TYPE agent_gate_pending_approvals gauge",
          f"agent_gate_pending_approvals {len(gate.pending())}",
          "# HELP agent_gate_stopped 1 when the STOP file is present (every call is denied)",
          "# TYPE agent_gate_stopped gauge",
          f"agent_gate_stopped {1 if os.path.exists(gate.cfg['stop_file']) else 0}",
          "# HELP agent_gate_chain_length Records in the audit chain",
          "# TYPE agent_gate_chain_length gauge",
          f"agent_gate_chain_length {n}",
          "# HELP agent_gate_chain_ok 1 when every record's hash chains to the previous one",
          "# TYPE agent_gate_chain_ok gauge",
          f"agent_gate_chain_ok {1 if ok else 0}"]
    if recs:
        t = parse_time(recs[-1].get("ts", ""))
        if t is not None:
            L += ["# HELP agent_gate_last_decision_timestamp Unix time of the last gate decision",
                  "# TYPE agent_gate_last_decision_timestamp gauge",
                  f"agent_gate_last_decision_timestamp {int(t.timestamp())}"]
    L += ["# HELP agent_gate_textfile_last_run_timestamp Unix time of the last run",
          "# TYPE agent_gate_textfile_last_run_timestamp gauge",
          f"agent_gate_textfile_last_run_timestamp {int(now_ts)}"]
    return "\n".join(L) + "\n"


def write(gate, out):
    text = render(gate, time.time())
    if not out:
        return text
    textfile.write(out, text)
    return text
