# 30ops

[繁體中文](README.zh-TW.md)

An on-prem operations platform for small and medium businesses to run themselves. One collector Linux VM runs metrics, logs, alerting, change records, drill records and an agent gate; nodes join through small installers. QNAP NAS, Proxmox VE, FortiGate and Linux nodes are supported first; other vendors plug in through adapters.

30ops merges eleven repositories from the "30 days of on-prem operations" series, plus the checklist and cost model from the series index, with their full history. See [docs/provenance.md](docs/provenance.md).

## Status

**v0.1.0**: the code lives in one repository and every module's tests pass at the new paths, but each module is still installed and configured on its own. A single `site.yaml`, the `30ops` command, installers and adapters come in later versions.

| Version | Scope |
|---|---|
| v0.1 | History-preserving import, one CI, publishing hygiene |
| v0.2 | Shared `ops30` library, deduplication, `drills.jsonl` v1 |
| v0.3 | `site.yaml`, `30ops validate`, `30ops render` |
| v0.4 | One compose project, one source for rules, Grafana image |
| v0.5 | Adapters, `30ops install`, `30ops doctor` |
| v0.6 | End-to-end tests, release pipeline (SHA256SUMS and provenance attestation) |
| v0.7 | `30ops readiness`, collector deadman, switch SNMP, UPS check |
| v0.8 | Live site cutover |
| v1.0 | Documentation, archive the source repositories |

## Layout

| Path | What | From |
|---|---|---|
| `collector/` | Prometheus, Alertmanager, Grafana, snmp and pve exporters, textfile scripts, alert rules, dashboards | onprem-metrics |
| `logs/` | VictoriaLogs, journald and syslog intake, WORM archive, firewall, AUP and audit reports, packet capture | onprem-logs |
| `changes/` | Markdown change records, format checks, `change-mark.sh`, rollback drills | onprem-changes |
| `gate/` | Agent gate (MCP): no change record, no tools; decisions go into a hash chain | onprem-agent-gate |
| `drills/` | PVE, NAS and cloud restore drills | three drill repositories |
| `checks/` | PVE QDevice check, operability checklist | pve-qdevice-on-qnap, series index |
| `inventory/` | One-year cost model (power, depreciation, cloud comparison) | series index |
| `plugins/` | Optional node modules: GB10 host guard, node baseline, NFS model library | gb10-ops, spark-baseline, nfs-model-library |
| `examples/sample-site/` | Asset list and cost sheet of a sample site | |
| `scripts/` | `hygiene.py`, `check-ci-pins.sh` | |

## Checks

CI runs one job per module, see `.github/workflows/check.yml`. Locally:

```sh
python3 scripts/hygiene.py          # em dash, private IPs, home paths, .pii-patterns
sh scripts/check-ci-pins.sh         # actions by SHA, downloads by sha256, images by digest
(cd collector && python3 -m unittest discover -s tests && sh tests/fake-nas.sh)
(cd changes && python3 -m unittest discover -s tests && python3 scripts/check.py --assets ../examples/sample-site/assets.tsv)
(cd gate && python3 -W error -m unittest discover -s tests)
(cd inventory && python3 -m unittest discover -s tests && python3 cost.py --check)
```

`.pii-patterns` is not tracked: one regex per line for strings that belong to your own site and must not reach a public repository.

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
