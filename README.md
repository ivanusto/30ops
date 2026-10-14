# 30ops

[繁體中文](README.zh-TW.md)

An on-prem operations platform for small and medium businesses to run themselves. One collector Linux VM runs metrics, logs, alerting, change records, drill records and an agent gate; nodes join through small installers. QNAP NAS, Proxmox VE, FortiGate and Linux nodes are supported first; other vendors plug in through adapters.

30ops merges eleven repositories from the "30 days of on-prem operations" series, plus the checklist and cost model from the series index, with their full history. See [docs/provenance.md](docs/provenance.md).

## Status

**v0.3.0**: one `site.yaml` describes the site, and `30ops render` generates every site-specific configuration file from it: Prometheus targets and exporter configs, Alertmanager, Grafana datasources, one cron file, the log allowlist, the WORM mount, the gate config and the node parameters ([docs/site-yaml.md](docs/site-yaml.md), [docs/render.md](docs/render.md)). `30ops import-legacy` drafts a `site.yaml` from an existing collector, and `render --compare-legacy` shows it does the same as that collector. Nothing installs the output yet: the compose project, the alert rules and `30ops install` come in v0.4 and v0.5.

| Version | Scope |
|---|---|
| v0.1 | History-preserving import, one CI, publishing hygiene |
| v0.2 | Shared `ops30` library, deduplication, `drills.jsonl` v1 |
| v0.3 | `site.yaml`, `30ops validate`, `30ops render`, `30ops import-legacy` |
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
| `examples/sample-site/` | `site.yaml`, asset list and cost sheet of a sample site | |
| `bin/` | `30ops` command: `validate`, `render`, `import-legacy`, `drill record`, `drill migrate` | |
| `lib/` | `python/ops30` and `sh/ops30.sh`, shared by the collector-side and drill scripts, see [docs/lib.md](docs/lib.md) | |
| `tests/` | `unit/` for lib, `golden/` textfile outputs that must not change and the sample site's render, `fixtures/legacy-root/` the pre-30ops layout, `sh/` | |
| `scripts/` | `hygiene.py`, `check-drift.py`, `check-ci-pins.sh`, `fetch-legacy.sh` | |

## Checks

CI runs one job per module, see `.github/workflows/check.yml`. Locally:

```sh
python3 scripts/hygiene.py          # em dash, private IPs, home paths, .pii-patterns
python3 scripts/check-drift.py      # nothing that lib/ already has is written again
python3 -m unittest discover -s tests/unit && python3 -m unittest tests/test_golden.py tests/test_render.py
sh tests/sh/test_ops30_sh.sh && sh tests/sh/test_fetch_legacy.sh
bin/30ops validate --site examples/sample-site/site.yaml && bin/30ops render --site examples/sample-site/site.yaml --compare-legacy tests/fixtures/legacy-root
sh scripts/check-ci-pins.sh         # actions by SHA, downloads by sha256, images by digest
(cd collector && python3 -m unittest discover -s tests && sh tests/fake-nas.sh)
(cd changes && python3 -m unittest discover -s tests && python3 scripts/check.py --assets ../examples/sample-site/assets.tsv)
(cd gate && python3 -W error -m unittest discover -s tests)
(cd inventory && python3 -m unittest discover -s tests && python3 cost.py --check)
```

`.pii-patterns` is not tracked: one regex per line for strings that belong to your own site and must not reach a public repository.

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
