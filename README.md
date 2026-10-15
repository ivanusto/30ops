# 30ops

[繁體中文](README.zh-TW.md)

An on-prem operations platform for small and medium businesses to run themselves. One collector Linux VM runs metrics, logs, alerting, change records, drill records and an agent gate; nodes join through small installers. QNAP NAS, Proxmox VE, FortiGate and Linux nodes are supported first; other vendors plug in through adapters.

30ops merges eleven repositories from the "30 days of on-prem operations" series, plus the checklist and cost model from the series index, with their full history. See [docs/provenance.md](docs/provenance.md).

## Status

**v0.7.0**: `30ops readiness` answers the operability checklist for a site, every item yes, no, unknown or accepted (with the reason written in `site.yaml`) and the evidence, against the collector's Prometheus or one that does not run 30ops yet; the collector's cron writes the result as `readiness.prom` ([docs/readiness.md](docs/readiness.md)). The collector is no longer its own single point of failure: an always-firing Watchdog goes every minute to `30ops-deadman` on another host (or an external check URL), which alerts by mail and webhook when the pushes stop ([docs/install.md](docs/install.md#deadman)). Switches and access points are scraped over SNMP v3 with a standard IF-MIB module; a NAS without a UPS raises an info alert unless `site.yaml` says `ups: none`; Linux and PVE hosts ship their journal by default; change records may record the staff time (`effort_min`). Plugins are self-describing: `plugin.yaml` declares what a plugin installs on a node and the scrape job, rules, thresholds, dashboard row and readiness items it brings, which the collector adds only when a host lists it ([docs/plugins.md](docs/plugins.md)). From v0.6: an end-to-end test installs the release tarball of each commit as a collector on a throwaway host and checks it against a fake LAN in a network namespace (a NAS over ssh and SNMPv3, two PVE nodes, a FortiGate API, an NFS share in place of the WORM folder, an alert receiver): every target up, the expected metric names present, a degraded pool reaching the webhook through Alertmanager, syslog, the FortiGate event log and journald in VictoriaLogs while a sender off the allowlist is dropped, a closed day archived and verified, doctor clean, the containers under 3 GiB ([docs/e2e.md](docs/e2e.md)). A tag `vX.Y.Z` (or `-rc.N`, a prerelease) runs the checks and the e2e test, then publishes a reproducible source tarball, `images.txt` and `SHA256SUMS`, each with a build provenance attestation ([docs/release.md](docs/release.md)). From v0.5: `30ops install collector` puts a rendered site on the collector: accounts, directories, the owner and mode of every secret file, the rendered files, the units, the docker volumes and images, the stack, then the cron file; it changes only what differs, so a second run changes nothing ([docs/install.md](docs/install.md)). `30ops install node` builds a deterministic bundle per node and runs it over ssh with sudo; NAS, firewalls and switches get their adapter's setup steps instead. `30ops doctor` checks the installed collector against `site.yaml`: image digests, targets, textfile ages, WORM mount, clock and time zone, disk, secrets, the Grafana password and render drift. Vendor code lives in adapters (`adapters/<kind>/<vendor>/`, [docs/adapters.md](docs/adapters.md)) with a contract test on recorded cases; QuTS status strings are normalised by the qnap adapter's status map into recording rules, and `ops30_adapter_info` names each host's vendor without relabelling any existing series. Accepted on a throwaway Ubuntu 24.04 VM: install twice, identical state, doctor clean. From v0.4: one compose project with every image pinned by digest, the alert rules in one place with the site's thresholds ([docs/rules.md](docs/rules.md)). From v0.3: `site.yaml`, `30ops render`, `import-legacy` and `render --compare-legacy` ([docs/site-yaml.md](docs/site-yaml.md), [docs/render.md](docs/render.md)).

| Version | Scope |
|---|---|
| v0.1 | History-preserving import, one CI, publishing hygiene |
| v0.2 | Shared `ops30` library, deduplication, `drills.jsonl` v1 |
| v0.3 | `site.yaml`, `30ops validate`, `30ops render`, `30ops import-legacy` |
| v0.4 | One compose project, one source for rules, Grafana image |
| v0.5 | Adapters, `30ops install`, `30ops doctor` |
| v0.6 | End-to-end tests, release pipeline (SHA256SUMS and provenance attestation) |
| v0.7 | `30ops readiness`, collector deadman, switch SNMP, UPS check, plugin contract |
| v0.8 | Live site cutover |
| v1.0 | Documentation, archive the source repositories |

## Layout

| Path | What | From |
|---|---|---|
| `collector/` | Prometheus, Alertmanager, Grafana, snmp and pve exporters, textfile scripts, alert rules, dashboards, `30ops-deadman` | onprem-metrics |
| `logs/` | VictoriaLogs, journald and syslog intake, WORM archive, firewall, AUP and audit reports, packet capture | onprem-logs |
| `changes/` | Markdown change records, format checks, `change-mark.sh`, rollback drills | onprem-changes |
| `gate/` | Agent gate (MCP): no change record, no tools; decisions go into a hash chain | onprem-agent-gate |
| `drills/` | PVE, NAS and cloud restore drills | three drill repositories |
| `checks/` | PVE QDevice check, the readiness checklist (`readiness/checklist.yaml`) | pve-qdevice-on-qnap, series index |
| `inventory/` | One-year cost model (power, depreciation, cloud comparison) | series index |
| `plugins/` | Optional node modules, each with a `plugin.yaml` ([docs/plugins.md](docs/plugins.md)): GB10 host guard and metrics, node baseline, NFS model library | gb10-ops, spark-baseline, nfs-model-library |
| `adapters/` | Vendor adapters (`<kind>/<vendor>/adapter.yaml` and `adapter.py`): qnap, fortigate, pve, generic-snmp, linux, see [docs/adapters.md](docs/adapters.md) | |
| `examples/sample-site/` | `site.yaml`, asset list and cost sheet of a sample site | |
| `bin/` | `30ops` command: `validate`, `render`, `import-legacy`, `install collector`, `install node`, `doctor`, `readiness`, `textfile`, `drill record`, `drill migrate` | |
| `lib/` | `python/ops30` and `sh/ops30.sh`, shared by the collector-side and drill scripts, see [docs/lib.md](docs/lib.md) | |
| `tests/` | `unit/` for lib, `golden/` textfile outputs that must not change and the sample site's render, `fixtures/legacy-root/` the pre-30ops layout, `fixtures/adapters/` the adapters' recorded cases, `sh/`, `e2e/` the end-to-end test and its fake LAN, `fakes/` stand-ins shared by the tests, `vm/` the install acceptance and the e2e run on a VM | |
| `scripts/` | `hygiene.py`, `check-drift.py`, `check-ci-pins.sh`, `fetch-legacy.sh`, `dist.sh` and `release-check.sh` (release files, [docs/release.md](docs/release.md)) | |

## Checks

CI runs one job per module, see `.github/workflows/check.yml`. Locally:

```sh
python3 scripts/hygiene.py          # em dash, private IPs, home paths, .pii-patterns
python3 scripts/check-drift.py      # nothing written twice: lib helpers, rules, thresholds, site files
python3 -m unittest discover -s tests/unit && python3 -m unittest tests/test_golden.py tests/test_render.py
sh tests/sh/test_ops30_sh.sh && sh tests/sh/test_fetch_legacy.sh && sh tests/sh/test_dist.sh
bin/30ops validate --site examples/sample-site/site.yaml && bin/30ops render --site examples/sample-site/site.yaml --compare-legacy tests/fixtures/legacy-root
sh scripts/check-ci-pins.sh         # actions by SHA, downloads by sha256, images by digest
sh scripts/test-rules.sh             # promtool check and test on the rendered rules (plugins' tests too)
(cd collector && python3 -m unittest discover -s tests && sh tests/fake-nas.sh && sh tests/compose-smoke.sh)
(cd changes && python3 -m unittest discover -s tests && python3 scripts/check.py --assets ../examples/sample-site/assets.tsv)
(cd gate && python3 -W error -m unittest discover -s tests)
(cd inventory && python3 -m unittest discover -s tests && python3 cost.py --check)
(cd plugins/gb10-ops && python3 -m unittest discover -s tests)
```

The end-to-end test changes its host for good, so it runs only on a throwaway one: the `e2e` workflow, or `tests/vm/e2e.sh USER@VM` ([docs/e2e.md](docs/e2e.md)).

`.pii-patterns` is not tracked: one regex per line for strings that belong to your own site and must not reach a public repository.

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
