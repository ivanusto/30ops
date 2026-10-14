# onprem-metrics

English | [繁體中文](README.zh-TW.md)

One Prometheus for a small on-prem AI lab: two NVIDIA DGX Spark (GB10) nodes, two QNAP NAS on QuTS hero, a two-node Proxmox VE cluster with a QDevice, and the restore drills from the backup days. Standard exporters cover most of it. This repo adds the three things they do not see, as node_exporter textfile collectors, plus the Prometheus config that ties the targets together.

| Path | Runs on | What it does |
|---|---|---|
| `textfile/gb10-textfile.py` | each DGX Spark, systemd timer every 10 s | Hottest thermal zone, GPU temp/power/util, **thermal soak seconds** (continuous time at or above 88 C), `NV_ERR_NO_MEMORY` count from dmesg, MemAvailable, the HOT flag from gb10-ops `hw-sample.py` (present only while hw-sample runs with `--hot-flag /run/gb10/HOT`). Soak state survives between runs; a timer gap resets it |
| `prometheus/snmp-build.py` and `prometheus/snmp.yml` | collector VM | Builds the snmp_exporter module from QNAP's QTS-MIB (enterprises 55062, QuTS hero) without the generator: disks and temperature, SMART attributes, RAID, pools, shared folders (WORM, compression, dedup), fans, CPU and system temperature, CPU and memory, UPS, firmware, exposed services, installed apps, plus IF-MIB interface counters. SNMP v3 only; the example is authPriv (SHA, DES, the most QuTS hero 6.0.2 offers), and `security_level` and the protocols must match what the NAS actually has. Auth in `snmp-auth.yml` (gitignored) |
| `textfile/nas-textfile.sh` | the collector host, cron every minute | Takes `LABEL=user@host`, so the `nas` label matches the SNMP target's `nas`. Over ssh to each NAS, only what the MIB does not have: ZFS pool list by name, dataset used, snapshots per dataset (count, newest, oldest, bytes), HBS 3 installed. Nothing is installed on the NAS |
| `textfile/drills-textfile.py` | the collector host, cron every 15 min | Reads the `drills.jsonl` files of the three drills, the archive and pcap verify (source `logs`) and the rollback drills (source `changes`), v1 and the older per-tool lines alike ([docs/drills-jsonl.md](../docs/drills-jsonl.md)), exposes the latest drill per label: timestamp, result, RTO, RPO, rate, last success |
| `prometheus/` | collector VM | `prometheus.yml`: the scrape jobs with three intervals (15 s GPU nodes, 60 s NAS and PVE); `30ops render` writes the site's copy with the site label, the file_sd targets and the exporter configs (`pve.yml`, `snmp-auth.yml`) to `/etc/30ops/prometheus/`. `thresholds.yml`: the alert thresholds a site may change in `site.yaml` `alerting.thresholds`. `rules/`: the one copy of the 69 alert rules, rendered with the site's thresholds ([docs/rules.md](../docs/rules.md)) |
| `compose.yml` | collector VM | The one compose project: Prometheus 3.5, pve-exporter, snmp-exporter, Alertmanager, Grafana (the 30ops image with the VictoriaLogs datasource baked in) and VictoriaLogs, images pinned by digest. Site settings (volume names, retention, time zone, Grafana port, secret files, which exporters run) come from the rendered `/etc/30ops/compose.env`; volumes are external, so a wrong name stops the start instead of creating an empty TSDB. Grafana on :3000 and VictoriaLogs (9428, syslog 514 and 515) are the ports open to the LAN; Prometheus, Alertmanager and the exporters publish on 127.0.0.1 only |
| `systemd/` | DGX Spark and collector | node_exporter unit, gb10-textfile service and timer. The collector's cron file is `/etc/cron.d/30ops` from `30ops render` |
| `install-node.sh` | each DGX Spark; `--collector` on the collector | Downloads node_exporter (arm64 or amd64), verifies sha256 against the release, installs the units. DGX Spark mode also installs gb10-textfile and `/run/gb10` (tmpfiles.d); `--collector` installs node_exporter and the textfile directory only |
| `verify.sh` | anywhere with curl, ssh and python3 | `up`, scrape duration and samples per target, one Prometheus value next to the original tool's value per source, the drill table. On the NAS it only reads what a plain account can (`getsysinfo` temperatures need root) |
| `prometheus/rules/thresholds.yml` | collector VM | Alerts on the numbers (Day 20): soak at 180 s or more (guard acts at 240 s; the textfile age, scrape step and evaluation wait take up to 45 s, measured on Day 20; the gb10 group evaluates every 15 s for this), MemAvailable 6 and 3 GiB, `NV_ERR_NO_MEMORY` increase, pool 80 and 90 %, pool and disk status strings as QuTS hero reports them, snapshots older than 2 days, quorum lost and one vote missing, HA resources in error, drills overdue or failed. Thresholds are defaults a site can override; [docs/rules.md](../docs/rules.md) gives the source of each |
| `prometheus/rules/firewall.yml` | collector VM | Firewall review alerts (Day 22) on `fw.prom`, which onprem-logs' `firewall/fw-report.py` writes from the collector's cron every 10 minutes: report stale, one source over a per-wall burst threshold (the walls' log rate limits differ by orders of magnitude), a source never dropped before, NAS login failures above the NAS's own ban rate, and an expected wall that logged nothing for 2 hours |
| `prometheus/rules/aup.yml`, `tests/rules_aup_test.yml` | collector VM | Acceptable-use alerts (Day 24) on the `aup.prom` that onprem-logs' `firewall/aup-report.py` writes every 10 minutes: one hit on an urgent category (Malicious Websites, Phishing, Spam URLs) is critical, 20 blocks from one workstation in an hour is a warning, six silent hours from an expected FortiGate is info, a stale report is a warning that inhibits the other three |
| `eol/assets.tsv`, `textfile/eol-textfile.py`, `prometheus/rules/eol.yml`, `tests/rules_eol_test.yml`, `tests/test_eol_textfile.py` | collector VM, cron daily | Day 25. Asset lifecycle: one TSV row per (asset, component, milestone) with the date, where it came from (vendor, estimate, licence, unknown) and a note. The textfile turns it into `asset_eol_timestamp_seconds`, keeps the rows without a date visible as `asset_eol_unknown`, checks the dates against endoflife.date (`--refresh`, cached a day) and reads the FortiGate's licence expiries over REST (`--fortigate`). Rules: 90 days warning, 30 days critical, already passed critical, unknown and source mismatch info, textfile stale warning; licences lapse together with their contract, so they alert once per device with a count (expired critical, within 90 days warning). The dashboard gets a row with the days left per asset and per licence |
| `prometheus/rules/changes.yml`, `tests/rules_changes_test.yml` | collector VM | Change records as alerts (Day 26), on the `changes.prom` that [onprem-changes](https://github.com/ivanusto/onprem-changes)' `changes-textfile.py` writes: a window closed an hour ago with the record still open is a warning, a change in progress and one starting within a day are info, a stale textfile is a warning that inhibits the other three. Day 28 adds two info rules on the rollback-drill metrics: a done high-risk record whose rollback was never drilled, and a drill older than 90 days |
| `prometheus/rules/audit.yml`, `tests/rules_audit_test.yml` | collector VM | Audit trail against the change records (Day 27), on the `audit.prom` that onprem-logs' `audit/audit-report.py` writes every 10 minutes: a FortiGate configuration change outside any change window is a warning, other unattributed administrative actions and a done record without change marks are info, a stale report is a warning that inhibits the rest |
| `prometheus/rules/agent.yml`, `tests/rules_agent_test.yml` | collector VM | The agent gate (Day 29), on the `agent-gate.prom` that [onprem-agent-gate](https://github.com/ivanusto/onprem-agent-gate)'s `gatectl textfile` writes: an L3 request waiting for a human for 2 minutes is a warning, the emergency stop is info, a broken audit chain is critical, more than 5 denials an hour is info, a stale textfile is a warning that inhibits the other four |
| `textfile/pve-quorum-textfile.sh` | the collector host, cron every minute | `LABEL=root@node1,root@node2`: ssh to the first node that answers and runs `pvecm status`, exposes expected, total and quorum votes, the Quorate flag, the QDevice vote and votes per node. The key is pinned on the node with `from=` and `command="/usr/bin/pvecm status",restrict` |
| `alertmanager/`, `grafana/` | collector VM | `alertmanager.base.yml`: the template render starts from, with the routes (critical now, warning in 30 s batches, info as a daily digest, the soak alert without batching) and eight inhibit rules so a dead pipeline does not also alert for every number it stopped reporting; render puts in the site's SMTP and receivers. `grafana/Dockerfile`: Grafana 12.2.10 with the VictoriaLogs datasource 0.32.0 (base by digest, plugin by sha256), published as `ghcr.io/ivanusto/30ops-grafana` with a build provenance attestation. The dashboard JSON is generated by `build-dashboard.py` (render draws it with the site's thresholds) and the UI cannot change it |
| `tests/` | CI | Fake sysfs, nvidia-smi, dmesg, zfs, zpool, getsysinfo, every output checked with `promtool check metrics`; promtool tests of the rules (`scripts/test-rules.sh` runs them on the rendered rules); `compose-smoke.sh` starts the merged stack on a render of the sample site |

## Why SNMP for hardware and ssh for ZFS

The ssh key the collector holds is a shell on the NAS. SNMP v3 read-only is a much narrower interface, so everything the QTS MIB can answer goes that way and the ssh path shrinks to `zfs list` and the HBS 3 state, which the MIB does not expose. `snmp-build.py` reads the MIB QNAP ships and writes the module; `snmp_exporter --dry-run` is the test.

## Why textfile and not another exporter

The soak counter needs memory between samples, the NAS has no package manager and the drill logs are files in three repos. A textfile is the simplest contract: write a file atomically, node_exporter serves it, Prometheus never knows the difference. Each file also carries a `*_last_run_timestamp` so a dead timer shows up as a stale metric, not as a frozen value that looks fine.

## Quick start

```sh
# collector VM, with the checkout in /opt/30ops and the site's site.yaml
bin/30ops validate --site site.yaml --strict
sudo bin/30ops render --site site.yaml --out /     # /etc/30ops, /etc/cron.d/30ops, units, ...
# until `30ops install` (v0.5): put the token and passphrases in place of the
# @secret: values in /etc/30ops/prometheus/pve.yml and snmp-auth.yml, and
# create the secret files compose mounts (owner = the uid the container runs as)
sudo install -d -m 0700 /etc/30ops/secrets
openssl rand -base64 24 | sudo install -m 0400 -o 472 /dev/stdin /etc/30ops/secrets/grafana-admin.pass
# SMTP password: owner 65534 (Alertmanager runs as nobody), mode 0400
# a new site creates its volumes; a moved one names its old ones in site.yaml
for v in prometheus alertmanager grafana victorialogs; do docker volume create "30ops_$v-data"; done
docker compose --env-file /etc/30ops/compose.env -f collector/compose.yml up -d
sudo ./collector/install-node.sh --collector
# Grafana reads the admin password only when it creates its database. If the
# file was unreadable on the first start, the password is "admin": fix the
# owner, then remove the grafana container and its volume and start again.

# PVE quorum: one line in /root/.ssh/authorized_keys on a node (it is
# /etc/pve/priv/authorized_keys, shared by the whole cluster)
#   from="COLLECTOR_IP",command="/usr/bin/pvecm status",restrict ssh-ed25519 AAAA... metrics@collector
# and on every PVE node, so the per-minute login does not start and stop a
# whole root user manager each time (about 75 journal lines per login,
# 108,000 a day, measured on Day 21):
#   loginctl enable-linger root
sudo -u metrics ./textfile/pve-quorum-textfile.sh lab=root@192.0.2.9,root@192.0.2.5 | promtool check metrics

# first SNMP walk: which OIDs does the real box answer
curl 'http://localhost:9116/snmp?module=qnap&auth=nas_v3&target=192.0.2.2'

# each DGX Spark
sudo ./install-node.sh
sudo ufw allow proto tcp from 192.0.2.49 to any port 9100   # collector only
curl -s localhost:9100/metrics | grep ^gb10_

# then, on the collector (Prometheus listens on 127.0.0.1 since Day 20;
# from elsewhere, ssh -L 9090:localhost:9090 to the collector first)
./verify.sh \
  --gb10 user@192.0.2.131 --gb10 user@192.0.2.141 \
  --nas primary=ops30@192.0.2.2 --nas secondary=ops30@192.0.2.22 \
  --pve root@192.0.2.9 > verify.md
```

## Metrics added

`gb10_zone_temp_celsius`, `gb10_gpu_temp_celsius`, `gb10_gpu_power_watts`, `gb10_gpu_utilization_percent`, `gb10_soak_seconds`, `gb10_soak_threshold_celsius`, `gb10_soak_budget_seconds`, `gb10_hot`, `gb10_mem_available_bytes`, `gb10_nv_err_no_memory_total`, `gb10_textfile_errors`, `gb10_textfile_last_run_timestamp`

`nas_up`, `nas_zpool_size_bytes`, `nas_zpool_alloc_bytes`, `nas_zpool_capacity_percent`, `nas_zpool_health`, `nas_zfs_used_bytes`, `nas_zfs_snapshots`, `nas_zfs_snapshot_used_bytes`, `nas_zfs_snapshot_newest_timestamp`, `nas_zfs_snapshot_oldest_timestamp`, `nas_hbs_installed`, `nas_textfile_last_run_timestamp`

SNMP (`qnap_*`, 48 metrics, see `prometheus/snmp.yml`): `qnap_disk_temperature_celsius`, `qnap_disk_status`, `qnap_smart_attribute_*`, `qnap_raid_*`, `qnap_pool_*`, `qnap_folder_*`, `qnap_fan_speed_rpm`, `qnap_cpu_temperature_celsius`, `qnap_system_temperature_celsius`, `qnap_cpu_usage_percent`, `qnap_memory_*`, `qnap_ups_*`, `qnap_firmware_*`, `qnap_service_*_enabled`, `qnap_app_info`, `ifHCInOctets`, `ifHCOutOctets`

`drill_last_timestamp`, `drill_last_result`, `drill_last_rto_seconds`, `drill_last_rpo_seconds`, `drill_last_rate_mib_per_second`, `drill_last_success_timestamp`, `drill_count_total`, `drills_textfile_last_run_timestamp`

`pve_quorum_up`, `pve_quorum_expected_votes`, `pve_quorum_total_votes`, `pve_quorum_quorum`, `pve_quorum_quorate`, `pve_quorum_qdevice_votes`, `pve_quorum_node_votes`, `pve_quorum_textfile_last_run_timestamp`

`fw_blocked`, `fw_top_source_blocked`, `fw_new_sources`, `nas_login_failed`, `nas_login_failed_top_source`, `fw_report_last_run_timestamp` (written by onprem-logs `firewall/fw-report.py`)

## Tests

```sh
python3 -m unittest discover -s tests
sh tests/fake-nas.sh
sh tests/compose-smoke.sh                    # docker; ports 3000, 9090, 9093, 9428, 514, 515
shellcheck textfile/nas-textfile.sh textfile/pve-quorum-textfile.sh verify.sh install-node.sh tests/fake-nas.sh tests/compose-smoke.sh grafana/build.sh
sh ../scripts/test-rules.sh                  # promtool check and test on the rendered rules
amtool check-config alertmanager/alertmanager.base.yml
python3 grafana/build-dashboard.py --check
```

## License

Apache-2.0
