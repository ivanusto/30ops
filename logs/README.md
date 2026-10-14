# onprem-logs

English | [繁體中文](README.zh-TW.md)

Log collection and retention for a small on-prem AI lab. Two DGX Spark nodes and two Proxmox VE nodes ship their journal with `systemd-journal-upload`, the uploader that comes with systemd. Two QuTS hero NAS send syslog with the sender built into QuLog Center. One VictoriaLogs container on the collector receives both. Nothing new is installed on the nodes or the NAS. Hot data is kept for 90 days. Every day the previous UTC day is exported as JSONL onto a WORM shared folder on the NAS (retention tentatively 180 days, to be confirmed against the site's records retention procedure), with a per-file sha256 and a manifest that proves the line count equals the query hit count.

| Path | Runs on | What it does |
|---|---|---|
| VictoriaLogs in `../collector/compose.yml` | collector VM | VictoriaLogs v1.52.0 pinned by digest, journald and syslog receivers; retention (default 90 days and 12 GiB) and the syslog time zone come from `site.yaml` through the rendered `compose.env`. It runs in the collector's compose project (profile `logs`), so Grafana and Prometheus reach it as `victorialogs:9428` |
| `collector/docker-user-allowlist.sh` | collector VM | Only the nodes may reach 9428 and only the NAS and the edge FortiGate may reach 514; every DROP has a rate-limited LOG in front of it (Day 22). Ports published by Docker bypass ufw, so the allowlist lives in the DOCKER-USER chain. `30ops render` writes its addresses (`/etc/default/30ops-allowlist`) and the unit that applies it at boot |
| `node/install-journal-upload.sh` | every DGX Spark and PVE node | Installs `systemd-journal-remote`, makes sure the journal is persistent, writes `journal-upload.conf`, adds a drop-in that keeps retrying every 30 s (the stock unit gives up within a second when the collector is not reachable at boot), enables the service; run it again to update a host; `--from-now` skips the existing history |
| `nas/qulog-log-sender.md` | every NAS | QuLog Center sender setup, the fields that arrive, time zone and TLS notes (Traditional Chinese) |
| `archive/archive-day.sh` | collector, cron 08:10 local (00:10 UTC) | Exports the previous UTC day per host, hour by hour, into a local staging area; copies to WORM only when every count matches, then writes `MANIFEST.tsv` and `SHA256SUMS`; refuses to touch a completed day; `ARCHIVE_SKIP` keeps named sources out by policy and records their hit count in the manifest |
| `archive/verify-archive.sh` | collector, cron 08:20 and quarterly by hand | Checks sha256, lines equal hits, decompressed line counts; `--against-live` re-asks VictoriaLogs; `DRILLS=` appends the result to drills.jsonl |
| `queries.md` | docs | LogsQL for each Day 20 alert, checked against field data (Traditional Chinese) |
| `retention.md` | docs | Source, hot and archive tiers, their limits and the WORM settings (Traditional Chinese) |
| `tests/smoke.sh` | CI and local | Starts a throwaway VictoriaLogs, sends one syslog and one journald entry, queries them back, archives and verifies, simulates a WORM-locked rerun, a tampered file and an unreachable collector |
| `firewall/fw-report.py` | collector, cron every 10 min and Monday 08:15 | Day 22. Reads the drops of five walls from VictoriaLogs (edge FortiGate, DGX Spark ufw, PVE pve-firewall, the collector's DOCKER-USER, QuLog's connection log) and answers who is knocking, where, and who is new; Markdown for people, `fw.prom` for onprem-metrics' `firewall.yml`. `FW_EXPECT` names the walls that must drop something, written as 0 when they log nothing |
| `firewall/collector-docker-user-log.md`, `pve-firewall.md`, `spark-ufw-logging.sh`, `pvefw-journal.service` | docs, PVE nodes, DGX Spark | How each wall is made to log, with what rate limit, and why the lab's Spark ufw and PVE firewall stay off for now (Traditional Chinese docs) |
| `firewall/queries.md` | docs | LogsQL per wall, checked against field data |
| `tests/smoke-firewall.sh` | CI and local | One line of each firewall shape into a throwaway VictoriaLogs; checks the counts, that an accept is not counted, that an expected silent host is written as 0, and the NAS failure |
| `pcap/install-pcap.sh`, `pcap@.service`, `pcap-run.sh`, `pcap-seal.sh`, `profiles/*.env`, `sudoers-pcap` | each DGX Spark and PVE node | Day 23. Packet capture with the least privilege that still works: tcpdump runs as the system user `pcap` with `CAP_NET_RAW` only (no promiscuous mode, no setcap on the binary), one systemd instance per profile (`systemctl start pcap@nfs`), a short snaplen by default (it bounds, not removes, payload: see pcap/README.md), a time limit (`-G/-W`) or a ring (`-C/-W`) so the disk is bounded. When tcpdump exits the files are sealed into `done/` with a sha256 each. `pcap-ops` members may start/stop the listed units with sudo; nothing else |
| `pcap/pcap-pull.sh`, `pcap-stat.py`, `verify-pcap.sh` | collector, cron hourly | Pulls each node's `done/` over ssh (forced `rrsync -ro`), checks every file against the node's sha256, publishes one batch per node to the WORM share with `MANIFEST.tsv` (bytes, packets, first/last timestamp, truncated flag, sha256) and `SHA256SUMS`; a shipped index keeps a file from being pulled twice. `verify-pcap.sh --latest --against-index` recounts the packets and checks the index, result into drills.jsonl |
| `tests/smoke-pcap.sh` | CI and local | Dry runs of every profile, a real capture on `lo` when root, seal, pull into a WORM stand-in, second pull publishes nothing, a lying sidecar is refused, a truncated capture is flagged, verify fails on a tampered file and on a batch not in the index |
| `firewall/aup-report.py`, `firewall/fortigate-webfilter.md` | collector, cron every 10 min and Monday 08:25 | Day 24. Acceptable-use review of the edge FortiGate's web-filter log: sites per workstation, categories, blocked per workstation, hits on the urgent categories. Online from VictoriaLogs or offline from an export file with `--from-file`, the same seven normalized fields either way. Markdown for people, `aup.prom` for `collector/prometheus/rules/aup.yml`. The .md holds the FortiGate change (monitor-all profile on policy 1) and the LogsQL |
| `firewall/aup-compare.sh`, `firewall/fortigate-export-load.py` | anywhere with docker or a VictoriaLogs binary | Loads an export into a throwaway VictoriaLogs the way the live feed stores it, runs aup-report online and offline on it, diffs the two reports; the browser viewer ([fortigate-log-viewer](https://github.com/ivanusto/fortigate-log-viewer)) is the third reading. The loader's `--field audit=fortigate` (Day 28) backfills an event-log export into the audit stream, `--source` keeps it apart from the live feed |
| `tests/smoke-aup.sh` | CI and local | online == offline on the fixture, the file reconciles (lines = parsed + skipped), non-webfilter lines stay out, textfile writes every urgent category and a silent FortiGate as 0, a line without a time is skipped by the loader and shows up as the one difference |
| `audit/audit-report.py`, `audit/ignore.txt`, `audit/queries.md` | collector, cron every 10 min and Monday 08:45 | Day 27. Every administrative action the pipeline already holds (FortiGate config changes and admin logins, Proxmox tasks, sudo and SSH logins, QuLog events, and since Day 29 the decisions of [onprem-agent-gate](https://github.com/ivanusto/onprem-agent-gate)) matched against the change windows in an onprem-changes clone: attributed, unattributed, ignored by `ignore.txt`, and done records whose window has no change-mark line. Markdown for people, `audit.prom` for `collector/prometheus/rules/audit.yml` |
| `audit/fortigate-syslogd3.md` | FortiGate, collector | The FortiGate's event log on its own syslog destination to port 515; the collector's second listener stamps `audit="fortigate"`, so the events are their own stream and their own archive source (`audit-<devname>`) while the traffic log stays out of the WORM share |
| `tests/smoke-audit.sh` | CI and local | Two listeners, one line of every action shape, three fake change records: attribution, ignore list, missing marks, the textfile, and the archive exporting `audit-*` as its own source while the traffic is skipped |

## Why not Graylog, Loki, or QuLog Center alone

Graylog needs MongoDB and OpenSearch next to it and does not fit a 2 vCPU, 4 GB collector. Loki needs an agent on every node. QuLog Center lives on the NAS, which is exactly the box that is gone for eight minutes when it reboots. VictoriaLogs ingests the journald export format natively, so the nodes need nothing but the uploader systemd already ships.

## Things the field taught

- Docker-published ports never reach ufw's INPUT rules. Restrict them in DOCKER-USER, matching the original port with `-m conntrack --ctorigdstport`, and publish on `0.0.0.0` only: a `[::]` listener is served by docker-proxy through INPUT.
- `systemd-journal-upload.service` runs with `DynamicUser=yes`; there is no static user and the cursor lives in `/var/lib/private/systemd/journal-upload/state`.
- VictoriaLogs drops anything older than its retention at ingestion (`vl_rows_dropped_total{reason="too_small_timestamp"}`), so a first upload of a long journal costs nothing beyond the retention window.
- QuLog Center sends RFC 3164 over TCP and UDP and RFC 5424 only over TLS. RFC 3164 carries no time zone, so `-syslog.timezone` is required.
- A single query's `sort` is capped by the container memory (about 122 MB at a 1 GiB limit); the archive exports hour by hour.
- On a WORM share everything written is locked after the lock delay, including half-written temp files. Build and check the day locally, copy last.

## Quick start

```sh
# collector: VictoriaLogs runs in the collector's compose project, and the
# cron lines, the allowlist and its unit, and the WORM mount unit come from
# `30ops render` (../collector/README.md, ../docs/render.md)
sudo systemctl daemon-reload && sudo systemctl enable --now 30ops-allowlist mnt-worm.mount
sudo install -d -o metrics /var/log/30ops /srv/drills/onprem-logs /var/tmp/onprem-logs-stage

# every node (DGX Spark, PVE)
sudo ./node/install-journal-upload.sh http://192.0.2.49:9428

# every NAS: follow nas/qulog-log-sender.md

# back on the collector
curl -s http://127.0.0.1:9428/select/logsql/query -d 'query=_time:5m | stats by (_HOSTNAME, hostname) count()'
```

## Tests

```sh
shellcheck -s sh archive/*.sh node/*.sh collector/*.sh firewall/*.sh pcap/*.sh tests/*.sh
VLBIN=/path/to/victoria-logs-prod sh tests/smoke.sh    # or leave VLBIN unset to use docker
sh tests/smoke-firewall.sh
sh tests/smoke-pcap.sh                                 # as root it also captures on lo; SMOKE_PCAP_REAL=0 skips that
sh tests/smoke-aup.sh                                  # VLBIN or docker, like smoke.sh
sh tests/smoke-audit.sh
```

## License

Apache-2.0
