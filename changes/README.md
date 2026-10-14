# onprem-changes

English | [繁體中文](README.zh-TW.md)

Change records for a small on-prem AI lab. One change is one Markdown file: front matter says who, what, when and who approved; six sections say why, impact, steps, verification, rollback, and what happened. Approval is a GitHub pull-request review. On the day, `change-mark.sh` writes begin and end into the journal (Day 21's collector picks it up), draws a Grafana annotation (the span shows on Day 20's dashboard) and opens an Alertmanager silence for the alerts the record expects, ending with the window. `check.py` verifies in CI that every record is complete enough for its status; `changes-textfile.py` turns windows and statuses into metrics.

Written for Day 26 of [onprem-ops-30days](https://github.com/ivanusto/onprem-ops-30days). The first record is what Day 25's alert pointed at: the QDevice VM from Debian 12 to 13.

## Records

<!-- INDEX:START -->
| Id | Title | Status | Risk | Assets | Window | Approver | Rollback drill |
|---|---|---|---|---|---|---|---|
<!-- INDEX:END -->

`scripts/render.py` generates this table.

## Life of a record

| Status | Who | Must have |
|---|---|---|
| `draft` | the requester opens a PR | all six sections, rollback not empty |
| `approved` | someone else reviews and merges the PR, then sets the status | `approver` differs from `implementer`; a one-person site writes `approval_exception` saying what stands in (self-review plus a 24 h cooling period, for instance) |
| `scheduled` | the implementer | `window_start`, `window_end` as RFC 3339 with an offset |
| `in_progress` | the implementer, after `change-mark.sh begin` | |
| `done` / `rolled_back` | the implementer, after `end` | `## 紀錄` with `begin`, `end`, `result`; `evidence` names what can be looked up (the VictoriaLogs query, the Grafana annotation, the drills.jsonl line) |
| `cancelled` | anyone, with a reason | |

Every status change is a commit, so `git log` on the file is the record's timeline. `type: emergency` may be done first and written up after, but needs an `approver` before `done` all the same.

## Run

```sh
# a new record
cp changes/TEMPLATE.md changes/CR-2026-0002-<slug>.md && $EDITOR changes/CR-2026-0002-<slug>.md
python3 scripts/check.py --assets ../onprem-metrics/eol/assets.tsv && python3 scripts/render.py
git checkout -b CR-2026-0002 && git add -A && git commit -m "CR-2026-0002: <title> (draft)" && git push -u origin HEAD
# open the PR, someone else reviews; after the merge, approved then scheduled, one commit each

# collector, once
sudo install -d -o metrics -g metrics /opt/onprem-changes
sudo -u metrics git clone https://github.com/ivanusto/onprem-changes /opt/onprem-changes   # metrics pulls it, so metrics owns it
sudo install -d -o metrics -g metrics /var/lib/onprem-changes
sudo install -d -m 0755 /etc/onprem-changes && sudo install -m 0600 -o metrics grafana.token /etc/onprem-changes/grafana.token
command -v amtool    # on the host, not only inside the Alertmanager container
sudo install -m 0644 collector.cron /etc/cron.d/onprem-changes       # git pull and the textfile every 15 minutes

# on the day, on the collector
sudo -u metrics /opt/onprem-changes/scripts/change-mark.sh begin CR-2026-0002
# back in the repo: status in_progress, commit (the collector only sees committed statuses)
# ... follow the record; on the target host too: logger -t change "CR-2026-0002 begin" ...
sudo -u metrics /opt/onprem-changes/scripts/change-mark.sh end CR-2026-0002

# Rollback drill (Day 28): inside the drill record's window, start it as the rollback starts; it stops when the verification exits 0
drills/drill.sh qdevice-snapshot-revert CR-2026-0011 CR-2026-0001 -t 600 -- \
  sh -c 'ssh root@pve1 /root/pve-qdevice-on-qnap/check.sh && ssh qdevice test ! -e /var/tmp/CR-2026-0011-marker'
# one more line in drills/drills.jsonl, committed with the drill record; the observations go into drills/drills.md by hand
```

The Grafana token belongs to a service account of its own with the Editor role: Grafana OSS has only the Viewer, Editor and Admin basic roles, a Viewer is refused with `Access denied to save the annotation`, and narrower permissions need Enterprise RBAC. Keep it a token used for nothing else. Branch protection ("one review before merge, not by the author") is what gives `approver` its meaning; `check.py` only checks that it is written down.

## Layout

| Path | What |
|---|---|
| `changes/CR-*.md` | the records; `TEMPLATE.md` is the blank form |
| `scripts/check.py` | format and status rules, run by CI on every push; `--assets` checks the assets exist in onprem-metrics' `eol/assets.tsv`; `agent:` (Day 29) names the agents [onprem-agent-gate](https://github.com/ivanusto/onprem-agent-gate) may let work under the record |
| `scripts/render.py` | rebuilds the index table in both READMEs; the 回退演練 column comes from `drills/drills.jsonl` |
| `scripts/changes-textfile.py` | `change_record`, `change_window_*`, `change_records{status}` for node_exporter; from `drills/drills.jsonl`, `change_rollback_last_drill_timestamp`, `change_rollback_last_drill_result` and `change_rollback_drills_total` per record (Day 28) |
| `scripts/change-mark.sh` | the three things at begin and end: journal, Grafana annotation, Alertmanager silence |
| `../lib/python/ops30/frontmatter.py` | the small front matter reader, no YAML library (shared with gate/ since 30ops v0.2) |
| `prometheus/changes.yml` | six rules, a copy; the one Prometheus loads lives in onprem-metrics. `ChangeWindowOverrun` is a window closed an hour ago with the record still open; `ChangeRollbackUndrilled` is a done high-risk record whose rollback was never drilled, `ChangeRollbackDrillStale` a drill older than 90 days |
| `drills/` | rollback drills (Day 28): `drill.sh` times one rollback and appends to `drills.jsonl`, `drills.md` is the table in Day 15's format. See [drills/README.md](drills/README.md) |
| `collector.cron` | pull and textfile on the collector |
| `tests/` | `unittest`, `promtool test rules`, `smoke-change-mark.sh`, `test_drill.sh` |

## License

Apache-2.0
