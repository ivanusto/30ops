# drills/

Rollback drills (Day 28). A rollback section is only as good as the last
time somebody ran it.

| File | What |
|---|---|
| [drill.sh](drill.sh) | Times one rollback: polls a verification command every 2 s until it exits 0 (or `-t` seconds pass), writes start and end to the journal with tag `drill`, appends one JSON line to `drills.jsonl` |
| `drills.jsonl` | One drills.jsonl v1 record per drill (kind `change-rollback`, [docs/drills-jsonl.md](../../docs/drills-jsonl.md)) with `cr` (the drill record) and `rollback_of` (the record whose rollback was run). Created by the first drill; site data, kept in the site repository |
| [drills.md](drills.md) | The human table, Day 15's format: expected, observed, with times |

```
drills/drill.sh <label> <drill CR> <rollback of CR> [-t SECONDS] -- <verify command...>

drills/drill.sh qdevice-snapshot-revert CR-2026-0011 CR-2026-0001 -t 600 -- \
    sh -c 'ssh root@pve1 /root/pve-qdevice-on-qnap/check.sh && ssh qdevice test ! -e /var/tmp/CR-2026-0011-marker'
```

Start it the moment the rollback starts (the revert is clicked, the PUT is
sent, `docker compose up` runs), so `rto_s` is wall-clock time including
the human steps. When the verification cannot be run from where the
rollback is performed, start `drill.sh` in the background two seconds
before the rollback command and `wait` for it (CR-2026-0011 does this for
the REST and compose drills).

The drill itself is a change record: window, silence, begin and end marks
like any other, with the drill lines and the observations committed in the
same PR that fills the record's 紀錄. Through the collector's clone
(`collector.cron`), `drills.jsonl` then feeds two things:

- onprem-metrics' `drills-textfile.py` reads it as source `changes`, so
  `drill_last_result{source="changes",label=...}` and friends exist, and
  Day 20's `DrillFailed` covers a failed rollback drill.
- `scripts/changes-textfile.py` reads it for `rollback_of` and writes
  `change_rollback_last_drill_timestamp{id}`,
  `change_rollback_last_drill_result{id}` and
  `change_rollback_drills_total{id}` per record. `ChangeRollbackUndrilled`
  (done, `risk: high`, no drill on file) and `ChangeRollbackDrillStale`
  (last drill over 90 days ago) are in `collector/prometheus/rules/changes.yml`.

The index in the READMEs gets a 回退演練 column from the same file.

`DRILLS=/path/to/drills.jsonl` writes elsewhere; `LOGGER=/bin/true` keeps a
test run out of the journal (`tests/test_drill.sh` uses a fake logger for
the same reason change-mark's smoke test does: the collector uploads this
journal, and a test run would otherwise show up in the audit report).
