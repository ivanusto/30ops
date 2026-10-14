# drills.jsonl v1

每次還原演練或回退演練寫一筆，一行一個 JSON 物件。v0.2 起六個寫入端都寫這個格式：pve-backup、nas-backup、cloud-offload 三種演練，changes 的 `drill.sh`，以及 logs 的 `verify-archive.sh` 與 `verify-pcap.sh`。寫入一律經過 `ops30.drills.append()`，sh 用 `ops30_drill`（也就是 `30ops drill record`），寫入前驗證欄位，並以 flock 附加。

```json
{"v":1,"t0":"2026-10-01T13:30:25Z","t1":"2026-10-01T13:50:23Z","kind":"nas-backup",
 "label":"2. 整個共享資料夾回復到快照","site":null,"host":"ops1","result":"pass",
 "rto_s":1198,"rpo_s":1799,"bytes":21474836480,"rate_bps":17825792,
 "checks":[{"name":"canary","result":"pass","detail":"1198s payload=ok"}],
 "cr":null,"rollback_of":null,"operator":null,"tool":"30ops 0.2.0",
 "extra":{"path":"/mnt/drill/share","code":0}}
```

## 欄位

| 欄位 | 型別 | 說明 |
|---|---|---|
| `v` | 1 | 必填 |
| `t0` | RFC 3339 | 必填，演練開始時間 |
| `t1` | RFC 3339 或 null | 演練結束時間 |
| `kind` | 字串 | 必填，`pve-backup`、`nas-backup`、`cloud-offload`、`change-rollback`、`logs-restore`、`qdevice` 其中之一 |
| `label` | 字串 | 必填，非空；metric 的 `label` 標籤就是它 |
| `result` | 字串 | 必填，`pass`、`fail`、`partial` 其中之一 |
| `rto_s`、`rpo_s`、`bytes` | 非負整數或 null | 量不到的值寫 null，不寫「-」或「?」 |
| `rate_bps` | 非負數或 null | 每秒位元組 |
| `checks` | 陣列 | 每項是 `{"name", "result", "detail"?}`，result 同上 |
| `cr`、`rollback_of` | `CR-YYYY-NNNN` 或 null | 演練本身的變更單，以及被回退的變更單 |
| `site`、`host`、`operator`、`tool` | 字串或 null | `tool` 由寫入端自動填入 |
| `extra` | 物件 | 各工具自己的欄位 |

不在表內的頂層欄位會被拒絕。`30ops drill record` 有兩種 extra 參數：`--extra k=v` 會把數字、true、false、null 存成 JSON 型別；`--extra-str k=v` 一律存成字串，用於路徑、備註與錯誤訊息。

## 舊格式

v0.2 以前每個工具各寫各的欄位。讀取端（`drills-textfile.py`、`changes-textfile.py`、`render.py`）都改用 `ops30.drills.load(path, hint)`，舊行與 v1 行可以放在同一個檔案。舊檔不改寫；需要 v1 副本時：

```sh
bin/30ops drill migrate --hint nas /srv/drills/nas-backup-drill/drills.jsonl > drills.v1.jsonl
```

`hint` 是收集端 cron 給 drills-textfile.py 的來源名稱：`pve`、`nas`、`cloud`、`logs`、`changes`。沒有 hint 時依欄位推斷。

| v1 | pve-backup | nas-backup | cloud-offload | changes | logs |
|---|---|---|---|---|---|
| `result` | `OK` 轉 pass，其他轉 fail | 同左 | 同左；`rclone rc=N` 這類原值放 `extra.result_raw` | 同左 | 同左 |
| `rto_s` | `rto_s` | `rto`（「-」轉 null） | `seconds` | `rto_s` | 無 |
| `rpo_s` | `rpo_s`（字串，空字串轉 null） | `rpo` | `rpo` | 無 | 無 |
| `rate_bps` | 無 | `rate_mbs` × 1048576 | `rate`（「52.0 MiB/s」）× 1048576 | 無 | 無 |
| `bytes` | 無 | 無 | `mib` × 1048576 | 無 | 無 |
| `extra` | vmid、ip、restore_point、t_exists、t_running、t_ping、t_ssh | path、kind、restore_point、appear、canary、manifest、payload、size_mb、code | target、note | checks（次數）、note | day、live、selection、index、code |

nas 的 `rate_mbs` 是 `du -sk` 除以 1024 再除以秒數，單位其實是 MiB/s，所以換算後 `drill_last_rate_mib_per_second` 的數值不變。

logs 舊紀錄的 `t0` 是驗證結束的時間；v1 起是開始時間。

## metric

`collector/textfile/drills-textfile.py` 的輸出名稱、標籤與數值都不變（`tests/golden/textfile/drills.prom`）：`drill_last_timestamp`、`drill_last_result`（pass 為 1）、`drill_last_rto_seconds`、`drill_last_rpo_seconds`、`drill_last_rate_mib_per_second`（rate_bps / 1048576）、`drill_last_success_timestamp`、`drill_count_total`，標籤是 `source` 與 `label`。
