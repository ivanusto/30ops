# readiness

`30ops readiness` 回答一個問題：這個場域的維運，哪些已經做到、哪些還沒有、哪些是刻意不做。題目在 `checks/readiness/checklist.yaml`，分四類；插件另外帶自己的題目。每一題的結果是下列四種之一，並附上證據：

| 結果 | 意思 |
|---|---|
| 是（yes） | 查到了，而且符合 |
| 否（no） | 查到了，不符合；或該有的資料不存在 |
| 未知（unknown） | 查不到：Prometheus 沒回應、人工題沒有答案、本機檢查沒有執行 |
| 明示接受（accepted） | 不是「是」，但 `site.yaml` 寫了為什麼可以接受 |

明示接受的題目仍然列出原本的證據，接受理由附在後面。退出碼：沒有未接受的「否」為 0，有則為 1（加 `--strict` 時「未知」也算），`site.yaml` 無效或 Prometheus 完全沒有回應為 2。

## 執行

```sh
# 收集端，以 root：連同 doctor 的映像與 render 檢查
bin/30ops readiness --site /opt/30ops-site/site.yaml --format md

# 任何地方，對某個收集端的 Prometheus（包括還沒裝 30ops 的舊收集端）
ssh -L 19090:localhost:9090 admin@collector     # Prometheus 只聽 127.0.0.1
bin/30ops readiness --site site.yaml --prometheus http://127.0.0.1:19090 --no-local --format md
```

`--format` 可以是 `text`（預設，一行一題）、`md`（依類別分表，語言依 `site.locale`）或 `json`。`--textfile PATH` 另外寫一份 readiness.prom。

收集端的 cron 每 15 分鐘以 `--plan /etc/30ops/readiness.json --no-local` 執行一次，寫 `readiness.prom`：

- `readiness_item{id,category,status} 1`：每一題一筆（本機檢查的題目除外，cron 的帳號跑不了 doctor）。
- `readiness_items{status}`：各結果的題數，四種都寫，含 0。
- `readiness_textfile_last_run_timestamp`：超過一小時沒更新時 `ReadinessTextfileStale`（info）。

cron 用的 `readiness.json` 是 render 依 `site.yaml` 寫的計畫：適用的題目、代入場域門檻的 PromQL、只看 `site.yaml` 就能判定的結果、`readiness.accept` 與 `readiness.answers`，以及內建檢查需要的主機清單。所以收集端不需要 `site.yaml`，cron 也不需要 PyYAML。

## 題目的判定方式

| 方式 | 怎麼判定 |
|---|---|
| `promql` | `ok` 必須查得到序列、`bad` 必須查不到（可只有其中一個）；`${鍵}` 換成場域的門檻。只用 30ops 之前的收集端就有的序列，或該題要查的東西本身，所以也能對舊收集端執行 |
| `builtin` | `lib/python/ops30/readiness.py` 的內建檢查，結合 `site.yaml` 的主機清單與 Prometheus 的資料 |
| `site` | 只看 `site.yaml`，render 寫計畫時就決定 |
| `local` | 在收集端以 root 跑 `30ops doctor` 的指定檢查 |
| `manual` | 只能由人確認。`readiness.answers` 寫了證據就是「是」，否則「未知」並顯示要看什麼 |

## 題目

### 封裝與版本（packaging）

| id | 問題 | 方式 |
|---|---|---|
| `pkg-images-pinned` | 每個服務都跑 compose.yml 以 digest 釘住的映像 | local：doctor images |
| `pkg-render-clean` | 安裝的設定檔與現在 render 的相同 | local：doctor render |
| `pkg-release-verified` | 安裝的版本來自 Release，驗過 SHA256SUMS 與 attestation | manual |
| `pkg-rollback` | 升級失敗退得回上一版 | manual |

### 監控與告警路徑（node-guard）

| id | 問題 | 方式 |
|---|---|---|
| `targets-up` | 每個抓取目標都抓得到 | promql：`up == 0` 查不到 |
| `textfiles-fresh` | 收集端 cron 寫的每個 textfile 都在期限內 | builtin：每個 `*_last_run_timestamp` 對照其過期告警的門檻 |
| `alert-path` | Prometheus 找得到 Alertmanager，每個接收者都有送達的地方 | builtin |
| `deadman` | 收集端整台停掉時，有收集端以外的東西會發告警 | builtin：30ops-deadman 最近收過推送且不在告警中；只有外部網址時看 Watchdog 是否在 firing |
| `journald-coverage` | 每台 Linux 與 PVE 主機都送 journal | site：收集端除外；寫了 `journal: false` 的主機算已決定 |
| `switch-monitored` | 交換器與基地台在監控裡而且抓得到 | builtin：`site.yaml` 有 switch 或 ap 主機、都有 `snmp.auth`、`up{job="switch-snmp"}` 都是 1 |
| `switch-in-assets` | 每台交換器與基地台都在 assets.tsv | site；只在有 switch 或 ap 時出題 |

### 儲存與備份（storage-backup）

| id | 問題 | 方式 |
|---|---|---|
| `pve-quorum` | PVE 叢集有法定票數 | promql；有 hypervisor 時 |
| `qdevice-vote` | QDevice 有在投票 | promql；有 qdevice 時 |
| `restore-drill-pve`、`restore-drill-nas` | 還原演練在 `drill_max_age_days` 內通過過 | promql |
| `offsite-copy` | 異地副本的還原演練在 `cloud_drill_max_age_days` 內通過過 | promql |
| `nas-snapshots` | 每個有快照的資料集，最新快照在 `nas_snapshot_max_age_days` 內 | promql |
| `ups-present` | 每台 NAS 都接了 UPS | builtin：`qnap_ups_status` 為 `-1` 的 NAS 是沒接；該主機寫了 `ups: none` 就列為明示接受，理由自動帶入 |
| `backup-of-backup` | 備份目標本身也有備份 | manual |

### 變更、日誌與稽核（change-mgmt）

| id | 問題 | 方式 |
|---|---|---|
| `logs-worm` | 日誌每天封存到 WORM 並驗證通過 | promql：`daily archive verify` 兩天內通過；有 `worm` 時 |
| `fw-reviewed` | 防火牆阻擋紀錄有在彙整 | promql；有 firewall 時 |
| `pcap` | 封包擷取進 WORM 並驗證通過 | promql：`pcap archive verify` 兩天內通過；有 pcap 時 |
| `aup` | 網頁過濾的報表有在產生 | promql；有 webfilter 時 |
| `eol` | 資產都有生命週期日期，沒有已過期還在用的 | promql |
| `change-records` | 變更以變更單記錄且收集端讀得到，沒有窗已關卻未結案的 | promql |
| `audit-attributed` | 設備上的管理動作都對得到變更單 | promql：稽核告警沒有在 firing；有 audit-source 時 |
| `rollback-drilled` | 高風險變更的回退都演練過且不過期 | promql |
| `agent-gate` | 代理人閘道在跑、稽核鏈完整 | promql；`gate.targets` 有設時 |
| `second-approver` | 核准過的變更單，核准者都不是執行者 | builtin |
| `change-effort` | 近 90 天完成的變更單都記了 `effort_min` | builtin |

### 插件的題目

| id | 問題 | 方式 |
|---|---|---|
| `gb10-ops:textfile-fresh` | 每台 GB10 的 gb10-textfile 在兩分鐘內更新 | promql |
| `gb10-ops:host-guard` | 每台 GB10 都跑著 gb10-host-guard | manual |
| `spark-baseline:snapshot` | 每台節點都有近期的 baseline-snapshot | manual |
| `nfs-model-library:verify-scheduled` | `mlib verify` 有排程且最近一次通過 | manual |

## 明示接受與人工答案

```yaml
readiness:
  accept:
    second-approver: 一人機房；每張單寫 approval_exception，合併前冷卻 24 小時
    switch-monitored: 交換器的 SNMP 由下一張變更單開啟
  answers:
    pkg-release-verified: v0.7.0 取自 GitHub Release，sha256sum -c 與 gh attestation verify 通過（10-15）
```

`30ops validate` 會檢查：id 必須是檢查表或插件的題目；理由與證據不能空白；`answers` 只能用在 manual 題，查得到的題目不能用一句話改成「是」。接受理由寫的是決定，不是藉口：寫清楚為什麼、到什麼時候、由誰再看。

## 與系列檢查表的對照

檢查表改寫自系列索引的 `lab/checklist.md`（v1.0.0，`e44faf6`，原文在本 repo 的 git 歷史）。原表四類 26 題與 7 項已知缺口，改寫成產品題目時：

- **併入產品題**：版本可重建（`pkg-images-pinned`、`pkg-release-verified`）、升級可回退（`pkg-rollback`）、Prometheus 加儀表板加分級告警（`targets-up`、`alert-path`）、每個 textfile 都有過期告警（`textfiles-fresh`）、PVE 兩節點加 QDevice（`pve-quorum`、`qdevice-vote`）、三種還原演練（`restore-drill-*`、`offsite-copy`）、備份目標本身的備份（`backup-of-backup`）、日誌進 WORM（`logs-worm`）、防火牆、封包、AUP、EOL、變更單、稽核、回退演練、代理人閘道各一題。
- **已知缺口變成題目**：交換器與 AP 不在監控（`switch-monitored`、`switch-in-assets`）、沒有 UPS（`ups-present`）、小 VM 的 journald（`journald-coverage`）、收集端單點（`deadman`）、沒有第二位核准者（`second-approver`）、人力時間沒有量（`change-effort`）、模型庫 verify 不常駐（`nfs-model-library:verify-scheduled`）。
- **移到插件**：GB10 的防護與指標（`gb10-ops:*`）、節點基準（`spark-baseline:snapshot`）。
- **沒有列入**：綁在系列實驗場域的題目（模型與硬體對照、上游修補移植紀錄、QPKG 的 GPU 安裝、把手工專案拉回範本省了什麼、儲存路徑試算）。它們回答的是那個場域怎麼搭起來，不是一個中小企業機房能不能維運。
