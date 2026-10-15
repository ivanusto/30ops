# 告警規則

規則只有一份，放在 `collector/prometheus/rules/`。`30ops render` 讀這些檔案，代入場域的門檻後寫到 `/etc/30ops/prometheus/rules/`，Prometheus 只載入這個輸出。共 70 條告警。另有 render 由 adapter 狀態對照產生的 recording rule（`rules/status.yml`，見下方 nas 一節），不在這份目錄裡。

- 告警名稱、等級與標籤是 Alertmanager 路由與抑制規則的依據（`collector/alertmanager/alertmanager.base.yml`），也是告警歷史的鍵，所以 v1 不改名。`NasPoolAbove80` 在門檻改成 85 之後仍叫這個名字。
- 等級的意思：`critical` 立即通知並每 2 小時重送，`warning` 合併 30 秒後通知，`info` 只進每日摘要。
- 測試：`collector/tests/rules_*test.yml`，由 `scripts/test-rules.sh` 對 render 產出執行 `promtool check rules` 與 `promtool test rules`。

## 門檻

規則裡可由場域調整的數字寫成 `${鍵}`，鍵與預設值定義在 `collector/prometheus/thresholds.yml`。場域在 `site.yaml` 覆寫：

```yaml
alerting:
  thresholds:
    nas_pool_warn_pct: 85
    drill_rto_target_s: 1200
```

`30ops validate` 會檢查：鍵必須存在於 thresholds.yml、值必須大於 0，以及成對的鍵大小順序正確（`nas_pool_warn_pct` 小於 `nas_pool_crit_pct`、`eol_crit_days` 小於 `eol_warn_days`、`gb10_mem_crit_gib` 小於 `gb10_mem_warn_gib`、`nas_login_failures_warn` 小於 `nas_login_failures_crit`）。儀表板的門檻線也來自同一份值。

以下兩類不開放調整：

- textfile 過期的門檻：與產品內建的 cron 排程綁在一起。
- `for:` 持續時間：屬於告警本身的定義。

| 鍵 | 預設 | 單位 | 告警 | 預設值的來源 |
|---|---|---|---|---|
| `gb10_soak_warn_s` | 180 | 秒 | Gb10SoakNearBudget | gb10-ops 防護在 240 秒動作。Prometheus 看到的值會落後 10 到 60 秒，實測以 200 為門檻時告警只比防護早 10 秒，最差情況會晚 5 秒，因此取 180 |
| `gb10_mem_warn_gib` | 6 | GiB | Gb10MemAvailableLow | 與 gb10-ops 防護的警告線相同 |
| `gb10_mem_crit_gib` | 3 | GiB | Gb10MemAvailableCritical | 與 gb10-ops 防護的動作線相同 |
| `nas_pool_warn_pct` | 80 | % | NasPoolAbove80 | ZFS 超過八成後配置變慢、碎片增加 |
| `nas_pool_crit_pct` | 90 | % | NasPoolAbove90 | 留給清理與擴充的最後餘裕 |
| `nas_disk_temp_c` | 50 | °C | NasDiskHot | 持續 15 分鐘高於此值才告警，偶發的高溫不算 |
| `nas_snapshot_max_age_days` | 2 | 天 | NasSnapshotStale | 每日快照漏了一次以上 |
| `nas_login_failures_warn` | 10 | 次／小時 | NasLoginFailures | NAS 一分鐘內失敗 5 次才封鎖 5 分鐘，每分鐘 4 次不會觸發；一小時 10 次代表有人刻意放慢速度 |
| `nas_login_failures_crit` | 50 | 次／小時 | NasLoginFailuresCritical | 封鎖已擋不住，應在上游阻擋來源 |
| `drill_max_age_days` | 30 | 天 | DrillStale | PVE 與 NAS 還原演練每月一次 |
| `cloud_drill_max_age_days` | 90 | 天 | CloudDrillStale | 雲端異地演練每季一次 |
| `drill_rto_target_s` | 900 | 秒 | DrillRtoOverTarget | PVE 還原的目標；實驗場域第一次演練 569 秒 |
| `eol_warn_days` | 90 | 天 | AssetEolWithin90Days | 一個採購週期：報價、變更單、維護窗與廠商緩衝 |
| `eol_crit_days` | 30 | 天 | AssetEolWithin30Days | 剩一個月仍未處理 |
| `licence_warn_days` | 90 | 天 | AssetLicenceExpiring | 與支援終止相同的採購週期 |
| `change_overrun_min` | 60 | 分鐘 | ChangeWindowOverrun | 窗關閉一小時後單子仍未結案 |
| `change_soon_h` | 24 | 小時 | ChangeStartsSoon | 前一天的每日摘要先提醒值班者 |
| `rollback_drill_max_age_days` | 90 | 天 | ChangeRollbackDrillStale | 回退演練每季一次，與雲端演練相同 |
| `gate_denials_per_h` | 5 | 次／小時 | AgentGateDenials | 偶爾被拒是正常的，大量被拒代表代理人一直在要單子沒涵蓋的東西 |
| `aup_blocked_burst` | 20 | 次／小時 | AupBlockedBurst | 一兩次是人，二十次是軟體在重試；第一份週報後再檢討 |
| `fw_burst_fortigate` | 1200 | 次／小時 | FwSourceBurst | FortiGate 不限速，實驗場域最忙的來源約每小時 550 次，取兩倍多 |
| `fw_burst_ufw` | 120 | 次／小時 | FwSourceBurst | ufw 每條規則每分鐘 3 次、突發 10，每小時最多約 190；120 代表限速被頂滿 40 分鐘 |
| `fw_burst_pvefw` | 600 | 次／小時 | FwSourceBurst | PVE 防火牆每秒 1 次、突發 5；600 代表限速被頂滿 10 分鐘 |
| `fw_burst_docker_user` | 30 | 次／小時 | FwSourceBurst | DOCKER-USER 平常是 0，30 代表有來源持續重試數分鐘 |

## 管線是否存活（staleness.yml）

這組告警只回答資料還有沒有進來。資料一斷，數值類告警會跟著沉默，Alertmanager 的抑制規則會讓過期告警壓住同一來源的其他告警。

| 告警 | 等級 | 持續 | 意義與處置 |
|---|---|---|---|
| Watchdog | none | | 永遠在 firing。Alertmanager 每分鐘只送給 deadman 接收者（`site.yaml` 的 `alerting.deadman`），推送停了由收集端以外的 30ops-deadman 或外部檢查網址發告警。不會出現在一般接收者 |
| TargetDown | warning | 5m | 某個 scrape 目標連不上。先看主機是否開機、node_exporter 或 exporter 是否在跑、防火牆是否擋住 |
| Gb10TextfileStale | warning | 2m | gb10-textfile 超過 2 分鐘沒寫，檢查節點上的 timer |
| NasTextfileStale | warning | 5m | nas-textfile 超過 10 分鐘沒寫，檢查收集端 cron 與到 NAS 的 SSH |
| NasSnmpNoData | warning | 5m | SNMP 走訪回來不到 50 筆。通常是 NAS 要求的安全等級（authPriv）高於設定，走訪回傳空結果但 up 仍為 1 |
| NasUnreachable | critical | 5m | 收集端無法以 SSH 讀取 NAS 的 zfs 資訊 |
| DrillsTextfileStale | info | 10m | drills-textfile 超過 2 小時沒寫 |
| PveQuorumTextfileStale | warning | 5m | pve-quorum-textfile 超過 5 分鐘沒寫，投票數指標已過期 |

## 數值告警（thresholds.yml）

### gb10（gb10-ops 插件，每 15 秒評估一次）

| 告警 | 等級 | 持續 | 門檻 | 意義與處置 |
|---|---|---|---|---|
| Gb10SoakNearBudget | warning | | `gb10_soak_warn_s` | 最熱區域超過上限的時間接近防護預算，防護即將終止最熱的程序；先移走或暫停工作 |
| Gb10HotFlag | warning | 2m | | hw-sample 設了 HOT 旗標 |
| Gb10MemAvailableLow | warning | 1m | `gb10_mem_warn_gib` | 可用記憶體低於警告線 |
| Gb10MemAvailableCritical | critical | | `gb10_mem_crit_gib` | 可用記憶體低於防護動作線 |
| Gb10NvErrNoMemory | critical | | | 10 分鐘內出現 NV_ERR_NO_MEMORY，統一記憶體耗盡，通常接著就是停擺 |
| Gb10TextfileErrors | warning | 5m | | gb10-textfile 有來源讀取失敗 |

### nas

| 告警 | 等級 | 持續 | 門檻 | 意義與處置 |
|---|---|---|---|---|
| NasPoolAbove80 | warning | 30m | `nas_pool_warn_pct` | pool 使用率超過警告線，規劃清理或擴充 |
| NasPoolAbove90 | critical | 10m | `nas_pool_crit_pct` | pool 使用率超過危險線，會抑制 NasPoolAbove80 |
| NasPoolNotOnline | critical | 2m | | zpool 狀態不是 ONLINE（DEGRADED、FAULTED 等），先看 `zpool status` |
| NasDiskNotGood | critical | 5m | | 硬碟狀態字串不是 Good |
| NasPoolStatusNotReady | critical | 5m | | 儲存池狀態字串不是 ready |
| NasDiskHot | warning | 15m | `nas_disk_temp_c` | 硬碟溫度過高，檢查風扇與機房溫度 |
| NasSnapshotStale | warning | 1h | `nas_snapshot_max_age_days` | 有快照的資料集，最新快照過舊，檢查快照排程 |
| NasUpsNotOnline | critical | 1m | | UPS 回報的狀態不是 online。沒接 UPS 時 QuTS hero 回傳 `-1`，不算告警 |
| NasTelnetEnabled | warning | 10m | | Telnet 被打開，屬於強化設定回退 |
| NasMemoryFragmented | warning | 10m | | 帶 GPU 的 NAS，Normal zone 6 小時內都沒有 512 KiB 以上的空閒區塊；GPU 容器可能無法啟動，在空檔重開 NAS |

狀態字串（NasDiskNotGood、NasPoolStatusNotReady、NasUpsNotOnline、NasTelnetEnabled）先由 qnap adapter 正規化，告警只比對結果：

- `adapters/nas/qnap/adapter.yaml` 的 `status:` 列出哪些字串算健康，值取自 QuTS hero 6.0.2 的第一次 walk：硬碟 `Good`（不分大小寫）、儲存池 `ready`、UPS `online` 開頭或 `-1`（沒接 UPS）。
- render 把每一項轉成 `rules/status.yml` 的 recording rule `nas:<metric>:ok`，健康為 1、其他為 0，保留來源序列的所有 label（含狀態字串），所以告警的 label 與 annotation 不變。告警是 `nas:<metric>:ok == 0`。
- 硬碟、儲存池、UPS 是 fail closed：沒見過的字串會觸發告警，這是刻意的設計。Telnet 是 fail open：只有 `yes` 會觸發。
- 換韌體或換廠商時只改 adapter.yaml 的對照，規則不動。recording rule 與告警在不同群組，告警最多晚一個評估間隔（60 秒）看到結果。

### pve

pve-exporter 經由兩個節點抓取，每個節點都會回報整個叢集，所以規則會去掉 instance 標籤，每個物件只告警一次。

| 告警 | 等級 | 持續 | 意義與處置 |
|---|---|---|---|
| PveQuorumLost | critical | | 叢集失去法定票數，HA 節點會自我隔離 |
| PveNodeOffline | critical | 2m | 節點離線 |
| PveVoteMissing | warning | 2m | 仍有法定票數，但少了票（對應 `checks/qdevice/check.sh` 回傳 1）；此時不能再失去任何一票 |
| PveQdeviceAbsent | warning | 2m | QDevice 沒有投票，常見原因是 NAS 重開或 qnetd 停止 |
| PveQuorumUnreadable | warning | 5m | 所有列出的節點都讀不到 `pvecm status`，檢查金鑰、`from=` 限制或節點狀態 |
| PveHaResourceError | critical | | HA 資源處於 error、fence 或 recovery |
| PveStorageUnavailable | critical | 2m | 儲存不可用，常見原因是 NAS 上的 NFS |
| PveReplicationFailing | warning | 10m | 複寫有失敗的同步 |
| PveGuestLockedLong | warning | 30m | 虛擬機鎖定超過 30 分鐘，可能有備份或遷移卡住 |

### drills

| 告警 | 等級 | 門檻 | 意義與處置 |
|---|---|---|---|
| DrillFailed | warning | | 最近一次演練失敗，看 drills.jsonl 的 checks |
| DrillStale | warning | `drill_max_age_days` | PVE 或 NAS 演練太久沒有通過 |
| CloudDrillStale | warning | `cloud_drill_max_age_days` | 雲端演練太久沒有通過 |
| DrillRtoOverTarget | info | `drill_rto_target_s` | PVE 還原的 RTO 超過目標。NAS 與雲端演練規模不同，不套用 |

## 資產生命週期（eol.yml）

資料來源是 `assets.tsv`，由 `eol-textfile.py` 每天寫成 `asset_eol_timestamp_seconds`。

| 告警 | 等級 | 門檻 | 意義與處置 |
|---|---|---|---|
| EolTextfileStale | warning | | eol-textfile 兩天沒有執行 |
| AssetEolWithin90Days | warning | `eol_warn_days` | 支援終止日期進入警告期，開始採購或升級的變更單 |
| AssetEolWithin30Days | critical | `eol_crit_days` | 支援終止日期進入危險期 |
| AssetEolPassed | critical | | 已過支援終止日。修正資料列、升級，或書面接受風險後改寫資料列 |
| AssetLicenceExpired | critical | | 授權已到期，每台設備一則並附件數 |
| AssetLicenceExpiring | warning | `licence_warn_days` | 授權即將到期 |
| AssetEolUnknown | info | | 查無公開日期，留在摘要直到有人補上或確認沒有 |
| AssetEolSourceMismatch | info | | endoflife.date 與 assets.tsv 不一致，人工核對後修改並註明原因 |

## 防火牆與 NAS 登入（firewall.yml）

資料來源是 `logs/firewall/fw-report.py`，每 10 分鐘以 1 小時視窗寫出。

| 告警 | 等級 | 持續 | 門檻 | 意義與處置 |
|---|---|---|---|---|
| FwReportStale | warning | 10m | | fw-report 30 分鐘沒寫 |
| FwSourceBurst | warning | 10m | `fw_burst_*` | 單一來源被擋的次數超過該道牆的門檻 |
| FwNewSource | info | | | 出現過去 7 天沒見過的被擋來源 |
| NasLoginFailures | warning | | `nas_login_failures_warn` | 單一來源登入 NAS 失敗次數偏高 |
| NasLoginFailuresCritical | critical | | `nas_login_failures_crit` | NAS 的封鎖擋不住，在上游阻擋來源 |
| FwSilent | info | 2h | | 預期整天都有阻擋紀錄的防火牆，兩小時沒有任何紀錄，檢查記錄與 syslog 目的地 |

## 可接受使用（aup.yml）

資料來源是 `logs/firewall/aup-report.py`，讀邊界 FortiGate 的 webfilter 日誌。

| 告警 | 等級 | 持續 | 門檻 | 意義與處置 |
|---|---|---|---|---|
| AupReportStale | warning | 10m | | aup-report 30 分鐘沒寫 |
| AupUrgentCategoryHit | critical | | | 有工作站連往惡意、釣魚或垃圾郵件類網站；已被阻擋，要查的是哪台工作站 |
| AupBlockedBurst | warning | 10m | `aup_blocked_burst` | 單一工作站一小時被擋太多次，多半是軟體在重試 |
| AupSilent | info | 6h | | 6 小時沒有 webfilter 紀錄，檢查政策上的 profile 與 syslog 篩選 |

## 稽核軌跡（audit.yml）

資料來源是 `logs/audit/audit-report.py`，把管線裡的管理動作與變更單的時間窗比對。

| 告警 | 等級 | 持續 | 意義與處置 |
|---|---|---|---|
| AuditReportStale | warning | 10m | audit-report 30 分鐘沒寫 |
| AuditUnattributedFortigateChange | warning | | FortiGate 設定變更不在任何變更窗內，補開或補登變更單（類型 emergency） |
| AuditUnattributedActions | info | | 其他不在變更窗內的管理動作，例行的寫進忽略清單，其餘補單 |
| AuditChangeWithoutMarks | info | | 已完成的變更單，時間窗內沒有 change-mark 開始紀錄 |

## 變更單（changes.yml）

資料來源是 `changes/scripts/changes-textfile.py`。

| 告警 | 等級 | 持續 | 門檻 | 意義與處置 |
|---|---|---|---|---|
| ChangesTextfileStale | warning | 10m | | changes-textfile 一小時沒寫 |
| ChangeWindowOverrun | warning | | `change_overrun_min` | 變更窗已關閉，單子仍是 scheduled 或 in_progress；補完紀錄，或承認超時 |
| ChangeInProgress | info | | | 有變更正在進行 |
| ChangeStartsSoon | info | | `change_soon_h` | 排定的變更即將開始 |
| ChangeRollbackUndrilled | info | | | 已完成的高風險變更，回退從未演練 |
| ChangeRollbackDrillStale | info | | `rollback_drill_max_age_days` | 回退演練過舊 |

## 代理人閘道（agent.yml）

資料來源是 `gatectl textfile`。

| 告警 | 等級 | 持續 | 門檻 | 意義與處置 |
|---|---|---|---|---|
| AgentGateTextfileStale | warning | 5m | | gatectl textfile 30 分鐘沒寫 |
| AgentGateApprovalWaiting | warning | 2m | | 有 L3 請求在等 `gatectl approve` |
| AgentGateStopped | info | | | 緊急停止已啟用，所有呼叫都被拒 |
| AgentGateChainBroken | critical | | | 稽核鏈驗證失敗，與 VictoriaLogs 裡的 journal 紀錄比對 |
| AgentGateDenials | info | | `gate_denials_per_h` | 一小時內拒絕次數偏高，用 `gatectl tail` 看原因 |
