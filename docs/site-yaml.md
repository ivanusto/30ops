# site.yaml（version 1）

一個場域一份 `site.yaml`，收集端與節點的站點設定都由它產生（`30ops render`，見 [render.md](render.md)）。範例在 [`examples/sample-site/site.yaml`](../examples/sample-site/site.yaml)，位址用 RFC 5737 文件保留段。

```sh
bin/30ops validate --site site.yaml            # 0 通過，1 有錯，2 用法錯
bin/30ops validate --site site.yaml --strict   # 警告也算錯
bin/30ops validate --site site.yaml --secrets  # 在收集端：credentials 的檔案存在且為 0600 或 0400
```

`--site` 省略時讀 `./site.yaml`，或環境變數 `OPS30_SITE`。錯誤訊息以欄位路徑開頭（`hosts[3].vendor ...`），一次列出全部。

## 載入規則

- 用 PyYAML（`python3-yaml`）的 SafeLoader。同一層出現兩次的鍵是錯誤，PyYAML 預設會默默留下後一個。
- 日期與時間一律保持字串，`2026-10-14` 不會變成 date 物件。
- 未知的鍵是錯誤，拼錯的欄位不會被忽略。

## 秘密

site.yaml 不放任何秘密值。`credentials` 的每一項只有 `file`（收集端上的絕對路徑）與選填的 `note`；其他段落以名稱引用。

```yaml
credentials:
  smtp: {file: /etc/30ops/secrets/smtp.pass}
alerting:
  smtp: {smarthost: "smtp.example.net:587", from: alerts@example.net, password: smtp}
```

鍵名是 `password`、`priv_password`、`token`、`passphrase`、`secret`、`key` 的欄位，值必須是 `credentials` 裡的名稱，否則 validate 報「plain-text secrets are not allowed」，且訊息不回顯該值。render 也不讀秘密檔，見 [render.md](render.md#秘密)。

## 欄位

| 欄位 | 必填 | 說明 |
|---|---|---|
| `version` | 是 | 1 |
| `site.id` | 是 | 小寫英數與 `-`，成為 Prometheus 的 `site` external label |
| `site.name` | | 顯示用名稱 |
| `site.timezone` | 是 | zoneinfo 名稱，cron 的每日與每週工作依此換算（見下方） |
| `site.locale` | | `zh-TW`（預設）或 `en` |
| `collector.host` | 是 | `hosts` 中唯一有 `collector` 角色的主機 |
| `collector.root` | | 30ops checkout 的位置，預設 `/opt/30ops` |
| `collector.user` | | cron 的執行帳號，預設 `metrics` |
| `collector.textfile_dir` | | 預設 `/var/lib/node_exporter/textfile` |
| `collector.log_dir` | | 預設 `/var/log/30ops` |
| `collector.reports_dir` | | 週報輸出，預設 `/srv/reports` |
| `collector.eol_cache` | | 預設 `/var/lib/onprem-metrics/eol` |
| `collector.victorialogs` | | 預設 `http://127.0.0.1:9428` |
| `collector.drills.{pve,nas,cloud,logs}` | | 各演練的 drills.jsonl，預設沿用舊路徑 `/srv/drills/<舊 repo 名>/drills.jsonl`，切換時不搬歷史 |
| `credentials.<名稱>` | | `{file, note}` |
| `hosts[]` | 是 | 見下表 |
| `pve.exporter` | | `user`、`token_name`、`token`（credentials 名稱）、`verify_ssl` |
| `snmp.auths.<名稱>` | | `username`、`security_level`（預設 authPriv）、`auth_protocol`、`password`、`priv_protocol`、`priv_password` |
| `worm` | | `host`、`export`、`mount`、`options`（預設 `rw,hard,timeo=600,retrans=2,noatime,nofail,vers=4.1,noexec,nosuid,nodev`） |
| `logs.archive.skip` | | 不進 WORM 的來源，例如 `syslog-<devname>` |
| `logs.admin_from` | | 可以查詢 VictoriaLogs 的主機名稱 |
| `logs.pcap` | 有 `pcap` 角色時 | `key`（拉取用 SSH 金鑰的 credentials 名稱）、`peer`（節點擷取設定檔指向的 NAS） |
| `alerting.smtp` | 有 email 收件者時 | `smarthost`、`from`、`username`、`password`、`require_tls`（預設 true） |
| `alerting.receivers` | 是 | 必須有 `ops-critical`、`ops-warning`、`ops-digest`（路由樹送往這三個），各自 `email[]`、`webhook[]`、`send_resolved` |
| `alerting.thresholds` | | 接受並檢查型別，v0.4 才套進規則 |
| `changes.clone` | | 變更單 repo 在收集端的 clone，預設 `/var/lib/30ops/changes` |
| `changes.state_dir` | | 預設 `/var/lib/onprem-changes` |
| `gate.targets[]` | | `asset`（`asset/component`，必須是 assets.tsv 的一列）、`ssh`（`user@host` 或 `local`） |
| `gate.principal`、`home`、`approval_ttl_s`、`approvers` | | 預設 `agent:ops`、`/var/lib/onprem-agent-gate`、600、`[implementer, approver]` |
| `assets` | | assets.tsv 的路徑，相對於 site.yaml，格式見 [assets-tsv.md](assets-tsv.md) |
| `cost` | | cost.yaml 的路徑，相對於 site.yaml，以 `inventory/cost.py` 的規則檢查 |

### hosts[]

| 欄位 | 說明 |
|---|---|
| `name` | 小寫英數與 `-`，不得重複 |
| `address` | IP 或主機名稱；`also[]` 列同一台的其他位址（例如有兩個 LAN 位址的 NAS） |
| `vendor` | `linux`、`pve`、`qnap`、`fortigate`、`generic-snmp`。收集端會連線的角色必填 |
| `roles[]` | 見下表 |
| `labels` | 照抄到 Prometheus targets 的 label。v1 不改 metric label，舊值寫在這裡（例如 `nas: primary`） |
| `plugins[]` | `gb10-ops`、`spark-baseline`、`nfs-model-library`。`gb10-ops` 的主機進 `gb10` job（15 秒） |
| `ssh.user` | 收集端登入用的帳號（NAS 健康檢查、PVE quorum） |
| `snmp.auth` | `snmp.auths` 的名稱 |
| `pve.cluster` | quorum 檢查的叢集名稱，同名的主機為同一叢集 |
| `api` | `url`、`token`（credentials 名稱）、`insecure`。FortiGate 的授權到期日讀這裡 |
| `syslog.devname` | 裝置在 syslog 裡的名稱（FortiGate 的 devname），`webfilter` 與 `audit-source` 角色必填 |
| `pcap` | `user`（預設 `pcap`）、`iface`（corosync 擷取的介面） |

| 角色 | 產生的設定 |
|---|---|
| `collector` | `collector-host` job、節點安裝參數 |
| `node` | node_exporter target（`gb10` 或 `node` job） |
| `journal` | allowlist `JOURNALD_FROM`、節點的 journal-upload 網址 |
| `syslog` | allowlist `SYSLOG_FROM`（含 `also`） |
| `audit-source` | allowlist `AUDIT_FROM`（515 埠） |
| `pcap` | `PCAP_NODES`、節點的擷取設定檔與 sudoers |
| `hypervisor` | `pve` job、quorum 檢查 |
| `nas` | `nas-snmp` job、`nas-textfile.sh` |
| `firewall` | `FW_EXPECT`、EOL 的授權到期日 |
| `webfilter` | `AUP_EXPECT` |
| `admin` | `AUDIT_QUIET_FROM` |
| `qdevice`、`switch`、`ap` | v0.3 只登錄，v0.5 起由 adapter 使用 |

## 時區與 cron

cron 用收集端的當地時間。每日與每週工作在程式裡以 UTC 固定（例如 WORM 封存在 UTC 00:10，前一個 UTC 日已經結束），render 依 `site.timezone` 的標準時差換算：Asia/Taipei 是 08:10。有夏令時間的時區，夏天會晚一小時執行。

## 從現行收集端產生

```sh
scripts/fetch-legacy.sh admin@collector snapshot/          # 唯讀，秘密值在主機端遮蔽
bin/30ops import-legacy --from snapshot/ -o site/site.yaml   # 另把 assets.tsv 複製到旁邊
bin/30ops render --site site/site.yaml --compare-legacy snapshot/
```

import-legacy 讀不出來的部分（同一台的第二個位址、沒有被抓取的主機的 vendor、cost.yaml）列在草稿開頭的 TODO。流程見 [render.md](render.md#比對現行收集端)。
