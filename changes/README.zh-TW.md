# onprem-changes

[English](README.md) | 繁體中文

小型地端 AI 機房的變更紀錄。一張變更單是一個 Markdown 檔，front matter 記誰、什麼、何時、誰核准，六個段落記目的、影響、步驟、驗證、回退、紀錄。核准走 GitHub 的 PR review，執行時 `change-mark.sh` 把開始與結束寫進 journal（Day 21 的收集端會收到）、畫成 Grafana 註記（Day 20 的儀表板看得到那一段）、對預期會響的告警開一個到窗結束的 silence。`check.py` 在 CI 驗每一張單子對它的狀態來說夠不夠完整，`changes-textfile.py` 讓窗與狀態變成指標。

為 [onprem-ops-30days](https://github.com/ivanusto/onprem-ops-30days) 的 Day 26 寫的。第一張單是 Day 25 告警指出的事，QDevice VM 從 Debian 12 升到 13。

## 變更單

<!-- INDEX:START -->
| 編號 | 標題 | 狀態 | 風險 | 資產 | 窗 | 核准 |
|---|---|---|---|---|---|---|
| [CR-2026-0007](changes/CR-2026-0007-fortigate-event-log-audit-trail.md) | 60F 的事件日誌送到收集端 515，收集端加第二個監聽器與稽核報告、規則（Day 27） | `done` | low | fgt-edge/FortiOS, collector/Ubuntu | 2026-10-11T16:30 to 18:30 | ivan (exception) |
| [CR-2026-0006](changes/CR-2026-0006-qdevice-root-password-reset.md) | 為取得 sudo，重設 QDevice VM 的 root 密碼並裝 sudo（未經單子，事後補單） | `done` | medium | qdevice/Debian | 2026-10-10T22:20 to 22:40 | ivan (exception) |
| [CR-2026-0005](changes/CR-2026-0005-accept-fortiguard-licence-risk.md) | 接受 60F 二十項 FortiGuard 授權過期的風險（Day 25） | `done` | high | fgt-edge/FortiGuard licences | 2026-10-09T19:59 to 20:01 | ivan (exception) |
| [CR-2026-0004](changes/CR-2026-0004-fortigate-webfilter-aup.md) | 60F 的 policy 1 掛上 aup-monitor 網頁過濾（Day 24） | `done` | high | fgt-edge/FortiOS, collector/Ubuntu | 2026-10-08T00:01 to 01:25 | ivan (exception) |
| [CR-2026-0003](changes/CR-2026-0003-packet-capture-on-pve.md) | 在兩台 PVE 節點裝封包擷取，收集端加拉取與驗證（Day 23） | `done` | medium | pve1/Proxmox VE, pve2/Proxmox VE, collector/Ubuntu | 2026-10-07T01:41 to 09:55 | ivan (exception) |
| [CR-2026-0002](changes/CR-2026-0002-fortigate-syslog-to-collector.md) | 讓 60F 把流量日誌送到收集端（Day 22） | `done` | medium | fgt-edge/FortiOS, collector/Ubuntu | 2026-10-06T11:32 to 13:20 | ivan (exception) |
| [CR-2026-0001](changes/CR-2026-0001-qdevice-debian-13.md) | 把 QDevice VM 從 Debian 12 升到 13 | `done` | medium | qdevice/Debian | 2026-10-10T22:45 to 23:45 | ivan (exception) |
<!-- INDEX:END -->

`scripts/render.py` 產生這張表。

## 一張單的生命

| 狀態 | 誰改的 | 要有什麼 |
|---|---|---|
| `draft` | 提出的人開 PR | 六個段落都在，`回退` 不是空的 |
| `approved` | 另一個人在 PR 上 review 並合併，然後把狀態改成 approved | `approver` 與 `implementer` 不同人。單人場域寫 `approval_exception` 說明用什麼代替，例如自審加 24 小時冷卻 |
| `scheduled` | 實作的人 | `window_start`、`window_end`，RFC 3339 帶時區 |
| `in_progress` | 實作的人在 `change-mark.sh begin` 之後改 | |
| `done` / `rolled_back` | 實作的人在 `end` 之後改 | `## 紀錄` 的 `begin`、`end`、`result` 填好，`evidence` 寫查得到的東西（VictoriaLogs 的查詢、Grafana 註記、drills.jsonl 的那一行） |
| `cancelled` | 任何人，寫原因 | |

每一次狀態改變是一個 commit，所以 git log 就是這張單的時間線。`type: emergency` 可以先做再補單，但 `done` 之前一樣要有 `approver`。

## 怎麼跑

```sh
# 開一張單
cp changes/TEMPLATE.md changes/CR-2026-0002-<slug>.md && $EDITOR changes/CR-2026-0002-<slug>.md
python3 scripts/check.py --assets ../onprem-metrics/eol/assets.tsv && python3 scripts/render.py
git checkout -b CR-2026-0002 && git add -A && git commit -m "CR-2026-0002: <title> (draft)" && git push -u origin HEAD
# 開 PR，另一個人 review。合併後把 status 改成 approved、scheduled，各一個 commit

# 收集端（一次）
sudo install -d -o metrics -g metrics /opt/onprem-changes
sudo -u metrics git clone https://github.com/ivanusto/onprem-changes /opt/onprem-changes   # 由 metrics pull，所以由 metrics 擁有
sudo install -d -o metrics -g metrics /var/lib/onprem-changes
sudo install -d -m 0755 /etc/onprem-changes && sudo install -m 0600 -o metrics grafana.token /etc/onprem-changes/grafana.token
command -v amtool    # 要在主機上，不能只在 Alertmanager 容器裡
sudo install -m 0644 collector.cron /etc/cron.d/onprem-changes       # 每 15 分鐘 git pull 與 textfile

# 執行當天，在收集端
sudo -u metrics /opt/onprem-changes/scripts/change-mark.sh begin CR-2026-0002
# 回到 repo，status 改成 in_progress 並 commit（收集端只看得到 commit 過的狀態）
# ... 照單子的步驟做，在目標主機上也 logger -t change "CR-2026-0002 begin" ...
sudo -u metrics /opt/onprem-changes/scripts/change-mark.sh end CR-2026-0002
```

Grafana 的 token 屬於一個專用的 service account，角色是 Editor。Grafana OSS 只有 Viewer、Editor、Admin 三個基本角色，Viewer 寫註記會被拒（`Access denied to save the annotation`），更細的權限要 Enterprise 的 RBAC。這把 token 不拿去做別的事。branch protection 設「合併前要一個 review，作者不能 review 自己」，`approver` 欄才有意義，`check.py` 只檢查它有沒有寫。

## 目錄

| 路徑 | 做什麼 |
|---|---|
| `changes/CR-*.md` | 變更單。`TEMPLATE.md` 是空白表 |
| `scripts/check.py` | 格式與狀態規則，CI 每次 push 跑。`--assets` 對 onprem-metrics 的 `eol/assets.tsv` 檢查資產真的存在 |
| `scripts/render.py` | 重建兩個 README 的索引表 |
| `scripts/changes-textfile.py` | `change_record`、`change_window_*`、`change_records{status}` 給 node_exporter |
| `scripts/change-mark.sh` | begin 與 end 的三件事，journal、Grafana 註記、Alertmanager silence |
| `scripts/frontmatter.py` | front matter 的小讀取器，不用 YAML 程式庫 |
| `prometheus/changes.yml` | 四條規則，複本，正本放 onprem-metrics。`ChangeWindowOverrun` 是窗關了一小時單子還沒結案 |
| `collector.cron` | 收集端的 pull 與 textfile |
| `tests/` | `unittest` 與 `promtool test rules` |

## 授權

Apache-2.0
