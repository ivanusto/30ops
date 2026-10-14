# onprem-metrics

[English](README.md) | 繁體中文

一套 Prometheus 收一個小型地端 AI 機房的指標，兩台 NVIDIA DGX Spark（GB10）、兩台 QuTS hero 的 QNAP NAS、兩節點加 QDevice 的 Proxmox VE，以及備份那幾天留下的還原演練紀錄。標準 exporter 看得到的交給標準 exporter，看不到的三件事以 node_exporter 的 textfile collector 補上，再加上把目標接在一起的 Prometheus 設定。

| 路徑 | 跑在哪 | 做什麼 |
|---|---|---|
| `textfile/gb10-textfile.py` | 每台 DGX Spark，systemd timer 每 10 秒 | 最熱的 thermal zone、GPU 溫度與功耗與使用率、**熱 soak 秒數**（88 度以上連續秒數）、dmesg 的 `NV_ERR_NO_MEMORY` 計數、MemAvailable、gb10-ops `hw-sample.py` 的 HOT 旗標（只有 hw-sample 以 `--hot-flag /run/gb10/HOT` 在跑時才會出現）。soak 狀態跨次保存，timer 斷掉就歸零 |
| `prometheus/snmp-build.py` 與 `prometheus/snmp.yml` | 收集端 VM | 不靠 generator，直接從 QNAP 的 QTS-MIB（enterprises 55062，QuTS hero）解析 OID 產生 snmp_exporter 模組。磁碟與溫度、SMART 屬性、RAID、儲存池、共享資料夾（WORM、壓縮、去重）、風扇、CPU 與系統溫度、CPU 與記憶體、UPS、韌體、對外服務、已安裝套件，加上 IF-MIB 的網卡計數。只用 SNMP v3，範例是 authPriv（SHA、DES，QuTS hero 6.0.2 介面能選的最高組合），`security_level` 與協定要跟 NAS 上實際生效的一致，認證放 `snmp-auth.yml`（不入庫） |
| `textfile/nas-textfile.sh` | 收集端主機，cron 每分鐘 | 參數是 `LABEL=user@host`，`nas` 標籤與 SNMP 目標的 `nas` 對得起來。經 ssh 到每台 NAS，只收 MIB 沒有的東西，依名稱列的 ZFS 池、資料集已用、每資料集快照數與最新最舊時間與佔用、HBS 3 是否安裝。NAS 上不裝任何東西 |
| `textfile/drills-textfile.py` | 收集端主機，cron 每 15 分鐘 | 讀三種演練、封存與封包驗證（來源 `logs`）、回退演練（來源 `changes`）的 `drills.jsonl`，v1 與舊的各工具格式都讀（[docs/drills-jsonl.md](../docs/drills-jsonl.md)），每個演練標籤只留最近一次，時間、結果、RTO、RPO、速率、最近一次成功 |
| `prometheus/` | 收集端 VM | `prometheus.yml` 是抓取 job 與三種間隔（GPU 節點 15 秒，NAS 與 PVE 60 秒）；`30ops render` 加上場域標籤、file_sd 目標與 exporter 設定（`pve.yml`、`snmp-auth.yml`），寫到 `/etc/30ops/prometheus/`。`thresholds.yml` 是場域可在 `site.yaml` 的 `alerting.thresholds` 調整的告警門檻。`rules/` 是 69 條告警規則唯一的一份，render 時代入場域門檻（[docs/rules.md](../docs/rules.md)） |
| `compose.yml` | 收集端 VM | 唯一的 compose 專案：Prometheus 3.5、pve-exporter、snmp-exporter、Alertmanager、Grafana（內含 VictoriaLogs 資料源外掛的 30ops 映像）與 VictoriaLogs，映像以 digest 釘住。場域設定（volume 名稱、保留期、時區、Grafana 埠、秘密檔、要跑哪些 exporter）來自 render 產生的 `/etc/30ops/compose.env`；volume 一律 external，名稱寫錯會停在啟動前，不會建出空的 TSDB。對區網開放的只有 Grafana 的 3000 與 VictoriaLogs（9428、syslog 514 與 515），Prometheus、Alertmanager 與 exporter 都只發佈到 127.0.0.1 |
| `systemd/` | DGX Spark 與收集端 | node_exporter 單元、gb10-textfile 的 service 與 timer。收集端的 cron 由 `30ops render` 產生 `/etc/cron.d/30ops` |
| `install-node.sh` | 每台 DGX Spark；`--collector` 給收集端 | 下載 node_exporter（arm64 或 amd64），對 release 的 sha256 校驗，安裝單元。DGX Spark 模式另裝 gb10-textfile 與 `/run/gb10`（tmpfiles.d）；`--collector` 只裝 node_exporter 與 textfile 目錄 |
| `verify.sh` | 任何有 curl、ssh 與 python3 的機器 | 每個目標的 `up`、抓取秒數與樣本數，每個來源一個 Prometheus 的值與原始工具的值並列，演練表。NAS 端只用一般帳號讀得到的來源（`getsysinfo` 的溫度要 root） |
| `prometheus/rules/thresholds.yml` | 收集端 VM | 數值告警（Day 20）。soak 達 180 秒（守護 240 秒動手，textfile 舊值、抓取跳階與規則評估最多吃掉 45 秒，Day 20 實測；gb10 群組因此每 15 秒評估一次）、MemAvailable 6 與 3 GiB、`NV_ERR_NO_MEMORY` 增量、儲存池 80 與 90 %、QuTS hero 回報的池與磁碟狀態字串、快照逾 2 天、失去法定人數與少一票、HA 資源異常、演練逾期與失敗。門檻是預設值，場域可覆寫，各自的出處見 [docs/rules.md](../docs/rules.md) |
| `prometheus/rules/firewall.yml` | 收集端 VM | 防火牆判讀告警（Day 22），讀 onprem-logs 的 `firewall/fw-report.py` 由收集端 cron 每 10 分鐘寫的 `fw.prom`。報告過期、單一來源超過各道牆自己的門檻（各道牆的日誌限速差了好幾個數量級）、從沒擋過的新來源、NAS 登入失敗超過 NAS 自己的封鎖速率、預期會擋東西的牆 2 小時零筆 |
| `prometheus/rules/aup.yml`、`tests/rules_aup_test.yml` | 收集端 VM | 可接受使用告警（Day 24），讀 onprem-logs 的 `firewall/aup-report.py` 每 10 分鐘寫的 `aup.prom`。緊急類別（Malicious Websites、Phishing、Spam URLs）一筆就 critical，單一工作站一小時被擋 20 次 warning，預期有紀錄的 FortiGate 6 小時零筆 info，報告過期 warning 並抑制其餘三條 |
| `eol/assets.tsv`、`textfile/eol-textfile.py`、`prometheus/rules/eol.yml`、`tests/rules_eol_test.yml`、`tests/test_eol_textfile.py` | 收集端 VM，cron 每天 | Day 25。資產生命週期。TSV 一列一個（資產、元件、里程碑），記日期、依據（vendor、estimate、licence、unknown）與備註。textfile 寫成 `asset_eol_timestamp_seconds`，沒有日期的列以 `asset_eol_unknown` 留在畫面上，`--refresh` 對 endoflife.date 比對（快取一天），`--fortigate` 以 REST 讀 FortiGate 的授權到期日。規則是 90 天 warning、30 天 critical、已過期 critical、未知與來源不一致 info、textfile 過期 warning；授權跟著合約一起到期，所以每台裝置只發一條並附項目數（已過期 critical、90 天內 warning）。儀表板多一列，每個資產與每項授權的剩餘天數 |
| `prometheus/rules/changes.yml`、`tests/rules_changes_test.yml` | 收集端 VM | 變更單的告警（Day 26），讀 [onprem-changes](https://github.com/ivanusto/onprem-changes) 的 `changes-textfile.py` 寫的 `changes.prom`。窗關了一小時單子還開著是 warning，進行中與一天內要開始的是 info，textfile 過期 warning 並抑制其餘。Day 28 多兩條 info，done 而且 high 的單子回退沒演練過，與演練超過 90 天 |
| `prometheus/rules/audit.yml`、`tests/rules_audit_test.yml` | 收集端 VM | 稽核軌跡對變更單（Day 27），讀 onprem-logs 的 `audit/audit-report.py` 每 10 分鐘寫的 `audit.prom`。FortiGate 設定變更落在所有變更窗之外是 warning，其他沒有單子的管理動作與沒有標記的已完成單子是 info，報告過期 warning 並抑制其餘 |
| `prometheus/rules/agent.yml`、`tests/rules_agent_test.yml` | 收集端 VM | 代理程式閘道（Day 29），讀 [onprem-agent-gate](https://github.com/ivanusto/onprem-agent-gate) 的 `gatectl textfile` 寫的 `agent-gate.prom`。L3 請求等人核准超過 2 分鐘 warning，緊急停止 info，稽核鏈斷掉 critical，一小時超過 5 次拒絕 info，textfile 過期 warning 並抑制其餘四條 |
| `textfile/pve-quorum-textfile.sh` | 收集端主機，cron 每分鐘 | 參數 `LABEL=root@節點1,root@節點2`，ssh 到第一台有回應的節點跑 `pvecm status`，輸出 expected、total、quorum 票數、Quorate 旗標、QDevice 票與各節點票。金鑰在節點上以 `from=` 與 `command="/usr/bin/pvecm status",restrict` 限定 |
| `alertmanager/`、`grafana/` | 收集端 VM | `alertmanager.base.yml` 是 render 的模板，含路由（critical 立即、warning 30 秒一批、info 每日彙整、soak 告警不等批次）與八條 inhibit，管線死掉時不會連帶對每個停止回報的數值告警；SMTP 與收件者由 render 依場域填入。`grafana/Dockerfile` 是 Grafana 12.2.10 加 VictoriaLogs 資料源 0.32.0（基底鎖 digest，外掛鎖 sha256），發佈為 `ghcr.io/ivanusto/30ops-grafana` 並附建置來源證明。儀表板 JSON 由 `build-dashboard.py` 產生（render 依場域門檻繪製），UI 改不了 |
| `tests/` | CI | 假的 sysfs、nvidia-smi、dmesg、zfs、zpool、getsysinfo，每份輸出都過 `promtool check metrics`；規則的 promtool 測試（`scripts/test-rules.sh` 對 render 產出的規則執行）；`compose-smoke.sh` 以範例場域的 render 產出啟動合併後的 stack |

## 為什麼硬體走 SNMP、ZFS 走 ssh

收集端持有的 ssh 金鑰是 NAS 上的一個 shell。SNMP v3 唯讀是窄得多的介面，QTS MIB 答得出來的都走它，ssh 縮到 `zfs list` 與 HBS 3 狀態這兩件 MIB 沒有的事。`snmp-build.py` 讀 QNAP 附的 MIB 產生模組，`snmp_exporter --dry-run` 是測試。

## 為什麼是 textfile

soak 計數要記住上一次的狀態，NAS 沒有套件管理器，演練紀錄是三個 repo 裡的檔案。textfile 是最簡單的契約，原子地寫一個檔，node_exporter 端出去，Prometheus 不需要知道差別。每個檔都帶 `*_last_run_timestamp`，timer 死掉會變成過期的指標，而不會變成看起來正常的凍結數值。

## 快速開始

```sh
# 收集端 VM，checkout 在 /opt/30ops，旁邊有場域的 site.yaml
bin/30ops validate --site site.yaml --strict
sudo bin/30ops render --site site.yaml --out /     # /etc/30ops、/etc/cron.d/30ops、單元檔等
# 在 `30ops install`（v0.5）之前：把 /etc/30ops/prometheus/pve.yml 與 snmp-auth.yml
# 裡的 @secret: 值換成 token 與密語，並建立 compose 掛載的秘密檔
# （擁有者是容器執行的 uid）
sudo install -d -m 0700 /etc/30ops/secrets
openssl rand -base64 24 | sudo install -m 0400 -o 472 /dev/stdin /etc/30ops/secrets/grafana-admin.pass
# SMTP 密碼：擁有者 65534（Alertmanager 以 nobody 執行），權限 0400
# 新場域自己建立 volume；從舊收集端搬過來的在 site.yaml 寫舊 volume 的名稱
for v in prometheus alertmanager grafana victorialogs; do docker volume create "30ops_$v-data"; done
docker compose --env-file /etc/30ops/compose.env -f collector/compose.yml up -d
sudo ./collector/install-node.sh --collector
# Grafana 只在建立資料庫那一次讀管理密碼。第一次啟動時檔案讀不到，密碼就是 admin，
# 改好擁有者之後要移除 grafana 容器與它的 volume 再啟動。

# PVE 票數：在一台節點的 /root/.ssh/authorized_keys 加一行（它就是叢集共用的
# /etc/pve/priv/authorized_keys）
#   from="收集端IP",command="/usr/bin/pvecm status",restrict ssh-ed25519 AAAA... metrics@collector
# 並在每台 PVE 節點執行下面這行，每分鐘的登入才不會每次起停整個 root 的
# user manager（每次約 75 行 journal，每天 10.8 萬行，Day 21 實測）：
#   loginctl enable-linger root
sudo -u metrics ./textfile/pve-quorum-textfile.sh lab=root@192.0.2.9,root@192.0.2.5 | promtool check metrics

# 第一次 SNMP 抓取，看實機有哪些 OID 回值
curl 'http://localhost:9116/snmp?module=qnap&auth=nas_v3&target=192.0.2.2'

# 每台 DGX Spark
sudo ./install-node.sh
sudo ufw allow proto tcp from 192.0.2.49 to any port 9100   # 只放收集端
curl -s localhost:9100/metrics | grep ^gb10_

# 然後
# Day 20 起 Prometheus 只聽 127.0.0.1，在收集端上跑；要從別台跑，先 ssh -L 9090:localhost:9090 到收集端
./verify.sh \
  --gb10 user@192.0.2.131 --gb10 user@192.0.2.141 \
  --nas primary=ops30@192.0.2.2 --nas secondary=ops30@192.0.2.22 \
  --pve root@192.0.2.9 > verify.md
```

## 測試

```sh
python3 -m unittest discover -s tests
sh tests/fake-nas.sh
sh tests/compose-smoke.sh                    # 需要 docker，佔用 3000、9090、9093、9428、514、515
shellcheck textfile/nas-textfile.sh textfile/pve-quorum-textfile.sh verify.sh install-node.sh tests/fake-nas.sh tests/compose-smoke.sh grafana/build.sh
sh ../scripts/test-rules.sh                  # 對 render 產出的規則跑 promtool check 與 test
amtool check-config alertmanager/alertmanager.base.yml
python3 grafana/build-dashboard.py --check
```

## 授權

Apache-2.0
