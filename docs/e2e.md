# 端到端測試（E2E）

`tests/e2e/run.sh` 把一台拋棄式 Ubuntu 24.04 主機裝成收集端，再用一個假 LAN 代替 NAS、PVE 節點、FortiGate 與告警收件端，從安裝一路驗到告警送達與日誌封存。GitHub Actions 的 `e2e.yml` 在每次推送 main 與每個 PR 執行它，`release.yml` 也會先跑它才發行。

## 驗什麼

| 階段 | 通過條件 |
|---|---|
| 取得 | 用 `scripts/dist.sh` 產生這個 commit 的 release tarball，解到 `/opt/30ops`，`bin/30ops --version` 等於 VERSION |
| 安裝 | `install collector --create-volumes` 完成；授權收集端金鑰給假 NAS 與假 PVE、釘 host key，收集端自己跑 node bundle（journal 角色）；第二次 install 為 0 個變更、0 個警告 |
| 抓取 | 每個 target 都是 up；`tests/e2e/expected-metrics.txt` 的每個 metric 名稱都查得到（每個來源至少一個）；render 出的告警規則全數載入 |
| 告警 | 假 NAS 的 pool 轉 DEGRADED 後，`NasPoolNotOnline` 在 Alertmanager 為 active，webhook 收件端收到 firing（route 到 ops-critical） |
| 日誌 | NAS 的 syslog（514）、FortiGate 的事件日誌（515，帶 `audit=fortigate`）、收集端自己的 journal（journal-upload）都進 VictoriaLogs；不在允許清單的來源被 DOCKER-USER 丟棄，並在 kernel log 留下 DROP 紀錄 |
| 封存 | 前一天（UTC，已結束的一天）由 `archive-day.sh` 寫到經 NFSv4 掛載的 WORM 代用目錄，MANIFEST.tsv 列出 syslog、audit、journald 三種來源，`verify-archive.sh --against-live` 通過並寫入 drills v1 紀錄 |
| 健檢 | `doctor --format json` 沒有 fail，warn 只能出現在 `tests/e2e/allowed-warn.txt`（目前是空的） |
| 資源 | 所有容器的記憶體合計低於 3 GiB（現場收集端是 2 vCPU、4 GB） |

證據放在 `$OUT`（預設 `/var/tmp/ops30e2e`）：每個階段的輸出、targets 與告警的 API 回應、compose 與各單元的日誌、textfile、doctor 的 json，以及 `summary.txt`。CI 失敗時會上傳成 artifact `e2e-evidence`。

## 假 LAN

```
 收集端（測試主機本身）                      network namespace ops30e2e
 ┌───────────────────────────────┐  veth   ┌─────────────────────────────────────────┐
 │ e2e0 192.0.2.49/24            │─────────│ e2e1                                    │
 │ docker：prometheus、           │         │ 192.0.2.2   nas-primary  sshd、snmpd     │
 │   alertmanager、grafana、      │         │ 192.0.2.9   pve1  sshd（pvecm）、API 8006 │
 │   victorialogs、exporters     │         │ 192.0.2.5   pve2  同上                   │
 │ node_exporter、cron、          │         │ 192.0.2.99  fgt-edge  API 10443          │
 │   journal-upload              │         │ 192.0.2.250 webhook 收件端 9999          │
 │ nfsd（WORM 代用，經 DNAT 成     │         │ 192.0.2.66  不在允許清單的來源            │
 │   192.0.2.2:2049）            │         └─────────────────────────────────────────┘
 └───────────────────────────────┘
```

- 位址都是 RFC 5737 的文件用網段，只存在測試主機內部，不會碰到真正的網路。
- 假節點送來的 syslog 從 veth 進入主機，和真的 LAN 一樣經過 PREROUTING 的 DNAT、FORWARD 與 DOCKER-USER，所以 `docker-user-allowlist.sh` 也一起測到。
- 容器連到 192.0.2.x 時經主機路由進 namespace，docker 的 MASQUERADE 讓來源成為 .49。

各假端點的作法（`tests/e2e/fakes/`）：

| 對象 | 作法 |
|---|---|
| NAS 的 ssh | namespace 內另起一個 sshd，`Match LocalAddress 192.0.2.2` 強制把 PATH 換成 `tests/fakes/qnap/bin` 的假 zpool、zfs、getcfg，再執行 qnap adapter 送來的 `sh -s`。`netns.sh degrade` 讓 pool 轉 DEGRADED |
| PVE 的 quorum | 同一個 sshd，`192.0.2.9` 與 `192.0.2.5` 強制回傳 fixture 的 `pvecm status` |
| PVE API | `httpfakes.py`，自簽 TLS，驗 API token，回應一個 quorate 的兩節點叢集、每節點一個 storage、沒有 guest，端點依 pve-exporter 3.5.5 實際呼叫的路徑 |
| FortiGate API | `httpfakes.py`，Bearer token，回應 fixture 的授權狀態 |
| SNMP | net-snmp 的 snmpd，SNMPv3（SHA、AES），QNAP 的 enterprise OID 由 `snmp/pass-persist.py` 供應，資料由 `snmp/build-data.py` 讀 `collector/prometheus/snmp.yml` 合成：表格兩列、狀態字串與列舉取健康值。不是真實 NAS 的 walk |
| WORM | 主機上的 nfs-kernel-server 匯出暫存目錄，主機 nat OUTPUT 把 `192.0.2.2:2049` 轉到本機，所以 render 出的掛載單元原封不動地掛載。掛載點是 `/srv/worm` 而不是範例場域的 `/mnt/worm`：GitHub runner 的 fstab 有一筆指向不存在磁碟的 `/mnt`，失敗的 `mnt.mount` 會讓 `/mnt` 底下的每個掛載都失敗 |
| 告警收件 | `httpfakes.py` 把每個 POST 寫進 `/run/ops30e2e/webhook.jsonl` |

E2E 場域是 `tests/e2e/site.yaml`：由範例場域縮減，廠商與位址相同，只留假 LAN 能代替的主機。

## 怎麼跑

只能在拋棄式主機上跑：它會建帳號、寫 `/etc/30ops` 與 cron、裝套件、建 NFS 匯出，沒有設 `OPS30_E2E_DISPOSABLE=1` 就拒絕執行。

- GitHub Actions：`e2e.yml`，也可以手動 workflow_dispatch。
- 拋棄式 VM（例如 PVE 上由 cloud image 模板連結複製的一台）：

  ```sh
  tests/vm/e2e.sh ops@<VM 位址> [REV]     # 證據取回 ./vm-e2e
  ```

  它在工作站產生 REV 的 tarball，傳到 VM 上以 sudo 執行 tarball 裡的 `run.sh`。每一輪用一台新的 VM。

- 主機上直接執行：

  ```sh
  sh scripts/dist.sh build
  sudo OPS30_E2E_DISPOSABLE=1 sh tests/e2e/run.sh build/30ops-*.tar.gz
  ```

映像先逐一拉取，每次 15 分鐘、最多三次：registry 的 CDN 曾以每秒約 400 kB 送 Grafana 映像 111 MB 的那一層，`install collector` 內的單次拉取（30 分鐘逾時）不會重試。

## 不涵蓋

- gb10 節點、agent gate、pcap、插件：不在 E2E 場域內，由各自的 smoke 與單元測試涵蓋。
- `install node` 經 ssh 的流程：E2E 只在收集端本機跑 bundle。
- WORM 的不可變性：代用目錄可寫一次，但沒有東西會鎖住檔案；鎖定後重跑的行為由 `logs/tests/smoke.sh` 以唯讀目錄模擬。
- 真實 QNAP 的 SNMP 回應：SNMP 資料是合成的，只證明 snmp_exporter 的 module、認證與規則接得起來。
- 真實 PVE、FortiGate 的 API 版本差異：假端點只回應 exporter 與 adapter 用到的欄位。
