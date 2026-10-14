# 安裝

`30ops install` 把 render 的結果裝到主機上。每一步都先檢查主機現況，只在有差異時才動手，所以第二次執行不會有任何變更。v0.5 的驗收就是在拋棄式 VM 上連裝兩次，比對結果相同，再讓 `30ops doctor` 通過。

## 收集端：`30ops install collector`

```sh
cd /opt/30ops                       # checkout 必須在 site.yaml 的 collector.root
sudo bin/30ops install collector --site site.yaml --dry-run
sudo bin/30ops install collector --site site.yaml [--create-volumes]
sudo bin/30ops doctor --site site.yaml
```

- `--dry-run` 只列出會做的事，什麼都不改。
- `--create-volumes` 用在新場域，會建立 docker volume。沒有這個選項時，volume 不存在就中止，避免 Prometheus 在一個空的 volume 上啟動，看起來像歷史資料不見了。從舊收集端搬過來的，在 `collector.volumes` 寫舊 volume 的名稱。
- 結束碼：0 表示完成（或沒有要做的事）；1 表示某一步失敗；2 表示前置檢查拒絕執行，此時什麼都沒改。

### 前置檢查（不通過就不動手）

- 必須以 root 執行，且有 docker compose v2。
- checkout 的實際路徑等於 `collector.root`，因為 cron 是從這裡執行腳本。
- 沒有 `/etc/cron.d/onprem-*`，也沒有執行中的 `onprem-metrics`、`onprem-logs` compose 專案，否則 cron 會跑兩次、埠號會衝突。從舊收集端切換時，先停掉舊的 stack（`docker compose down`，不加 `-v`），再把舊 cron 檔移出 `/etc/cron.d`。
- 每個 volume 都存在（或加了 `--create-volumes`），而且沒有被 `30ops` 以外的 compose 專案使用。
- `credentials` 的每個檔案都存在。pcap 拉取金鑰例外，缺了會自動產生。
- 同一個憑證只能有一個讀取者。不同讀取者需要不同的擁有者，請各給一個 `credentials` 項目。

### 步驟

| 步驟 | 做什麼 |
|---|---|
| 帳號 | `node-exporter` 群組與帳號、`metrics`（`collector.user`，家目錄 `/var/lib/metrics`）；gate 有 targets 時另建 `agent-gate`。兩者都加入 `node-exporter` 群組，因為 textfile 目錄是 `node-exporter:node-exporter 2775` |
| node_exporter | 版本、單元檔或啟用狀態不對時，執行 `collector/install-node.sh --collector` |
| 目錄 | 每個 cron job 會寫的目錄，擁有者是執行它的帳號：log、reports、eol 快取、演練紀錄、變更狀態、封存暫存區、pcap 暫存區 |
| ssh 金鑰 | `metrics` 自己的 `id_ed25519` 與 pcap 拉取金鑰，只在不存在時產生 |
| 變更單 clone | `changes.clone` 不存在且有 `changes.remote` 時，以 `metrics` 帳號 clone |
| 秘密檔 | 依讀取者設定擁有者與權限（下表）；Grafana 管理密碼只在不存在時產生 |
| 檔案 | render 產出的檔案（`nodes/` 與 cron 除外），連同擁有者與權限；`@secret:` 以憑證檔的值代入 |
| 單元 | 單元檔有變更時 `daemon-reload`，啟用 allowlist service 與 WORM mount |
| volume、映像 | 依 `--create-volumes` 建立 volume；缺少的映像依 digest 拉取 |
| stack | `docker compose up -d`，接著處理 compose 沒有重建、但設定已變更的容器（下表） |
| 健康檢查 | Prometheus、Alertmanager、Grafana、VictoriaLogs 都要有回應，最多等 180 秒 |
| cron | 最後才部署 `/etc/cron.d/30ops`，避免 stack 還沒好就有 job 執行 |
| 首次執行 | 每個還沒有 textfile 的 job，以它的帳號跑一次，doctor 才不會在剛裝好時就判過期 |

秘密檔的擁有者：

| 憑證 | 讀取者 | 擁有者與權限 |
|---|---|---|
| 防火牆的 `api.token` | eol-textfile（cron，`metrics`） | `metrics` 0400 |
| `logs.pcap.key` | pcap-pull（ssh 私鑰） | `metrics` 0600 |
| `pve.exporter.token`、SNMP 密碼 | install（代入 `pve.yml`、`snmp-auth.yml`） | root 0400 |
| `alerting.smtp.password` | Alertmanager（compose secret，以 nobody 執行） | 65534 0400 |
| `/etc/30ops/secrets/grafana-admin.pass` | Grafana（compose secret） | 472 0400 |

`/etc/30ops/secrets` 本身是 `root:metrics 0750`，cron 的 job 才進得去讀 token。

### 設定變更後的處理

容器以單檔 bind mount 讀設定時，install 以 rename 原子替換檔案，容器仍會讀到舊的 inode，`/-/reload` 也只會重讀舊內容。所以這類檔案變更時要重建容器：

| 變更 | 處理 |
|---|---|
| `prometheus/` 下的規則、targets、`prometheus.yml`（目錄掛載） | `POST /-/reload` |
| `pve.yml`、`snmp-auth.yml`、`alertmanager.yml`、SMTP 秘密 | 該服務 `up -d --force-recreate` |
| Grafana 的 datasources、儀表板、管理密碼 | restart grafana |
| `compose.env` | `up -d` 本身會重建受影響的服務 |

被 `up -d` 剛建立或重建的容器不再處理。沒有變更時什麼都不做，容器 ID 維持不變。

被替換或移除的檔案（不再 render 的檔案，依上一次的 `manifest.json` 判斷）會備份到 `/etc/30ops/.backup/<UTC 時間>/`。只有內容真的改變時才備份，所以第二次執行不會產生新的備份目錄。

### install 不做的事

install 只動收集端本身。下列設備要另外設定，install 結束時會列出還沒完成的項目：

- NAS：授權 `metrics` 的公鑰，`ssh-keyscan` 取得 host key 後與 NAS 上的指紋比對，再寫入 `known_hosts`。install 不會自動信任 host key。
- PVE：`30ops install node <host>` 寫入只能執行 `pvecm status` 的受限金鑰。
- Grafana：如果 volume 已經存在但管理密碼是新產生的，Grafana 仍沿用第一次啟動時的密碼，install 會印出重設指令。

## 節點：`30ops install node`

見下一節（v0.5 第 7 步）。
