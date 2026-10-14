# 安裝

`30ops install` 把 render 的結果裝到主機上。每一步都先檢查主機現況，只在有差異時才動手，所以第二次執行不會有任何變更。v0.5 的驗收就是在拋棄式 VM 上連裝兩次，比對結果相同，再讓 `30ops doctor` 通過。

## 取得與驗證

從 GitHub Release 下載原始碼 tarball，核對 sha256 與 build provenance attestation，再解到 `collector.root`（預設 `/opt/30ops`）：

```sh
gh release download vX.Y.Z --repo ivanusto/30ops
sha256sum -c SHA256SUMS
gh attestation verify 30ops-X.Y.Z.tar.gz --repo ivanusto/30ops
sudo mkdir -p /opt/30ops
sudo tar xzf 30ops-X.Y.Z.tar.gz -C /opt/30ops --strip-components=1
/opt/30ops/bin/30ops --version
```

`images.txt` 列出 compose 釘住的映像與 digest，`install collector` 依這些 digest 拉取。發行流程與驗證方式見 [release.md](release.md)。git clone 也可以，只要 checkout 的路徑等於 `collector.root`。

Release 不附節點 bundle：bundle 依場域與主機產生，在收集端裝好之後以 `30ops install node <host> --bundle` 建立（下文）。

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

```sh
bin/30ops install node spark01 --site site.yaml --ssh ops@192.0.2.131   # 經 ssh，遠端以 sudo 執行
bin/30ops install node pve1 --site site.yaml                             # hosts[].ssh 是 root 時不用 sudo
bin/30ops install node spark01 --site site.yaml --bundle /tmp/           # 只產生 bundle
bin/30ops install node nas-primary --site site.yaml                      # 設備：列出要在設備上做的設定
```

先裝收集端：bundle 要帶收集端的公鑰（pcap 拉取金鑰、quorum 用的 `metrics` 金鑰）。

### bundle

`30ops-node-<主機>.tar.gz` 解開是 `30ops-node-<主機>/`，內容依主機的角色決定：

| 內容 | 何時 |
|---|---|
| `node-install.sh`、`install.env` | 一律 |
| `collector/install-node.sh` 與 node_exporter 單元；有 gb10-ops 插件時加 gb10-textfile | 角色 node |
| `logs/node/install-journal-upload.sh` | 角色 journal |
| `logs/pcap/` 的安裝程式、render 產出的 `etc/pcap/*.env` 與 `etc/sudoers.d/pcap`、`keys/pcap-pull.pub` | 角色 pcap |
| `keys/quorum.pub` | 角色 hypervisor 且有 `pve.cluster` |

bundle 是確定性的：條目排序，mtime、uid、gid 都是 0，gzip 檔頭的時間也是 0。同一份 site.yaml 產生相同的位元組，sha256 就代表裝了什麼。

### 節點上做的事（`node-install.sh`，以 root 執行）

| 角色 | 做什麼 |
|---|---|
| node | node_exporter（版本相同時不下載，單元檔沒變時不重啟）；ufw 啟用時允許 `SCRAPE_FROM` 連 9100 |
| journal | systemd-journal-upload 送到收集端，從現在開始送；設定沒變時不重啟 journald 與上傳程式 |
| pcap | 擷取單元、render 產出的設定檔與 sudoers，收集端的拉取金鑰限定為 `rrsync -ro` |
| hypervisor | 收集端的金鑰限定只能從收集端執行 `pvecm status`，`loginctl enable-linger root`。PVE 的 `/root/.ssh/authorized_keys` 是指向 `/etc/pve/priv` 的 symlink（叢集共用），所以直接附加到實際檔案，不用 rename 取代，否則 symlink 會變成本機檔案 |

每一步都可以重複執行，第二次執行不會有任何變更。

### 經 ssh

上傳與執行走同一條 ControlMaster 連線：先以 `cat > /tmp/...` 傳 bundle，再開一個互動 session 執行 `sudo sh node-install.sh`，sudo 要密碼時可以直接輸入。有 pcap 或 hypervisor 角色時，順便從這條已驗證的連線讀節點的 host key，寫進收集端 `metrics` 的 `known_hosts`，cron 的拉取與 quorum 檢查才不會在第一次連線時盲目信任。不是以 root 執行時，改為印出要執行的指令。

### 設備

NAS、防火牆、交換器不裝任何東西，`install node` 改印出該 adapter 的設定步驟（SNMP v3 唯讀帳號、ssh 帳號與金鑰、QuLog 記錄傳送、FortiGate 的唯讀 API 帳號與 syslogd2、syslogd3）。改設備設定之前先備份並開變更單。

## 檢查：`30ops doctor`

```sh
sudo bin/30ops doctor --site site.yaml [--format json] [--skip CHECK]
```

只讀不寫。每一項回報 ok、warn 或 fail，有任何 fail 就 exit 1。

| 檢查 | fail 的條件 |
|---|---|
| images | 有服務沒在執行，或執行中的映像 digest 不是 compose.yml 釘的那個 |
| targets | Prometheus 有 target 不是 up |
| textfile | cron job 寫的 textfile 不存在，或比它的 stale 告警門檻還舊（門檻與規則相同，見 `render/cron.py` 的 `TEXTFILES`）；檔案裡有 `*_up 0` 時為 warn；node_exporter 解析失敗 |
| cron | cron 沒有在執行 |
| worm | WORM 分享沒掛上、不是 nfs4、唯讀，或 `metrics` 不能寫入。doctor 不寫測試檔，因為 WORM 上的檔案 10 分鐘後就鎖定、刪不掉 |
| clock | 時區不是 `site.timezone`（cron 以本地時間排程，時區錯了，封存會在 UTC 那一天還沒結束時就執行）；NTP 未同步為 warn |
| disk | `/`、docker 根目錄、textfile 目錄有一個超過 90 %（超過 80 % 為 warn） |
| secrets | 憑證檔不存在，或擁有者與權限和上表不符 |
| grafana | 管理密碼仍是 `admin`。doctor 先用秘密檔的密碼登入，失敗才試一次 `admin`，避免觸發 Grafana 的登入鎖定 |
| accounts | `metrics` 不在 `node-exporter` 群組 |
| render | 已安裝的檔案與 render 結果不同（內容、權限或擁有者） |
