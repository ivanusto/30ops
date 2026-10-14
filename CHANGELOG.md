# Changelog

## v0.5.0（2026-10-14）

- adapter：`adapters/<kind>/<vendor>/` 的 `adapter.yaml` 宣告能力，`adapter.py` 實作，共用的 schema、輸出、連線方式（ssh、本機、HTTP、錄製重放）與載入在 `lib/python/ops30/adapters/`。v0.5 有 qnap、fortigate、pve、generic-snmp、linux 五個；尚未實作的能力標 `planned` 與版本（pve 的 backup_jobs，fortigate 的 facts、config_backup、managed_aps，generic-snmp 的交換器抓取在 v0.7）。`30ops validate` 依角色找 adapter，找不到就是錯誤。契約測試（`tests/unit/adapters/test_contract.py`）對 `tests/fixtures/adapters/` 的錄製 case 重放，輸出要與預期完全相同，family 與 label 要等於 schema。見 `docs/adapters.md`。
- qnap 的 health 與 pve 的 quorum 改為 Python（`30ops textfile nas|pve-quorum`），`nas-textfile.sh` 與 `pve-quorum-textfile.sh` 保留為 shim，cron 指令不變。輸出由新的 golden（`nas.prom`、`pve-quorum.prom`，先以舊的 shell 寫入器錄下）鎖定。修正：NAS 的 ssh 在中途斷線時，舊版會輸出半份資料再加一行 `nas_up 0`，node_exporter 因重複的序列拒收整個檔案；新版以遠端的 `@@end` 判斷完整，不完整就只輸出 `nas_up 0`。多叢集時 pve-quorum 的樣本改為依 family 分組。每個 textfile 有 flock，前一輪還沒結束時不疊加。
- FortiGate 的授權查詢移進 fortigate adapter，`eol-textfile.py` 改呼叫，`eol.prom` 不變。`pve.yml` 由 pve adapter 產生。
- 狀態字串正規化：qnap adapter 的 `status:` 宣告哪些 QuTS 字串算健康，render 產出 `rules/status.yml` 的 recording rule `nas:<metric>:ok`，NasDiskNotGood、NasPoolStatusNotReady、NasUpsNotOnline、NasTelnetEnabled 改為比對它，名稱、for、labels 與 annotation 不變；測試證明對照等於 v0.3 的 matcher。
- `ops30_adapter_info`：render 產出靜態的 `30ops-adapters.prom`，每台主機每個 kind 一筆，附既有序列用來指主機的 label。既有指標不加 `vendor` label，TSDB 序列不斷。
- `30ops install collector [--dry-run] [--create-volumes]`：前置檢查（root、compose v2、checkout 位置、舊 cron 與舊 compose 專案、volume 存在且沒被其他專案使用、憑證檔、同一憑證只有一個讀取者），帳號（`metrics` 加入 `node-exporter` 群組，修正 textfile 目錄寫不進去的缺口），各 job 的目錄，ssh 金鑰，變更單 clone（新的選填欄位 `changes.remote`），秘密檔依讀取者設定擁有者與權限（`secrets/` 改為 `root:metrics 0750`，cron 才讀得到 token），Grafana 管理密碼，依 manifest 部署（`@secret:` 代入，換掉或移除的檔案備份到 `/etc/30ops/.backup/`），單元，volume，依 digest 拉映像，`compose up -d` 與單檔掛載的重建處理，健康檢查，最後部署 cron 並讓每個 textfile job 先跑一次。見 `docs/install.md`。
- `30ops install node <host> [--bundle] [--ssh]`：確定性 bundle（條目排序、時間與 uid 為 0），節點端 `collector/node/node-install.sh` 依角色安裝 node_exporter、journal-upload、pcap 與 PVE 的 quorum 受限金鑰；經 ssh 時共用一條 ControlMaster 連線，並把節點的 host key 釘進 `metrics` 的 known_hosts。設備改印 adapter 的設定步驟。`install-node.sh` 加 `--plain`，版本相同時不下載；`install-journal-upload.sh` 只在設定改變時重啟；`install-pcap.sh` 加 `--profiles` 與 `--sudoers`，改用 render 產出。
- `30ops doctor [--format json] [--skip]`：映像 digest、targets、textfile 新鮮度（門檻與 stale 規則相同）與 `*_up 0`、cron、WORM（不寫測試檔）、時區與 NTP、磁碟、秘密檔、Grafana 預設密碼、帳號、render 差異。
- `render --diff` 略過 `nodes/`，也比對權限；以 root 執行或加 `--owners` 時比對擁有者。
- `tests/vm/`：在拋棄式 Ubuntu 24.04 VM 上的驗收（連裝兩次比對狀態、doctor、bundle 兩次）。v0.5.0 在 PVE 上的 VM 通過：第二次 0 個變更、狀態相同、doctor 15 項全過。
- yamlio 接受 YAML 的 `<<` 合併鍵（compose 檔用到）。

## v0.4.0（2026-10-14）

- 單一 compose：`collector/compose.yml` 取代 `collector/docker-compose.yml` 與 `logs/docker-compose.yml`，VictoriaLogs 併入同一個專案，不再需要 external network。掛載改為 render 產出的 `/etc/30ops`；場域設定（專案名稱、profiles、volume 名稱、保留期、syslog 時區、Grafana 埠、秘密檔）由新的 `etc/30ops/compose.env` 提供。volume 一律 external，名稱錯誤時停在啟動前。site.yaml 新增 `collector.volumes`、`collector.retention`、`collector.grafana_port`。
- 規則單一來源：69 條告警只留 `collector/prometheus/rules/` 一份，刪除 changes、gate、logs 的五份複本與兩份測試複本。門檻改為佔位，鍵與預設值在 `collector/prometheus/thresholds.yml`（25 個），render 依 `alerting.thresholds` 代入並寫到 `etc/30ops/prometheus/rules/`。validate 檢查鍵、正值與警告線和危險線的順序。預設門檻下，每條告警的 expr、for、labels 與 v0.3.0 相同（`tests/unit/test_rules_render.py`）。告警名稱不變。
- `docs/rules.md`：69 條告警的意義、門檻鍵與處置方式，以及門檻表。規則註解與 annotation 不再引用系列天數；annotation 的門檻數字跟著場域值。
- promtool 測試改為對 render 產出執行（`scripts/test-rules.sh`），並補上 NasDiskHot、NasSnapshotStale、CloudDrillStale 與 FwSourceBurst 其餘三道牆的測試。
- Grafana 映像：Dockerfile 移到 `collector/grafana/`，外掛以 `ADD --checksum` 鎖 sha256，`fetch-plugin.sh` 刪除。新的 `grafana-image` workflow 建置 amd64 與 arm64，發佈 `ghcr.io/ivanusto/30ops-grafana:12.2.10-vlogs0.32.0` 並附 build provenance，compose 以 digest 引用。修正漂移：repo 的 compose 原本用上游 grafana 映像，沒有 VictoriaLogs 外掛。
- 儀表板：`build-dashboard.py` 的門檻改讀 `thresholds.yml`，render 依場域門檻產生 `etc/30ops/grafana/dashboards/onprem-overview.json`；說明文字不再引用系列天數。
- Alertmanager 的 `smtp_auth_password_file` 改為 compose secret 的 `/run/secrets/smtp`。`alertmanager.yml.example` 改名 `alertmanager.base.yml`（render 的模板）。
- victorialogs scrape job 併入 `collector/prometheus/prometheus.yml`，刪除 `logs/collector/prometheus-scrape.yml`。
- `render --compare-legacy` 與 `import-legacy` 涵蓋 compose：服務、實際 volume 名稱、保留期、syslog 時區、Grafana 埠。
- 刪除由 render 取代的手寫場域檔：7 個 cron 片段、允許清單與其 service、WORM mount、targets 與 exporter 設定的 `.example`。`tests/fixtures/legacy-root/` 保留 v0.3 時的副本並補上兩個 compose 檔。
- `scripts/check-drift.py` 新增單一來源檢查：規則只在 `collector/prometheus/rules/`、佔位與 thresholds.yml 一致、規則不引用系列天數、儀表板的 datasource uid 都有 provision、規則與儀表板的 job 都是 scrape job、不得出現手抄指示、compose 映像帶 digest。
- CI：collector job 對 render 產出跑 promtool、`docker compose config`（不再 `|| true`）與 compose smoke（啟動合併後的 stack，檢查 69 條規則、外掛、datasource、儀表板與 VictoriaLogs 抓取）；changes 與 gate job 不再測規則複本。

## v0.3.0（2026-10-14）

- 新增 `site.yaml`（version 1）與 `30ops validate`：schema、參照、重複的名稱與位址、zoneinfo、明文秘密一律拒絕（只能引用 `credentials` 的檔案），assets.tsv 與 cost.yaml 以原本的規則檢查。`--strict` 把警告當錯誤，`--secrets` 在收集端檢查秘密檔的權限。欄位見 `docs/site-yaml.md`，範例在 `examples/sample-site/site.yaml`。
- 新增 `30ops render`：由 site.yaml 產生 Prometheus targets、prometheus.yml（併入 victorialogs job）、pve.yml 與 snmp-auth.yml（秘密為佔位）、alertmanager.yml、Grafana datasources、單一 `/etc/cron.d/30ops`、日誌允許清單與 service、WORM mount、gate 的 config.json 與 tools.json、assets.tsv、各節點的安裝參數與擷取設定檔，另附 `manifest.json`。輸出具確定性，以 `tests/golden/render/sample-site/` 驗證。`--diff` 對已安裝的檔案比對。說明見 `docs/render.md`。
- 新增 `30ops import-legacy` 與 `scripts/fetch-legacy.sh`：從現行收集端唯讀抓取設定快照（秘密在主機端遮蔽），草擬 site.yaml。`render --compare-legacy` 對舊佈局做語意比對：targets、cron、允許清單、mount、收件者、gate 設定。
- 範例場域的 render 與 repo 原有的手寫設定（targets、五個 cron 片段、允許清單、mount、gate 設定）比對為 0 差異；實際場域的 site.yaml 對收集端 .49 的快照比對也是 0 差異。compose 與告警規則不在 v0.3 範圍，v0.4 處理。
- `scripts/check-drift.py` 新增規則：repo 內不得新增手寫的場域設定檔，既有的列在 `LEGACY_SITE`，v0.4 移除。
- `snmp-auth.yml.example` 的範例帳號改為 `ops30`，與 cron 範例一致。
- CI 的 `lib` 與 `collector` job 安裝 `python3-yaml`，並對範例場域的 render 產出跑 promtool、amtool、snmp_exporter dry-run、`systemd-analyze verify` 與 `visudo -c`。

## v0.2.0（2026-10-14）

- 新增共用函式庫 `lib/python/ops30`（frontmatter、rfc3339、textfile、jsonl、drills）與 `lib/sh/ops30.sh`，說明見 `docs/lib.md`。
- 刪除兩份相同的 `frontmatter.py`。changes、gate、collector 與 logs 共 7 支 textfile 寫入器改用 ops30：label 一律跳脫，暫存檔寫入加 fsync，失敗時清掉暫存檔。metric 名稱、label 與數值不變，以 `tests/golden/textfile/` 驗證。
- drills.jsonl v1（`docs/drills-jsonl.md`）：6 個寫入端改用 `30ops drill record`，寫入前驗證欄位並以 flock 附加。讀取端同時讀 v1 與 5 種舊格式。`30ops drill migrate` 可產出 v1 副本，舊檔不改。
- gate 稽核鏈的讀取與寫入包在同一個 flock 內，兩個呼叫端不會再拿到同一個 seq。
- 修正：
  - `offload-drill.sh` 的 NBD 預設路徑在 monorepo 失效，RPO 一直是「-」。
  - `changes/tests/test_drill.sh` 第 4 步一直被跳過。
  - `drills-textfile.py` 遇到非物件的 JSON 行會當掉。
  - inventory 測試的 import 路徑錯誤。
  - `render.py` 在 `drills/drills.md` 不存在時仍輸出連結。
- 新增 `scripts/check-drift.py`，確認 lib 已有的寫法不會在別處再寫一份，並加入 CI。
- 部署方式改變：收集端腳本需要完整的 30ops checkout。gate 的安裝步驟已更新。

## v0.1.0（2026-10-14）

- 以保留歷史的方式併入 12 個 repo，對照見 `docs/provenance.md`。
- 授權統一為 Apache-2.0（gb10-ops 與索引 repo 的部分原為 MIT，見 `NOTICE`）。
- 單一 CI：十個模組的檢查併成 `.github/workflows/check.yml`，action 釘 commit SHA，下載的工具驗 sha256。
- `scripts/hygiene.py`：破折號、私有 IP、家目錄路徑、`.pii-patterns`。
- `scripts/check-ci-pins.sh`：action、下載、映像都要鎖定。
- 範例位址改用文件保留段，場域樣本移到 `examples/sample-site/`，真實變更單不在本 repo。
- `change_rollback_drills_total` 的 TYPE 由 gauge 改為 counter，名稱不變。原 repo 的 CI 在 unittest 之後才裝 promtool，`promtool check metrics` 從未實際執行。
