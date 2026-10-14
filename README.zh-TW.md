# 30ops

[English](README.md)

給中小企業自建的地端維運平台。一台收集端 Linux VM 跑指標、日誌、告警、變更單、演練紀錄與代理程式閘道，節點用小型安裝程式加入。第一級支援 QNAP NAS、Proxmox VE、FortiGate 與 Linux 節點，其他廠商透過 adapter 接入。

30ops 由「地端維運三十天」系列的 11 個 repo 與索引 repo 的清單、成本模型合併而成，保留完整歷史，來源見 [docs/provenance.md](docs/provenance.md)。

## 狀態

**v0.6.0**：端到端測試把每個 commit 的 release tarball 裝成拋棄式主機上的收集端，再以 network namespace 裡的假 LAN 驗證（經 ssh 與 SNMPv3 的 NAS、兩台 PVE 節點、FortiGate API、代替 WORM 資料夾的 NFS 分享、告警收件端）：每個 target up、預期的 metric 名稱都在、pool 轉 degraded 後告警經 Alertmanager 送到 webhook、syslog、FortiGate 事件日誌與 journald 進 VictoriaLogs 而不在允許清單的來源被丟棄、已結束的一天封存並通過驗證、doctor 無誤、容器合計低於 3 GiB（[docs/e2e.md](docs/e2e.md)）。推送 tag `vX.Y.Z`（或預發的 `-rc.N`）會先跑檢查與端到端測試，再發行可重現的原始碼 tarball、`images.txt` 與 `SHA256SUMS`，每個檔案都有 build provenance attestation（[docs/release.md](docs/release.md)）。v0.5 起：`30ops install collector` 把 render 的結果裝到收集端：帳號、目錄、每個秘密檔的擁有者與權限、render 產出的檔案、單元、docker volume 與映像、stack，最後才是 cron。只改有差異的地方，所以第二次執行不會有任何變更（[docs/install.md](docs/install.md)）。`30ops install node` 為每個節點產生確定性的 bundle，經 ssh 以 sudo 執行；NAS、防火牆與交換器改印出該 adapter 的設定步驟。`30ops doctor` 依 `site.yaml` 檢查已安裝的收集端：映像 digest、targets、textfile 新鮮度、WORM 掛載、時鐘與時區、磁碟、秘密檔、Grafana 密碼與 render 差異。廠商相關的程式改放在 adapter（`adapters/<kind>/<vendor>/`，[docs/adapters.md](docs/adapters.md)），以錄製的 case 跑契約測試；QuTS 的狀態字串由 qnap adapter 的狀態對照轉成 recording rule，`ops30_adapter_info` 標出每台主機的廠商，既有序列的 label 一個都不改。驗收：在拋棄式 Ubuntu 24.04 VM 上連裝兩次，狀態相同，doctor 全過。v0.4 起：單一 compose 專案、映像全部以 digest 釘住，69 條告警規則只有一份並套用場域門檻（[docs/rules.md](docs/rules.md)）。v0.3 起：`site.yaml`、`30ops render`、`import-legacy` 與 `render --compare-legacy`（[docs/site-yaml.md](docs/site-yaml.md)、[docs/render.md](docs/render.md)）。

| 版本 | 內容 |
|---|---|
| v0.1 | 保留歷史匯入、單一 CI、發布衛生檢查 |
| v0.2 | 共用函式庫 `ops30`、去除重複、`drills.jsonl` v1 格式 |
| v0.3 | `site.yaml`、`30ops validate`、`30ops render`、`30ops import-legacy` |
| v0.4 | 單一 compose、規則單一來源、Grafana 映像 |
| v0.5 | adapter、`30ops install`、`30ops doctor` |
| v0.6 | 端對端測試、發行管線（SHA256SUMS 與 provenance attestation） |
| v0.7 | `30ops readiness`、收集端 deadman、交換器 SNMP、UPS 檢查 |
| v0.8 | 現場切換 |
| v1.0 | 文件、封存原 repo |

## 目錄

| 路徑 | 內容 | 來源 |
|---|---|---|
| `collector/` | Prometheus、Alertmanager、Grafana、snmp 與 pve exporter、textfile 腳本、告警規則、儀表板 | onprem-metrics |
| `logs/` | VictoriaLogs、journald 與 syslog 收集、WORM 封存、防火牆、AUP、稽核報告、封包擷取 | onprem-logs |
| `changes/` | Markdown 變更單、格式檢查、`change-mark.sh`、回退演練 | onprem-changes |
| `gate/` | 代理程式閘道（MCP），沒有變更單就沒有工具，決定寫進雜湊鏈 | onprem-agent-gate |
| `drills/` | PVE、NAS、雲端三種還原演練 | 三個 drill repo |
| `checks/` | PVE QDevice 檢查、可維運檢查清單 | pve-qdevice-on-qnap、索引 repo |
| `inventory/` | 一年成本模型（電費、攤提、雲端對照） | 索引 repo |
| `plugins/` | 可選的節點模組：GB10 主機防護、節點基線、NFS 模型庫 | gb10-ops、spark-baseline、nfs-model-library |
| `adapters/` | 廠商 adapter（`<kind>/<vendor>/adapter.yaml` 與 `adapter.py`）：qnap、fortigate、pve、generic-snmp、linux，見 [docs/adapters.md](docs/adapters.md) | |
| `examples/sample-site/` | 範例場域的 `site.yaml`、資產清單與成本表 | |
| `bin/` | `30ops` 指令：`validate`、`render`、`import-legacy`、`install collector`、`install node`、`doctor`、`textfile`、`drill record`、`drill migrate` | |
| `lib/` | `python/ops30` 與 `sh/ops30.sh`，收集端與演練腳本共用，見 [docs/lib.md](docs/lib.md) | |
| `tests/` | `unit/` 測 lib，`golden/` 是不得改變的 textfile 輸出與範例場域的 render 產出，`fixtures/legacy-root/` 是 30ops 之前的佈局，`fixtures/adapters/` 是 adapter 的錄製 case，`sh/`，`e2e/` 是端到端測試與它的假 LAN，`fakes/` 是各測試共用的替身，`vm/` 是在 VM 上的安裝驗收與端到端測試 | |
| `scripts/` | `hygiene.py`、`check-drift.py`、`check-ci-pins.sh`、`fetch-legacy.sh`、`dist.sh` 與 `release-check.sh`（發行檔，[docs/release.md](docs/release.md)） | |

## 檢查

CI 的每個模組一個 job，見 `.github/workflows/check.yml`。本機可以先跑：

```sh
python3 scripts/hygiene.py          # 破折號、私有 IP、家目錄路徑、.pii-patterns
python3 scripts/check-drift.py      # 不得寫兩份：lib 函式、規則、門檻、場域檔
python3 -m unittest discover -s tests/unit && python3 -m unittest tests/test_golden.py tests/test_render.py
sh tests/sh/test_ops30_sh.sh && sh tests/sh/test_fetch_legacy.sh && sh tests/sh/test_dist.sh
bin/30ops validate --site examples/sample-site/site.yaml && bin/30ops render --site examples/sample-site/site.yaml --compare-legacy tests/fixtures/legacy-root
sh scripts/check-ci-pins.sh         # action 釘 SHA、下載驗 sha256、映像帶 digest
sh scripts/test-rules.sh             # 對 render 產出的規則跑 promtool check 與 test
(cd collector && python3 -m unittest discover -s tests && sh tests/fake-nas.sh && sh tests/compose-smoke.sh)
(cd changes && python3 -m unittest discover -s tests && python3 scripts/check.py --assets ../examples/sample-site/assets.tsv)
(cd gate && python3 -W error -m unittest discover -s tests)
(cd inventory && python3 -m unittest discover -s tests && python3 cost.py --check)
```

端到端測試會永久改變它所在的主機，只在拋棄式主機上跑：`e2e` workflow，或 `tests/vm/e2e.sh USER@VM`（[docs/e2e.md](docs/e2e.md)）。

`.pii-patterns` 不進版控，一行一個 regex，放只屬於自己場域、不該出現在公開 repo 的字串。

## 授權

Apache-2.0，見 [LICENSE](LICENSE) 與 [NOTICE](NOTICE)。
