# 30ops

[English](README.md)

給中小企業自建的地端維運平台。一台收集端 Linux VM 跑指標、日誌、告警、變更單、演練紀錄與代理程式閘道，節點用小型安裝程式加入。第一級支援 QNAP NAS、Proxmox VE、FortiGate 與 Linux 節點，其他廠商透過 adapter 接入。

30ops 由「地端維運三十天」系列的 11 個 repo 與索引 repo 的清單、成本模型合併而成，保留完整歷史，來源見 [docs/provenance.md](docs/provenance.md)。

## 狀態

**v0.3.0**：以一份 `site.yaml` 描述場域，`30ops render` 由它產生所有場域相關的設定檔：Prometheus targets 與 exporter 設定、Alertmanager、Grafana datasources、單一 cron 檔、日誌允許清單、WORM 掛載、gate 設定與節點參數（[docs/site-yaml.md](docs/site-yaml.md)、[docs/render.md](docs/render.md)）。`30ops import-legacy` 可從現有收集端草擬 `site.yaml`，`render --compare-legacy` 證明產出與該收集端作用相同。產出尚無安裝程式：compose、告警規則與 `30ops install` 在 v0.4、v0.5 完成。

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
| `examples/sample-site/` | 範例場域的 `site.yaml`、資產清單與成本表 | |
| `bin/` | `30ops` 指令：`validate`、`render`、`import-legacy`、`drill record`、`drill migrate` | |
| `lib/` | `python/ops30` 與 `sh/ops30.sh`，收集端與演練腳本共用，見 [docs/lib.md](docs/lib.md) | |
| `tests/` | `unit/` 測 lib，`golden/` 是不得改變的 textfile 輸出與範例場域的 render 產出，`fixtures/legacy-root/` 是 30ops 之前的佈局，`sh/` | |
| `scripts/` | `hygiene.py`、`check-drift.py`、`check-ci-pins.sh`、`fetch-legacy.sh` | |

## 檢查

CI 的每個模組一個 job，見 `.github/workflows/check.yml`。本機可以先跑：

```sh
python3 scripts/hygiene.py          # 破折號、私有 IP、家目錄路徑、.pii-patterns
python3 scripts/check-drift.py      # lib/ 已有的寫法不得在別處再寫一份
python3 -m unittest discover -s tests/unit && python3 -m unittest tests/test_golden.py tests/test_render.py
sh tests/sh/test_ops30_sh.sh && sh tests/sh/test_fetch_legacy.sh
bin/30ops validate --site examples/sample-site/site.yaml && bin/30ops render --site examples/sample-site/site.yaml --compare-legacy tests/fixtures/legacy-root
sh scripts/check-ci-pins.sh         # action 釘 SHA、下載驗 sha256、映像帶 digest
(cd collector && python3 -m unittest discover -s tests && sh tests/fake-nas.sh)
(cd changes && python3 -m unittest discover -s tests && python3 scripts/check.py --assets ../examples/sample-site/assets.tsv)
(cd gate && python3 -W error -m unittest discover -s tests)
(cd inventory && python3 -m unittest discover -s tests && python3 cost.py --check)
```

`.pii-patterns` 不進版控，一行一個 regex，放只屬於自己場域、不該出現在公開 repo 的字串。

## 授權

Apache-2.0，見 [LICENSE](LICENSE) 與 [NOTICE](NOTICE)。
