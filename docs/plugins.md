# 插件

插件是可選的節點模組，放在 `plugins/<名稱>/`，由一份 `plugin.yaml` 宣告 30ops 要拿它做什麼。場域在主機的 `plugins:` 列出插件就啟用；沒有任何主機列出時，插件的抓取 job、規則、儀表板列與 readiness 題目都不會出現在 render 結果裡。

插件目錄裡的程式會被複製到節點上單獨執行，維持自給自足，不 import `ops30`（[lib.md](lib.md#不使用-lib-的檔案)）。`plugin.yaml`、規則、門檻與儀表板片段由收集端的 30ops 讀取。

| 插件 | 用途 | 安裝內容 | 規則與儀表板 |
|---|---|---|---|
| `gb10-ops` | NVIDIA DGX Spark（GB10）的熱 soak 與統一記憶體防護 | gb10-textfile 與 timer、`/run/gb10` | 7 條告警、`gb10` 抓取 job（15 秒）、GPU 節點儀表板列 |
| `spark-baseline` | 節點狀態快照與 SSH 強化 | `/usr/local/sbin/baseline-snapshot` | 無 |
| `nfs-model-library` | NAS 上的模型庫，一個寫入者、每個檔案有校驗與來源 | `/usr/local/bin/mlib` | 無 |

## plugin.yaml

```yaml
plugin: 1                       # 這份檔案的格式版本
name: gb10-ops                  # 必須與目錄相同
version: 1                      # 插件輸出改變時遞增
license: Apache-2.0
summary: 一句話說明
roles: [node]                   # 主機至少要有其中一個角色
vendors: [linux]                # 主機的廠商必須是其中之一
install:
  files: [install.sh, textfile/gb10-textfile.py, systemd/gb10-textfile.service, systemd/gb10-textfile.timer]
textfile:                       # 節點寫的 textfile；max_age_s 是它的過期告警門檻
  - {file: gb10.prom, prefix: gb10_textfile, max_age_s: 120}
scrape:                         # 列出插件的主機改由這個 job 抓取
  job: gb10
  port: 9100
  replaces: node                # 這些主機不再出現在 node job
  config: {scrape_interval: 15s, relabel_configs: [...]}
rules: [rules/gb10.yml]         # 規則檔，可用 ${鍵} 引用門檻
thresholds: thresholds.yml      # 門檻目錄，格式同 collector/prometheus/thresholds.yml
threshold_order:                # 成對的門檻，前者必須小於後者
  - [gb10_mem_crit_gib, gb10_mem_warn_gib]
dashboard: dashboard.py         # rows(h, y, th) -> (panels, y)
readiness:                      # 題目，格式同 checks/readiness/checklist.yaml
  - id: textfile-fresh
    category: node-guard
    question: {zh-TW: ..., en: ...}
    check: {type: promql, ok: '...', bad: '...'}
```

除了 `plugin`、`name`、`version`、`license`、`summary` 以外都是選填。`tests/unit/test_plugins.py` 對每個插件檢查：鍵只能是上列幾個、`name` 等於目錄名、授權是 Apache-2.0、角色與廠商在 `site.yaml` 的列舉內、`install.files` 都存在且帶 `install.sh`、`.sh` 與 `.py` 可執行、textfile 的 `max_age_s` 等於規則裡過期告警的門檻、插件門檻不與核心門檻同名，以及 `site.PLUGINS` 就是目錄裡的插件。

## 30ops 怎麼使用它

| 項目 | 由誰讀 | 結果 |
|---|---|---|
| `roles`、`vendors` | `30ops validate` | 主機列了插件卻沒有對應角色或廠商時報錯 |
| `install` | `30ops install node` | 節點 bundle 帶上這些檔案（`plugins/<名稱>/…`）；`node-install.sh` 裝完角色後，依 `PLUGINS` 逐一執行 `plugins/<名稱>/install.sh`。hook 必須冪等，第二次執行不改任何東西 |
| `scrape` | `render`（prometheus） | `prometheus.yml` 在 `collector-host` 之前加入這個 job，目標檔 `targets/<job>.yml` |
| `rules`、`thresholds` | `render`（rules） | 代入門檻後寫成 `rules/plugin-<名稱>.yml`；`site.yaml` 的 `alerting.thresholds` 可以覆寫插件的門檻 |
| `dashboard` | `render`（grafana） | 儀表板第一列之後插入插件的列。repo 內的 `onprem-overview.json` 含所有插件的列 |
| `readiness` | `render`（readiness） | 題目 id 加上插件名稱（`gb10-ops:textfile-fresh`），只在有主機列出插件時出題 |
| 規則與門檻 | `scripts/check-drift.py` | `plugins/*/rules/` 是核心 `collector/prometheus/rules/` 以外唯一合法的規則來源；佔位符必須是核心或插件門檻的鍵，每個鍵都要有規則用到，規則引用的 job 必須存在 |

promtool 測試放在 `plugins/<名稱>/tests/rules_*test.yml`，`scripts/test-rules.sh` 只在 render 結果有 `rules/plugin-<名稱>.yml` 時一併執行。Alertmanager 的路由與抑制規則仍在 `collector/alertmanager/alertmanager.base.yml`（gb10 的兩條在那裡），插件的 Alertmanager 片段留到 v1.x。

## 新增一個插件

1. 建 `plugins/<名稱>/`，放程式、`plugin.yaml` 與冪等的 `install.sh`。
2. 有指標就寫 textfile，宣告 `textfile:` 與過期告警；需要另外抓取再宣告 `scrape:`。
3. 規則、門檻、儀表板片段與 readiness 題目都放在插件目錄裡。
4. `python3 -m unittest tests/unit/test_plugins.py`、`python3 scripts/check-drift.py`，在範例或測試場域的主機列出插件後跑 `sh scripts/test-rules.sh`。
