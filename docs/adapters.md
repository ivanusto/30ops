# Adapter

adapter 定義 30ops 怎麼跟某一類設備的某個廠商溝通。每個 adapter 放在 `adapters/<kind>/<vendor>/`：`adapter.yaml` 宣告它能做什麼，`adapter.py` 是實作。共用的部分在 `lib/python/ops30/adapters/`，包括 kind 契約（`schema.py`）、指標輸出（`base.py`）、連線方式（`transport.py`）與載入（`registry.py`）。

## kind 與角色

| kind | site.yaml 角色 | 能力 | v0.5 的 adapter |
|---|---|---|---|
| nas | nas | facts、health、snapshots、share_canary、snmp_module、syslog_profile | qnap |
| firewall | firewall、audit-source、webfilter | facts、licences、audit_source、config_backup、syslog_profile、managed_aps | fortigate |
| hypervisor | hypervisor | facts、quorum、backup_jobs、restore_test、exporter_config | pve |
| network | switch、ap | interfaces、sensors、uptime | generic-snmp |
| os | collector、node、journal、pcap、qdevice | journal、node_exporter、pcap | linux |

`30ops validate` 對每台主機的每個角色找 adapter：先找 `adapters/<該角色的 kind>/<vendor>/`。若是 os 類角色，主機廠商的 adapter.yaml 寫了 `os:`，就改用那個 os adapter（例如 PVE 節點的 journal 與 pcap 由 `os/linux` 處理）。找不到就是錯誤。

## adapter.yaml

```yaml
adapter: 1            # 這份檔案的格式版本
kind: nas             # 必須與目錄相同
vendor: qnap          # 必須與目錄相同，也必須在 site.yaml 的 vendor 列舉內
version: 1            # adapter 輸出改變時遞增
os: linux             # 選填：這台設備的 OS 類角色交給哪個 os adapter
tested: ["QuTS hero 6.0.2"]
capabilities:
  health:
    face: collect     # collect、snmp、render、descriptor、install
    status: implemented   # 或 planned（可加 milestone）
    textfile: nas.prom
  snapshots: {face: collect, status: implemented, textfile: nas.prom, via: health}
  share_canary: {face: descriptor, status: implemented, ref: drills/nas-backup/share-canary.sh}
```

| face | 意義 | 契約測試檢查 |
|---|---|---|
| collect | cron 以 `30ops textfile` 執行，寫 node_exporter textfile | `adapter.py` 有同名函式，每個錄製 case 重放後與 `expected.prom` 完全相同，family 與 label 等於 `schema.FAMILIES` |
| data | 回傳資料，由 `ref` 指的程式寫成 textfile | `adapter.py` 有同名函式，每個 case 重放後與 `expected.json` 相同 |
| snmp | 由 snmp_exporter 的模組取得 | `metrics` 列的指標都在 `collector/prometheus/snmp.yml` |
| render | `30ops render` 產出設定檔 | `adapter.py` 有 `render` 函式 |
| descriptor | 由既有的程式或文件負責，adapter 只指過去 | `ref` 存在 |
| install | `30ops install node` 在節點上安裝 | `ref` 存在 |

`via` 表示這個能力由同一個 adapter 的另一個能力一併完成（qnap 的 snapshots 在 health 的同一次 ssh 裡）。

## collect 函式

```python
def health(targets, transport, now):   # -> textfile 文字
```

- `targets` 是 `base.Target` 的清單，由 cron 參數 `LABEL=user@host[,user@host...]` 解析而來。cron 明列主機，`render --compare-legacy` 才看得到主機清單的漂移。
- `transport` 是 `transport.Ssh`、`Local`、`Replay` 或 `Record`，都提供 `run(dest, argv, stdin)` 與 `get(url, headers, insecure)`，回傳 `Result(rc, out, err)`。連不上不丟例外，而是回傳非零 rc，由函式輸出 `*_up 0`。
- `now` 是 Unix 時間，寫進 `*_last_run_timestamp`。
- 輸出用 `base.Metrics`，數值是已格式化的字串，和原本 shell 寫入器輸出的文字一致。

## ops30_adapter_info

既有指標不加 `vendor` label（加了會變成新序列，切換時 TSDB 斷開），改由 render 產出靜態的 `<textfile_dir>/30ops-adapters.prom`，每台主機每個 kind 一筆：

```
ops30_adapter_info{name="nas-primary",kind="nas",vendor="qnap",version="1",nas="primary"} 1
```

最後一個 label 是該 kind 既有序列用來指主機的 label（nas 用 `nas`，hypervisor 用 `cluster`，firewall 用 `host`，os 用 `instance`），需要 vendor 時以它 join，例如 `nas_up * on (nas) group_left (vendor) ops30_adapter_info{kind="nas"}`。

## data 函式

FortiGate 的 licences 不自己寫 textfile，由 `eol-textfile.py` 合併進 `eol.prom`，所以 face 是 `data`：函式回傳資料，case 的 `case.json` 以 `args` 給參數，結果與 `expected.json` 比對；預期失敗的 case 寫 `raises`（例外訊息的 regex）。

```python
def licences(transport, url, token, insecure=False):   # -> [(component, status, expires)]
```

## 錄製 fixture

```
tests/fixtures/adapters/<vendor>/<capability>/<case>/
  case.json        {"targets": ["primary=ops30@192.0.2.2"], "now": 1791892800, "source": "..."}
  requests.jsonl   每行一個請求，依序重放
  001.out ...      每個請求的回應
  expected.prom    重放後應得的輸出
```

`requests.jsonl` 的格式：

```json
{"op": "run", "dest": "ops30@192.0.2.2", "argv": ["sh", "-s", "primary"], "stdin_sha256": "...", "rc": 0, "out": "001.out"}
{"op": "get", "url": "https://192.0.2.99/api/v2/monitor/license/status", "rc": 200, "out": "002.out"}
```

- `Replay` 嚴格依序比對 dest、argv 與 url，有 `stdin_sha256` 時連送出的 stdin 也要相同（遠端腳本改了，fixture 就要重錄）。錄製的請求沒有全部用完也算失敗。
- 用 `transport.Record` 包住真的連線即可錄製。錄下來的內容是原始資料，進版控前要匿名化：位址改成 RFC 5737（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24），名稱改成 example.net，序號與 MAC 改成假值，再跑一次 `scripts/hygiene.py`（含本機 `.pii-patterns`）。

## 新增 adapter

1. 建 `adapters/<kind>/<vendor>/adapter.yaml`，能力名稱只能用該 kind 的清單。
2. vendor 加進 `lib/python/ops30/site.py` 的 `VENDORS`（契約測試確認兩者一致）。
3. 實作 `adapter.py`，為每個 collect 能力錄至少一個 case。
4. `python3 -m unittest tests/unit/adapters/test_contract.py`。
