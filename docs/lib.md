# 共用函式庫（lib/）

v0.2 起，收集端與演練編排端共用的程式只放在 `lib/`。`scripts/check-drift.py` 在 CI 確認同樣的寫法不會在別處再出現一份。

## 引用方式

Python：腳本用自己的位置推出 repo 根，再把 `lib/python` 加進 `sys.path`。logs 的測試用 `python3 -I` 執行，-I 會忽略 `PYTHONPATH`，所以不能靠環境變數。

```python
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "lib", "python"))
from ops30 import textfile
```

sh：先設 `OPS30_SH`，再 source。函式庫靠 `OPS30_SH` 找到 repo 根（`OPS30_ROOT`），`ops30_drill` 用它呼叫 `bin/30ops`。

```sh
HERE=$(cd "$(dirname "$0")" && pwd)
OPS30_SH=${OPS30_SH:-$HERE/../../lib/sh/ops30.sh}
# shellcheck source=../../lib/sh/ops30.sh
. "$OPS30_SH"
```

repo 根的 `.shellcheckrc` 設了 `source-path=SCRIPTDIR`，shellcheck 會跟著 `source=` 指令檢查函式庫。

**部署：** 使用這些腳本的機器要有完整的 30ops checkout，不能只複製單一模組目錄。gate 的安裝步驟見 `gate/docs/targets.md`。

## lib/python/ops30

Python 3.12 標準函式庫；只有讀寫 site.yaml 的 `yamlio` 需要 PyYAML（`python3-yaml`，apt 版本，`python3 -I` 下也找得到），而且是用到時才載入，`drill` 子命令不需要它。

| 模組 | 內容 |
|---|---|
| `frontmatter` | `parse(text)` 回傳 `(meta, body, body_line)`；`sections(body)`；`FrontMatterError`。變更單與 gate 共用 |
| `rfc3339` | `parse(s)` 回傳 UTC 的 aware datetime，接受 Z 或時差，沒有時差的回傳 None；`to_epoch`、`format`、`from_epoch`、`now` |
| `textfile` | `esc(v)` 依 exposition format 跳脫反斜線、引號與換行；`family(lines, name, help, type)`；`write(path, text)`：同目錄暫存檔、0644、fsync、rename，失敗時清掉暫存檔 |
| `jsonl` | `lock(path)` 以 flock 取得獨占附加權；`write_line`；`append(path, obj)`；`read(path)` 回傳 `(records, skipped)`，略過空行、壞行與非物件行 |
| `drills` | drills.jsonl v1：`new`、`validate`、`append`、`normalise(rec, hint)`、`load(path, hint)`，見 [drills-jsonl.md](drills-jsonl.md) |
| `yamlio` | `load`、`loads`：SafeLoader，重複鍵報錯，日期保持字串；`dumps`：固定順序的 block style |
| `site` | site.yaml：`load`、`validate(doc, base, strict, secrets)` 回傳 `(errors, warnings)`、`resolve` 補預設值，見 [site-yaml.md](site-yaml.md) |
| `render` | `render(site, sha)` 回傳安裝路徑到 `Output` 的對照，`write(tree, out)`，見 [render.md](render.md) |
| `legacy` | 舊佈局的語意比對 `compare(tree, root, site)`；`legacy_import.draft(root)` 從舊佈局草擬 site.yaml |
| `cli` | `30ops` 指令：`validate`、`render`、`import-legacy`、`drill record`、`drill migrate` |

gate 的稽核鏈在 `jsonl.lock` 之內讀最後一筆再寫下一筆，兩個呼叫端不會拿到同一個 seq。鏈上遇到壞行仍然報錯，不會略過，因為壞行本身就是竄改的證據。

## lib/sh/ops30.sh

POSIX sh。`date -d @EPOCH` 在 GNU date 與 busybox date 都可用。

| 函式 | 內容 |
|---|---|
| `ops30_now` | 現在的 Unix 時間（UTC） |
| `ops30_iso [EPOCH]` | 轉成 `2026-10-13T12:30:00Z`，省略參數時用現在 |
| `ops30_to_epoch X` | 數字原樣輸出，其他交給 `date -d` |
| `ops30_since EPOCH` | 距今秒數 |
| `ops30_expired EPOCH LIMIT` | 超過 LIMIT 秒時為真 |
| `ops30_die MSG` | 以 `OPS30_PROG`（預設腳本檔名）為前綴寫到 stderr，exit 1 |
| `ops30_need CMD...` | 任一指令不存在就 die |
| `ops30_sha256 FILE` | 用 sha256sum，沒有就用 openssl |
| `ops30_drill ...` | `30ops drill record` 的參數，寫一筆 v1 紀錄 |
| `ops30_last_field FILE PATH` | 最後一行 JSON 的某個欄位（測試用） |

## 不使用 lib 的檔案

下列檔案會被複製到其他主機單獨執行，所以維持自給自足，不 source 也不 import lib。check-drift 對它們豁免，清單也寫在 `scripts/check-drift.py` 的 `NODE_SIDE`。

| 檔案 | 執行位置 |
|---|---|
| `adapters/nas/qnap/remote.sh` | 經 ssh 送到 NAS 的 sh 執行 |
| `collector/node/node-install.sh` | 節點上，從 `30ops install node` 的 bundle 執行 |
| `drills/pve-backup/canary.sh` | 還原演練的 VM 內，`/usr/local/bin/canary.sh` |
| `drills/nas-backup/share-canary.sh` | NAS 的 cron |
| `drills/nas-backup/nas-audit.sh` | NAS |
| `drills/nas-backup/replica-verify.sh` | NAS 或副本主機 |
| `plugins/` 全部 | 各自的節點（例如 `gb10-textfile.py`、各插件的 `install.sh`） |

另外兩個檔案解析的是特定來源的格式，也豁免：`logs/firewall/fortigate-export-load.py` 讀 FortiGate 的 date、time、tz 欄位；`logs/firewall/aup-compare.sh` 是一次性的比對工具。
