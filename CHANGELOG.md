# Changelog

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
