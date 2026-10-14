# Changelog

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
