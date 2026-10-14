# Changelog

## v0.1.0（2026-10-14）

- 以保留歷史的方式併入 12 個 repo，對照見 `docs/provenance.md`。
- 授權統一為 Apache-2.0（gb10-ops 與索引 repo 的部分原為 MIT，見 `NOTICE`）。
- 單一 CI：十個模組的檢查併成 `.github/workflows/check.yml`，action 釘 commit SHA，下載的工具驗 sha256。
- `scripts/hygiene.py`：破折號、私有 IP、家目錄路徑、`.pii-patterns`。
- `scripts/check-ci-pins.sh`：action、下載、映像都要鎖定。
- 範例位址改用文件保留段，場域樣本移到 `examples/sample-site/`，真實變更單不在本 repo。
- `change_rollback_drills_total` 的 TYPE 由 gauge 改為 counter，名稱不變。原 repo 的 CI 在 unittest 之後才裝 promtool，`promtool check metrics` 從未實際執行。
