# Provenance

30ops 由下列 repo 併入，保留完整 git 歷史（`git filter-repo --to-subdirectory-filter` 後以 merge 併入）。每個 merge commit 的訊息帶 `Imported-From:`。原 repo 的 tag 沒有帶進來，避免與 30ops 自己的版本號衝突；原 repo 不改寫，系列文章與索引 repo（onprem-ops-30days v1.0.0）釘住的 tag 與 SHA 都仍然有效。

| 模組 | 來源 | 最後 tag | 來源 commit | 原授權 |
|---|---|---|---|---|
| `collector/` | ivanusto/onprem-metrics | v0.3.4 | `2dfbdb59ea94d8010714373e3f172dd9a0de5e0d` | Apache-2.0 |
| `logs/` | ivanusto/onprem-logs | v0.5.4 | `d15459843b58819c6fdcd6d52289697c94895f9a` | Apache-2.0 |
| `changes/` | ivanusto/onprem-changes | v0.3.0 之後 4 個 commit | `abb437f1877538fce26225aba5cf5884480b1b65` | Apache-2.0 |
| `gate/` | ivanusto/onprem-agent-gate | v0.1.0 | `d123e111c8a2994fab1d10491bf2b81e68fa3f61` | Apache-2.0 |
| `drills/pve-backup/` | ivanusto/pve-backup-drill | v0.1.0 | `59b4def1ee8821f98f9d9299da2082f8876a2665` | Apache-2.0 |
| `drills/nas-backup/` | ivanusto/nas-backup-drill | v0.1.0 | `543850bb8c28d52c64e4d0dc78096382516053ac` | Apache-2.0 |
| `drills/cloud-offload/` | ivanusto/cloud-offload-drill | v0.1.0 之後 1 個 commit | `c65cf856a7fb7b596b9ea1904665b19510dba1d9` | Apache-2.0 |
| `checks/qdevice/` | ivanusto/pve-qdevice-on-qnap | v0.1.0 | `3bba84ef1f3c4d50b5c7a9f6e6596d2bbce98c24` | Apache-2.0 |
| `plugins/gb10-ops/` | ivanusto/gb10-ops | v0.2.0 之後 1 個 commit | `77ce25dc1fcc94996273324049184486c648b933` | MIT |
| `plugins/spark-baseline/` | ivanusto/spark-baseline | v0.1.2 | `11fa1ce4721ae964f07c3b4f2ca817d85a4dcd64` | Apache-2.0 |
| `plugins/nfs-model-library/` | ivanusto/nfs-model-library | v0.1.0 | `64dec6f217d2c1fe0158086afd5f24eaf4a324c9` | Apache-2.0 |
| `checks/readiness/`、`inventory/` | ivanusto/onprem-ops-30days（只取 `lab/checklist.md`、`lab/cost.yaml`、`scripts/cost.py`、`tests/test_cost.py`、`tests/cost-fixture.yaml`） | v1.0.0 | `e44faf6a101f174d76f88de2b4bd029bff5b34e0` | MIT（v0.7 起 `lab/checklist.md` 改寫為 `checks/readiness/checklist.yaml`，原文留在 git 歷史，對照見 `docs/readiness.md`） |

## 匯入時排除的內容

- onprem-changes 的真實變更單（`changes/CR-*.md`）與演練紀錄（`drills/drills.jsonl`、`drills/drills.md`）是場域資料，從匯入的歷史中整個排除，不在本 repo。測試用的範例單仍在 `changes/tests/fixtures/`。
- onprem-ops-30days 只取上表的五個檔，系列的 `series.yaml`、文章索引與設備清單不在本 repo。

## 匯入後的調整（v0.1.0）

- 範例與測試裡的私有位址改成文件保留段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24），同一檔內一致替換。
- `assets.tsv` 與 `cost.yaml` 移到 `examples/sample-site/`。
- 各模組的 LICENSE 與 workflow 收到根目錄。
