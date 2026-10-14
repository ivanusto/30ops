# 發行

推送 tag `vX.Y.Z` 或 `vX.Y.Z-rc.N` 就會觸發 `.github/workflows/release.yml`。發行檔只有原始碼，沒有預先建好的節點 bundle：bundle 依場域與主機產生（含 `install.env` 與收集端的公鑰），在現場以 `30ops install node <host> --bundle` 建立（[install.md](install.md)）。

## 發行的檔案

| 檔案 | 內容 |
|---|---|
| `30ops-X.Y.Z.tar.gz` | tag 那個 commit 的整棵樹，目錄 `30ops-X.Y.Z/`，與 `git archive` 相同：沒有 `.git`，沒有未提交的檔案 |
| `images.txt` | `collector/compose.yml` 釘住的每個映像與 digest，一行一個 |
| `SHA256SUMS` | 上面兩個檔案的 sha256 |

三個檔案都有 GitHub 的 build provenance attestation（Sigstore 簽章，記錄由哪個 workflow、哪個 commit 建出）。

## 流程（release.yml）

1. `check.yml` 與 `e2e.yml` 在 tag 的 commit 上全部通過，才進入下一步。
2. `scripts/release-check.sh`：
   - tag 必須是 `v` 加 VERSION（正式版），或 `v` 加 VERSION 加 `-rc.N`（預發版，N 從 1 起）。
   - `CHANGELOG.md` 必須有 `## vX.Y.Z（` 段落，這一段就是 Release 的說明；預發版在開頭加一行標示。
3. `scripts/dist.sh` 產生兩次並逐位元比對，確認可重現：git archive 的 mtime 取自 commit，gzip 以 `-n` 不寫檔名與時間。
4. 產生 `SHA256SUMS`。
5. `gh attestation verify` 確認 `images.txt` 裡的 Grafana 映像（`ghcr.io/ivanusto/30ops-grafana`，由 `grafana-image.yml` 建置）帶有本 repo 的 attestation。
6. 對三個檔案產生 attestation，建立 GitHub Release；`-rc.N` 標為 prerelease。

## 發行步驟（維護者）

```sh
# 1. VERSION 與 CHANGELOG.md 的新段落寫好，推上 main，等 check 與 e2e 綠
# 2. 預發版：確認 workflow 與檔案都對
git tag -a v0.6.0-rc.1 -m v0.6.0-rc.1 && git push origin v0.6.0-rc.1
# 3. 下載驗證（見下一節）
# 4. 正式版
git tag -a v0.6.0 -m v0.6.0 && git push origin v0.6.0
```

## 驗證下載的檔案

```sh
gh release download vX.Y.Z --repo ivanusto/30ops
sha256sum -c SHA256SUMS
gh attestation verify 30ops-X.Y.Z.tar.gz --repo ivanusto/30ops
gh attestation verify images.txt --repo ivanusto/30ops
```

沒有 `gh` 時，至少核對 `SHA256SUMS`；attestation 也可以在 Release 頁面的 Attestations 連結查看。
