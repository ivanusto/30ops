# 行為偵測（behavior）

收集端已經有每一種動作的紀錄：防火牆的連線與 UTM、節點的登入與 sudo、NAS 的事件、封包。這個目錄把它們變成「某個帳號在某一天做了什麼，和他自己平常比起來如何」，交給地端的語言模型判讀，再把每個判讀寫進一條不能改的鏈。模型看不到任何真名、主機名或位址，因為在它之前有一個假名化的步驟，而且後面所有檔案都只從假名化後的檔案產生。

```
events.py        pseudonymize.py       summarize.py          detect.py                    evaluate.py
site's logs  ->  events.jsonl  ->  events.p.jsonl  ->  summaries.jsonl  ->  detections.jsonl (chain)  ->  report.md
(Zeek, FortiGate,   one schema      HMAC pseudonyms,   one user-day a line,   stage 1 small model,         metrics.json
 Windows, VL)                        prefix-kept IPs,   features, z against    stage 2 large model          behavior.prom
                                     cut names/paths    own baseline, text
```

研究用途：這個目錄同時是一篇學位論文的實作，論文的三層架構裡第一層的隱私處理與第二層的二段式推論就是這五支程式，第三層的稽核是 detections.jsonl 的 hash 鏈與收集端既有的 WORM 封存。

## 檔案

| 檔 | 做什麼 |
|---|---|
| `events.py` | 統一事件結構（docstring 是規格），與載入器：Zeek conn/files（TSV 或 JSON）、FortiGate 的 traffic/utm/vpn 行、Windows 安全事件的 JSON 匯出（4624/4625/5145/4663/307/6416）、VictoriaLogs（FortiGate 行與 sshd 的 Accepted/Failed）。`probe` 只數不寫 |
| `pseudonymize.py` | 三個等級的假名化，見下表。金鑰不在 repo、不在輸出、不印出；`--vault` 把真名對假名的表寫到金鑰保管人的地方，沒有它就沒有人能還原。整批耗時寫進 `timing.jsonl` |
| `summarize.py` | 每個使用者每一天一行：25 個計數、每個計數對本人基線的 z、沒在基線出現過的共享區／網域／內部目的／登入來源／登入目標、一個透明的規則分數 `prescreen`、規則會猜的情境、給模型讀的中文摘要 `text`。基線是測試期之前的工作日；天數不夠的帳號（新進人員）用同職務的，再不夠用全站的 |
| `detect.py` | 二段式。第一段小模型讀每一行，標記值得複核的；第二段大模型只讀被標記的，給 verdict、情境、0 到 100 的風險與理由。後端有 Ollama、OpenAI 相容伺服器（vLLM 等）與規則三種，兩段可以各選一種。兩段都先跑完才寫檔，一台機器放不下兩個模型時只需各載入一次。每筆記錄帶 `prev` 與 `hash`，`verify` 重算整條鏈。`--backend rules` 不用模型，門檻就是規則分數，輸出形狀相同，CI 用它 |
| `evaluate.py` | 對注入排程表算 Precision、Recall、F1、每使用者日偽陽性率，bootstrap 95% 信賴區間，六類情境各自的召回與類別正確率，兩段各放行多少，三層的延遲，漏報與誤報各附模型給的理由。Markdown、json、`behavior.prom` |
| `synth.py` | 合成場域：40 人、七種職務、35 天（前 21 天基線），每人有自己的工時、共享區、對外網域與日流量；IT 每天碰伺服器，服務帳號每晚備份。測試期有四個「合法但看起來可疑」的難例，與六類情境的注入各 5 次，排程表就是標準答案。位址用文件保留段，可以進公開 repo |
| `run.sh` | 上面五步接起來跑進一個目錄 |
| `../tests/smoke-behavior.sh`、`../tests/test_behavior.py` | 冒煙與單元測試，不需要模型也不需要 VictoriaLogs |

## 假名化等級

| 等級 | 帳號、主機、共享區 | 位址 | 網域 | 路徑與檔名 | 時間 | 位元組 |
|---|---|---|---|---|---|---|
| `minimal` | HMAC-SHA256 假名（u-、h-、s-） | 同主機名處理 | 原樣 | 原樣 | 原樣 | 原樣 |
| `standard` | 同上 | 逐一 octet 保留前綴：同前綴進，同前綴出（Crypto-PAn 的想法，octet 粒度） | 截到註冊網域 | 共享區／第一層目錄／`*.副檔名` | 到分鐘 | 原樣 |
| `strict` | 同上 | 同上 | 只留類別 `[cloud_storage]` | 只留共享區，檔名去掉 | 到小時 | 兩位有效數字 |

三個等級的差別就是論文裡「隱私嚴格程度與偵測即時性的取捨」的實驗變因：同一份事件以三個等級各跑一次，比較偵測指標與第一層耗時。任何不在事件結構裡的鍵（備註、主旨、內容）在這一步全部丟掉並計數。

## 規則分數

`summaries.jsonl` 的 `prescreen` 是一組寫在 `summarize.py` 的 `RULES` 裡的門檻與分數：個人儲存超過 100 MB 加 4、新共享區加 3、單一主機 15 個埠以上加 4、多次失敗後成功加 4……再加上六個計數的 z 超過 3 的部分。它有三個用途：`--backend rules` 的判準、`--prescreen-min` 的成本模式（分數太低的不送小模型）、報告裡解釋每個誤報與漏報的那一欄。它不是偵測器本身，模型是。

## 鏈

`detections.jsonl` 每一行是一筆判讀，`seq` 遞增，`prev` 是上一筆的 `hash`，`hash` 是 sha256(prev + "\n" + 去掉 hash 後排序的 JSON)，與 agent gate 的 audit.jsonl 同一種寫法。改一個字、刪一行、換順序，`detect.py verify` 都會指出是哪一行。每筆帶 `summary_sha256`，對得回它讀的那一行摘要；`run-manifest.json` 記模型名稱、兩段提示的 sha256、輸入檔的 sha256、門檻、30ops 與 Python 版本、Ollama 版本。

## 評估

| 指標 | 意義 |
|---|---|
| Precision、Recall、F1 | 以使用者日為單位，排程表有注入的日子是正樣本，最終 verdict 為 THREAT 是陽性 |
| 每使用者日偽陽性率 | FP ÷ 沒有注入的使用者日 |
| 六類情境 | 各類被標記、被判為威脅、類別也對的數量；被判為此類的裡面有幾個真的是 |
| 二段式 | 小模型標記了多少（這就是大模型的負載）、注入的日子有多少被標記、大模型的精確率 |
| 延遲 | 第一層整批與攤到每個使用者日、兩段各自的平均／中位數／p95、走完兩段的端對端與三層占比 |

`behavior.prom` 給 node_exporter 的 textfile collector：`behavior_f1`、`behavior_fpr`、`behavior_*_ci{bound}`、`behavior_scenario_recall{scenario}`、`behavior_stage_calls{stage}`、`behavior_latency_ms{stage,stat}`、`behavior_eval_last_run_timestamp`。告警規則與儀表板列留到下一版。

## 怎麼跑

```sh
# 合成場域，不用模型（CI 跑的就是這個）
sh run.sh --out /tmp/b1

# 合成場域，本機 Ollama 的兩個模型（思考關閉、JSON 輸出、temperature 0）
sh run.sh --out /tmp/b2 --backend ollama --slm gemma4:e4b-mlx --llm gemma4:26b-nvfp4

# 推論節點上的 vLLM（或任何 OpenAI 相容伺服器），兩段同一個模型；或初篩在本機、判讀在節點
sh run.sh --out /tmp/b3 --backend openai --base-url http://198.51.100.31:8000 --slm dsv41-flash-exl3 --llm dsv41-flash-exl3
sh run.sh --out /tmp/b4 --slm-backend ollama --slm gemma4:e4b-mlx --llm-backend openai --llm dsv41-flash-exl3 --base-url http://198.51.100.31:8000

# 真實事件：先用 events.py 把三個來源合成一份，再給排程表與金鑰
python3 events.py load --zeek conn.log --zeek files.log --fortigate fgt-traffic.log --winsec security.jsonl --out /srv/behavior/events.jsonl
openssl rand -hex 32 > /etc/30ops/behavior.key && chmod 0400 /etc/30ops/behavior.key
sh run.sh --out /srv/behavior/run-2026-10 --events /srv/behavior/events.jsonl --schedule /srv/behavior/schedule.tsv \
  --key-file /etc/30ops/behavior.key --level standard --backend ollama

# 同一份事件，三個等級
for L in minimal standard strict; do sh run.sh --out /srv/behavior/level-$L --events ... --schedule ... --key-file ... --level $L --backend ollama; done
```

排程表是 tsv，欄位 `start end user host scenario note`，時間帶時區（`2026-09-30T23:33+08:00`），一次注入一行；`user` 與 `host` 用場域的真名，假名化時與事件同一把金鑰換掉，`note` 清空。

## 資料治理

- 金鑰由不是研究者的人產生與保管；研究者拿到的是 `events.p.jsonl` 之後的檔案。`--vault` 的對照表放在金鑰保管人那裡。
- `raw/` 與任何真實事件檔不進版控；`.pii-patterns` 列場域的字串，`scripts/hygiene.py` 會擋。
- 模型在本機或場域內的推論節點上跑，不出網路；manifest 記的是 Ollama 的位址，不是資料。
- 合成場域的位址是 192.0.2.0/24、198.51.100.0/24、203.0.113.0/24，名稱是 example.net。

## 還沒有的

- VictoriaLogs 來源表只有 FortiGate 行與 sshd；Windows 事件與 NAS 的檔案存取要看場域的收容系統吐什麼格式，`events.py` 的 `from_winsec` 以常見欄位名猜。
- CERT 公開資料集（logon、device、http、email、file）的轉接器，讓同一條管線在另一個分佈上重跑。
- 告警規則（例如 `behavior_eval_last_run_timestamp` 過期、F1 低於門檻）、儀表板列、cron 行。
- 判讀結果回寫 agent gate 的同一條鏈或 WORM 封存的 `behavior-<day>` 來源。
