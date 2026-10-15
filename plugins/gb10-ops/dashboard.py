"""The gb10-ops row of the overview dashboard.

collector/grafana/build-dashboard.py calls rows(h, y, th) after its first
row when a host lists the plugin: h holds build-dashboard's helpers (row,
stat, ts, steps, target and the rest), y the next free grid row, th the site's thresholds.
It returns the panels and the next free row.
"""

SOAK_BUDGET = 240   # the gb10-ops guard acts here; not a site setting


def rows(h, y, th):
    SOAK_WARN = th["gb10_soak_warn_s"]
    MEM_WARN, MEM_CRIT = th["gb10_mem_warn_gib"] * 1024 ** 3, th["gb10_mem_crit_gib"] * 1024 ** 3
    P = []
    P.append(h.row("GPU 節點（DGX Spark）", y)); y += 1
    P.append(h.stat("熱 soak 秒數", 0, y, 6, 5, "gb10_soak_seconds", "{{node}}", unit="s",
                    thresholds=h.steps((None, "green"), (SOAK_WARN, "orange"), (SOAK_BUDGET, "red")),
                    desc=f"最熱 thermal zone 連續 ≥ 88 °C 的秒數。守護在 {SOAK_BUDGET} s 動手，告警在 {SOAK_WARN} s，差額涵蓋 textfile 最多 10 s 的舊值、抓取 10 或 20 s 的跳階、規則評估最多 15 s"))
    P.append(h.stat("可用記憶體", 6, y, 6, 5, "gb10_mem_available_bytes", "{{node}}", unit="bytes",
                    thresholds=h.steps((None, "red"), (MEM_CRIT, "orange"), (MEM_WARN, "green")),
                    desc="MemAvailable。統一記憶體看不到 GPU 配置，這個數掉到 6 GiB 以下 hw-sample 會警告，3 GiB 以下動手（gb10-ops）"))
    P.append(h.stat("NV_ERR_NO_MEMORY（24h）", 12, y, 6, 5, "increase(gb10_nv_err_no_memory_total[24h])", "{{node}}",
                    thresholds=h.steps((None, "green"), (1, "red")), decimals=0,
                    desc="dmesg 裡 NV_ERR_NO_MEMORY 24 小時內增加的筆數。非零就是統一記憶體耗盡的早期訊號"))
    P.append(h.stat("HOT 旗標", 18, y, 6, 5, "gb10_hot", "{{node}}",
                    thresholds=h.steps((None, "green"), (1, "orange")), decimals=0,
                    desc="hw-sample.py 立的 HOT 旗標，批次工作在階段之間要看它"))
    y += 5
    P.append(h.ts("溫度", 0, y, 12, 8,
                  [h.target("gb10_zone_temp_celsius", "zone {{node}}"), h.target("gb10_gpu_temp_celsius", "gpu {{node}}")],
                  unit="celsius", lines=((88, "orange"),), minv=30, maxv=100,
                  desc="最熱 zone 與 nvidia-smi 的 GPU 溫度。橘線 88 °C 是 soak 門檻"))
    P.append(h.ts("soak 累積", 12, y, 12, 8,
                  [h.target("gb10_soak_seconds", "{{node}}")],
                  unit="s", lines=((SOAK_WARN, "orange"), (SOAK_BUDGET, "red")), minv=0, maxv=300,
                  desc="15 s 抓取下一次升溫約 15 個點，守護動手時歸零"))
    y += 8
    P.append(h.ts("GPU 功耗", 0, y, 12, 6, [h.target("gb10_gpu_power_watts", "{{node}}")], unit="watt"))
    P.append(h.ts("GPU 使用率", 12, y, 12, 6, [h.target("gb10_gpu_utilization_percent", "{{node}}")], unit="percent", minv=0, maxv=100))
    y += 6
    return P, y
