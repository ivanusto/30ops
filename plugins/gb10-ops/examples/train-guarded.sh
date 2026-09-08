#!/usr/bin/env bash
# 微調的正式入口：一律走冷卻閘門與熱看門狗。
#
# 0909 量功耗才發現微調吃 80 W、把機殼推到 zone 94 度，跟影片生成同一個等級，
# 而閘門與看門狗當時只掛在影片鏈上。這支就是把那個缺口補起來。
# 直接呼叫 scripts/train.py 仍然可行，但那是裸奔，別這樣做。
#
#   ./train-guarded.sh run 4 1536 2
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$HOME/bin/thermal-run.py" \
  --cool "${COOL_C:-55}" \
  --soak-zone "${SOAK_ZONE:-88}" \
  --soak-seconds "${SOAK_SECONDS:-240}" \
  --log "$HERE/out/thermal-run.log" \
  -- "$HERE/venv/bin/python" "$HERE/scripts/train.py" "$@"
