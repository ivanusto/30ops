#!/usr/bin/env bash
# The front door for a fine-tune: always behind the cooling gate and the watchdog.
#
# Why: measuring power on 2026-09-09 showed that fine-tuning draws 80 W and
# pushes the chassis to zone 94 C, the same class of load as video generation,
# while the gate and the watchdog were only attached to the video chain. Calling
# your training script directly still works, but it runs unguarded. Do not.
#
# Pass your own command as the arguments to this script. It is run verbatim as a
# child process group, and the whole group is taken down together if the box
# soaks for longer than the budget.
#
#   ./train-guarded.sh ./venv/bin/python train.py run 4 1536 2
#   COOL_C=50 SOAK_SECONDS=180 ./train-guarded.sh ./venv/bin/python train.py
#   ./train-guarded.sh                  # no arguments: runs a harmless placeholder
#
# Exit code 75 means the watchdog aborted the job. Anything else is your own
# command's exit code.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$HERE/../guards/thermal-run.py"

if [[ $# -gt 0 ]]; then
  CMD=( "$@" )
else
  CMD=( python3 -c 'print("replace this with your training command")' )
fi

mkdir -p "$HERE/out"

exec python3 "$GUARD" \
  --cool "${COOL_C:-55}" \
  --soak-zone "${SOAK_ZONE:-88}" \
  --soak-seconds "${SOAK_SECONDS:-240}" \
  --log "$HERE/out/thermal-run.log" \
  -- "${CMD[@]}"
