#!/bin/sh
# run: the behaviour pipeline end to end into one directory.
#
#   sh run.sh --out DIR                                   # synthetic site, rules backend (no model)
#   sh run.sh --out DIR --backend ollama [--slm M --llm M] # synthetic site, the models
#   sh run.sh --out DIR --backend openai --base-url http://node:8000 --slm M --llm M   # vLLM or another OpenAI-compatible server
#   sh run.sh --out DIR --slm-backend ollama --slm gemma4:e4b-mlx --llm-backend openai --llm M --base-url ...
#   sh run.sh --out DIR --events events.jsonl --schedule schedule.tsv --key-file /etc/30ops/behavior.key [--baseline-days 21]
#
# Steps and the files they leave in DIR:
#   synth.py        raw/events.jsonl raw/schedule.tsv raw/site.json   (only without --events)
#   pseudonymize.py events.p.jsonl schedule.p.tsv timing.jsonl        (--level minimal|standard|strict)
#   summarize.py    summaries.jsonl baseline.json timing.jsonl
#   detect.py       detections.jsonl run-manifest.json
#   evaluate.py     report.md metrics.json behavior.prom
#
# With real events a key file is required; the demo key is used for the
# synthetic site only. DIR must not exist or must be empty: a detection
# chain is never appended to by accident.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=""; backend=rules; level=standard; seed=7; users=40; days=35; baseline=21; slm=gemma4:e4b-mlx; llm=gemma4:26b-nvfp4
events=""; schedule=""; key=""; tz="+08:00"; extra_detect=""; bootstrap=1000
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out=$2; shift 2;;
    --backend) backend=$2; shift 2;;
    --level) level=$2; shift 2;;
    --seed) seed=$2; shift 2;;
    --users) users=$2; shift 2;;
    --days) days=$2; shift 2;;
    --baseline-days) baseline=$2; shift 2;;
    --slm) slm=$2; shift 2;;
    --llm) llm=$2; shift 2;;
    --events) events=$2; shift 2;;
    --schedule) schedule=$2; shift 2;;
    --key-file) key=$2; shift 2;;
    --tz) tz=$2; shift 2;;
    --bootstrap) bootstrap=$2; shift 2;;
    --prescreen-min|--t1|--t2|--limit|--slm-backend|--llm-backend|--base-url|--api-key) extra_detect="$extra_detect $1 $2"; shift 2;;
    --think) extra_detect="$extra_detect --think"; shift;;
    *) echo "run.sh: unknown argument $1" >&2; exit 2;;
  esac
done
[ -n "$out" ] || { echo "run.sh: --out DIR is required" >&2; exit 2; }
if [ -e "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
  echo "run.sh: $out is not empty; a run never appends to an existing chain" >&2; exit 2
fi
mkdir -p "$out"
if [ -z "$events" ]; then
  python3 "$here/synth.py" --out "$out/raw" --seed "$seed" --users "$users" --days "$days" --baseline-days "$baseline"
  events="$out/raw/events.jsonl"; schedule="$out/raw/schedule.tsv"
  keyarg="--demo-key"
else
  [ -n "$key" ] || { echo "run.sh: --key-file is required with real events" >&2; exit 2; }
  [ -n "$schedule" ] || { echo "run.sh: --schedule is required with real events (the injection schedule is the ground truth)" >&2; exit 2; }
  keyarg="--key-file $key"
fi
# shellcheck disable=SC2086
python3 "$here/pseudonymize.py" $keyarg --level "$level" --in "$events" --out "$out/events.p.jsonl" \
  --schedule "$schedule" --schedule-out "$out/schedule.p.tsv" --timing "$out/timing.jsonl"
python3 "$here/summarize.py" --in "$out/events.p.jsonl" --out "$out/summaries.jsonl" --tz "$tz" \
  --baseline-days "$baseline" --baseline-out "$out/baseline.json" --timing "$out/timing.jsonl"
# shellcheck disable=SC2086
python3 "$here/detect.py" run --in "$out/summaries.jsonl" --out "$out/detections.jsonl" --backend "$backend" \
  --slm "$slm" --llm "$llm" --manifest "$out/run-manifest.json" $extra_detect
python3 "$here/detect.py" verify --in "$out/detections.jsonl"
python3 "$here/evaluate.py" --detections "$out/detections.jsonl" --schedule "$out/schedule.p.tsv" --summaries "$out/summaries.jsonl" \
  --timing "$out/timing.jsonl" --manifest "$out/run-manifest.json" --out "$out/report.md" --json "$out/metrics.json" \
  --textfile "$out/behavior.prom" --bootstrap "$bootstrap"
echo "run.sh: report at $out/report.md"
