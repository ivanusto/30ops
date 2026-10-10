#!/bin/sh
# change-mark: mark the beginning and the end of a change where the rest of
# the pipeline will see it.
#   1. a journal line on this host, tag "change", priority notice. The
#      collector uploads its own journal (Day 21), so the line is in
#      VictoriaLogs within seconds and `"CR-2026-0001"` finds it
#   2. a Grafana annotation tagged change,<id>, closed at `end` so every
#      panel shows the window as a shaded span (Day 20's dashboard)
#   3. an Alertmanager silence for the matchers in the record's `silence:`
#      field, ending at the record's window_end; expired at `end`
#
#   change-mark.sh begin CR-2026-0001
#   change-mark.sh end   CR-2026-0001
#
# Environment (defaults fit the collector VM)
#   CHANGES_DIR        clone of this repo's changes/   [/opt/onprem-changes/changes]
#   STATE_DIR          where annotation and silence ids are kept between begin
#                      and end                          [/var/lib/onprem-changes]
#   GRAFANA_URL        [http://127.0.0.1:3000]
#   GRAFANA_TOKEN_FILE service account token, role Editor (OSS has no narrower
#                      role that can write annotations)  [/etc/onprem-changes/grafana.token]
#   ALERTMANAGER_URL   [http://127.0.0.1:9093]
#   AMTOOL             [amtool]  (silence step is skipped with a warning when absent)
#   LOGGER             [logger]  (the tests point it at a fake)
#
# Every step is best effort except the journal line: an unreachable Grafana
# or Alertmanager is reported and the exit code is 1, but the mark itself
# (the journal line) always happens first.
set -u

CHANGES_DIR=${CHANGES_DIR:-/opt/onprem-changes/changes}
STATE_DIR=${STATE_DIR:-/var/lib/onprem-changes}
GRAFANA_URL=${GRAFANA_URL:-http://127.0.0.1:3000}
GRAFANA_TOKEN_FILE=${GRAFANA_TOKEN_FILE:-/etc/onprem-changes/grafana.token}
ALERTMANAGER_URL=${ALERTMANAGER_URL:-http://127.0.0.1:9093}
AMTOOL=${AMTOOL:-amtool}
LOGGER=${LOGGER:-logger}

action=${1:-}; id=${2:-}
case "$action" in begin|end) ;; *) sed -n '2,28p' "$0"; exit 64 ;; esac
case "$id" in CR-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]) ;; *) echo "id must look like CR-2026-0001" >&2; exit 64 ;; esac

rec=$(find "$CHANGES_DIR" -maxdepth 1 -name "$id-*.md" 2>/dev/null | LC_ALL=C sort | head -n1)
[ -n "$rec" ] || { echo "no record $id in $CHANGES_DIR" >&2; exit 2; }
# front matter fields: the first block between --- lines, `key: value`
fm() { awk -v k="$1" 'NR==1&&$0!="---"{exit} /^---$/{c++; next} c==1 && index($0, k": ")==1 {sub(k": *", ""); print; exit}' "$rec"; }
title=$(fm title); matchers=$(fm silence); wend=$(fm window_end)
mkdir -p "$STATE_DIR" 2>/dev/null || true
state="$STATE_DIR/$id.state"
rc=0
now_ms=$(( $(date +%s) * 1000 ))

# 1. journal, first and unconditionally
"$LOGGER" -t change -p notice "$id $action $title"

# 2. Grafana annotation
if [ -r "$GRAFANA_TOKEN_FILE" ]; then
  tok=$(cat "$GRAFANA_TOKEN_FILE")
  if [ "$action" = begin ]; then
    body=$(printf '{"time":%s,"tags":["change","%s"],"text":"%s begin: %s"}' "$now_ms" "$id" "$id" "$(printf '%s' "$title" | sed 's/"/\\"/g')")
    resp=$(curl -sS -m 10 -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d "$body" "$GRAFANA_URL/api/annotations") \
      && ann=$(printf '%s' "$resp" | sed -n 's/.*"id": *\([0-9]*\).*/\1/p')
    if [ -n "${ann:-}" ]; then
      printf 'annotation=%s\n' "$ann" >> "$state"
      echo "grafana: annotation $ann"
    else
      echo "grafana: annotation failed: ${resp:-no response}" >&2; rc=1
    fi
  else
    ann=$(sed -n 's/^annotation=//p' "$state" 2>/dev/null | tail -n1)
    if [ -n "$ann" ]; then
      if curl -sS -m 10 -o /dev/null -f -X PATCH -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
           -d "{\"timeEnd\":$now_ms}" "$GRAFANA_URL/api/annotations/$ann"; then
        echo "grafana: annotation $ann closed"
      else
        echo "grafana: closing annotation $ann failed" >&2; rc=1
      fi
    else
      echo "grafana: no annotation id recorded at begin, nothing to close" >&2
    fi
  fi
else
  echo "grafana: $GRAFANA_TOKEN_FILE not readable, annotation skipped" >&2; rc=1
fi

# 3. Alertmanager silence
if [ -n "$matchers" ]; then
  if command -v "$AMTOOL" >/dev/null 2>&1; then
    if [ "$action" = begin ]; then
      [ -n "$wend" ] || { echo "silence: record has no window_end" >&2; wend=$(date -u -d '+2 hours' +%Y-%m-%dT%H:%M:%SZ); }
      # shellcheck disable=SC2086   # matchers are space separated on purpose
      sid=$("$AMTOOL" --alertmanager.url="$ALERTMANAGER_URL" silence add $matchers --end="$wend" --author="change-mark" --comment="$id $title" 2>&1)
      if printf '%s' "$sid" | grep -qE '^[0-9a-f-]{36}$'; then
        printf 'silence=%s\n' "$sid" >> "$state"; echo "alertmanager: silence $sid until $wend"
      else
        echo "alertmanager: silence failed: $sid" >&2; rc=1
      fi
    else
      sid=$(sed -n 's/^silence=//p' "$state" 2>/dev/null | tail -n1)
      if [ -n "$sid" ]; then
        if "$AMTOOL" --alertmanager.url="$ALERTMANAGER_URL" silence expire "$sid" >/dev/null 2>&1; then
          echo "alertmanager: silence $sid expired"
        else
          echo "alertmanager: expiring silence $sid failed" >&2; rc=1
        fi
      fi
    fi
  else
    echo "alertmanager: $AMTOOL not found, silence step skipped" >&2; rc=1
  fi
fi

[ "$action" = end ] && [ "$rc" -eq 0 ] && rm -f "$state"
echo "change-mark: $id $action recorded in the journal (tag change)"
exit "$rc"
