#!/bin/sh
# smoke-change-mark: begin and end against a fake Grafana (a few lines of
# python answering /api/annotations) and a fake amtool, so the script's
# plumbing is exercised without a collector.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'kill $gpid 2>/dev/null || true; rm -rf "$tmp"' EXIT
port=18300

cat > "$tmp/grafana.py" <<'EOF'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
log = open(sys.argv[2], "a")
class H(BaseHTTPRequestHandler):
    def _body(self): return self.rfile.read(int(self.headers.get("Content-Length", 0)))
    def do_POST(self):
        b = self._body(); log.write(f"POST {self.path} {self.headers.get('Authorization')} {b.decode()}\n"); log.flush()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"message": "Annotation added", "id": 42}).encode())
    def do_PATCH(self):
        b = self._body(); log.write(f"PATCH {self.path} {b.decode()}\n"); log.flush()
        self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
python3 "$tmp/grafana.py" "$port" "$tmp/grafana.log" & gpid=$!
sleep 1
cat > "$tmp/amtool" <<'EOF'
#!/bin/sh
echo "$@" >> "${AMTOOL_LOG}"
case "$*" in *"silence add"*) echo 123e4567-e89b-12d3-a456-426614174000 ;; *"silence expire"*) exit 0 ;; esac
EOF
chmod +x "$tmp/amtool"
printf 'fake-token\n' > "$tmp/grafana.token"

# A fake logger too: the real one writes to this host's journal, which on a
# site like Day 21's is uploaded, and a test run would then show up in a
# VictoriaLogs search for the record id.
cat > "$tmp/logger" <<'EOF'
#!/bin/sh
echo "$@" >> "${LOGGER_LOG}"
EOF
chmod +x "$tmp/logger"

export CHANGES_DIR="$here/tests/fixtures" LOGGER="$tmp/logger" LOGGER_LOG="$tmp/logger.log" STATE_DIR="$tmp/state" GRAFANA_URL="http://127.0.0.1:$port" \
       GRAFANA_TOKEN_FILE="$tmp/grafana.token" AMTOOL="$tmp/amtool" AMTOOL_LOG="$tmp/amtool.log"

sh "$here/scripts/change-mark.sh" begin CR-2026-0001 > "$tmp/begin.out"
grep -q 'grafana: annotation 42' "$tmp/begin.out" || { cat "$tmp/begin.out"; exit 1; }
grep -q 'alertmanager: silence 123e4567-e89b-12d3-a456-426614174000 until 2026-10-11T23:00:00+08:00' "$tmp/begin.out" || { cat "$tmp/begin.out"; exit 1; }
grep -q 'POST /api/annotations Bearer fake-token {"time":[0-9]*,"tags":\["change","CR-2026-0001"\],"text":"CR-2026-0001 begin: ' "$tmp/grafana.log" || { cat "$tmp/grafana.log"; exit 1; }
grep -q 'silence add alertname=PveQdeviceAbsent --end=2026-10-11T23:00:00+08:00 --author=change-mark --comment=CR-2026-0001 ' "$tmp/amtool.log" || { cat "$tmp/amtool.log"; exit 1; }
[ "$(cat "$tmp/state/CR-2026-0001.state")" = "$(printf 'annotation=42\nsilence=123e4567-e89b-12d3-a456-426614174000')" ] || { cat "$tmp/state/CR-2026-0001.state"; exit 1; }

sh "$here/scripts/change-mark.sh" end CR-2026-0001 > "$tmp/end.out"
grep -q 'grafana: annotation 42 closed' "$tmp/end.out" || { cat "$tmp/end.out"; exit 1; }
grep -q 'alertmanager: silence 123e4567-e89b-12d3-a456-426614174000 expired' "$tmp/end.out" || { cat "$tmp/end.out"; exit 1; }
grep -q 'PATCH /api/annotations/42 {"timeEnd":[0-9]*}' "$tmp/grafana.log" || { cat "$tmp/grafana.log"; exit 1; }
grep -q 'silence expire 123e4567-e89b-12d3-a456-426614174000' "$tmp/amtool.log" || { cat "$tmp/amtool.log"; exit 1; }
[ ! -e "$tmp/state/CR-2026-0001.state" ] || { echo "state file should be gone after end"; exit 1; }

# no token: the journal line still happens, the rest is reported, exit 1
rc=0; GRAFANA_TOKEN_FILE="$tmp/missing" sh "$here/scripts/change-mark.sh" begin CR-2026-0001 > "$tmp/notok.out" 2>&1 || rc=$?
[ "$rc" = 1 ] || { echo "missing token: expected exit 1, got $rc"; cat "$tmp/notok.out"; exit 1; }
grep -q 'change-mark: CR-2026-0001 begin recorded in the journal' "$tmp/notok.out" || { cat "$tmp/notok.out"; exit 1; }
# the journal line came first every time: begin, end, and the begin without a token
[ "$(grep -c '^-t change -p notice CR-2026-0001 ' "$tmp/logger.log")" = 3 ] || { cat "$tmp/logger.log"; exit 1; }
# unknown id
rc=0; sh "$here/scripts/change-mark.sh" begin CR-2099-0001 >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || { echo "unknown record: expected 2, got $rc"; exit 1; }
echo "smoke-change-mark: OK"
