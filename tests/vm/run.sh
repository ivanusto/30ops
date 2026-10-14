#!/bin/sh
# run.sh: the v0.5 acceptance on a fresh Ubuntu 24.04 VM, from a workstation.
#
#   tests/vm/run.sh USER@VM [REV]
#
# USER has passwordless sudo on the VM (the cloud-init default user). The
# VM becomes its own collector (tests/vm/site.yaml.in with its address):
#   1. time zone, docker, compose v2, python3-yaml, git; the commit REV
#      (default HEAD) at /opt/30ops; a bare repository for the changes clone
#   2. install collector --create-volumes, then state A
#   3. install collector again: it must report 0 changes; then state B,
#      which must equal A
#   4. doctor must exit 0
#   5. install node --bundle twice: the same sha256; the bundle run twice
#      on the VM: the node-side files do not change on the second run
# Output and the two states go to $OUT (default ./vm-run).
set -eu
DEST=${1:?usage: run.sh USER@VM [REV]}
REV=${2:-HEAD}
here=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-./vm-run}
mkdir -p "$OUT"
r() { ssh -o BatchMode=yes "$DEST" "$@"; }
step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; exit 1; }
addr=${DEST#*@}

step "prepare $DEST ($(git -C "$here" rev-parse --short "$REV"))"
r 'sudo timedatectl set-timezone Asia/Taipei && sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq &&
   sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 python3-yaml git >/dev/null &&
   docker --version && docker compose version'
git -C "$here" archive --format=tar "$REV" | r 'sudo rm -rf /opt/30ops && sudo mkdir -p /opt/30ops && sudo tar x -C /opt/30ops'
sed "s/@ADDR@/$addr/" "$here/tests/vm/site.yaml.in" | r 'sudo mkdir -p /opt/30ops-site && sudo tee /opt/30ops-site/site.yaml >/dev/null'
# the changes clone's upstream: a bare repository on the VM, seeded with
# one record; root owns it and metrics reads it, which git refuses unless
# the path is a safe.directory (a real site clones over ssh or https)
r 'sudo sh -s' <<'EOF'
set -e
grep -qs 'directory = /srv/git/changes.git' /etc/gitconfig || git config --system --add safe.directory /srv/git/changes.git
if git -C /srv/git/changes.git rev-parse -q --verify refs/heads/main >/dev/null 2>&1; then exit 0; fi
rm -rf /srv/git/changes.git
git init -q --bare -b main /srv/git/changes.git
t=$(mktemp -d)
cd "$t"
git init -q -b main
mkdir changes drills
: > drills/drills.jsonl
cp /opt/30ops/changes/tests/fixtures/CR-*.md changes/
git add -A
git -c user.name=vmtest -c user.email=vmtest@example.net commit -q -m seed
git push -q /srv/git/changes.git main
chmod -R a+rX /srv/git/changes.git
rm -rf "$t"
EOF
I="cd /opt/30ops && sudo bin/30ops"
S="--site /opt/30ops-site/site.yaml"

step "install collector, first run"
r "$I install collector $S --create-volumes" | tee "$OUT/install-1.log"
r 'sudo sh -s' < "$here/tests/vm/state.sh" > "$OUT/state-a.txt"

step "install collector, second run"
r "$I install collector $S" | tee "$OUT/install-2.log"
grep -q '^30ops install collector: 0 change(s), 0 warning(s)$' "$OUT/install-2.log" || fail "the second run changed something"
r 'sudo sh -s' < "$here/tests/vm/state.sh" > "$OUT/state-b.txt"
diff -u "$OUT/state-a.txt" "$OUT/state-b.txt" || fail "state A and state B differ"
echo "state A = state B ($(wc -l < "$OUT/state-a.txt") lines)"

step "doctor"
# every target scraped at least once (the slowest job scrapes every 60 s)
# shellcheck disable=SC2016 # runs on the VM
r 'for i in $(seq 1 40); do curl -fsS "http://127.0.0.1:9090/api/v1/targets?state=active" | grep -q "\"health\":\"unknown\"" || exit 0; sleep 3; done; exit 1' \
  || fail "a target was still not scraped after 120 s"
r "$I doctor $S" | tee "$OUT/doctor.log"
grep -q ' 0 warn, 0 fail$' "$OUT/doctor.log" || fail "doctor reported a warning or a failure"

step "install node bundle, twice"
r "$I install node vm $S --bundle /tmp/b1.tar.gz >/dev/null && $I install node vm $S --bundle /tmp/b2.tar.gz >/dev/null &&
   sha256sum /tmp/b1.tar.gz /tmp/b2.tar.gz" | tee "$OUT/bundle.log"
[ "$(awk '{print $1}' "$OUT/bundle.log" | sort -u | wc -l)" = 1 ] || fail "the two bundles differ"
node_state='find /etc/systemd/journald.conf.d /etc/systemd/journal-upload.conf /etc/systemd/system/systemd-journal-upload.service.d -type f -exec stat -c "%n %a %U:%G %i %Y" {} + | sort;
  systemctl show -p ActiveEnterTimestampMonotonic --value systemd-journal-upload systemd-journald'
r 'cd /tmp && tar xzf b1.tar.gz && sudo sh 30ops-node-vm/node-install.sh' > "$OUT/node-1.log" 2>&1 || { cat "$OUT/node-1.log"; fail "node-install, first run"; }
r "sudo sh -c '$node_state'" > "$OUT/node-a.txt"
r 'cd /tmp && sudo sh 30ops-node-vm/node-install.sh' > "$OUT/node-2.log" 2>&1 || { cat "$OUT/node-2.log"; fail "node-install, second run"; }
r "sudo sh -c '$node_state'" > "$OUT/node-b.txt"
diff -u "$OUT/node-a.txt" "$OUT/node-b.txt" || fail "the second node-install changed the node"
echo "node state unchanged on the second run"
r "$I doctor $S" > "$OUT/doctor-2.log" || { cat "$OUT/doctor-2.log"; fail "doctor after node-install"; }
grep -q ' 0 fail$' "$OUT/doctor-2.log" || { cat "$OUT/doctor-2.log"; fail "doctor after node-install"; }

step "passed"
