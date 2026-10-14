#!/bin/sh
# changes-repo.sh: the upstream of a test site's changes clone, a bare
# repository at /srv/git/changes.git seeded with the fixture change records
# and an empty drills.jsonl. Root owns it and metrics reads it, which git
# refuses unless the path is a safe.directory (a real site clones over ssh
# or https). Run as root on the test host (tests/vm/run.sh pipes it over
# ssh, tests/e2e/run.sh runs it); a second run leaves an existing one.
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
git -c user.name=30ops-test -c user.email=test@example.net commit -q -m seed
git push -q /srv/git/changes.git main
chmod -R a+rX /srv/git/changes.git
rm -rf "$t"
