#!/bin/sh
# e2e.sh: tests/e2e/run.sh on a throwaway VM, from a workstation.
#
#   tests/vm/e2e.sh USER@VM [REV]
#
# Builds the release tarball of REV (default HEAD) with scripts/dist.sh,
# streams it to the VM, runs the run.sh inside it with sudo and
# OPS30_E2E_DISPOSABLE=1, and fetches the evidence into $OUT (default
# ./vm-e2e). USER has passwordless sudo on the VM (the cloud-init default
# user); SSH_OPTS adds ssh options, as for tests/vm/run.sh. The VM is
# changed for good: use a fresh one for every run.
set -eu
DEST=${1:?usage: e2e.sh USER@VM [REV]}
REV=${2:-HEAD}
here=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-./vm-e2e}
# shellcheck disable=SC2086
r() { ssh -o BatchMode=yes ${SSH_OPTS:-} "$DEST" "$@"; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sh "$here/scripts/dist.sh" --rev "$REV" "$tmp"
tgz=$(basename "$tmp"/30ops-*.tar.gz)
name=${tgz%.tar.gz}
r 'rm -rf /tmp/ops30e2e-in && mkdir -p /tmp/ops30e2e-in'
r "cat > /tmp/ops30e2e-in/$tgz" < "$tmp/$tgz"
rm -rf "$OUT" && mkdir -p "$OUT"
rc=0
r "cd /tmp/ops30e2e-in && tar xzf $tgz && sudo OPS30_E2E_DISPOSABLE=1 $name/tests/e2e/run.sh /tmp/ops30e2e-in/$tgz" 2>&1 \
  | tee "$OUT/run.log" || rc=$?
r 'sudo tar c -C /var/tmp ops30e2e' | tar x -C "$OUT" || true
grep -q '^30ops e2e passed' "$OUT/ops30e2e/summary.txt" 2>/dev/null || rc=1
echo "e2e on $DEST: $( [ "$rc" = 0 ] && echo passed || echo FAILED ), evidence in $OUT"
exit "$rc"
