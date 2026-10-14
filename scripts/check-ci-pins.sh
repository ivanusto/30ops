#!/bin/sh
# Fail unless what CI and the stack pull is pinned: every GitHub Action by a
# full commit SHA, every tarball a workflow downloads checked by sha256, and
# every container image in a compose file or Dockerfile pinned by digest.
# Tags can be moved by their owners; a SHA or a digest cannot.
# Adapted from ivanusto/qpkg-template scripts/check-ci-pins.sh.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FAIL=0

# 1. Actions: owner/repo@<40 hex>, optionally followed by "# vX.Y.Z".
for F in "$ROOT"/.github/workflows/*.yml "$ROOT"/.github/workflows/*.yaml; do
    [ -f "$F" ] || continue
    grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:' "$F" | while IFS= read -r LINE; do
        REF=$(echo "$LINE" | sed -E 's/.*uses:[[:space:]]*([^[:space:]#]+).*/\1/')
        case "$REF" in ./*) continue ;; esac
        if ! echo "$REF" | grep -Eq '@[0-9a-f]{40}$'; then
            echo "$(basename "$F"):${LINE%%:*}: action not pinned to a commit SHA: $REF" >&2
            exit 1
        fi
    done || FAIL=1

    # 2. Downloads: every "curl ... -o FILE" is followed by a sha256sum check of FILE.
    grep -nE 'curl[^|]*-o[[:space:]]+[^[:space:]]+' "$F" | while IFS= read -r LINE; do
        OUT=$(echo "$LINE" | sed -E 's/.*-o[[:space:]]+([^[:space:]]+).*/\1/')
        if ! grep -qF "  $OUT\" | sha256sum -c" "$F"; then
            echo "$(basename "$F"):${LINE%%:*}: download $OUT is not checked by sha256" >&2
            exit 1
        fi
    done || FAIL=1
done

# 3. Images: compose files and Dockerfiles pin by digest.
for F in $(cd "$ROOT" && git ls-files '*docker-compose*.yml' '*compose*.yml' '*Dockerfile*'); do
    grep -nE '^[[:space:]]*image:|^FROM ' "$ROOT/$F" | while IFS= read -r LINE; do
        # shellcheck disable=SC2016 # matching a literal ${ in the file
        case "$LINE" in *'${'*) continue ;; esac   # built locally, named by a variable
        echo "$LINE" | grep -Eq '@sha256:[0-9a-f]{64}' || { echo "$F:${LINE%%:*}: image not pinned by digest" >&2; exit 1; }
    done || FAIL=1
done

[ "$FAIL" -eq 0 ] && echo "CI pins: actions by SHA, downloads by sha256, images by digest"
exit "$FAIL"
