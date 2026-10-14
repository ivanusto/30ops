#!/bin/sh
# dist.sh: the release files of one commit.
#
#   scripts/dist.sh [--rev REV] [--name NAME] OUTDIR
#
# OUTDIR/30ops-NAME.tar.gz   the tree of REV (default HEAD) under 30ops-NAME/,
#                            as git archive gives it: no .git, nothing that
#                            is not committed (.pii-patterns stays out)
# OUTDIR/images.txt          every image collector/compose.yml pins, with
#                            its digest, one per line, sorted
# NAME defaults to the VERSION file of REV. The tarball is reproducible:
# git archive takes every mtime from the commit and gzip -n leaves out the
# name and time, so the same REV gives the same sha256 (release.yml builds
# it twice and compares). Prints the sha256 of both files.
set -eu
REV=HEAD
NAME=
while [ $# -gt 1 ]; do
  case "$1" in
    --rev) REV=$2; shift 2 ;;
    --name) NAME=$2; shift 2 ;;
    *) break ;;
  esac
done
OUT=${1:?usage: dist.sh [--rev REV] [--name NAME] OUTDIR}
here=$(cd "$(dirname "$0")/.." && pwd)
g() { git -C "$here" "$@"; }
commit=$(g rev-parse --verify "$REV^{commit}")
[ -n "$NAME" ] || NAME=$(g show "$commit:VERSION" | tr -d '[:space:]')
case "$NAME" in
  ''|*[!0-9A-Za-z.-]*) echo "dist.sh: bad name '$NAME'" >&2; exit 2 ;;
esac
mkdir -p "$OUT"
tgz="$OUT/30ops-$NAME.tar.gz"
g archive --format=tar --prefix="30ops-$NAME/" "$commit" | gzip -n -9 > "$tgz.tmp"
mv "$tgz.tmp" "$tgz"
g show "$commit:collector/compose.yml" | sed -n 's/^[[:space:]]*image:[[:space:]]*\([^[:space:]#]*\).*/\1/p' | LC_ALL=C sort -u > "$OUT/images.txt"
if grep -v '@sha256:[0-9a-f]\{64\}$' "$OUT/images.txt"; then
  echo "dist.sh: the images above are not pinned by digest" >&2
  exit 1
fi
(cd "$OUT" && sha256sum "30ops-$NAME.tar.gz" images.txt)
