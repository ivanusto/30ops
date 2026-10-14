#!/bin/sh
# release-check.sh: may this tag be released, and how?
#
#   scripts/release-check.sh TAG [NOTES]
#
# TAG must be v$VERSION (a release) or v$VERSION-rc.N (a prerelease), with
# VERSION the file at the top of the checkout. CHANGELOG.md must have a
# "## v$VERSION（" section; it is written to NOTES (default
# build/release-notes.md) as the Release body, under a line that marks a
# prerelease. Prints name= and prerelease=, and appends them to
# $GITHUB_OUTPUT when that is set. Exit 1 with the reason otherwise.
set -eu
TAG=${1:?usage: release-check.sh TAG [NOTES]}
here=$(cd "$(dirname "$0")/.." && pwd)
NOTES=${2:-$here/build/release-notes.md}
die() { echo "release-check: $*" >&2; exit 1; }
v=$(tr -d '[:space:]' < "$here/VERSION")
case "$v" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "VERSION is '$v', not X.Y.Z" ;;
esac
name=${TAG#v}
case "$name" in
  "$v") pre=false ;;
  "$v"-rc.[1-9]|"$v"-rc.[1-9][0-9]) pre=true ;;
  *) die "tag $TAG is neither v$v nor v$v-rc.N (VERSION is $v)" ;;
esac
[ "$TAG" = "v$name" ] || die "tag $TAG does not start with v"
notes=$(awk -v h="## v$v（" '
  index($0, h) == 1 { on = 1; next }
  on && /^## v/ { exit }
  on { print }' "$here/CHANGELOG.md")
[ -n "$(printf '%s' "$notes" | tr -d '[:space:]')" ] || die "CHANGELOG.md has no '## v$v（' section"
mkdir -p "$(dirname "$NOTES")"
{
  [ "$pre" = true ] && printf '預發版本（release candidate），內容同 v%s 的 CHANGELOG：\n' "$v"
  printf '%s\n' "$notes" | sed '/./,$!d'
} > "$NOTES"
printf 'name=%s\nprerelease=%s\n' "$name" "$pre"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'name=%s\nprerelease=%s\n' "$name" "$pre" >> "$GITHUB_OUTPUT"
fi
