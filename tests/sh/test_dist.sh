#!/bin/sh
# scripts/dist.sh and scripts/release-check.sh: the release files are
# reproducible and usable, and only a tag that matches VERSION and has a
# CHANGELOG section is released.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
n=0
ok() { n=$((n + 1)); }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
# dist.sh packs HEAD, so the expectations come from HEAD too
V=$(git -C "$ROOT" show HEAD:VERSION | tr -d '[:space:]')

# dist.sh: the same commit gives the same bytes
sh "$ROOT/scripts/dist.sh" "$tmp/a" > "$tmp/a.sums"
sh "$ROOT/scripts/dist.sh" "$tmp/b" > "$tmp/b.sums"
cmp -s "$tmp/a.sums" "$tmp/b.sums" || fail "two builds of HEAD differ"; ok
grep -q "  30ops-$V.tar.gz$" "$tmp/a.sums" || fail "no 30ops-$V.tar.gz in $(cat "$tmp/a.sums")"; ok

# the tarball: one top directory, the commit's files, nothing else
tar tzf "$tmp/a/30ops-$V.tar.gz" > "$tmp/list"
[ "$(cut -d/ -f1 "$tmp/list" | sort -u)" = "30ops-$V" ] || fail "more than one top directory"; ok
[ "$(grep -cv '/$' "$tmp/list")" = "$(git -C "$ROOT" ls-files | wc -l)" ] || fail "file count differs from git ls-files"; ok
! grep -qE '/\.git/|\.pii-patterns$' "$tmp/list" || fail ".git or .pii-patterns in the tarball"; ok

# unpacked, it runs: the version, and the sample site validates
mkdir "$tmp/x"
tar xzf "$tmp/a/30ops-$V.tar.gz" -C "$tmp/x"
[ "$("$tmp/x/30ops-$V/bin/30ops" --version)" = "30ops $V" ] || fail "--version from the tarball"; ok
"$tmp/x/30ops-$V/bin/30ops" validate --site "$tmp/x/30ops-$V/examples/sample-site/site.yaml" --strict > /dev/null || fail "validate from the tarball"; ok

# images.txt: every compose image, each with its digest
[ "$(wc -l < "$tmp/a/images.txt")" = "$(grep -c '^[[:space:]]*image:' "$ROOT/collector/compose.yml")" ] || fail "images.txt count"; ok
! grep -v '@sha256:[0-9a-f]\{64\}$' "$tmp/a/images.txt" || fail "an image without a digest"; ok

# --name names the tarball and its directory (a release candidate)
sh "$ROOT/scripts/dist.sh" --name "$V-rc.1" "$tmp/c" > /dev/null
tar tzf "$tmp/c/30ops-$V-rc.1.tar.gz" | head -n1 | grep -q "^30ops-$V-rc.1/" || fail "--name"; ok

# release-check.sh on a copy of the checkout's VERSION and CHANGELOG
mkdir -p "$tmp/r/scripts"
cp "$ROOT/scripts/release-check.sh" "$tmp/r/scripts/"
git -C "$ROOT" show HEAD:VERSION > "$tmp/r/VERSION"
git -C "$ROOT" show HEAD:CHANGELOG.md > "$tmp/r/CHANGELOG.md"
rc() { sh "$tmp/r/scripts/release-check.sh" "$@" > "$tmp/out" 2>&1; }
rc "v$V" "$tmp/notes" || fail "v$V refused: $(cat "$tmp/out")"
{ grep -qx "prerelease=false" "$tmp/out" && grep -qx "name=$V" "$tmp/out"; } || fail "v$V outputs"; ok
{ [ -s "$tmp/notes" ] && ! grep -q '^## ' "$tmp/notes"; } || fail "notes are not the one section"; ok
{ rc "v$V-rc.1" "$tmp/notes" && grep -qx "prerelease=true" "$tmp/out"; } || fail "rc.1"; ok
head -n1 "$tmp/notes" | grep -q '^預發版本' || fail "rc notes are not marked"; ok
{ GITHUB_OUTPUT="$tmp/gh" rc "v$V" "$tmp/notes" && grep -qx "prerelease=false" "$tmp/gh"; } || fail "GITHUB_OUTPUT"; ok
for bad in "v9.9.9" "$V" "v$V-rc.0" "v$V-beta" "v$V-rc.1x"; do
  ! rc "$bad" "$tmp/notes" || fail "$bad accepted"
done; ok
sed -i "s/^## v$V（/## vX（/" "$tmp/r/CHANGELOG.md"
! rc "v$V" "$tmp/notes" || fail "accepted without a CHANGELOG section"; ok

echo "test_dist: $n ok"
