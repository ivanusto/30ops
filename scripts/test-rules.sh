#!/bin/sh
# Run promtool on the alert rules as Prometheus gets them: render a site
# (the sample site by default, which overrides no threshold), then check
# the rendered rules and run collector/tests/rules_*test.yml against them.
# The test files name their rules as rules/<file>.yml, next to which they
# are copied.
#
#   scripts/test-rules.sh [SITE_YAML]
#
# PROMTOOL names the promtool to run (default: promtool on PATH); it is
# run from inside the rendered prometheus directory.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
site=${1:-$here/examples/sample-site/site.yaml}
promtool=${PROMTOOL:-promtool}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$here/bin/30ops" render --site "$site" --out "$tmp" > /dev/null
cd "$tmp/etc/30ops/prometheus"
cp "$here"/collector/tests/rules_*test.yml .
# shellcheck disable=SC2086 # PROMTOOL may be a command with arguments
$promtool check rules rules/*.yml
# shellcheck disable=SC2086
$promtool test rules rules_*test.yml
