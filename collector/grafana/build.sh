#!/bin/sh
# Build the 30ops Grafana image locally (the Dockerfile pins the base by
# digest and the plugin by sha256) and print its ID. The published image is
# ghcr.io/ivanusto/30ops-grafana, built by .github/workflows/grafana-image.yml
# from the same Dockerfile; compose.yml refers to that one by digest.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
TAG=${TAG:-30ops/grafana:12.2.10-vlogs0.32.0}
docker build -q -t "$TAG" "$here"
docker image inspect -f '{{.Id}}  {{index .RepoTags 0}}' "$TAG"
