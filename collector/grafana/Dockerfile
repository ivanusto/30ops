# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Grafana with the VictoriaLogs datasource baked in, so nothing is fetched
# from the Grafana catalog when the container starts. Both inputs are
# pinned: the base image by digest and the plugin release by sha256 (ADD
# refuses a download that does not match). Published as
# ghcr.io/ivanusto/30ops-grafana by .github/workflows/grafana-image.yml;
# ./build.sh builds the same image locally.
#
# The plugin release carries its backend for every platform, so the one
# tarball serves both amd64 and arm64.
ARG BASE=grafana/grafana:12.2.10@sha256:d2ac2dae86601550e941f7e1c0b4b7e1f21fadebfa5956ba06fe0b3a64de7cf4

FROM ${BASE} AS plugin
USER root
ADD --checksum=sha256:e100b767f19cd614ac8ac3860458a3fb33f5aa7a876e924d0340010e40d1c0d4 \
    https://github.com/VictoriaMetrics/victorialogs-datasource/releases/download/v0.32.0/victoriametrics-logs-datasource-v0.32.0.tar.gz \
    /tmp/vlogs.tar.gz
RUN mkdir /out && tar -xzf /tmp/vlogs.tar.gz -C /out

FROM ${BASE}
# /var/lib/grafana is a named volume; anything the image put there would be
# hidden by an existing volume, so plugins live elsewhere
COPY --from=plugin /out/ /opt/grafana-plugins/
ENV GF_PATHS_PLUGINS=/opt/grafana-plugins
LABEL org.opencontainers.image.source=https://github.com/ivanusto/30ops \
      org.opencontainers.image.description="Grafana 12.2.10 with the VictoriaLogs datasource 0.32.0 for 30ops" \
      org.opencontainers.image.licenses=AGPL-3.0-only
