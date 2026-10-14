# Grafana with the VictoriaLogs datasource baked in, so nothing is fetched
# from the Grafana catalog when the container starts. Both inputs are pinned:
# the base image by digest (same one onprem-metrics uses) and the plugin by
# the sha256 that fetch-plugin.sh checks. Build with ./build.sh.
FROM grafana/grafana:13.2.3@sha256:b28bae15e219c998fb0e0424ed724930cc61b1f61fb404d47c862f9a23f9e572
# /var/lib/grafana is a named volume in onprem-metrics; anything the image
# put there would be hidden by the existing volume, so plugins live elsewhere
COPY plugins/ /opt/grafana-plugins/
ENV GF_PATHS_PLUGINS=/opt/grafana-plugins
