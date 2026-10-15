# Upstream image with the fork's backend binary and frontend assets swapped in. Built by ./build.sh.
FROM grafana/grafana:13.2.4
ARG TARGETARCH
COPY bin/linux-${TARGETARCH}/grafana /usr/share/grafana/bin/grafana
COPY public-build /usr/share/grafana/public
