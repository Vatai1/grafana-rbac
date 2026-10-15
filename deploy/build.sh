#!/usr/bin/env bash
# Builds the Grafana fork image (run from anywhere; sources are the repo root, artifacts land in deploy/).
#   ./build.sh dev           native arch, then restarts the local docker compose stack
#   ./build.sh push [tag]    linux/amd64 image pushed as $IMAGE:<tag> and $IMAGE:latest (run `docker login` first)
#                            IMAGE defaults to vatai12/grafana-rbac, tag to <grafana version>-<commit>
#
# Frontend assets are platform independent, so they are always built natively (fast);
# only the Go binary and the base image layer differ per architecture.
set -euo pipefail
cd "$(dirname "$0")"

MODE=${1:?usage: ./build.sh dev | push [tag]}
HOST_ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
VERSION=$(jq -r .version ../package.json)
COMMIT=$(git rev-parse --short HEAD)$(git diff --quiet HEAD -- .. || echo -dirty)

case $MODE in
  dev)  ARCH=$HOST_ARCH ;;
  push) ARCH=amd64; IMAGE=${IMAGE:-vatai12/grafana-rbac}; TAG=${2:-$VERSION-$COMMIT} ;;
  *)    echo "unknown mode: $MODE" >&2; exit 1 ;;
esac

echo "==> backend linux/$ARCH ($VERSION, $COMMIT)"
(cd .. && GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build \
  -ldflags "-X main.version=$VERSION -X main.commit=$COMMIT -X main.buildBranch=$(git rev-parse --abbrev-ref HEAD)" \
  -o "deploy/bin/linux-$ARCH/grafana" ./pkg/cmd/grafana)

echo "==> frontend (native linux/$HOST_ARCH, shared by all image platforms)"
rm -rf public-build .js-out
docker build --build-arg JS_PLATFORM="linux/$HOST_ARCH" --target js-assets --output type=local,dest=.js-out ..
mv .js-out/public public-build && rm -rf .js-out

if [ "$MODE" = dev ]; then
  docker compose up -d --build
else
  echo "==> image $IMAGE:$TAG (linux/amd64)"
  docker build --platform linux/amd64 -t "$IMAGE:$TAG" -t "$IMAGE:latest" .
  docker push "$IMAGE:$TAG"
  docker push "$IMAGE:latest"
fi
