#!/usr/bin/env bash
# build static binaries for all target architectures.
#
# The udp / reality-udp transports are pure Go stdlib, but the browser transport
# pulls in quic-go (for real HTTP/3). Its go.mod uses `replace` to fetch the
# golang.org/x/* modules from their GitHub mirrors, because some networks block
# the golang.org vanity hosts. So the build resolves modules directly from GitHub
# (GOPROXY=direct) rather than a module proxy. GitHub must be reachable.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
VERSION=${1:-dev}
export GOFLAGS=-mod=mod
export GOPROXY=${GOPROXY:-direct}
export GOSUMDB=off
export GOTOOLCHAIN=local
for t in linux/amd64 linux/arm64 linux/arm; do
  os=${t%/*}; arch=${t#*/}
  echo "building $os/$arch ..."
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" \
    -o "dist/tvtunx-$os-$arch" ./cmd/tvtunx
done
echo "done:"; ls -la dist/
