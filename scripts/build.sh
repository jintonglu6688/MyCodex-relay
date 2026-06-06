#!/usr/bin/env sh
set -eu

VERSION="${1:-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

build_one() {
  GOOS="$1" GOARCH="$2" NAME="$3"
  export GOOS GOARCH
  go build -trimpath -ldflags "-s -w -X github.com/mycodex/mycodex-relay/internal/cli.Version=$VERSION" -o "$DIST/$NAME" ./cmd/mycodex-relay
  echo "Built $DIST/$NAME"
}

build_one windows amd64 mycodex-relay-windows-x64.exe
build_one linux amd64 mycodex-relay-linux-x64
build_one linux arm64 mycodex-relay-linux-arm64
build_one darwin amd64 mycodex-relay-macos-x64
build_one darwin arm64 mycodex-relay-macos-arm64
