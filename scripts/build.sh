#!/usr/bin/env sh
set -eu

VERSION="${1:-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"
rm -f "$DIST"/mycodex-relay-*

build_one() {
  GOOS="$1" GOARCH="$2" DIR="$3" BINARY="$4" SCRIPT_SET="${5:-}"
  export GOOS GOARCH
  TARGET_DIR="$DIST/$DIR"
  mkdir -p "$TARGET_DIR"
  go build -trimpath -ldflags "-s -w -X github.com/mycodex/mycodex-relay/internal/cli.Version=$VERSION" -o "$TARGET_DIR/$BINARY" ./cmd/mycodex-relay
  echo "Built $TARGET_DIR/$BINARY"

  if [ -n "$SCRIPT_SET" ] && [ -d "$ROOT/scripts/package/$SCRIPT_SET" ]; then
    cp "$ROOT/scripts/package/$SCRIPT_SET"/* "$TARGET_DIR/"
    case "$SCRIPT_SET" in
      darwin-*) chmod +x "$TARGET_DIR"/*.command 2>/dev/null || true ;;
      linux) chmod +x "$TARGET_DIR"/*.sh 2>/dev/null || true ;;
    esac
  fi
}

build_one windows amd64 windows-x64 mycodex-relay.exe windows-x64
build_one linux amd64 linux-x64 mycodex-relay linux
build_one linux arm64 linux-arm64 mycodex-relay linux
build_one darwin amd64 darwin-x64 mycodex-relay darwin-x64
build_one darwin arm64 darwin-arm64 mycodex-relay darwin-arm64
