#!/usr/bin/env sh
set -eu

VERSION="${1:-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
case "$VERSION" in
  ""|*[!A-Za-z0-9._-]*)
    echo "Version may contain only letters, numbers, dots, underscores, and hyphens." >&2
    exit 1
    ;;
esac

mkdir -p "$DIST"
case "$DIST" in
  "$ROOT/dist") ;;
  *)
    echo "Unsafe dist directory: $DIST" >&2
    exit 1
    ;;
esac
rm -rf \
  "$DIST/windows-x64" \
  "$DIST/linux-x64" \
  "$DIST/linux-arm64" \
  "$DIST/darwin-x64" \
  "$DIST/darwin-arm64" \
  "$DIST/macos-intel" \
  "$DIST/macos-apple-silicon"
rm -f "$DIST"/mycodex-relay-*.zip "$DIST"/mycodex-relay-*.tar.gz "$DIST/SHA256SUMS.txt"

build_one() {
  GOOS="$1" GOARCH="$2" DIR="$3" BINARY="$4" SCRIPT_SET="$5" DOC_SET="$6" FORMAT="$7"
  export GOOS GOARCH
  TARGET_DIR="$DIST/$DIR"
  mkdir -p "$TARGET_DIR"
  go build -trimpath -ldflags "-s -w -X github.com/mycodex/mycodex-relay/internal/cli.Version=$VERSION" -o "$TARGET_DIR/$BINARY" ./cmd/mycodex-relay
  echo "Built $TARGET_DIR/$BINARY"

  cp "$ROOT/resources/release/common/README.md" "$TARGET_DIR/"
  cp "$ROOT/resources/release/$DOC_SET/DEPLOYMENT.md" "$TARGET_DIR/"
  printf '%s\n' "$VERSION" >"$TARGET_DIR/VERSION.txt"

  if [ -n "$SCRIPT_SET" ] && [ -d "$ROOT/scripts/package/$SCRIPT_SET" ]; then
    cp "$ROOT/scripts/package/$SCRIPT_SET"/* "$TARGET_DIR/"
    case "$SCRIPT_SET" in
      darwin-*) chmod +x "$TARGET_DIR"/*.command 2>/dev/null || true ;;
      linux) chmod +x "$TARGET_DIR"/*.sh 2>/dev/null || true ;;
    esac
  fi

  for REQUIRED in "$BINARY" README.md DEPLOYMENT.md VERSION.txt; do
    [ -f "$TARGET_DIR/$REQUIRED" ] || {
      echo "Package $DIR is missing $REQUIRED" >&2
      exit 1
    }
  done

  ARCHIVE_BASE="mycodex-relay-$VERSION-$DIR"
  case "$FORMAT" in
    zip)
      command -v zip >/dev/null 2>&1 || {
        echo "zip is required to build the Windows release package" >&2
        exit 1
      }
      (cd "$DIST" && zip -qr "$ARCHIVE_BASE.zip" "$DIR")
      ARCHIVE="$DIST/$ARCHIVE_BASE.zip"
      zip -T "$ARCHIVE" >/dev/null
      ;;
    tar.gz)
      ARCHIVE="$DIST/$ARCHIVE_BASE.tar.gz"
      tar -C "$DIST" -czf "$ARCHIVE" "$DIR"
      tar -tzf "$ARCHIVE" >/dev/null
      ;;
    *)
      echo "Unknown archive format: $FORMAT" >&2
      exit 1
      ;;
  esac
  [ -s "$ARCHIVE" ] || {
    echo "Package archive was not created: $ARCHIVE" >&2
    exit 1
  }
  echo "Packaged $ARCHIVE"
}

build_one windows amd64 windows-x64 mycodex-relay.exe windows-x64 windows zip
build_one linux amd64 linux-x64 mycodex-relay linux linux tar.gz
build_one linux arm64 linux-arm64 mycodex-relay linux linux tar.gz
build_one darwin amd64 macos-intel mycodex-relay darwin-x64 macos tar.gz
build_one darwin arm64 macos-apple-silicon mycodex-relay darwin-arm64 macos tar.gz

(
  cd "$DIST"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum mycodex-relay-*.zip mycodex-relay-*.tar.gz
  else
    shasum -a 256 mycodex-relay-*.zip mycodex-relay-*.tar.gz
  fi
) >"$DIST/SHA256SUMS.txt"
[ "$(wc -l <"$DIST/SHA256SUMS.txt" | tr -d ' ')" -eq 5 ] || {
  echo "Expected 5 checksums in SHA256SUMS.txt" >&2
  exit 1
}
echo "Wrote $DIST/SHA256SUMS.txt"
