#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

BIN="./mycodex-relay"
if [ "$#" -gt 0 ]; then
  CONFIG="$1"
elif [ -f relay-config.local.json ]; then
  CONFIG="relay-config.local.json"
else
  CONFIG="relay-config.json"
fi

if [ ! -f "$BIN" ]; then
  echo "mycodex-relay not found in $DIR."
  read -r -p "Press Enter to close..."
  exit 1
fi

chmod +x "$BIN" 2>/dev/null || true

if [ ! -f "$CONFIG" ]; then
  echo "$CONFIG not found. Creating default config..."
  "$BIN" configure --config "$CONFIG" --state relay-state.db
  echo
fi

"$BIN" info --config "$CONFIG" --ensure-tenant --tenant-name Local
echo
read -r -p "Press Enter to close..."
