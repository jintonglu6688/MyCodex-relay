#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

BIN="./mycodex-relay"
STATE="relay-state.db"
if [ "$#" -gt 0 ]; then
  CONFIG="$1"
  STATE="$(basename "$CONFIG" .json).db"
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
  "$BIN" local init --config "$CONFIG" --state "$STATE" --json >/dev/null
fi

"$BIN" local ensure-tenant --config "$CONFIG" --name Local --json
echo
read -r -p "Press Enter to close..."
