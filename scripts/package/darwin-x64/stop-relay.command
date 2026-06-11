#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

if [ -f mycodex-relay.pid ]; then
  PID="$(cat mycodex-relay.pid)"
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
  fi
  rm -f mycodex-relay.pid
fi

pkill -f "$DIR/mycodex-relay" 2>/dev/null || true
pkill -x mycodex-relay 2>/dev/null || true

echo "MyCodex Relay stopped."
