#!/usr/bin/env bash
# Dev loop without Docker:
#   rebuild UI once for the embed, then run Go server (:8080) + Vite (:5173).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-8080}"
DATA="$ROOT/data"
KEY="$DATA/pp.key"

cleanup() { kill "$SERVER_PID" "$FRONT_PID" 2>/dev/null || true; }
trap cleanup EXIT

# 1. master/admin keys first run + USB flag
if [ ! -f "$KEY" ] || [ ! -f "$DATA/admin.pem" ]; then
  echo "[dev] no keys yet, running init (keys go to $DATA)"
  (cd server && go run ./cmd/server init -key "$KEY" -data "$DATA" -admin-out "$DATA/admin.pem")
fi

# 2. UI embed (only if not built yet)
if [ ! -d "server/internal/web/dist/assets" ]; then
  echo "[dev] building frontend into the embed"
  (cd frontend && npm install && npm run build)
  rm -rf server/internal/web/dist/*
  cp -r frontend/dist/* server/internal/web/dist/
fi

# 3. offline placeholder tiles for the sample embed
(cd server && go run ./cmd/gentiles)

# 4. run Go backend
echo "[dev] backend  http://localhost:$PORT"
(cd server && go run ./cmd/server run -port ":$PORT" -data "$DATA" -key "$KEY" -watch=false) &
SERVER_PID=$!

# give the watcher a moment, then the watcher will fail if key vanished
sleep 1

# 5. run Vite
echo "[dev] frontend http://localhost:5173"
(cd frontend && npm run dev) &
FRONT_PID=$!

wait