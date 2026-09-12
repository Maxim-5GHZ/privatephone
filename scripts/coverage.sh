#!/usr/bin/env bash
# Cross-package Go coverage gate. Fails (exit 1) when the aggregate coverage of
# the internal/... packages drops below COVER_THRESHOLD (default 80).
set -euo pipefail
export LC_ALL=C

cd "$(dirname "$0")/../server"

THRESHOLD="${COVER_THRESHOLD:-80}"
PROFILE="$(mktemp)"
trap 'rm -f "$PROFILE"' EXIT

go test -coverpkg=./internal/... -coverprofile="$PROFILE" ./internal/... > /dev/null

COV="$(go tool cover -func="$PROFILE" | awk '/^total:/ { gsub("%", "", $3); printf "%.1f", $3 }')"

echo "go coverage: ${COV}% (threshold ${THRESHOLD}%)"
if [ "$(awk -v c="$COV" -v t="$THRESHOLD" 'BEGIN { print (c >= t) ? 1 : 0 }')" != "1" ]; then
    echo "coverage gate FAILED"
    exit 1
fi
echo "coverage gate OK"