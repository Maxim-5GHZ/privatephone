#!/usr/bin/env bash
# Cross-package Go coverage gate. Fails (exit 1) when the aggregate coverage of
# the internal/... packages drops below COVER_THRESHOLD (default 80).
#
# Coverage is measured as the UNION across every package's test binary:
# `go test -coverpkg=./internal/...` instruments all internal packages in each
# binary, so naively concatenating the profiles would re-count the same blocks
# once per binary and under-report any function that runs in only some of them
# (e.g. the REST handlers exercised solely by the api tests would read ~30%
# instead of ~60%). Merging the MAX count per block across the binaries yields
# the honest "executed at least once somewhere" percentage.
set -euo pipefail
export LC_ALL=C

cd "$(dirname "$0")/../server"

THRESHOLD="${COVER_THRESHOLD:-80}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

i=0
for pkg in $(go list ./internal/...); do
    i=$((i + 1))
    if ! go test -coverpkg=./internal/... -covermode=count -coverprofile="$WORK/p$i" "$pkg" > /dev/null; then
        echo "coverage: tests failed in $pkg"
        exit 1
    fi
done

# Union-merge: keep the maximum count observed per (file, block) across binaries.
awk 'FNR == 1 && /^mode:/ { next }
     {
         if ($1 in seen) {
             if ($3 > seen[$1]) seen[$1] = $3
         } else {
             seen[$1] = $3
             stmts[$1] = $2
         }
     }
     END {
         print "mode: count"
         for (b in seen) print b, stmts[b], seen[b]
     }' "$WORK"/p* > "$WORK/merged.profile"

COV="$(go tool cover -func="$WORK/merged.profile" | awk '/^total:/ { gsub("%", "", $3); printf "%.1f", $3 }')"

echo "go coverage: ${COV}% (threshold ${THRESHOLD}%)"
if [ "$(awk -v c="$COV" -v t="$THRESHOLD" 'BEGIN { print (c >= t) ? 1 : 0 }')" != "1" ]; then
    echo "coverage gate FAILED"
    exit 1
fi
echo "coverage gate OK"