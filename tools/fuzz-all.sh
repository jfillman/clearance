#!/usr/bin/env bash
# Runs every Go fuzz target in the module for $1 (default 10s) each, one target per `go test -fuzz` as Go requires.
# Targets are found with `go test -list`, so a new Fuzz* function runs in CI without editing the workflow.
set -euo pipefail
fuzztime="${1:-10s}"
count=0
for pkg in $(go list ./...); do
  names=$(go test -list '^Fuzz' "$pkg" | grep -E '^Fuzz' | sort -u || true)
  for name in $names; do
    echo "== $pkg $name ($fuzztime)"
    go test -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime" "$pkg"
    count=$((count + 1))
  done
done
if [ "$count" -eq 0 ]; then
  echo "fuzz-all: no fuzz targets found" >&2
  exit 1
fi
echo "fuzz-all: $count targets"
