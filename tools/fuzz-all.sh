#!/usr/bin/env bash
# Runs every Go fuzz target in the module for $1 (default 10s) each, one target per `go test -fuzz` as Go requires.
# Targets are found with `go test -list`, so a new Fuzz* function runs in CI without editing the workflow.
set -euo pipefail
fuzztime="${1:-10s}"
# Minimizing a new interesting input may take up to Go's default 60s, past a short -fuzztime: the run then ends
# "context deadline exceeded" with nothing found. Cap it; a crasher is still written (minimized as far as it got).
minimize="${FUZZ_MINIMIZE_TIME:-5s}"
count=0
for pkg in $(go list ./...); do
  names=$(go test -list '^Fuzz' "$pkg" | grep -E '^Fuzz' | sort -u || true)
  for name in $names; do
    echo "== $pkg $name ($fuzztime)"
    # The fuzzer can fail with only "context deadline exceeded" when a worker is slow to stop at -fuzztime
    # (golang/go#56238). That is not a finding: no input is saved under testdata/fuzz. Retry such a run once; any
    # other failure, or a saved crasher, fails the job.
    out=$(mktemp)
    if ! go test -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime" -fuzzminimizetime "$minimize" "$pkg" 2>&1 | tee "$out"; then
      if grep -q 'context deadline exceeded' "$out" && ! grep -q 'Failing input written to' "$out"; then
        echo "fuzz-all: $name stopped on the fuzzer's own deadline; retrying once"
        go test -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime" -fuzzminimizetime "$minimize" "$pkg"
      else
        rm -f "$out"
        exit 1
      fi
    fi
    rm -f "$out"
    count=$((count + 1))
  done
done
if [ "$count" -eq 0 ]; then
  echo "fuzz-all: no fuzz targets found" >&2
  exit 1
fi
echo "fuzz-all: $count targets"
