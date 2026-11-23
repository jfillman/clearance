#!/usr/bin/env bash
# Benchmarks of the clearance-cmp plugin's hot paths, this checkout against its merge base, on one machine (W-34 P4;
# docs/gate.md, "Benchmarks"). It fails when a benchmark is slower, or allocates more, than the merge base by more than
# THRESHOLD percent and benchstat finds the difference significant (p < 0.05).
#
#   tools/cmp-bench.sh BASE_REF OUT_DIR       # BASE_REF is the commit to compare with; the merge base of it and HEAD is used
#
# Environment: THRESHOLD (percent, default 25), RUNS (samples per benchmark and side, default 6), BENCHTIME (default
# 300ms), BENCHSTAT (the benchstat binary, default the one on PATH).
#
# The merge base is checked out in a worktree and the head's own test files (the benchmarks and the helpers they use)
# are copied over it, so both sides run the same benchmark code and only the product code differs. If that does not
# compile (the change renamed something the tests use), the merge base runs its own tests, and benchmarks it has not
# got are left out of the comparison with a warning. Each side's test binary is built once, then the two are run
# alternately RUNS times, so a drift of the machine's speed lands on both sides.
#
# OUT_DIR gets base.txt and head.txt (the raw benchmark output), benchstat.txt (the comparison, as benchstat prints it)
# and benchstat.csv (the same, which the check reads).
set -euo pipefail
base_ref="${1:?usage: tools/cmp-bench.sh BASE_REF OUT_DIR}"
out="${2:?usage: tools/cmp-bench.sh BASE_REF OUT_DIR}"
threshold="${THRESHOLD:-25}"
runs="${RUNS:-6}"
benchtime="${BENCHTIME:-300ms}"
benchstat="${BENCHSTAT:-benchstat}"
pkgs=(providers/argocd/cmp internal/argosrc)

root="$(git rev-parse --show-toplevel)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
: > "$out/base.txt"; : > "$out/head.txt"; : > "$out/run.log"
cd "$root"

base="$(git merge-base "$base_ref" HEAD)"
echo "head $(git rev-parse HEAD), merge base $base"
wt="$(mktemp -d)"
cleanup() { git -C "$root" worktree remove --force "$wt/base" >/dev/null 2>&1 || true; rm -rf "$wt"; }
trap cleanup EXIT
git worktree add --detach "$wt/base" "$base" >/dev/null

# The head's tests over the merge base's product code.
overlay() {
  for p in "${pkgs[@]}"; do
    rm -f "$wt/base/$p"/*_test.go
    cp "$root/$p"/*_test.go "$wt/base/$p/"
    if [ -d "$root/$p/testdata" ]; then rm -rf "$wt/base/$p/testdata"; cp -R "$root/$p/testdata" "$wt/base/$p/testdata"; fi
  done
}
overlay
overlaid=1
if ! (cd "$wt/base" && go test -c -o /dev/null "./${pkgs[0]}" && go test -c -o /dev/null "./${pkgs[1]}") >> "$out/run.log" 2>&1; then
  echo "::warning::the head's tests do not compile against the merge base; the merge base runs its own tests, and a benchmark it lacks is not compared"
  git -C "$wt/base" checkout -q -- . && git -C "$wt/base" clean -fdq
  overlaid=0
fi
echo "same benchmark code on both sides: $([ "$overlaid" = 1 ] && echo yes || echo no)"

# One test binary per side and package; each runs in its package directory (the tests' testdata is relative).
for side in base head; do
  src="$root"; [ "$side" = base ] && src="$wt/base"
  for p in "${pkgs[@]}"; do
    (cd "$src" && go test -c -o "$wt/$side-$(basename "$p").test" "./$p")
  done
done

for i in $(seq 1 "$runs"); do
  for side in base head; do
    src="$root"; [ "$side" = base ] && src="$wt/base"
    for p in "${pkgs[@]}"; do
      (cd "$src/$p" && "$wt/$side-$(basename "$p").test" -test.run '^$' -test.bench . -test.benchmem -test.benchtime "$benchtime" -test.count 1) \
        >> "$out/$side.txt" 2>> "$out/run.log"
    done
  done
  echo "sample $i of $runs done"
done

"$benchstat" "$out/base.txt" "$out/head.txt" | tee "$out/benchstat.txt"
"$benchstat" -format csv "$out/base.txt" "$out/head.txt" > "$out/benchstat.csv"

# benchstat prints a delta only where it finds one significant (p < 0.05), and "~" otherwise. The csv holds one table
# per unit: a header row names the unit, then a row per benchmark (name, old, CI, new, CI, delta, p).
awk -F, -v limit="$threshold" '
  $1 == "" && ($2 == "sec/op" || $2 == "B/op" || $2 == "allocs/op") { unit = $2; next }
  $1 == "" || $1 == "geomean" || $1 ~ /^(goos|goarch|pkg|cpu):/ || unit == "" { next }
  $2 !~ /^[0-9.eE+-]+$/ { next }
  { seen[unit]++ }
  $6 ~ /^[+-][0-9.]+%$/ {
    d = substr($6, 1, length($6) - 1) + 0
    if (d > limit && (unit == "sec/op" || unit == "allocs/op")) { printf "REGRESSION %s %s %s (%s)\n", $1, unit, $6, $7; bad++ }
  }
  END {
    if (seen["sec/op"] == 0) { print "no benchmark was compared: the two outputs share none"; exit 2 }
    printf "%d benchmarks compared; threshold +%s%% on sec/op and allocs/op at p < 0.05\n", seen["sec/op"], limit
    exit bad > 0
  }' "$out/benchstat.csv" | tee "$out/verdict.txt"
