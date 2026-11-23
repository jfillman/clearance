#!/usr/bin/env bash
# Soak test of the clearance-cmp plugin (W-34 F7): N renders of the fixtures in a loop, each its own process as the
# cmp-server starts them, on one cache directory, with the metrics server running the whole time.
#
#   tools/cmp-soak.sh BIN [N]        # N defaults to 200
#
# The inputs cycle through three chart tags (three commits) and four sets of injected values, against a chart cache
# bounded to two entries, so the chart cache evicts, the pre-render cache hits and misses, and last-known-good and the
# metrics store are written on every run. It fails on:
#   - any render that does not exit 0, or that emits other bytes than the first render of the same inputs;
#   - a render's scratch left in TMPDIR, a temporary file left in a cache, or a render step's process still running;
#   - a cache past its bounds (chart entries, pre-render entries), or a cache directory that still grows in the second
#     half of the run, when every input has been seen;
#   - the long-lived `clearance-cmp metrics` server's open files or threads growing (Linux, /proc), or its counts not
#     matching the renders made;
# and then runs 8 renders at once on the same cache, five times, and a render killed with SIGKILL mid-run (Argo CD's
# exec timeout, an OOM kill), after which the next renders must succeed with the same bytes. KEEP=1 keeps the work directory.
set -uo pipefail
bin="${1:?usage: tools/cmp-soak.sh BIN [N]}"
n="${2:-200}"
. "$(dirname "$0")/cmp-fixture.sh"

work="$(mktemp -d)"
cleanup() { [ -n "${mpid:-}" ] && kill "$mpid" 2>/dev/null; fixture_down; [ "${KEEP:-}" = 1 ] && echo "kept $work" || rm -rf "$work"; }
trap cleanup EXIT
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }

fixture_up "$work" || exit 2
cache="$work/cache"; metrics="$work/metrics"; tmp="$work/tmp"; mkdir -p "$cache" "$metrics" "$tmp" "$work/refs"
opts=(TMPDIR="$tmp" CLEARANCE_CMP_LAST_KNOWN_GOOD=on CLEARANCE_CMP_METRICS_DIR="$metrics" CLEARANCE_CMP_CHART_CACHE_MAX_ENTRIES=2)

mport="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
env -i PATH="$PATH" CLEARANCE_CMP_METRICS_DIR="$metrics" CLEARANCE_CMP_METRICS_ADDR="127.0.0.1:$mport" "$bin" metrics 2>"$work/metrics.err" &
mpid=$!
scrape() { curl -fsS "http://127.0.0.1:$mport/metrics" 2>/dev/null; }
for _ in $(seq 50); do scrape >/dev/null && break; sleep 0.1; done
proc_stat() { # PID: "fds threads", or "" without /proc
  [ -d "/proc/$1/fd" ] || return 0
  echo "$(ls "/proc/$1/fd" | wc -l | tr -d ' ') $(awk '/^Threads:/{print $2}' "/proc/$1/status")"
}
cache_bytes() { du -sk "$cache" | awk '{print $1}'; }
leftovers() { # temporary files of any cache, and a render's scratch
  find "$cache" \( -name '.tmp-*' -o -name '.trash-*' -o -name '.entry-*' \) -print 2>/dev/null
  find "$metrics" -name '.cmp-metrics-*' -print 2>/dev/null
  find "$tmp" -mindepth 1 -maxdepth 1 -print 2>/dev/null
}
steps_running() { pgrep -f 'helm template|kustomize build|__clearance-sandbox-exec' 2>/dev/null | tr '\n' ' '; }

# variant I: the tag and the injected values of render I
variant() { echo "${fx_tags[$(($1 % 3))]} {\"injected\":\"v$(($1 % 4))\"}"; }
one() { # I NAME: one render of variant I; checks its exit code and its bytes against the variant's first render
  local i="$1" name="$2" tag inj code ref
  read -r tag inj <<<"$(variant "$i")"
  code="$(fixture_render "$bin" "$cache" "$work/$name.out" "$work/$name.err" "$tag" "$inj" "${opts[@]}")"
  if [ "$code" != 0 ]; then bad "$name ($tag $inj): exit $code"; sed 's/^/     /' "$work/$name.err"; return 1; fi
  ref="$work/refs/$tag-$((i % 4)).out"
  if [ ! -s "$ref" ]; then cp "$work/$name.out" "$ref"
  elif ! cmp -s "$ref" "$work/$name.out"; then bad "$name ($tag $inj): other bytes than this variant's first render"; diff "$ref" "$work/$name.out" | head -10; return 1; fi
  return 0
}

echo "== $n renders in a loop"
start=$(date +%s)
renders=0 base_stat="" mid_bytes=0 errs=0
for i in $(seq 1 "$n"); do
  one "$i" "r" && renders=$((renders + 1)) || errs=$((errs + 1))
  [ "$errs" -gt 3 ] && { bad "stopping after $errs failed renders"; break; }
  left="$(leftovers)"; [ -z "$left" ] || { bad "render $i left: $left"; errs=$((errs + 1)); }
  running="$(steps_running)"; [ -z "$running" ] || { bad "render $i left render steps running: $running"; errs=$((errs + 1)); }
  [ "$i" = 24 ] && base_stat="$(proc_stat "$mpid")" && scrape >/dev/null
  [ "$i" = $((n / 2)) ] && mid_bytes="$(cache_bytes)"
  [ $((i % 25)) = 0 ] && scrape >/dev/null # the server is read throughout, as Prometheus would
done
echo "     $renders renders in $(( $(date +%s) - start ))s"
[ "$errs" = 0 ] && ok "$renders renders, every one exit 0 with its variant's bytes, nothing left behind after any" || bad "$errs problems in the loop"

charts="$(find "$cache/charts" -mindepth 1 -maxdepth 1 -type d -name '????????????????????????????????????????????????????????????????' | wc -l | tr -d ' ')"
[ "$charts" -le 2 ] && ok "chart cache: $charts entries (bound 2, three commits in use)" || bad "chart cache: $charts entries past its bound of 2"
prer="$(find "$cache/renders" -maxdepth 1 -name '*.json' | wc -l | tr -d ' ')"
[ "$prer" -le 12 ] && ok "pre-render cache: $prer entries for 12 distinct renders" || bad "pre-render cache: $prer entries for 12 distinct renders"
end_bytes="$(cache_bytes)"
[ "$end_bytes" -le $((mid_bytes + 64)) ] && ok "the cache directory is steady: ${mid_bytes} KiB at render $((n / 2)), ${end_bytes} KiB at the end" \
  || bad "the cache directory grew from ${mid_bytes} KiB to ${end_bytes} KiB over inputs it had all seen"
end_stat="$(proc_stat "$mpid")"
if [ -n "$base_stat" ] && [ -n "$end_stat" ]; then
  read -r f0 t0 <<<"$base_stat"; read -r f1 t1 <<<"$end_stat"
  [ "$f1" -le $((f0 + 2)) ] && [ "$t1" -le $((t0 + 4)) ] && ok "the metrics server: $f0 -> $f1 open files, $t0 -> $t1 threads" \
    || bad "the metrics server leaks: $f0 -> $f1 open files, $t0 -> $t1 threads"
else
  echo "     (no /proc: the metrics server's files and threads are not checked here)"
fi
cleared="$(scrape | sed -n 's/^clearance_cmp_renders_total{version="[^"]*",outcome="cleared"} //p' | awk '{s+=$1} END {print s+0}')"
[ "$cleared" = "$renders" ] && ok "the metrics store counted $cleared cleared renders" || bad "the metrics store counted $cleared cleared renders, $renders were made"

echo "== 8 renders at once on the same cache, five times"
par_fail=0
for round in 1 2 3 4 5; do
  pids=()
  for j in 1 2 3 4 5 6 7 8; do one $((round * 8 + j)) "p$j" & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p" || par_fail=1; done
done
left="$(leftovers)"
[ "$par_fail" = 0 ] && [ -z "$left" ] && ok "40 concurrent renders: every one exit 0 with its variant's bytes, nothing left behind" || bad "concurrent renders failed or left: $left"

echo "== a render killed with SIGKILL mid-run, then the next renders"
if command -v timeout >/dev/null; then
  # New injected values each time, so the killed run is a full render (clone or restore, helm, kustomize), not a hit.
  killed=0
  for delay in 0.02 0.05 0.1 0.2 0.4; do
    code="$(fx_wrap=(timeout -s KILL "$delay"); fixture_render "$bin" "$cache" "$work/k.out" "$work/k.err" v0.0.3 "{\"injected\":\"killed-$delay\"}" "${opts[@]}")"
    [ "$code" = 137 ] && killed=$((killed + 1))
  done
  sleep 2 # a step the killed plugin started finishes on its own; nothing waits for it
  running="$(steps_running)"; [ -z "$running" ] || bad "render steps still running after the SIGKILLs: $running"
  after_fail=0
  for i in 1 2 3 4; do one "$i" "after$i" || after_fail=1; done
  [ "$killed" -ge 1 ] || bad "no render was killed: every one finished inside its delay"
  [ "$after_fail" = 0 ] && ok "after $killed renders killed mid-run, the next renders exit 0 with the same bytes" || bad "a render after the SIGKILLs failed"
  # A killed run's scratch stays in TMPDIR (it never ran its cleanup); a later render removes it once it is older than
  # any live run can be (10 minutes). Age it, render once more, and it must be gone.
  stale="$(find "$tmp" -mindepth 1 -maxdepth 1 -name 'clearance-*' | wc -l | tr -d ' ')"
  python3 -c 'import os,sys,time; t=time.time()-3600; [os.utime(os.path.join(sys.argv[1],e),(t,t)) for e in os.listdir(sys.argv[1])]' "$tmp"
  code="$(fixture_render "$bin" "$cache" "$work/sweep.out" "$work/sweep.err" v0.0.3 '{"injected":"sweep"}' "${opts[@]}")" # a full render
  [ "$code" = 0 ] || bad "the sweeping render: exit $code"
  left="$(find "$tmp" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
  [ "$left" = 0 ] && ok "the killed runs' scratch ($stale directories) was swept by the next render once stale" || bad "$left entries left in TMPDIR after the sweep ($stale before)"
else
  echo "     (no timeout(1): the SIGKILL check is skipped here; CI runs it)"
fi

[ "$fail" = 0 ] && echo "cmp-soak: PASS" || echo "cmp-soak: FAIL"
exit "$fail"
