#!/usr/bin/env bash
# Upgrade test of the clearance-cmp plugin (W-34 F7): the previous release's binary and this build's, on the same cache
# directory and metrics store, as a sidecar's /tmp emptyDir and metrics volume see them when the image is re-pinned and
# the container restarts (the volume outlives the container).
#
#   tools/cmp-upgrade.sh OLD_BIN NEW_BIN
#
# OLD_BIN is the latest released clearance-cmp (built from the newest v* tag before this one), NEW_BIN this build; each
# built with its own -X main.pluginVersion, so their pre-render keys and metrics series differ as two images' do. The
# fixture is tools/cmp-fixture.sh: a real git checkout, a chart served over git://, the fake core, real helm and kustomize.
# It asserts that:
#   1. the old binary fills every cache: the chart cache, the pre-render cache, the tree cache, last-known-good and the
#      metrics store (so the rest is not vacuous);
#   2. the new binary, on that cache, exits 0 and emits the same manifests as the old one, byte for byte; it reuses the
#      old chart cache entry or ignores it safely (reported); it does not serve the old binary's pre-render entry (the
#      key holds the plugin's version);
#   3. its own pre-render cache then answers, and with a cold cache it emits the same bytes again;
#   4. the metrics store is read, not reset: the old version's counts are kept beside the new one's;
#   5. rolling back, the old binary on the cache the new one wrote exits 0 with the same manifests;
#   6. with the chart host down, the new binary serves the old binary's last-known-good entry (the key leaves the
#      plugin's version out on purpose) after the core confirms it.
# ALLOW_OUTPUT_CHANGE=1 turns check 2's comparison of the old and new manifests into a warning, for a release whose
# notes say its output changes on purpose. KEEP=1 keeps the work directory.
set -uo pipefail
old="${1:?usage: tools/cmp-upgrade.sh OLD_BIN NEW_BIN}"
new="${2:?usage: tools/cmp-upgrade.sh OLD_BIN NEW_BIN}"
. "$(dirname "$0")/cmp-fixture.sh"

work="$(mktemp -d)"
cleanup() { fixture_down; [ "${KEEP:-}" = 1 ] && echo "kept $work" || rm -rf "$work"; }
trap cleanup EXIT
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
show() { sed 's/^/     /' "$1"; }

fixture_up "$work" || exit 2
cache="$work/cache"; metrics="$work/metrics"; mkdir -p "$cache" "$metrics"
inj='{"injected":"from-platform"}'
opts=(CLEARANCE_CMP_LAST_KNOWN_GOOD=on CLEARANCE_CMP_METRICS_DIR="$metrics")
render() { # BIN NAME [CACHE [VAR=VALUE ...]]: echoes the exit code
  local bin="$1" name="$2" c="${3:-$cache}"
  shift $(($# < 3 ? $# : 3))
  fixture_render "$bin" "$c" "$work/$name.out" "$work/$name.err" v0.0.1 "$inj" "${opts[@]}" "$@"
}
same() { cmp -s "$work/$1.out" "$work/$2.out"; }

echo "== old ($old): fills the caches"
code="$(render "$old" old1)"; show "$work/old1.err"
[ "$code" = 0 ] && [ -s "$work/old1.out" ] && ok "old: first render exit 0, $(wc -c < "$work/old1.out") bytes" || bad "old: first render exit $code"
grep -q 'chart-cache=miss' "$work/old1.err" && ok "old: the chart was fetched and kept" || bad "old: no chart-cache=miss"
code="$(render "$old" old2)"; show "$work/old2.err"
[ "$code" = 0 ] && same old1 old2 && grep -q 'serving the cleared render' "$work/old2.err" && ok "old: the second render is a pre-render hit, same bytes" || bad "old: the second render was not a pre-render hit (exit $code)"
count() { find "$1" -maxdepth 1 -name "$2" 2>/dev/null | wc -l | tr -d ' '; }
charts="$(find "$cache/charts" -mindepth 1 -maxdepth 1 -type d -name '????????????????????????????????????????????????????????????????' | wc -l | tr -d ' ')"
renders="$(count "$cache/renders" '*.json')"; lkg="$(count "$cache/lkg" '*.json')"; trees="$(count "$cache" '*.json')"
[ "$charts" -ge 1 ] && [ "$renders" -ge 1 ] && [ "$lkg" -ge 1 ] && [ "$trees" -ge 1 ] && [ -s "$metrics/cmp-metrics.json" ] \
  && ok "old filled every cache: $charts chart, $renders pre-render, $lkg last-known-good, $trees tree entries, the metrics store" \
  || bad "old did not fill every cache: $charts chart, $renders pre-render, $lkg last-known-good, $trees tree, metrics $(ls "$metrics")"
cp -R "$cache" "$work/cache-old" # the state the old binary left, for the last-known-good check

echo "== new on the old binary's cache"
code="$(render "$new" new1)"; show "$work/new1.err"
[ "$code" = 0 ] && [ -s "$work/new1.out" ] && ok "new: exit 0 on the old cache" || bad "new: exit $code on the old cache"
if same old1 new1; then ok "new emits the old binary's manifests, byte for byte"
elif [ "${ALLOW_OUTPUT_CHANGE:-}" = 1 ]; then echo "WARN the manifests differ from the old release's (ALLOW_OUTPUT_CHANGE=1)"; diff "$work/old1.out" "$work/new1.out" | head -20
else bad "the manifests differ from the old release's:"; diff "$work/old1.out" "$work/new1.out" | head -20; fi
grep -q 'serving the cleared render' "$work/new1.err" && bad "new served the old binary's pre-render entry: the key must hold the plugin version" || ok "new did not serve the old binary's pre-render entry"
how="$(sed -n 's/.*chart-cache=\([a-z]*\).*/\1/p' "$work/new1.err" | head -1)"
case "$how" in
  hit) ok "new reused the old chart cache entry (chart-cache=hit)";;
  miss) ok "new ignored the old chart cache entry and fetched again (chart-cache=miss): safe, a cache format change";;
  *) bad "new reported chart-cache=$how";;
esac
code="$(render "$new" new2)"
[ "$code" = 0 ] && same new1 new2 && grep -q 'serving the cleared render' "$work/new2.err" && ok "new's own pre-render entry answers its next render" || bad "new's second render was not a pre-render hit (exit $code)"
code="$(render "$new" cold "$work/cache-cold")"
[ "$code" = 0 ] && same new1 cold && ok "new with a cold cache emits the same bytes" || bad "new with a cold cache: exit $code or other bytes"

echo "== the metrics store, read by the new binary's server"
mport="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
env -i PATH="$PATH" CLEARANCE_CMP_METRICS_DIR="$metrics" CLEARANCE_CMP_METRICS_ADDR="127.0.0.1:$mport" "$new" metrics 2>"$work/metrics.err" &
mpid=$!
scrape=""
for _ in $(seq 50); do scrape="$(curl -fsS "http://127.0.0.1:$mport/metrics" 2>/dev/null)" && break; sleep 0.1; done
kill "$mpid" 2>/dev/null; wait "$mpid" 2>/dev/null
echo "$scrape" | grep -E '^clearance_cmp_(renders_total|metrics_store_up|metrics_store_resets_total)' | sed 's/^/     /'
echo "$scrape" | grep -q '^clearance_cmp_metrics_store_up 1$' && ok "the new server reads the store" || bad "store_up is not 1"
echo "$scrape" | grep -Eq '^clearance_cmp_metrics_store_resets_total 0$' && ok "the store was not reset" || bad "the store was reset (or the series is missing)"
oldv="$(echo "$scrape" | sed -n 's/^clearance_cmp_renders_total{version="\([^"]*\)",outcome="cleared"} 2$/\1/p' | head -1)"
newv="$(echo "$scrape" | sed -n 's/^clearance_cmp_renders_total{version="\([^"]*\)",outcome="cleared"} 3$/\1/p' | head -1)"
[ -n "$oldv" ] && [ -n "$newv" ] && [ "$oldv" != "$newv" ] && ok "both versions are counted: $oldv 2 runs, $newv 3 runs" || bad "the per-version counts are not the old 2 and the new 3"

echo "== rollback: the old binary on the cache the new one wrote"
code="$(render "$old" back)"; show "$work/back.err"
[ "$code" = 0 ] && same old1 back && ok "old after new: exit 0, same bytes" || bad "old after new: exit $code or other bytes"

echo "== last-known-good across the upgrade: the chart host is down"
kill "$fx_daemon_pid" 2>/dev/null; wait "$fx_daemon_pid" 2>/dev/null
code="$(render "$new" lkg "$work/cache-old")"; show "$work/lkg.err"
[ "$code" = 0 ] && grep -q 'LAST-KNOWN-GOOD served' "$work/lkg.err" && same old1 lkg && ok "new served the old binary's last-known-good render, same bytes" || bad "new did not serve the old last-known-good entry (exit $code)"

[ "$fail" = 0 ] && echo "cmp-upgrade: PASS" || echo "cmp-upgrade: FAIL"
exit "$fail"
