#!/usr/bin/env bash
# Smoke test of the BUILT clearance-cmp image, run the way Argo CD runs the plugin (I-38: 0.52.0 passed every unit
# test, which fake git and helm and pass an absolute directory, and refused every value file on the first real run,
# because the plugin runs with the source directory ".").
#
#   tools/cmp-smoke.sh IMAGE
#
# It builds nothing (the workflow builds IMAGE from providers/argocd/cmp/Dockerfile). It creates, on disk:
#   - a gitops checkout with real value files (hangar-smoke/base.yaml, hangar-smoke/dev/values.yaml, release.yaml) and
#     a kustomize directory;
#   - a second checkout whose values.yaml is a symlink to a file outside it (must be refused);
#   - a chart repository served by `git daemon` (git://), the only kind of source the plugin's allow list accepts
#     that needs no network beyond this machine;
#   - tools/cmpsmoke, a fake Clearance core that answers the register call as "cleared".
# and runs the image's clearance-cmp (plugin.yaml's generate command) with cwd = the checkout, the environment Argo CD
# sets (ARGOCD_APP_*, PARAM_*, KUBE_*), the sidecar's uid 999, a read-only root filesystem, a tmpfs /tmp, no
# capabilities and the token mounted read-only, as apron renders the sidecar.
#
# Environment: ENGINE (docker, default; `container` works too), HOST_ADDR (127.0.0.1: where the container reaches this
# machine; with the default `--network host` that is loopback), BIND_ADDR (defaults to HOST_ADDR), NET_ARGS (default
# "--network host"), TMPFS_OPT (default "/tmp:rw,mode=1777"), KEEP=1 keeps the work directory.
set -uo pipefail

image="${1:?usage: tools/cmp-smoke.sh IMAGE}"
engine="${ENGINE:-docker}"
host="${HOST_ADDR:-127.0.0.1}"
bind="${BIND_ADDR:-$host}"
net_args="${NET_ARGS---network host}"
tmpfs_opt="${TMPFS_OPT:-/tmp:rw,mode=1777}"
root="$(cd "$(dirname "$0")/.." && pwd)"
git_id=(-c user.name=smoke -c user.email=smoke@example.test -c commit.gpgsign=false -c tag.gpgsign=false)

work="$(mktemp -d)"
chmod 755 "$work" # mktemp makes it 0700; the container runs as uid 999 and must read the checkouts
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && { kill "$p"; wait "$p"; } 2>/dev/null; done
  [ "${KEEP:-}" = 1 ] && echo "kept $work" || rm -rf "$work"
}
trap cleanup EXIT

fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
write() { mkdir -p "$(dirname "$1")"; cat > "$1"; }

# The tool versions the image must ship are the Dockerfile's own: one place to move them.
want_helm="$(sed -n 's/^ARG HELM_VERSION=//p' "$root/providers/argocd/cmp/Dockerfile")"
want_kustomize="$(sed -n 's/^ARG KUSTOMIZE_VERSION=//p' "$root/providers/argocd/cmp/Dockerfile")"
[ -n "$want_helm" ] && [ -n "$want_kustomize" ] || { echo "cannot read the tool versions from the Dockerfile"; exit 2; }

# ---- the chart repository, served over git:// -------------------------------------------------------------------
chart_src="$work/chart-src"
write "$chart_src/charts/app/Chart.yaml" <<'Y'
apiVersion: v2
name: app
version: 0.0.1
Y
write "$chart_src/charts/app/templates/configmap.yaml" <<'Y'
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-config
  labels:
    app.kubernetes.io/managed-by: {{ .Release.Service }}
data:
  base: {{ .Values.base | quote }}
  env: {{ .Values.envValue | quote }}
  tag: {{ .Values.image.tag | quote }}
  injected: {{ .Values.injected | quote }}
Y
write "$chart_src/charts/app/values.yaml" <<'Y'
base: unset
envValue: unset
injected: unset
image: {tag: unset}
Y
git -C "$chart_src" init -q -b main
git -C "$chart_src" add .
git -C "$chart_src" "${git_id[@]}" commit -q -m chart
git -C "$chart_src" "${git_id[@]}" tag v0.0.1
mkdir -p "$work/repos"
git clone -q --bare "$chart_src" "$work/repos/chart.git"
chmod -R a+rX "$work/repos"

gitport="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
git daemon --reuseaddr --export-all --base-path="$work/repos" --listen="$bind" --port="$gitport" >/dev/null 2>"$work/daemon.log" &
pids+=($!)
chart_url="git://$host:$gitport/chart.git"

# ---- the fake core ------------------------------------------------------------------------------------------------
(cd "$root" && go build -o "$work/stub" ./tools/cmpsmoke) || { echo "cannot build the fake core"; exit 2; }
"$work/stub" -listen "$bind:0" -log "$work/register.log" -port-file "$work/stub.port" 2>"$work/stub.err" &
pids+=($!)
for _ in $(seq 50); do [ -s "$work/stub.port" ] && break; sleep 0.1; done
[ -s "$work/stub.port" ] || { echo "the fake core did not start"; cat "$work/stub.err"; exit 2; }
core_url="http://$host:$(cat "$work/stub.port")"
printf 'smoke-token' > "$work/token"; chmod 644 "$work/token"
for _ in $(seq 50); do (exec 3<>"/dev/tcp/$host/$gitport") 2>/dev/null && break; sleep 0.1; done

# ---- the gitops checkouts ---------------------------------------------------------------------------------------
mkcheckout() { # DIR
  local d="$1"
  write "$d/hangar-smoke/base.yaml" <<'Y'
base: from-base
releaseTracking: {releaseId: rel-smoke-1}
Y
  write "$d/hangar-smoke/dev/values.yaml" <<'Y'
envValue: from-env-values
Y
  write "$d/hangar-smoke/dev/release.yaml" <<'Y'
image: {tag: "1.2.3"}
Y
  write "$d/configmap/kustomization.yaml" <<'Y'
namePrefix: kz-
resources: [cm.yaml]
Y
  write "$d/configmap/cm.yaml" <<'Y'
apiVersion: v1
kind: ConfigMap
metadata: {name: extra}
data: {from: kustomize}
Y
}
good="$work/gitops-good"; mkcheckout "$good"
link="$work/gitops-link"; mkcheckout "$link"
# A value file that is a symlink to a file outside the checkout (a stand-in for a service-account token).
rm "$link/hangar-smoke/dev/values.yaml"; ln -s /etc/passwd "$link/hangar-smoke/dev/values.yaml"
for d in "$good" "$link"; do
  git -C "$d" init -q -b main; git -C "$d" add .; git -C "$d" "${git_id[@]}" commit -q -m gitops
done
chmod -R a+rX "$work/gitops-good" "$work/gitops-link"

# ---- the image's tools --------------------------------------------------------------------------------------------
tools_out="$("$engine" run --rm --entrypoint sh "$image" -c 'command -v helm; helm version --template "{{.Version}}"; echo; command -v kustomize; kustomize version; command -v clearance-cmp' 2>&1)"
echo "$tools_out" | sed 's/^/     image: /'
echo "$tools_out" | grep -qx '/usr/local/bin/helm' && echo "$tools_out" | grep -qx '/usr/local/bin/kustomize' || bad "helm and kustomize are not the image's /usr/local/bin binaries"
echo "$tools_out" | grep -qxF "$want_helm" && ok "the image ships helm $want_helm" || bad "the image's helm is not $want_helm"
echo "$tools_out" | grep -qxF "$want_kustomize" && ok "the image ships kustomize $want_kustomize" || bad "the image's kustomize is not $want_kustomize"

# ---- the canary plugin config baked into the image (docs/gate.md, "Rolling out a plugin release") ---------------------
# A second sidecar is started with --config-dir-path /home/argocd/cmp-server/config-canary: that directory's plugin.yaml
# must be in the BUILT image, be the same plugin (name clearance, the same generate command) with version canary, so it
# registers as clearance-canary; and the default plugin.yaml must still have no version (its name stays clearance).
echo "== canary plugin config in the image"
cfg_dir=/home/argocd/cmp-server
strip() { grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$'; }
def_cfg="$("$engine" run --rm --entrypoint cat "$image" "$cfg_dir/config/plugin.yaml" 2>&1)"
can_cfg="$("$engine" run --rm --entrypoint cat "$image" "$cfg_dir/config-canary/plugin.yaml" 2>&1)"
echo "$can_cfg" | grep -q 'kind: ConfigManagementPlugin' && ok "config-canary/plugin.yaml exists in the image and is a ConfigManagementPlugin" || bad "config-canary/plugin.yaml is missing or not a plugin: $can_cfg"
echo "$can_cfg" | grep -qx '  name: clearance' && ok "the canary plugin's metadata.name is clearance" || bad "the canary plugin's metadata.name is not clearance"
echo "$can_cfg" | grep -qx '  version: canary' && ok "the canary plugin's spec.version is canary (so it is clearance-canary)" || bad "the canary plugin's spec.version is not canary"
echo "$def_cfg" | grep -q 'version:' && bad "the default plugin.yaml has a version: its name would no longer be clearance" || ok "the default plugin.yaml has no version (its name stays clearance)"
echo "$can_cfg" | grep -qF 'command: [/usr/local/bin/clearance-cmp]' && echo "$def_cfg" | grep -qF 'command: [/usr/local/bin/clearance-cmp]' \
  && ok "both generate commands are /usr/local/bin/clearance-cmp" || bad "a generate command is not /usr/local/bin/clearance-cmp"
[ "$(echo "$def_cfg" | strip)" = "$(echo "$can_cfg" | strip | grep -vx '  version: canary')" ] && ok "the two plugin files differ only by the version" || bad "the canary plugin.yaml differs from the default beyond its version"

# ---- run the plugin as Argo CD does -----------------------------------------------------------------------------
default_injected='{"injected":"from-platform"}'
metrics_args=() # set by the metrics section: the store's volume and CLEARANCE_CMP_METRICS_DIR
run_plugin() { # CHECKOUT OUT ERR [CACHE_DIR [VALUESJSON]] : echoes the exit code. CACHE_DIR is a host directory mounted
  # as the plugin's cache directory, so that two runs share it as two renders in one sidecar's /tmp do.
  local dir="$1" out="$2" err="$3" cachedir="${4:-}" injected="${5:-$default_injected}" rev cache_mount=()
  [ -n "$cachedir" ] && cache_mount=(-v "$cachedir:/tmp/clearance-cmp-cache")
  rev="$(git -C "$dir" rev-parse HEAD)"
  # shellcheck disable=SC2086
  "$engine" run --rm $net_args --user 999:999 --read-only --tmpfs "$tmpfs_opt" --cap-drop ALL \
    --workdir /src ${cache_mount[@]+"${cache_mount[@]}"} ${metrics_args[@]+"${metrics_args[@]}"} -v "$dir:/src:ro" -v "$work/token:/var/run/secrets/tokens/clearance:ro" \
    --entrypoint /usr/local/bin/clearance-cmp \
    -e ARGOCD_APP_NAME=smoke-app-dev -e ARGOCD_APP_NAMESPACE=app-smoke-app-dev -e ARGOCD_APP_REVISION="$rev" \
    -e ARGOCD_APP_SOURCE_REPO_URL=https://git.example.test/acme/gitops-smoke.git -e ARGOCD_APP_SOURCE_PATH=. \
    -e ARGOCD_APP_PROJECT_NAME=default -e KUBE_VERSION=1.34.0 -e KUBE_API_VERSIONS=v1,apps/v1 \
    -e PARAM_APP=smoke-app -e PARAM_ENV=dev -e PARAM_CLUSTER=hangar-smoke \
    -e PARAM_CHARTREPO="$chart_url" -e PARAM_CHARTREVISION=v0.0.1 -e PARAM_CHARTPATH=charts/app \
    -e PARAM_VALUEFILES=hangar-smoke/base.yaml,hangar-smoke/dev/values.yaml,hangar-smoke/dev/release.yaml \
    -e PARAM_VALUESJSON="$injected" -e PARAM_KUSTOMIZEDIR=configmap \
    -e CLEARANCE_URL="$core_url" -e CLEARANCE_TOKEN_FILE=/var/run/secrets/tokens/clearance \
    -e CLEARANCE_CHART_REPOS="$chart_url" -e CLEARANCE_WAIT_IMAGE=registry.example.test/clearance-wait:smoke \
    -e CLEARANCE_CMP_CACHE_DIR=/tmp/clearance-cmp-cache \
    "$image" > "$out" 2> "$err"
  echo $?
}

echo "== good checkout: value files, a chart served over git://, a kustomize directory, a cleared change"
: > "$work/register.log"
code="$(run_plugin "$good" "$work/good.out" "$work/good.err")"
sed 's/^/     stderr: /' "$work/good.err"
[ "$code" = 0 ] && ok "exit 0" || bad "exit $code, want 0"
[ -s "$work/good.out" ] && ok "a non-empty manifest stream ($(wc -c < "$work/good.out") bytes)" || bad "the manifest stream is empty"
for want in '"name":"smoke-app-dev-config"' '"base":"from-base"' '"env":"from-env-values"' '"tag":"1.2.3"' '"injected":"from-platform"' '"name":"kz-extra"' '"from":"kustomize"' '"app.kubernetes.io/managed-by":"Helm"' 'chg-smoke'; do
  grep -q "$want" "$work/good.out" && ok "output has $want" || bad "output lacks $want"
done
# The private network namespace (CLEARANCE_CMP_NETNS, default try): the state is part of the summary line. Under
# docker's default seccomp profile (the RuntimeDefault stand-in) it is expected to be "unavailable" and the render
# still passes; it is reported, not required, so the smoke job shows what such a profile does on the runner.
netns_state="$(sed -n 's/.*, netns=\([a-z]*\).*/\1/p' "$work/good.err" | head -1)"
case "$netns_state" in
  on|unavailable|off) ok "the summary line reports netns=$netns_state (CLEARANCE_CMP_NETNS unset = try)";;
  *) bad "the summary line has no netns= state";;
esac
# The filesystem sandbox (CLEARANCE_CMP_FS_SANDBOX, default try; W-34 X6): Landlock is unprivileged and docker's
# default seccomp profile allows it, so on a kernel that has it (the CI runner's) the state must be "on". Set
# ALLOW_NO_LANDLOCK=1 to run this script on a kernel without Landlock.
fs_state="$(sed -n 's/.*, fs-sandbox=\([a-z]*\).*/\1/p' "$work/good.err" | head -1)"
case "$fs_state" in
  on) ok "the summary line reports fs-sandbox=on: render steps ran under Landlock";;
  unavailable|off) [ "${ALLOW_NO_LANDLOCK:-}" = 1 ] && ok "the summary line reports fs-sandbox=$fs_state (ALLOW_NO_LANDLOCK=1)" || bad "fs-sandbox=$fs_state: this kernel or seccomp profile gave the render steps no Landlock";;
  *) bad "the summary line has no fs-sandbox= state";;
esac
n="$(wc -l < "$work/register.log" | tr -d ' ')"
[ "$n" = 1 ] && ok "one register call reached the core" || bad "$n register calls reached the core, want 1"
grep -q '"app":"smoke-app"' "$work/register.log" && grep -q '"_authorization":true' "$work/register.log" && grep -q '"render":"ok"' "$work/register.log" \
  && ok "the call carried the app, a bearer token and the render check" || bad "the register call is not what the plugin sends"

echo "== symlinked value file: must be refused before anything is rendered or registered"
: > "$work/register.log"
code="$(run_plugin "$link" "$work/link.out" "$work/link.err")"
sed 's/^/     stderr: /' "$work/link.err"
[ "$code" != 0 ] && ok "exit $code (non-zero)" || bad "a symlinked value file rendered"
grep -q 'refused: value file hangar-smoke/dev/values.yaml resolves outside the repository' "$work/link.err" \
  && ok "the refusal names the value file" || bad "the expected refusal is missing"
grep -q '^clearance-cmp: CMP-RENDER-REFUSED: ' "$work/link.err" \
  && ok "its first line carries the render-error code CMP-RENDER-REFUSED" || bad "the refusal's first line lacks its error code"
[ ! -s "$work/link.out" ] && ok "no manifests were written" || bad "manifests were written for a refused checkout"
[ ! -s "$work/register.log" ] && ok "nothing was registered" || bad "a refused checkout was registered"

echo "== the filesystem sandbox in the built image: a render step cannot read the mounted token"
# The image's own shim (what OSRun starts every git, helm and kustomize through), as the sidecar runs: uid 999, a
# read-only root, no capabilities, docker's default seccomp profile, the token mounted read-only where the install
# guide mounts it. The control (the same shim, Landlock off) reads the token, so the refusal is the sandbox's.
shim() { # LANDLOCK(true|false) : prints the step's output, echoes nothing else
  "$engine" run --rm --user 999:999 --read-only --tmpfs "$tmpfs_opt" --cap-drop ALL \
    -v "$work/token:/var/run/secrets/tokens/clearance:ro" --entrypoint /usr/local/bin/clearance-cmp \
    -e CLEARANCE_CMP_SANDBOX_SPEC="{\"landlock\":$1,\"rx\":[\"/usr\",\"/bin\",\"/sbin\",\"/lib\",\"/etc\"],\"ro\":[\"/proc\"],\"rw\":[\"/tmp\"],\"dev\":[\"/dev\"]}" \
    "$image" __clearance-sandbox-exec /bin/cat /var/run/secrets/tokens/clearance 2>&1
}
ctl_out="$(shim false)"
echo "$ctl_out" | grep -q smoke-token && ok "control: without Landlock the step reads the token (uid 999 can)" || bad "control: the token was not readable even without the sandbox: $ctl_out"
if [ "$fs_state" = on ]; then
  ll_out="$(shim true)"
  echo "$ll_out" | sed 's/^/     shim: /'
  echo "$ll_out" | grep -q smoke-token && bad "a sandboxed step read the token" || ok "a sandboxed step cannot read the token"
  echo "$ll_out" | grep -qi 'permission denied' && ok "it was refused with EACCES" || bad "the sandboxed read did not fail with EACCES"
fi

echo "== doctor: the preflight, in the built image, with the sidecar's own environment (no PARAM_*, no ARGOCD_APP_*)"
run_doctor() { # OUT CHART_REPOS : echoes the exit code
  local out="$1" repos="$2"
  # shellcheck disable=SC2086
  "$engine" run --rm $net_args --user 999:999 --read-only --tmpfs "$tmpfs_opt" --cap-drop ALL \
    -v "$work/token:/var/run/secrets/tokens/clearance:ro" \
    --entrypoint /usr/local/bin/clearance-cmp \
    -e CLEARANCE_URL="$core_url" -e CLEARANCE_TOKEN_FILE=/var/run/secrets/tokens/clearance \
    -e CLEARANCE_CHART_REPOS="$repos" -e CLEARANCE_WAIT_IMAGE=registry.example.test/clearance-wait:smoke \
    -e CLEARANCE_CMP_CACHE_DIR=/tmp/clearance-cmp-cache \
    "$image" doctor > "$out" 2>&1
  echo $?
}
: > "$work/register.log"
code="$(run_doctor "$work/doctor.out" "$chart_url")"
sed 's/^/     doctor: /' "$work/doctor.out"
[ "$code" = 0 ] && ok "doctor exits 0 on a good setup" || bad "doctor exit $code, want 0"
for want in '^ok    settings' '^(ok|warn)  *token' '^ok    core ' '^ok    core-auth' '^ok    chart-repos' '^ok    cache' '^ok    git ' '^ok    helm .*'"$want_helm" '^ok    kustomize .*'"$want_kustomize" '^(ok|warn)  *netns' '^(ok|warn)  *fs-sandbox' '^(ok|warn)  *render-limits' '^doctor: [0-9]+ ok, [0-9]+ warn, 0 fail'; do
  grep -Eq "$want" "$work/doctor.out" && ok "doctor prints $want" || bad "doctor output lacks $want"
done
grep -q 'smoke-token' "$work/doctor.out" && bad "doctor printed the token" || ok "doctor did not print the token"
[ ! -s "$work/register.log" ] && ok "doctor registered nothing" || bad "doctor registered a change"
code="$(run_doctor "$work/doctor-bad.out" "")"
sed 's/^/     doctor: /' "$work/doctor-bad.out"
[ "$code" != 0 ] && ok "doctor exit $code (non-zero) with CLEARANCE_CHART_REPOS empty" || bad "doctor passed with no chart allow list"
grep -Eq '^fail  chart-repos' "$work/doctor-bad.out" && ok "doctor names the failing check" || bad "doctor does not name chart-repos"

echo "== the chart cache: a second render in the same /tmp does not fetch the chart again"
cache="$work/cmp-cache"; mkdir -p "$cache"; chmod 777 "$cache"
code="$(run_plugin "$good" "$work/c1.out" "$work/c1.err" "$cache")"
sed 's/^/     run 1 stderr: /' "$work/c1.err"
[ "$code" = 0 ] && grep -q 'chart-cache=miss' "$work/c1.err" && ok "the first render fetched the chart and kept it (chart-cache=miss)" || bad "the first render did not report chart-cache=miss (exit $code)"
# Different platform values: the render is not the same one (no pre-render hit), but the chart commit is.
code="$(run_plugin "$good" "$work/c2.out" "$work/c2.err" "$cache" '{"injected":"from-platform-2"}')"
sed 's/^/     run 2 stderr: /' "$work/c2.err"
[ "$code" = 0 ] && grep -q 'chart-cache=hit' "$work/c2.err" && ok "the second render used the cached chart (chart-cache=hit)" || bad "the second render did not report chart-cache=hit (exit $code)"
grep -q '"injected":"from-platform-2"' "$work/c2.out" && ok "and rendered the new values" || bad "the second render's output lacks the new values"
# The identical render again: answered by the pre-render cache (no clone, helm or kustomize), and the core is asked
# only if the tree cache's two minutes are over (here they are not).
: > "$work/register.log"
code="$(run_plugin "$good" "$work/c3.out" "$work/c3.err" "$cache" '{"injected":"from-platform-2"}')"
sed 's/^/     run 3 stderr: /' "$work/c3.err"
[ "$code" = 0 ] && grep -q 'serving the cleared render' "$work/c3.err" && cmp -s "$work/c2.out" "$work/c3.out" \
  && ok "an unchanged render is served from the cache, byte for byte" || bad "the unchanged render was not served from the cache (exit $code)"
[ ! -s "$work/register.log" ] && ok "and asked the core nothing inside the tree cache's lifetime" || bad "a cached hit inside the lifetime reached the core"

echo "== metrics (F6): a run records into CLEARANCE_CMP_METRICS_DIR, and clearance-cmp metrics serves it"
mdir="$work/cmp-metrics"; mkdir -p "$mdir"; chmod 777 "$mdir"
metrics_args=(-v "$mdir:/var/run/clearance-cmp-metrics" -e CLEARANCE_CMP_METRICS_DIR=/var/run/clearance-cmp-metrics)
code="$(run_plugin "$good" "$work/m1.out" "$work/m1.err")"
metrics_args=()
[ "$code" = 0 ] && ok "a render with metrics on exits 0" || bad "a render with metrics on exited $code"
grep -q 'metrics were not recorded' "$work/m1.err" && bad "the run could not record: $(grep 'metrics were not recorded' "$work/m1.err")" || ok "the run recorded without a warning"
grep -q '"cleared":1' "$mdir/cmp-metrics.json" 2>/dev/null && ok "the store counts the cleared run" || bad "the store lacks the cleared run: $(cat "$mdir/cmp-metrics.json" 2>&1)"
grep -q 'smoke-token' "$mdir/cmp-metrics.json" 2>/dev/null && bad "the store holds the token" || ok "the store does not hold the token"
# The server, as its own container runs it (the store read-only, no token mounted), scraped from inside the container.
# shellcheck disable=SC2086
mout="$("$engine" run --rm $net_args --user 999:999 --read-only --cap-drop ALL -v "$mdir:/var/run/clearance-cmp-metrics:ro" \
  -e CLEARANCE_CMP_METRICS_DIR=/var/run/clearance-cmp-metrics -e CLEARANCE_CMP_METRICS_ADDR=127.0.0.1:9464 --entrypoint /bin/sh "$image" \
  -c '/usr/local/bin/clearance-cmp metrics & pid=$!; for i in 1 2 3 4 5 6 7 8 9 10; do wget -qO- http://127.0.0.1:9464/metrics && break; sleep 0.5; done; kill "$pid"' 2>&1)"
echo "$mout" | grep -E '^clearance_cmp_(renders_total|metrics_store_up)' | sed 's/^/     metrics: /'
echo "$mout" | grep -q '^clearance_cmp_renders_total{version="smoke",outcome="cleared"} 1$' && ok "the server serves the run, labelled with the image's version" || bad "the server did not serve the run: $mout"
echo "$mout" | grep -q '^clearance_cmp_metrics_store_up 1$' && ok "the store reads (store_up 1)" || bad "store_up is not 1"
# Off by default: no CLEARANCE_CMP_METRICS_ADDR, nothing listens and the command says so.
# shellcheck disable=SC2086
off="$("$engine" run --rm $net_args --user 999:999 --read-only --cap-drop ALL --entrypoint /usr/local/bin/clearance-cmp "$image" metrics 2>&1)"; offcode=$?
[ "$offcode" = 2 ] && echo "$off" | grep -q 'nothing listens' && ok "with CLEARANCE_CMP_METRICS_ADDR unset, metrics refuses to start (exit 2)" || bad "metrics without an address: exit $offcode, $off"

[ "$fail" = 0 ] && echo "cmp-smoke: PASS" || echo "cmp-smoke: FAIL"
exit "$fail"
