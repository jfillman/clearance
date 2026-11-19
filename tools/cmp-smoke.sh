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

# ---- run the plugin as Argo CD does -----------------------------------------------------------------------------
default_injected='{"injected":"from-platform"}'
run_plugin() { # CHECKOUT OUT ERR [CACHE_DIR [VALUESJSON]] : echoes the exit code. CACHE_DIR is a host directory mounted
  # as the plugin's cache directory, so that two runs share it as two renders in one sidecar's /tmp do.
  local dir="$1" out="$2" err="$3" cachedir="${4:-}" injected="${5:-$default_injected}" rev cache_mount=()
  [ -n "$cachedir" ] && cache_mount=(-v "$cachedir:/tmp/clearance-cmp-cache")
  rev="$(git -C "$dir" rev-parse HEAD)"
  # shellcheck disable=SC2086
  "$engine" run --rm $net_args --user 999:999 --read-only --tmpfs "$tmpfs_opt" --cap-drop ALL \
    --workdir /src ${cache_mount[@]+"${cache_mount[@]}"} -v "$dir:/src:ro" -v "$work/token:/var/run/secrets/tokens/clearance:ro" \
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
[ ! -s "$work/link.out" ] && ok "no manifests were written" || bad "manifests were written for a refused checkout"
[ ! -s "$work/register.log" ] && ok "nothing was registered" || bad "a refused checkout was registered"

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

[ "$fail" = 0 ] && echo "cmp-smoke: PASS" || echo "cmp-smoke: FAIL"
exit "$fail"
