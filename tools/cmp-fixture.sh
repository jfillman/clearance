# Shared fixture for tools/cmp-upgrade.sh and tools/cmp-soak.sh (sourced, not run). It runs the clearance-cmp BINARY on
# this machine the way Argo CD's plugin sidecar runs it (cwd = a real git checkout, the ARGOCD_APP_*, PARAM_* and KUBE_*
# environment, a token file, CLEARANCE_CHART_REPOS), against:
#   - a chart repository with three tags (v0.0.1, v0.0.2, v0.0.3: three commits), served by `git daemon` over git://;
#   - tools/cmpsmoke, the fake core that answers every register call "cleared" (change chg-smoke);
#   - a gitops checkout with three value files and a kustomize directory, committed.
# helm, kustomize and git must be on PATH (tools/install-cmp-tools.sh installs the versions the image ships).
#
#   . tools/cmp-fixture.sh; fixture_up WORKDIR
#   code="$(fixture_render BIN CACHE_DIR OUT ERR TAG INJECTED_JSON [VAR=VALUE ...])"   # echoes the exit code
#   fixture_down
# fixture_up sets: fx_work, fx_checkout, fx_chart_url, fx_core_url, fx_token, fx_tags (array), fx_pids (array).

fx_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fx_git_id=(-c user.name=fixture -c user.email=fixture@example.test -c commit.gpgsign=false -c tag.gpgsign=false)
fx_pids=()
fx_wrap=()

fx_write() { mkdir -p "$(dirname "$1")"; cat > "$1"; }

fixture_up() { # WORKDIR
  fx_work="$1"
  mkdir -p "$fx_work/home" "$fx_work/secrets" "$fx_work/repos"
  # ---- the chart repository: three tags, each a commit with a different default value -------------------------
  local src="$fx_work/chart-src" i
  fx_write "$src/charts/app/Chart.yaml" <<'Y'
apiVersion: v2
name: app
version: 0.0.1
Y
  fx_write "$src/charts/app/templates/configmap.yaml" <<'Y'
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
  chart: {{ .Values.chartRelease | quote }}
Y
  git -C "$src" init -q -b main
  fx_tags=(v0.0.1 v0.0.2 v0.0.3)
  for i in "${fx_tags[@]}"; do
    printf 'base: unset\nenvValue: unset\ninjected: unset\nimage: {tag: unset}\nchartRelease: %s\n' "$i" > "$src/charts/app/values.yaml"
    git -C "$src" add .
    git -C "$src" "${fx_git_id[@]}" commit -q -m "chart $i"
    git -C "$src" "${fx_git_id[@]}" tag "$i"
  done
  git clone -q --bare "$src" "$fx_work/repos/chart.git"
  local port
  port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
  git daemon --reuseaddr --export-all --base-path="$fx_work/repos" --listen=127.0.0.1 --port="$port" >/dev/null 2>"$fx_work/daemon.log" &
  fx_pids+=($!)
  fx_daemon_pid=$!
  fx_chart_url="git://127.0.0.1:$port/chart.git"
  # ---- the fake core --------------------------------------------------------------------------------------------
  (cd "$fx_root" && go build -o "$fx_work/stub" ./tools/cmpsmoke) || { echo "cannot build the fake core"; return 2; }
  "$fx_work/stub" -listen 127.0.0.1:0 -log "$fx_work/register.log" -port-file "$fx_work/stub.port" 2>"$fx_work/stub.err" &
  fx_pids+=($!)
  for _ in $(seq 50); do [ -s "$fx_work/stub.port" ] && break; sleep 0.1; done
  [ -s "$fx_work/stub.port" ] || { echo "the fake core did not start"; cat "$fx_work/stub.err"; return 2; }
  fx_core_url="http://127.0.0.1:$(cat "$fx_work/stub.port")"
  # The token is outside HOME and every directory a render step may read (the plugin refuses one under them).
  fx_token="$fx_work/secrets/token"
  printf 'smoke-token' > "$fx_token"; chmod 600 "$fx_token"
  for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break; sleep 0.1; done
  # ---- the gitops checkout ----------------------------------------------------------------------------------------
  fx_checkout="$fx_work/gitops"
  fx_write "$fx_checkout/env/base.yaml" <<'Y'
base: from-base
releaseTracking: {releaseId: rel-fixture-1}
Y
  fx_write "$fx_checkout/env/dev/values.yaml" <<'Y'
envValue: from-env-values
Y
  fx_write "$fx_checkout/env/dev/release.yaml" <<'Y'
image: {tag: "1.2.3"}
Y
  fx_write "$fx_checkout/configmap/kustomization.yaml" <<'Y'
namePrefix: kz-
resources: [cm.yaml]
Y
  fx_write "$fx_checkout/configmap/cm.yaml" <<'Y'
apiVersion: v1
kind: ConfigMap
metadata: {name: extra}
data: {from: kustomize}
Y
  git -C "$fx_checkout" init -q -b main
  git -C "$fx_checkout" add .
  git -C "$fx_checkout" "${fx_git_id[@]}" commit -q -m gitops
  fx_rev="$(git -C "$fx_checkout" rev-parse HEAD)"
}

# fixture_render BIN CACHE_DIR OUT ERR TAG INJECTED_JSON [VAR=VALUE ...]: one `generate`, as the cmp-server starts it
# (a fresh process, a clean environment). TMPDIR defaults to $fx_work/tmp-<cache dir's name>; pass TMPDIR=... to set it.
# fx_wrap (an array, empty by default) is a command the binary is run under, such as (timeout -s KILL 0.2).
fixture_render() {
  local bin="$1" cache="$2" out="$3" err="$4" tag="$5" injected="$6"
  shift 6
  local tmpdir="$fx_work/tmp-$(basename "$cache")"
  mkdir -p "$tmpdir"
  (cd "$fx_checkout" && env -i PATH="$PATH" HOME="$fx_work/home" TMPDIR="$tmpdir" \
    ARGOCD_APP_NAME=fixture-app-dev ARGOCD_APP_NAMESPACE=app-fixture-dev ARGOCD_APP_REVISION="$fx_rev" \
    ARGOCD_APP_SOURCE_REPO_URL=https://git.example.test/acme/gitops-fixture.git ARGOCD_APP_SOURCE_PATH=. \
    ARGOCD_APP_PROJECT_NAME=default KUBE_VERSION=1.34.0 KUBE_API_VERSIONS=v1,apps/v1 \
    PARAM_APP=fixture-app PARAM_ENV=dev PARAM_CLUSTER=ci \
    PARAM_CHARTREPO="$fx_chart_url" PARAM_CHARTREVISION="$tag" PARAM_CHARTPATH=charts/app \
    PARAM_VALUEFILES=env/base.yaml,env/dev/values.yaml,env/dev/release.yaml \
    PARAM_VALUESJSON="$injected" PARAM_KUSTOMIZEDIR=configmap \
    CLEARANCE_URL="$fx_core_url" CLEARANCE_TOKEN_FILE="$fx_token" CLEARANCE_CHART_REPOS="$fx_chart_url" \
    CLEARANCE_WAIT_IMAGE=registry.example.test/clearance-wait:fixture CLEARANCE_CMP_CACHE_DIR="$cache" \
    "$@" ${fx_wrap[@]+"${fx_wrap[@]}"} "$bin" > "$out" 2> "$err")
  echo $?
}

fixture_down() {
  local p
  for p in "${fx_pids[@]:-}"; do [ -n "$p" ] && { kill "$p"; wait "$p"; } 2>/dev/null; done
  fx_pids=()
}
