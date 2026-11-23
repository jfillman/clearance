#!/usr/bin/env bash
# Argo CD conformance of the BUILT clearance-cmp image (W-34 F3): the image as a Config Management Plugin sidecar of a
# real Argo CD, installed with the official argo-cd Helm chart and the documented values
# (docs/examples/argo-cd-repo-server-values.yaml), in a kind cluster, with Applications that use the plugin.
#
#   tools/cmp-conformance.sh IMAGE ARGO_CD_CHART_VERSION [ARGO_CD_VERSION]
#
# The cluster must exist and be the current kubectl context (the workflow creates it with kind); IMAGE must be in the
# local docker daemon. ARGO_CD_VERSION, when given, is checked against the repo-server's image tag, so a matrix leg
# cannot silently test another Argo CD than it names. It creates, in the cluster:
#   - the test double (tools/cmpsmoke, image built from tools/cmpsmoke/Dockerfile): the plugin's core, which answers
#     "cleared", "denied" for the app `denied` and an unreadable answer for the app `fault`, and the git host (smart
#     HTTP) serving a gitops repository and a chart repository built here;
#   - Argo CD from the argo-cd chart, with the example values: the image as the clearance-cmp sidecar and the metrics
#     container, the double's URL as the core and its chart repository as the allow list;
#   - Applications that name the plugin: a Helm, a Kustomize and a plain directory source (the generic mode, the
#     `sources` parameter), the chart-parameter mode, and three that must fail: a denied change, a core answer the
#     plugin cannot read, and a chart repository that is not on the allow list.
# and asserts: each cleared Application syncs and is Healthy, with its objects stamped with the change; each failing
# one shows its stable error code in its ComparisonError (a refusal, a plugin fault and a render error, each its own
# class); `doctor` in the sidecar has no fail and no warn outside a named allow list; the metrics container serves /metrics with those runs counted.
#
# Environment: KIND_CLUSTER (kind cluster name, default clearance), ARTIFACTS (a directory: the cluster's state and
# every log are written there when a check fails), TIMEOUT (seconds all the Applications together are given to settle,
# default 300).
set -uo pipefail

image="${1:?usage: tools/cmp-conformance.sh IMAGE ARGO_CD_CHART_VERSION [ARGO_CD_VERSION]}"
chart_version="${2:?usage: tools/cmp-conformance.sh IMAGE ARGO_CD_CHART_VERSION [ARGO_CD_VERSION]}"
want_argocd="${3:-}"
cluster="${KIND_CLUSTER:-clearance}"
artifacts="${ARTIFACTS:-}"
timeout="${TIMEOUT:-300}"
root="$(cd "$(dirname "$0")/.." && pwd)"
git_id=(-c user.name=conformance -c user.email=conformance@example.test -c commit.gpgsign=false -c tag.gpgsign=false)
double_image=clearance-cmp-double:conformance
ns_double=clearance-conformance
ns_argo=argocd
base_url="http://cmp-double.$ns_double.svc.cluster.local"
gitops_url="$base_url/git/acme/gitops.git"
charts_url="$base_url/git/platform/charts.git"
unlisted_url="$base_url/git/other/charts.git"

work="$(mktemp -d)"
started=$SECONDS
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
die() { echo "FAIL $*"; fail=1; finish; }
write() { mkdir -p "$(dirname "$1")"; cat > "$1"; }
step() { echo "== [$((SECONDS - started))s] $*"; }

collect() { # the cluster's state and every log, for the workflow's artifact
  [ -n "$artifacts" ] || return 0
  mkdir -p "$artifacts"
  echo "collecting the cluster's state and logs into $artifacts"
  kubectl get all,applications,events -A -o wide > "$artifacts/resources.txt" 2>&1
  kubectl -n "$ns_argo" get applications -o yaml > "$artifacts/applications.yaml" 2>&1
  kubectl -n "$ns_argo" describe pods > "$artifacts/argocd-pods.txt" 2>&1
  kubectl -n "$ns_double" describe pods > "$artifacts/double-pods.txt" 2>&1
  local p c
  for p in $(kubectl -n "$ns_argo" get pods -o name 2>/dev/null); do
    for c in $(kubectl -n "$ns_argo" get "$p" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' 2>/dev/null); do
      kubectl -n "$ns_argo" logs "$p" -c "$c" > "$artifacts/${p#pod/}.$c.log" 2>&1
      kubectl -n "$ns_argo" logs "$p" -c "$c" --previous > "$artifacts/${p#pod/}.$c.previous.log" 2>/dev/null || rm -f "$artifacts/${p#pod/}.$c.previous.log"
    done
  done
  kubectl -n "$ns_double" logs deploy/cmp-double > "$artifacts/double.log" 2>&1
  kubectl -n "$ns_double" exec deploy/cmp-double -- cat /tmp/register.log > "$artifacts/register.log" 2>&1
  cp "$work/argocd-values.yaml" "$artifacts/" 2>/dev/null
}
finish() {
  echo "cmp-conformance: Argo CD chart $chart_version${want_argocd:+ ($want_argocd)}, $((SECONDS - started))s"
  if [ "$fail" = 0 ]; then
    echo "cmp-conformance: PASS"
  else
    collect
    echo "cmp-conformance: FAIL"
  fi
  rm -rf "$work"
  exit "$fail"
}

# ---- the fixture repositories ---------------------------------------------------------------------------------------
step "the fixture repositories"
mkrepo() { # SRC BARE [TAG]: commit SRC and clone it bare to BARE
  git -C "$1" init -q -b main && git -C "$1" add . && git -C "$1" "${git_id[@]}" commit -q -m fixture || return 1
  [ -z "${3:-}" ] || git -C "$1" "${git_id[@]}" tag "$3" || return 1
  git clone -q --bare "$1" "$2" && git -C "$2" update-server-info
}
chart_files() { # DIR: a chart that renders one ConfigMap
  write "$1/Chart.yaml" <<'Y'
apiVersion: v2
name: app
version: 0.0.1
Y
  write "$1/values.yaml" <<'Y'
greeting: unset
env: unset
Y
  write "$1/templates/configmap.yaml" <<'Y'
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-config
data:
  greeting: {{ .Values.greeting | quote }}
  env: {{ .Values.env | quote }}
Y
}
src="$work/src"
# The chart repository on the allow list: one chart at the tag v0.0.1 (the chart-parameter mode).
chart_files "$src/charts/charts/app"
# The gitops repository: what the Application's own source is, and every generic-mode source's repository.
chart_files "$src/gitops/helm/app"
write "$src/gitops/helm/app/values-ci.yaml" <<'Y'
greeting: from-a-helm-source
Y
write "$src/gitops/kustomize/app/kustomization.yaml" <<'Y'
namePrefix: kz-
resources: [configmap.yaml]
Y
write "$src/gitops/kustomize/app/configmap.yaml" <<'Y'
apiVersion: v1
kind: ConfigMap
metadata: {name: config}
data: {greeting: from-a-kustomize-source}
Y
write "$src/gitops/directory/configmap.yaml" <<'Y'
apiVersion: v1
kind: ConfigMap
metadata: {name: directory-config}
data: {greeting: from-a-directory-source}
Y
write "$src/gitops/cluster-a/base.yaml" <<'Y'
greeting: from-the-chart-parameters
Y
write "$src/gitops/cluster-a/ci/values.yaml" <<'Y'
env: ci
Y
double="$work/double"
mkdir -p "$double/repos/platform" "$double/repos/acme" "$double/repos/other"
mkrepo "$src/charts" "$double/repos/platform/charts.git" v0.0.1 || die "cannot build the chart repository"
mkrepo "$src/gitops" "$double/repos/acme/gitops.git" || die "cannot build the gitops repository"
cp -R "$double/repos/platform/charts.git" "$double/repos/other/charts.git" # the same chart, from a repository not listed
chmod -R a+rX "$double/repos"

# ---- the test double ----------------------------------------------------------------------------------------------
step "the test double (core and git host)"
(cd "$root" && CGO_ENABLED=0 GOOS=linux go build -trimpath -o "$double/cmpsmoke" ./tools/cmpsmoke) || die "cannot build the stub"
docker build -q -f "$root/tools/cmpsmoke/Dockerfile" -t "$double_image" "$double" > /dev/null || die "cannot build the double's image"
kind load docker-image "$image" "$double_image" --name "$cluster" > /dev/null || die "kind load failed"
kubectl create namespace "$ns_double" > /dev/null
kubectl apply -f - > /dev/null <<Y || die "cannot create the double"
apiVersion: apps/v1
kind: Deployment
metadata: {name: cmp-double, namespace: $ns_double}
spec:
  replicas: 1
  selector: {matchLabels: {app: cmp-double}}
  template:
    metadata: {labels: {app: cmp-double}}
    spec:
      containers:
        - name: double
          image: $double_image
          imagePullPolicy: Never
          args: [-listen, ":8080", -log, /tmp/register.log, -port-file, /tmp/port, -token, "", -deny, denied, -garble, fault, -git-root, /srv/git]
          ports: [{containerPort: 8080}]
          readinessProbe: {httpGet: {path: /healthz, port: 8080}}
          securityContext: {runAsNonRoot: true, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
          volumeMounts: [{name: tmp, mountPath: /tmp}]
      volumes: [{name: tmp, emptyDir: {}}]
---
apiVersion: v1
kind: Service
metadata: {name: cmp-double, namespace: $ns_double}
spec:
  selector: {app: cmp-double}
  ports: [{port: 80, targetPort: 8080}]
Y
kubectl -n "$ns_double" rollout status deploy/cmp-double --timeout=120s || die "the double did not become ready"
ok "the double is ready"

# ---- Argo CD, with the documented values ----------------------------------------------------------------------------
step "Argo CD (argo-cd chart $chart_version) with docs/examples/argo-cd-repo-server-values.yaml"
# The example as it is, with its placeholders replaced: the images by the one under test, the core and the allow list
# by the double's. Nothing else in it changes.
python3 - "$root/docs/examples/argo-cd-repo-server-values.yaml" "$work/argocd-values.yaml" "$image" "$base_url" "$charts_url" <<'PY' || die "cannot fill in the example values"
import sys, yaml
src, dst, image, core, charts = sys.argv[1:]
v = yaml.safe_load(open(src))
set_env = {"CLEARANCE_URL": core, "CLEARANCE_CHART_REPOS": charts,
           "CLEARANCE_WAIT_IMAGE": "registry.example.test/clearance-wait:conformance"}
names = []
for c in v["repoServer"]["extraContainers"]:
    names.append(c["name"])
    c["image"] = image
    c["imagePullPolicy"] = "Never"  # kind-loaded: a pull would mean the image under test is not the one running
    for e in c.get("env", []):
        if e["name"] in set_env:
            e["value"] = set_env[e["name"]]
assert names == ["clearance-cmp", "clearance-cmp-metrics"], names
out = yaml.safe_dump(v, sort_keys=False)
assert "<" not in out and "example.test/platform" not in out, "a placeholder is left in the values"
open(dst, "w").write(out)
PY
helm repo add argo https://argoproj.github.io/argo-helm > /dev/null 2>&1
helm repo update argo > /dev/null || die "cannot reach the argo-helm repository"
# Only what Argo CD runs that this test does not use is turned off (dex, notifications); everything else is the
# chart's default.
chart_args=(argocd argo/argo-cd --version "$chart_version" -n "$ns_argo" -f "$work/argocd-values.yaml"
  --set dex.enabled=false --set notifications.enabled=false)
# Every image the chart runs is pulled into the kind node first, with retries: a public registry's rate limit (a 429
# on the redis image) would otherwise leave a pod in ImagePullBackOff until helm's wait gives up. The pods then start
# from the node's copy (the chart's pullPolicy is IfNotPresent). The image under test is not pulled: it is kind-loaded.
node="$(kind get nodes --name "$cluster" | head -1)"
images="$(helm template "${chart_args[@]}" | sed -n 's/^ *image: *"\{0,1\}\([^" ]*\)"\{0,1\} *$/\1/p' | sort -u | grep -vxF "$image")"
[ -n "$images" ] || die "no image found in the argo-cd chart's render"
# Bounded: every pull 120 s at most, and all of them with their retries 6 minutes, so this, helm's 8 minutes and the
# Applications' TIMEOUT fit in the job's 30 and leave time to collect the logs.
pull_deadline=$((SECONDS + 360))
pull() { # IMAGE: up to 4 tries, inside the deadline
  local try
  for try in 1 2 3 4; do
    timeout 120 docker exec "$node" crictl pull "$1" > /dev/null 2>&1 && return 0
    { [ "$try" = 4 ] || [ $((SECONDS + try * 10)) -ge "$pull_deadline" ]; } && return 1
    echo "     pull $1 failed (try $try), retrying in $((try * 10))s"
    sleep $((try * 10))
  done
}
for img in $images; do
  if pull "$img"; then ok "pulled $img"; continue; fi
  # The AWS mirror of a Docker Official Image (the chart's redis) answers anonymous runners with 429s for minutes at a
  # time. The same image is on Docker Hub under the same name and tag: pull it there and tag it in the node as the
  # chart names it, so the chart's values stay as they are. Only a tag (not a digest) can be re-tagged this way.
  rest=""
  case "$img" in
    ecr-public.aws.com/docker/library/*) rest="${img#ecr-public.aws.com/docker/library/}";;
    public.ecr.aws/docker/library/*) rest="${img#public.ecr.aws/docker/library/}";;
  esac
  case "$rest" in ""|*@*) die "cannot pull $img into the kind node";; esac
  pull "docker.io/library/$rest" || die "cannot pull $img, nor docker.io/library/$rest, into the kind node"
  docker exec "$node" ctr -n k8s.io images tag --force "docker.io/library/$rest" "$img" > /dev/null || die "cannot tag docker.io/library/$rest as $img"
  ok "pulled $img (from its Docker Hub copy, docker.io/library/$rest)"
done
helm install "${chart_args[@]}" --create-namespace --wait --timeout 8m > /dev/null || die "helm install of argo-cd $chart_version failed"
repo_image="$(kubectl -n "$ns_argo" get deploy argocd-repo-server -o jsonpath='{.spec.template.spec.containers[?(@.name=="repo-server")].image}')"
echo "     repo-server image: $repo_image"
if [ -n "$want_argocd" ]; then
  [ "${repo_image##*:}" = "$want_argocd" ] && ok "the repo-server runs Argo CD $want_argocd" || die "the repo-server runs $repo_image, not Argo CD $want_argocd"
fi
kubectl -n "$ns_argo" rollout status deploy/argocd-repo-server --timeout=180s > /dev/null || die "the repo-server did not become ready"
ready="$(kubectl -n "$ns_argo" get pod -l app.kubernetes.io/name=argocd-repo-server -o jsonpath='{range .items[*].status.containerStatuses[*]}{.name}={.ready} {end}')"
echo "     containers: $ready"
for c in repo-server clearance-cmp clearance-cmp-metrics; do
  echo " $ready " | grep -q " $c=true " && ok "the repo-server pod's $c container is ready" || bad "the $c container is not ready"
done

step "doctor in the sidecar"
doctor="$(kubectl -n "$ns_argo" exec deploy/argocd-repo-server -c clearance-cmp -- /usr/local/bin/clearance-cmp doctor 2>&1)"; code=$?
echo "$doctor" | sed 's/^/     doctor: /'
[ "$code" = 0 ] && ok "doctor exits 0" || bad "doctor exit $code"
echo "$doctor" | grep -q '^fail' && bad "doctor has a fail line" || ok "doctor has no fail line"
# No warn either: the documented values must pass the plugin's own preflight. Only these checks may warn, each for a
# reason of this test's own, never of the example's:
#   netns     kind's nodes refuse the unshare a private network namespace needs under the RuntimeDefault seccomp profile
#             (the netns hardening is optional and needs a Localhost profile; the guide's own sample output shows it)
#   core-tls  the double serves the core over plain http inside the cluster; the example's own core URL is https
allowed_warns="netns core-tls"
echo "$doctor" | grep -Eq '^doctor: [0-9]+ ok, [0-9]+ warn, [0-9]+ fail$' || bad "doctor printed no summary line"
unexpected=0
for w in $(echo "$doctor" | awk '$1 == "warn" {print $2}'); do
  case " $allowed_warns " in
    *" $w "*) ok "doctor: warn $w is expected in this test" ;;
    *) bad "doctor: unexpected warn $w (the documented values do not pass doctor)"; unexpected=1 ;;
  esac
done
[ "$unexpected" = 0 ] && ok "doctor has no warn outside the allow list ($allowed_warns)"
echo "$doctor" | grep -Eq '^ok +core-auth' && ok "doctor: the core accepted the projected token" || bad "doctor: core-auth is not ok"

# ---- the Applications -----------------------------------------------------------------------------------------------
step "the Applications"
app() { # NAME PARAMS_YAML: an Application whose only source is the plugin, over the gitops repository
  cat <<Y
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: {name: $1, namespace: $ns_argo}
spec:
  project: default
  destination: {server: https://kubernetes.default.svc, namespace: conf-$1}
  syncPolicy:
    automated: {}
    syncOptions: [CreateNamespace=true]
  source:
    repoURL: $gitops_url
    targetRevision: main
    path: .
    plugin:
      name: clearance
      parameters:
        - {name: app, string: $1}
        - {name: env, string: ci}
        - {name: cluster, string: cluster-a}
$2
Y
}
chart_params() { # CHART_REPO
  cat <<Y
        - {name: chartRepo, string: "$1"}
        - {name: chartRevision, string: v0.0.1}
        - {name: chartPath, string: charts/app}
        - {name: valueFiles, string: "cluster-a/base.yaml,cluster-a/ci/values.yaml"}
Y
}
sources() { # JSON
  printf "        - name: sources\n          string: '%s'\n" "$1"
}
{
  app helm "$(sources '[{"repoURL":"'"$gitops_url"'","path":"helm/app","targetRevision":"main","helm":{"valueFiles":["values-ci.yaml"]}}]')"
  app kustomize "$(sources '[{"repoURL":"'"$gitops_url"'","path":"kustomize/app","targetRevision":"main"}]')"
  app directory "$(sources '[{"repoURL":"'"$gitops_url"'","path":"directory","targetRevision":"main"}]')"
  app chart "$(chart_params "$charts_url")"
  app denied "$(chart_params "$charts_url")"
  app fault "$(chart_params "$charts_url")"
  app unlisted "$(chart_params "$unlisted_url")"
} > "$work/applications.yaml"
kubectl apply -f "$work/applications.yaml" > /dev/null || die "cannot create the Applications"
ok "7 Applications created"

field() { kubectl -n "$ns_argo" get application "$1" -o jsonpath="$2" 2>/dev/null; }
conditions() { field "$1" '{range .status.conditions[*]}{.type}: {.message}{"\n"}{end}'; }

# A cleared render: synced, Healthy, and the objects carry the change the double cleared.
cleared() { # APP CONFIGMAP GREETING
  local a="$1" sync health
  while :; do
    sync="$(field "$a" '{.status.sync.status}')"; health="$(field "$a" '{.status.health.status}')"
    [ "$sync" = Synced ] && [ "$health" = Healthy ] && break
    [ "$SECONDS" -ge "$apps_deadline" ] && { bad "$a: sync=$sync health=$health when the Applications' ${timeout}s ran out"; conditions "$a" | sed 's/^/     /'; return; }
    sleep 3
  done
  ok "$a: Synced and Healthy ($((SECONDS - started))s)"
  local cm
  cm="$(kubectl -n "conf-$a" get configmap "$2" -o json 2>/dev/null)"
  echo "$cm" | grep -q "\"greeting\": \"$3\"" && ok "$a: ConfigMap $2 has greeting=$3" || bad "$a: ConfigMap $2 is missing or lacks greeting=$3"
  echo "$cm" | grep -q '"chg-smoke"' && ok "$a: its objects are stamped with the cleared change" || bad "$a: the ConfigMap carries no stamp of the cleared change"
}
# A failed render: its ComparisonError's message carries CODE, and no code of another class.
refused() { # APP CODE OTHER_CLASSES_REGEX
  local a="$1" msg
  while :; do
    msg="$(conditions "$a")"
    echo "$msg" | grep -q "$2" && break
    [ "$SECONDS" -ge "$apps_deadline" ] && { bad "$a: no condition carries $2 when the Applications' ${timeout}s ran out"; echo "$msg" | sed 's/^/     /'; return; }
    sleep 3
  done
  echo "$msg" | sed 's/^/     /'
  ok "$a: the Application's condition carries $2 ($((SECONDS - started))s)"
  echo "$msg" | grep -q '^ComparisonError: ' && ok "$a: as a ComparisonError" || bad "$a: the code is not in a ComparisonError"
  # Argo CD prefixes the plugin's stderr with its own text ("rpc error: ... plugin sidecar failed ..."); the plugin's part
  # starts at the first "clearance-cmp:", which must be the code line, with no warning before it.
  local first before
  first="$(echo "$msg" | grep -o 'clearance-cmp: .*' | head -n 1)"
  before="${msg%%clearance-cmp: *}"
  case "$first" in "clearance-cmp: $2: "*) ok "$a: the plugin's first line is \"clearance-cmp: <code>: <summary>\"" ;; *) bad "$a: the first clearance-cmp: line is not the $2 line: $first" ;; esac
  echo "$before" | grep -q 'WARNING' && bad "$a: a warning precedes the code line" || ok "$a: no warning before the code line"
  echo "$msg" | grep -Eq "$3" && bad "$a: the condition also carries another class's code" || ok "$a: and no code of another class"
  [ "$(field "$a" '{.status.sync.status}')" != Synced ] && ok "$a: not synced" || bad "$a: a failed render synced"
  kubectl get namespace "conf-$a" > /dev/null 2>&1 && bad "$a: its destination namespace was created" || ok "$a: nothing was applied"
}

# One deadline for every Application below, not one each: seven times TIMEOUT would outlast the job and lose the logs.
apps_deadline=$((SECONDS + timeout))
step "cleared renders"
cleared helm helm-config from-a-helm-source
cleared kustomize kz-config from-a-kustomize-source
cleared directory directory-config from-a-directory-source
cleared chart chart-config from-the-chart-parameters

step "a refusal, a plugin fault and a render error, each its own code"
refused denied CMP-REFUSED-DENIED 'CMP-(FAULT|DEP|RENDER)-'
conditions denied | grep -q 'hold: .*chg-denied' && ok "denied: the refusal links the change (hold:)" || bad "denied: no hold: line naming the change"
refused fault CMP-FAULT-CORE-RESPONSE 'CMP-(REFUSED|DEP|RENDER)-'
refused unlisted CMP-RENDER-REFUSED 'CMP-(REFUSED|DEP|FAULT)-'
conditions unlisted | grep -q 'CLEARANCE_CHART_REPOS' && ok "unlisted: the refusal names CLEARANCE_CHART_REPOS" || bad "unlisted: the refusal does not name the allow list"

step "what reached the core"
reg="$(kubectl -n "$ns_double" exec deploy/cmp-double -- cat /tmp/register.log 2>&1)"
for a in helm kustomize directory chart denied fault; do
  echo "$reg" | grep -q "\"app\":\"$a\"" && ok "$a was registered" || bad "$a never reached the core"
done
echo "$reg" | grep -q '"app":"unlisted"' && bad "an Application refused before its render was registered" || ok "unlisted was refused before anything was registered"
echo "$reg" | grep -q '"_authorization":false' && bad "a register call came without a bearer token" || ok "every register call carried a bearer token"

step "metrics: the metrics container serves /metrics"
metrics="$(kubectl -n "$ns_argo" exec deploy/argocd-repo-server -c clearance-cmp-metrics -- wget -qO- http://127.0.0.1:9464/metrics 2>&1)"
echo "$metrics" | grep -E '^clearance_cmp_(renders_total|render_errors_total|metrics_store_up)' | sed 's/^/     metrics: /'
# SERIES_AND_LABELS (a regex up to the closing brace): the series is served with a count of at least 1.
series() { echo "$metrics" | grep -Eq "^$1[^}]*\} [1-9][0-9]*$"; }
series 'clearance_cmp_renders_total\{[^}]*outcome="cleared"' && ok "cleared runs are counted" || bad "no cleared run is counted"
series 'clearance_cmp_render_errors_total\{[^}]*class="refusal",code="CMP-REFUSED-DENIED"' && ok "the refusal is counted as class refusal" || bad "the refusal is not counted"
series 'clearance_cmp_render_errors_total\{[^}]*class="fault",code="CMP-FAULT-CORE-RESPONSE"' && ok "the fault is counted as class fault" || bad "the fault is not counted"
series 'clearance_cmp_render_errors_total\{[^}]*class="render",code="CMP-RENDER-REFUSED"' && ok "the render error is counted as class render" || bad "the render error is not counted"
echo "$metrics" | grep -q '^clearance_cmp_metrics_store_up 1$' && ok "the store reads (store_up 1)" || bad "store_up is not 1"

finish
