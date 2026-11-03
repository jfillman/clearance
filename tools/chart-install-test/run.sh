#!/usr/bin/env bash
# The chart's install test, on a kind cluster that kubectl already points at (.github/workflows/chart.yaml makes
# one; release.yaml reruns it on the published chart and image). Nothing from Airframe, Glidepath or Autopilot is
# installed: a plain Postgres, the chart, and a fake provider pod.
#
#   CHART              the chart: a path (charts/clearance) or oci://ghcr.io/jfillman/charts/clearance
#   CHART_VERSION      with an oci:// chart, its version
#   IMAGE_REPO, IMAGE_TAG   the clearance image, already loaded into kind (pullPolicy Never)
#   INSTALLTEST_IMAGE  the installtest image (Dockerfile target installtest), already loaded into kind
#   API                true: the chart's api Deployment is on and checked (needs `clearance api` in the image)
#   MAX_IMAGE_BYTES (40000000), MAX_IDLE_BYTES (67108864: 64 MiB), IDLE_SECONDS (60)
#
# Prints PASS/FAIL lines; writes a Markdown summary to $GITHUB_STEP_SUMMARY when set. Exits non-zero on a failure.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
ns=clearance
: "${CHART:?}" "${IMAGE_REPO:?}" "${IMAGE_TAG:?}" "${INSTALLTEST_IMAGE:?}"
API=${API:-false}
MAX_IMAGE_BYTES=${MAX_IMAGE_BYTES:-40000000}
MAX_IDLE_BYTES=${MAX_IDLE_BYTES:-67108864}
IDLE_SECONDS=${IDLE_SECONDS:-60}
summary=${GITHUB_STEP_SUMMARY:-/dev/null}
fail=0

dump() {
  echo "::group::diagnostics"
  kubectl get pods,svc,networkpolicy -A -o wide || true
  kubectl -n "$ns" describe pods || true
  kubectl -n "$ns" logs deploy/clearance-core --tail=200 || true
  kubectl -n "$ns" logs deploy/clearance-api --tail=100 || true
  kubectl -n clearance-test logs installtest || true
  echo "::endgroup::"
}
trap 'rc=$?; if [ $rc -ne 0 ]; then dump; fi' EXIT

kubectl create namespace "$ns"
# A random password, never printed: the Secrets are created from stdin-free literals in this shell only.
pw=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
kubectl -n "$ns" create secret generic clearance-db-password --from-literal=password="$pw" >/dev/null
kubectl -n "$ns" create secret generic clearance-db \
  --from-literal=uri="postgres://clearance:${pw}@postgres.${ns}.svc:5432/clearance?sslmode=disable" >/dev/null
unset pw
kubectl -n "$ns" apply -f "$here/postgres.yaml"
kubectl -n "$ns" rollout status deploy/postgres --timeout=180s

version_args=()
if [ -n "${CHART_VERSION:-}" ]; then version_args=(--version "$CHART_VERSION"); fi
helm install clearance "$CHART" "${version_args[@]}" -n "$ns" \
  -f "$here/../../charts/clearance/ci/install-values.yaml" \
  --set image.repository="$IMAGE_REPO" --set image.tag="$IMAGE_TAG" --set image.pullPolicy=Never \
  --set api.enabled="$API" --wait --timeout 5m

api_url=""
if [ "$API" = true ]; then api_url="http://clearance-api.${ns}.svc:8080"; fi
INSTALLTEST_IMAGE="$INSTALLTEST_IMAGE" API_URL="$api_url" envsubst '${INSTALLTEST_IMAGE} ${API_URL}' \
  < "$here/installtest-pod.yaml" | kubectl apply -f -
# Wait for the pod to finish (Succeeded or Failed), then read its verdict.
for _ in $(seq 1 150); do
  phase=$(kubectl -n clearance-test get pod installtest -o jsonpath='{.status.phase}')
  case "$phase" in Succeeded|Failed) break ;; esac
  sleep 2
done
kubectl -n clearance-test logs installtest | tee installtest.log
{
  echo "### Install test"; echo; echo '```'; cat installtest.log; echo '```'
} >> "$summary"
if [ "$phase" != Succeeded ]; then echo "FAIL installtest pod: $phase"; fail=1; fi

# The evidence chain verifies from genesis, read-only (helm test).
if helm test clearance -n "$ns" --logs | tee helmtest.log; then
  echo "PASS helm test (chain verify)"
else
  echo "FAIL helm test (chain verify)"; fail=1
fi
{ echo; echo '```'; cat helmtest.log; echo '```'; } >> "$summary"

# Image size (uncompressed, docker's size of the single-arch image the runner built or pulled) and the core's idle memory (the kubelet's working set).
node=$(kubectl -n "$ns" get pod -l app.kubernetes.io/component=core -o jsonpath='{.items[0].spec.nodeName}')
img_bytes=$(docker image inspect -f '{{.Size}}' "${IMAGE_REPO}:${IMAGE_TAG}" 2>/dev/null || echo 0)
echo "waiting ${IDLE_SECONDS}s idle"
sleep "$IDLE_SECONDS"
pod=$(kubectl -n "$ns" get pod -l app.kubernetes.io/component=core -o jsonpath='{.items[0].metadata.name}')
mem_bytes=$(kubectl get --raw "/api/v1/nodes/${node}/proxy/stats/summary" | python3 -c '
import sys, json
pod = sys.argv[1]
for p in json.load(sys.stdin)["pods"]:
    if p["podRef"]["name"] == pod:
        for c in p["containers"]:
            if c["name"] == "core":
                print(c["memory"]["workingSetBytes"]); sys.exit(0)
print(0)' "$pod")
mib() { python3 -c "print(f'{$1/1048576:.1f} MiB')"; }
mb() { python3 -c "print(f'{$1/1e6:.1f} MB')"; }
line_img="image ${IMAGE_REPO}:${IMAGE_TAG}: $(mb "$img_bytes") uncompressed (budget $(mb "$MAX_IMAGE_BYTES"))"
line_mem="core idle working set after ${IDLE_SECONDS}s: $(mib "$mem_bytes") (budget $(mib "$MAX_IDLE_BYTES"))"
if [ "$img_bytes" -gt 0 ] && [ "$img_bytes" -lt "$MAX_IMAGE_BYTES" ]; then echo "PASS $line_img"; else echo "FAIL $line_img"; fail=1; fi
if [ "$mem_bytes" -gt 0 ] && [ "$mem_bytes" -lt "$MAX_IDLE_BYTES" ]; then echo "PASS $line_mem"; else echo "FAIL $line_mem"; fail=1; fi
{ echo; echo "- $line_img"; echo "- $line_mem"; } >> "$summary"

# One writer: the core is one replica and upgrades with Recreate.
kubectl -n "$ns" get deploy clearance-core -o jsonpath='{.spec.replicas} {.spec.strategy.type}{"\n"}' | grep -qx '1 Recreate' &&
  echo "PASS core is one replica, Recreate" || { echo "FAIL core replicas/strategy"; fail=1; }

exit "$fail"
