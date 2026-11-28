#!/usr/bin/env bash
# The whole-install upgrade test (N-6f), on a kind cluster that kubectl already points at (.github/workflows/upgrade.yaml
# makes one). Nothing from Airframe, Glidepath or Autopilot is installed: a plain Postgres, the previous release's chart and
# image, the candidate's, and the install test's fake provider (tools/installtest) as the traffic.
#
#   PREV_CHART      the previous release's chart directory (a checkout of its tag)
#   PREV_TAG        its image tag, already loaded into kind (repository clearance)
#   NEW_CHART       the candidate's chart directory
#   NEW_TAG         the candidate's image tag, already loaded into kind
#   INSTALLTEST_IMAGE   the installtest image, already loaded into kind
#   COMPAT          the candidate's internal/compat/compat.json
#   VERSION         the candidate's release (X.Y.Z), whose compat row says expand-only or no-rollback
#
# 1. install the previous release, run traffic, verify the chain (helm test), take the pre-upgrade backup (pg_dump);
# 2. upgrade to the candidate (its migrations run at core start), run traffic, verify the chain;
# 3. expand-only release: roll back to the previous core on the upgraded schema, run traffic (a write), verify again;
#    no-rollback release: the previous core refuses the schema (its log names schema_requires_newer_core), then the restore:
#    stop the core, restore the backup, start the previous core, run traffic, verify the chain.
#
# NOT covered: that the restore's gap (what was written after the backup) is recorded as an exception. That is
# `clearance restore verify` (N-11), which does not exist yet; this test checks the chain verifies and continues.
set -euo pipefail

: "${PREV_CHART:?}" "${PREV_TAG:?}" "${NEW_CHART:?}" "${NEW_TAG:?}" "${INSTALLTEST_IMAGE:?}" "${COMPAT:?}" "${VERSION:?}"
here=$(cd "$(dirname "$0")" && pwd)
ci=$here/../chart-install-test
ns=clearance
summary=${GITHUB_STEP_SUMMARY:-/dev/null}
fail=0
note() { echo "$*"; echo "- $*" >> "$summary"; }

dump() {
  echo "::group::diagnostics"
  kubectl get pods,svc -A -o wide || true
  kubectl -n "$ns" describe pods || true
  kubectl -n "$ns" logs deploy/clearance-core --tail=200 --all-containers || true
  kubectl -n clearance-test logs installtest || true
  echo "::endgroup::"
}
trap 'rc=$?; if [ $rc -ne 0 ]; then dump; fi' EXIT

# no_rollback: does the candidate's compat row (the newest at or below VERSION) mark it no-rollback?
no_rollback=$(python3 - "$COMPAT" "$VERSION" <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))
v = lambda s: tuple(int(x) for x in s.split("-")[0].lstrip("v").split("."))
rows = [r for r in t["releases"] if v(r["core"]) <= v(sys.argv[2])]
print("true" if rows and rows[-1]["core"] == sys.argv[2] and rows[-1]["no_rollback"] else "false")
PY
)
note "candidate $VERSION: no_rollback=$no_rollback"

kubectl create namespace "$ns"
pw=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
kubectl -n "$ns" create secret generic clearance-db-password --from-literal=password="$pw" >/dev/null
kubectl -n "$ns" create secret generic clearance-db \
  --from-literal=uri="postgres://clearance:${pw}@postgres.${ns}.svc:5432/clearance?sslmode=disable" >/dev/null
unset pw
kubectl -n "$ns" apply -f "$ci/postgres.yaml"
kubectl -n "$ns" rollout status deploy/postgres --timeout=180s

install() { # CHART TAG: install or upgrade the release with that chart and image
  helm upgrade --install clearance "$1" -n "$ns" -f "$1/ci/install-values.yaml" \
    --set image.repository=clearance --set image.tag="$2" --set image.pullPolicy=Never --set api.enabled=false --wait --timeout 5m
}

traffic() { # LABEL: the fake provider decides, records and clears; then the chain verifies from genesis
  kubectl delete pod installtest outsider -n clearance-test --ignore-not-found --wait=true >/dev/null
  INSTALLTEST_IMAGE="$INSTALLTEST_IMAGE" API_URL="" envsubst '${INSTALLTEST_IMAGE} ${API_URL}' < "$ci/installtest-pod.yaml" | kubectl apply -f -
  local phase=""
  for _ in $(seq 1 150); do
    phase=$(kubectl -n clearance-test get pod installtest -o jsonpath='{.status.phase}')
    case "$phase" in Succeeded|Failed) break ;; esac
    sleep 2
  done
  kubectl -n clearance-test logs installtest | tail -n 5
  if [ "$phase" != Succeeded ]; then note "FAIL $1: traffic (installtest pod $phase)"; fail=1; return; fi
  if helm test clearance -n "$ns" --logs >/dev/null; then note "PASS $1: traffic recorded and the chain verifies (helm test)"; else note "FAIL $1: chain verify"; fail=1; fi
}

echo "### Upgrade test" >> "$summary"
install "$PREV_CHART" "$PREV_TAG"
traffic "previous release ($PREV_TAG)"
kubectl -n "$ns" exec deploy/postgres -- pg_dump -U clearance -Fc clearance > "$PWD/pre-upgrade.dump"
test -s pre-upgrade.dump && note "PASS pre-upgrade backup taken ($(wc -c < pre-upgrade.dump) bytes)"

install "$NEW_CHART" "$NEW_TAG"
traffic "candidate ($VERSION) after the upgrade"
kubectl -n "$ns" logs deploy/clearance-core --tail=400 | grep -i "clearance schema migrated\|clearance store open" | tail -n 5 || true

if [ "$no_rollback" = false ]; then
  install "$PREV_CHART" "$PREV_TAG"
  traffic "previous core on the upgraded schema ($PREV_TAG, expand-only rollback)"
else
  # The previous core must refuse the schema, with the named code.
  if helm upgrade clearance "$PREV_CHART" -n "$ns" -f "$PREV_CHART/ci/install-values.yaml" \
      --set image.repository=clearance --set image.tag="$PREV_TAG" --set image.pullPolicy=Never --set api.enabled=false --wait --timeout 90s; then
    note "FAIL the previous core started on a no-rollback schema"; fail=1
  else
    sleep 5
    if kubectl -n "$ns" logs deploy/clearance-core --all-containers --previous 2>/dev/null | grep -q schema_requires_newer_core ||
       kubectl -n "$ns" logs deploy/clearance-core --all-containers 2>/dev/null | grep -q schema_requires_newer_core; then
      note "PASS the previous core refused the no-rollback schema (schema_requires_newer_core)"
    else
      note "FAIL the previous core did not start, but its log does not name schema_requires_newer_core"; fail=1
    fi
  fi
  # The restore path: stop the core, restore the pre-upgrade backup into a fresh database, start the previous core.
  kubectl -n "$ns" scale deploy/clearance-core --replicas=0
  kubectl -n "$ns" exec deploy/postgres -- psql -U clearance -d postgres -c "DROP DATABASE clearance WITH (FORCE)" -c "CREATE DATABASE clearance"
  kubectl -n "$ns" exec -i deploy/postgres -- pg_restore -U clearance -d clearance --no-owner < pre-upgrade.dump
  note "restored the pre-upgrade backup"
  install "$PREV_CHART" "$PREV_TAG"
  kubectl -n "$ns" scale deploy/clearance-core --replicas=1
  kubectl -n "$ns" rollout status deploy/clearance-core --timeout=180s
  traffic "previous core on the restored backup"
fi
exit "$fail"
