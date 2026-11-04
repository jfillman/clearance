#!/usr/bin/env bash
# Spike d on hangar-dev: one sync with the webhook receiver up, one with it down (scaled to 0 for the sync, then back).
# Compare the receiver's log with a watch on the Application (run beside it:
#   kubectl get application spike-a2 -w --output-watch-events -o json | jq -c ...).
set -uo pipefail
CTX=${CTX:-hangar-dev}
[ "$CTX" = hangar-dev ] || { echo "refusing: hangar-dev only" >&2; exit 2; }
K="kubectl --context $CTX -n clearance-spike-argo"
HERE=$(cd "$(dirname "$0")" && pwd)
# The receiver, and the webhook service, template, trigger and subscription merged into argocd-notifications-cm.
yq 'select(.metadata.name != "argocd-notifications-cm")' "$HERE/manifests/50-notifications.yaml" | kubectl --context "$CTX" apply -f -
$K patch configmap argocd-notifications-cm --type merge -p "$(yq -o json 'select(.metadata.name == "argocd-notifications-cm") | {"data": .data}' "$HERE/manifests/50-notifications.yaml")"
sync() {
  local prev f
  prev=$($K get application spike-a2 -o jsonpath='{.status.operationState.finishedAt}')
  $K patch application spike-a2 --type merge -p '{"operation":{"initiatedBy":{"username":"g-argo-1-spike"},"sync":{"prune":true}}}' >/dev/null
  until f=$($K get application spike-a2 -o jsonpath='{.status.operationState.finishedAt}'); [ -n "$f" ] && [ "$f" != "$prev" ]; do sleep 3; done
  echo "sync finished $f phase $($K get application spike-a2 -o jsonpath='{.status.operationState.phase}')"
}
$K rollout status deploy/spike-receiver --timeout=300s
echo "== 1: receiver up"; sync; sleep 20
echo "== 2: receiver down"; $K scale deploy/spike-receiver --replicas=0; $K wait --for=delete pod -l app=spike-receiver --timeout=180s
sync; sleep 20
$K scale deploy/spike-receiver --replicas=1; $K rollout status deploy/spike-receiver --timeout=300s; sleep 60
echo "== receiver log (the new pod after 2)"; $K logs deploy/spike-receiver
echo "== notifications controller log"; $K logs deploy/argocd-notifications-controller --since=15m | grep -i -E 'notif|webhook|error|fail' | tail -20
