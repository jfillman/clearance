#!/usr/bin/env bash
# Spike c on hangar-dev: server-side dry runs as the scratch Argo CD's controller (impersonated), one per case, with
# the policies in Warn (replace, so a request is always sent). Prints each case and the admission warnings (or refusal) it got. Nothing is persisted.
set -uo pipefail
CTX=${CTX:-hangar-dev}
[ "$CTX" = hangar-dev ] || { echo "refusing: hangar-dev only" >&2; exit 2; }
NS=clearance-spike-prot
AS=${AS:-system:serviceaccount:clearance-spike-argo:argocd-application-controller}
K="kubectl --context $CTX -n $NS"
live() { $K get cm app-config -o json | jq 'del(.metadata.resourceVersion,.metadata.uid,.metadata.creationTimestamp,.metadata.managedFields,.metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"])'; }
try() { # name, jq filter on the live ConfigMap, [as]
  local name=$1 filter=$2 as=${3-$AS} t0 t1 out asflag=()
  [ -n "$as" ] && asflag=(--as="$as")
  t0=$(python3 -c 'import time;print(time.time_ns())')
  out=$(live | jq "$filter" | $K replace --dry-run=server ${asflag[@]+"${asflag[@]}"} -f - 2>&1)
  t1=$(python3 -c 'import time;print(time.time_ns())')
  [ "$name" = "unlisted object" ] && out=$(live | jq "$filter" | $K create --dry-run=server ${asflag[@]+"${asflag[@]}"} -f - 2>&1)
  printf '%-34s %5sms  %s\n' "$name" "$(( (t1 - t0) / 1000000 ))" "$(echo "$out" | grep -E 'Warning|Error|denied' | sed 's/^Warning: //' | tr '\n' ' ' | cut -c1-260)"
}
try "listed, stamped hash"         '.'
try "content changed, stamp kept"  '.data.LOG_LEVEL = "debug"'
try "stamp changed"                '.metadata.annotations["clearance.hangar.io/rendered"] = "sha256:00"'
try "unlisted object"              '.metadata.name = "not-in-grant"'
try "no stamp"                     'del(.metadata.annotations["clearance.hangar.io/rendered"])'
try "another writer (not matched)" '.metadata.annotations["clearance.hangar.io/rendered"] = "sha256:00"' ""

# The grant marked invalid (what the agent does on expiry), then restored.
$K patch clearancegrant spike-grant --type merge -p '{"status":{"valid":false}}' >/dev/null; sleep 3
try "grant status.valid=false"     '.'
$K patch clearancegrant spike-grant --type merge -p '{"status":{"valid":true}}' >/dev/null

# A second active grant (a newer change) that does not list the object: paramRef by selector evaluates EVERY match.
sleep 3; $K get clearancegrant spike-grant -o json | jq '.metadata = {name: "spike-grant-2", namespace: .metadata.namespace, labels: .metadata.labels} | .spec.index = {"/ConfigMap/other": "sha256:11"}' | $K create -f - >/dev/null
try "two active grants, one lists it" '.'
$K delete clearancegrant spike-grant-2 >/dev/null

# A subresource write by the controller is not matched (the guard).
t0=$(python3 -c 'import time;print(time.time_ns())')
out=$($K patch deploy spike-web --subresource=scale --type merge -p '{"spec":{"replicas":0}}' --dry-run=server --as="$AS" 2>&1)
t1=$(python3 -c 'import time;print(time.time_ns())')
printf '%-34s %5sms  %s\n' "scale subresource" "$(( (t1 - t0) / 1000000 ))" "$(echo "$out" | grep -E 'Warning|Error|denied' | tr '\n' ' ' | cut -c1-200)"
