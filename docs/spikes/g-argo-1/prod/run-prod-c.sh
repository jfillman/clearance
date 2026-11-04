#!/usr/bin/env bash
# G-ARGO-1 prod spike c (hangar-prod, Warn): one server-side dry run every 10 s for 30 minutes as the spike writer,
# against both policies at once. Each line: UTC time, latency, and what came back (ok, the VAP's warning, Kyverno's
# warning, or Kyverno's webhook failing). Nothing is persisted (dry run). The user runs this; see ../prod-plan.md.
set -uo pipefail
[ "${CONFIRM:-}" = hangar-prod ] || { echo "set CONFIRM=hangar-prod to run against hangar-prod" >&2; exit 2; }
N=${N:-180}; EVERY=${EVERY:-10}
K="kubectl --context hangar-prod -n clearance-spike-prot"
AS=system:serviceaccount:clearance-spike-prot:clearance-spike-writer
base=$($K get cm app-config -o json | jq -c 'del(.metadata.resourceVersion,.metadata.uid,.metadata.creationTimestamp,.metadata.managedFields)')
for i in $(seq 1 "$N"); do
  # Alternate a listed write (expect ok) and a wrong stamp (expect both policies to warn).
  if [ $((i % 2)) -eq 0 ]; then body=$base; case=listed; else
    body=$(echo "$base" | jq -c '.metadata.annotations["clearance.hangar.io/rendered"] = "sha256:00"'); case=bad-stamp; fi
  t0=$(python3 -c 'import time;print(time.time_ns())')
  out=$(echo "$body" | $K replace --dry-run=server --as="$AS" -f - 2>&1)
  t1=$(python3 -c 'import time;print(time.time_ns())')
  cls=""
  echo "$out" | grep -q "ValidatingAdmissionPolicy 'spike-clearance-protected-writes'" && cls="$cls vap-warn"
  echo "$out" | grep -q "Policy spike-clearance-protected-writes failed" && cls="$cls kyverno-warn"
  echo "$out" | grep -q "failed calling webhook" && cls="$cls kyverno-webhook-error"
  echo "$out" | grep -q "replaced (server dry run)" && cls="$cls admitted"
  printf '%s %-9s %6sms%s\n' "$(date -u +%H:%M:%S)" "$case" "$(( (t1 - t0) / 1000000 ))" "${cls:- other: $(echo "$out" | tr '\n' ' ' | cut -c1-160)}"
  sleep "$EVERY"
done
