#!/usr/bin/env bash
# G-ARGO-1 prod spike e: does a hangar-prod workload identity other than Tower's backend reach and authenticate to
# the core on hangar-dev through the route? The user runs it (see ../prod-plan.md). It mints a 10-minute token for
# clearance-spike-prot/clearance-spike-cmp into a shell variable (never a file, never printed) and POSTs an empty body to
# the core's registration route. The empty body is refused before anything is recorded, so the answer says only who
# the core thinks the caller is:
#   401 "... may not call this Clearance"   the service account is not in CLEARANCE_FOREIGN_SERVICE_ACCOUNTS
#   403 "<principal> is not a verifier"     authenticated as hangar-prod/clearance-spike-prot/clearance-spike-cmp
#   400 (a bad change)                      authenticated and a verifier (only after step e3)
set -uo pipefail
[ "${CONFIRM:-}" = hangar-prod ] || { echo "set CONFIRM=hangar-prod" >&2; exit 2; }
ROUTE=${ROUTE:-http://192.168.1.72}   # hangar-dev's ingress, the address prod Backstage's hostAlias uses
TOKEN=$(kubectl --context hangar-prod -n clearance-spike-prot create token clearance-spike-cmp --audience clearance --duration 10m)
for path in /v1/clearances /v1/records; do
  resp=$(curl -s -m 15 -w '\n%{http_code}' -X POST -H 'Host: clearance.hangar-dev.local' \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}' "$ROUTE$path")
  echo "POST $path -> $(echo "$resp" | tail -1) $(echo "$resp" | sed '$d' | head -c 300)"
done
unset TOKEN
