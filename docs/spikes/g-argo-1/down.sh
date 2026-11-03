#!/usr/bin/env bash
# Remove everything the G-ARGO-1 spike created on hangar-dev.
set -uo pipefail
CTX=${CTX:-hangar-dev}
[ "$CTX" = hangar-dev ] || { echo "refusing: this spike runs on hangar-dev only" >&2; exit 2; }
K="kubectl --context $CTX"
# Applications first, without cascading into the namespaces we delete anyway.
$K -n clearance-spike-argo patch applications --all --type=json -p='[{"op":"remove","path":"/metadata/finalizers"}]' 2>/dev/null
$K -n clearance-spike-argo delete applications --all --wait=false 2>/dev/null
$K delete validatingadmissionpolicybinding -l hangar.io/spike=g-argo-1 --ignore-not-found
$K delete validatingadmissionpolicy -l hangar.io/spike=g-argo-1 --ignore-not-found
$K delete mutatingadmissionpolicybinding -l hangar.io/spike=g-argo-1 --ignore-not-found
$K delete mutatingadmissionpolicy -l hangar.io/spike=g-argo-1 --ignore-not-found
$K delete validatingpolicies.policies.kyverno.io -l hangar.io/spike=g-argo-1 --ignore-not-found
$K delete namespace clearance-spike-prot clearance-spike-argo --ignore-not-found
$K delete crd clearancegrants.spike.clearance.hangar.io --ignore-not-found
