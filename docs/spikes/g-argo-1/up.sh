#!/usr/bin/env bash
# G-ARGO-1 spike: a namespaced Argo CD 3.5.0 with the spike CMP, in clearance-spike-argo, deploying into
# clearance-spike-prot. hangar-dev ONLY: the context is fixed and checked.
set -euo pipefail
CTX=${CTX:-hangar-dev}
[ "$CTX" = hangar-dev ] || { echo "refusing: this spike runs on hangar-dev only" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -r "$WORK"' EXIT
K="kubectl --context $CTX"

$K apply -f "$HERE/manifests/00-namespaces.yaml"

# The upstream namespaced install, without the API server, Dex and the ApplicationSet controller.
curl -sSfL -o "$WORK/install.yaml" https://raw.githubusercontent.com/argoproj/argo-cd/v3.5.0/manifests/namespace-install.yaml
yq 'select(.metadata.name | test("applicationset|dex|argocd-server") | not)' "$WORK/install.yaml" > "$WORK/base.yaml"
P="$HERE/manifests/repo-server-patch.yaml"
yq -i "(select(.kind == \"Deployment\" and .metadata.name == \"argocd-repo-server\") | .spec.template.spec.initContainers) += load(\"$P\").spec.template.spec.initContainers |
       (select(.kind == \"Deployment\" and .metadata.name == \"argocd-repo-server\") | .spec.template.spec.containers) += load(\"$P\").spec.template.spec.containers |
       (select(.kind == \"Deployment\" and .metadata.name == \"argocd-repo-server\") | .spec.template.spec.volumes) += load(\"$P\").spec.template.spec.volumes" "$WORK/base.yaml"

# The spike binary (linux/arm64, hangar-dev's arch), gzipped and split so each part fits a ConfigMap.
(cd "$HERE/cmp" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o "$WORK/clearance-cmp-spike" .)
gzip -9 -c "$WORK/clearance-cmp-spike" > "$WORK/bin.gz"
half=$(( ($(wc -c < "$WORK/bin.gz") + 1) / 2 ))
split -b "$half" "$WORK/bin.gz" "$WORK/part-"
for p in a b; do
  $K -n clearance-spike-argo create configmap "clearance-spike-cmp-bin-$p" --from-file=part="$WORK/part-a$p" \
    --dry-run=client -o yaml | $K apply --server-side -f -
done

$K -n clearance-spike-argo apply -f "$HERE/manifests/12-cmp.yaml"
$K -n clearance-spike-argo apply --server-side -f "$WORK/base.yaml"
$K apply -f "$HERE/manifests/11-argocd-cluster.yaml"
$K -n clearance-spike-argo patch configmap argocd-cm --type merge --patch-file "$HERE/manifests/13-argocd-cm-patch.yaml"
$K -n clearance-spike-argo rollout restart sts/argocd-application-controller
$K -n clearance-spike-argo rollout status deploy/argocd-repo-server --timeout=300s
$K -n clearance-spike-argo rollout status sts/argocd-application-controller --timeout=300s
