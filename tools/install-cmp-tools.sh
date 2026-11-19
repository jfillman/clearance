#!/usr/bin/env bash
# Installs the helm and kustomize the clearance-cmp image ships into DEST, verified against the sha256 checksums in
# providers/argocd/cmp/Dockerfile (the one place the versions and checksums live), so CI renders with the same
# tools Argo CD's plugin sidecar does and the real-binary tests run instead of skipping.
#
#   tools/install-cmp-tools.sh DEST      # then put DEST first on PATH
set -euo pipefail
dest="${1:?usage: tools/install-cmp-tools.sh DEST}"
dockerfile="$(cd "$(dirname "$0")/.." && pwd)/providers/argocd/cmp/Dockerfile"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) arch=amd64;;
  Linux-aarch64 | Linux-arm64) arch=arm64;;
  *) echo "unsupported platform (the Dockerfile pins linux checksums only) $(uname -s)-$(uname -m)"; exit 1;;
esac

helm_v="$(sed -n 's/^ARG HELM_VERSION=//p' "$dockerfile")"
kust_v="$(sed -n 's/^ARG KUSTOMIZE_VERSION=//p' "$dockerfile")"
line="$(grep -E "^[[:space:]]*${arch}\) HELM_SHA=" "$dockerfile")"
helm_sha="$(sed -E 's/.*HELM_SHA=([0-9a-f]{64});.*/\1/' <<<"$line")"
kust_sha="$(sed -E 's/.*KUSTOMIZE_SHA=([0-9a-f]{64});.*/\1/' <<<"$line")"
for v in "$helm_v" "$kust_v" "$helm_sha" "$kust_sha"; do [ -n "$v" ] || { echo "cannot read the pins from $dockerfile"; exit 1; }; done
[ "${#helm_sha}" = 64 ] && [ "${#kust_sha}" = 64 ] || { echo "cannot read the checksums for $arch from $dockerfile"; exit 1; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$dest"
curl -fsSL -o "$tmp/helm.tgz" "https://get.helm.sh/helm-${helm_v}-linux-${arch}.tar.gz"
echo "${helm_sha}  $tmp/helm.tgz" | sha256sum -c -
tar -xzf "$tmp/helm.tgz" -C "$tmp" "linux-${arch}/helm"
install -m 0755 "$tmp/linux-${arch}/helm" "$dest/helm"
curl -fsSL -o "$tmp/kustomize.tgz" "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F${kust_v}/kustomize_${kust_v}_linux_${arch}.tar.gz"
echo "${kust_sha}  $tmp/kustomize.tgz" | sha256sum -c -
tar -xzf "$tmp/kustomize.tgz" -C "$dest" kustomize
echo "installed helm $helm_v and kustomize $kust_v into $dest"
