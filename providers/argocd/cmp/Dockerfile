# syntax=docker/dockerfile:1.7
# The Clearance Argo CD plugin sidecar for argocd-apps' repo-server (G-ARGO-4): the static `clearance-cmp` binary,
# plugin.yaml, and the tools a render needs (git, helm, kustomize), nothing else. Run it as an Argo CD CMP sidecar
# (command /var/run/argocd/argocd-cmp-server, copied in by repo-server's copyutil init container), uid 999.
# Build from the repository root:
#   container build -f providers/argocd/cmp/Dockerfile --build-arg VERSION=dev -t clearance-cmp:dev .
#
# helm and kustomize are verified against the checksums below (published with the releases) for the target arch.
# The sidecar mounts the clearance token (a projected service-account token, audience clearance) and nothing else
# that is secret: no repository credentials; the gitops repository is Argo CD's to fetch.

ARG GO_IMAGE=golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd
ARG TOOLS_IMAGE=alpine:3.22

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY client/ client/
COPY internal/ internal/
COPY schemas/ schemas/
COPY providers/ providers/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" \
      -o /out/clearance-cmp ./providers/argocd/cmp

FROM ${TOOLS_IMAGE} AS tools
ARG TARGETARCH
ARG HELM_VERSION=v3.21.3
ARG KUSTOMIZE_VERSION=v5.7.1
RUN apk add --no-cache curl
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) HELM_SHA=15e041a93a590dce8100f39385cd98c84a765c9e36aeeb9e2dc6ff9e4769e2e0; KUSTOMIZE_SHA=ea375e7372f9aa029129d4b2d16c66b7750b7f1213c4f66f910d981c895818d8;; \
      arm64) HELM_SHA=67f58155079ff9ffab98ba5c88daff0ed9b542f3a4732f5dd426dde7dd0f5244; KUSTOMIZE_SHA=4261a040217df3bd6896597c3986d1465925726e4f22a945304b5233a4dcdbda;; \
      *) echo "unsupported arch ${TARGETARCH}"; exit 1;; \
    esac; \
    curl -fsSL -o /tmp/helm.tgz "https://get.helm.sh/helm-${HELM_VERSION}-linux-${TARGETARCH}.tar.gz"; \
    echo "${HELM_SHA}  /tmp/helm.tgz" | sha256sum -c -; \
    tar -xzf /tmp/helm.tgz -C /tmp "linux-${TARGETARCH}/helm"; mv "/tmp/linux-${TARGETARCH}/helm" /usr/local/bin/helm; \
    curl -fsSL -o /tmp/kustomize.tgz "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F${KUSTOMIZE_VERSION}/kustomize_${KUSTOMIZE_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    echo "${KUSTOMIZE_SHA}  /tmp/kustomize.tgz" | sha256sum -c -; \
    tar -xzf /tmp/kustomize.tgz -C /usr/local/bin kustomize

FROM ${TOOLS_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="clearance-cmp" \
      org.opencontainers.image.description="Clearance's Argo CD plugin: renders, hashes and registers a change before Argo CD applies it" \
      org.opencontainers.image.source="https://github.com/jfillman/clearance" \
      org.opencontainers.image.licenses="NOASSERTION" \
      org.opencontainers.image.version="${VERSION}"
RUN apk add --no-cache git ca-certificates && mkdir -p /home/argocd/cmp-server/config /home/argocd/cmp-server/plugins && chown -R 999:999 /home/argocd
COPY --from=tools /usr/local/bin/helm /usr/local/bin/kustomize /usr/local/bin/
COPY --from=build /out/clearance-cmp /usr/local/bin/clearance-cmp
COPY providers/argocd/cmp/plugin.yaml /home/argocd/cmp-server/config/plugin.yaml
ENV HOME=/home/argocd
USER 999:999
