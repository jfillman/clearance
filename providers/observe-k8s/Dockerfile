# syntax=docker/dockerfile:1.7
# Clearance's Kubernetes audit collector (providers/observe-k8s): one static binary on distroless static, nonroot
# (uid 65532), no shell. Build from the repository root:
#
#   docker buildx build -f providers/observe-k8s/Dockerfile --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=v0.33.0 -t ghcr.io/jfillman/clearance-observe-k8s:v0.33.0 .
#
# Same bases and flags as the repository Dockerfile (pinned by digest, reproducible: -trimpath, no VCS stamp, an empty
# build id); bump the digests together with it.

ARG GO_IMAGE=golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

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
COPY providers/ providers/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= -X main.version=${VERSION#v}" -o /out/observe-k8s ./providers/observe-k8s/cmd/observe-k8s

FROM ${BASE_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="clearance-observe-k8s" \
      org.opencontainers.image.description="Clearance's Kubernetes audit collector: audit webhook receiver, durable queue, observation pipeline, health" \
      org.opencontainers.image.source="https://github.com/jfillman/clearance" \
      org.opencontainers.image.licenses="NOASSERTION" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/observe-k8s /observe-k8s
USER 65532:65532
ENTRYPOINT ["/observe-k8s"]
