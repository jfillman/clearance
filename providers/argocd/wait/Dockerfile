# syntax=docker/dockerfile:1.7
# The PreSync wait Job's image (G-ARGO-5): the static `clearance-wait` binary on distroless, nonroot, no shell.
# Build from the repository root:
#   container build -f providers/argocd/wait/Dockerfile --build-arg VERSION=dev -t clearance-wait:dev .

ARG GO_IMAGE=golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS=linux
ARG TARGETARCH
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
      -o /out/clearance-wait ./providers/argocd/wait

FROM ${BASE_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="clearance-wait" \
      org.opencontainers.image.description="Clearance's Argo CD PreSync wait: holds a sync until its change is cleared" \
      org.opencontainers.image.source="https://github.com/jfillman/clearance" \
      org.opencontainers.image.licenses="NOASSERTION" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/clearance-wait /clearance-wait
USER 65532:65532
ENTRYPOINT ["/clearance-wait"]
