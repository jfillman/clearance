# syntax=docker/dockerfile:1.7
# Clearance's image: the one static `clearance` binary on distroless static, nonroot (uid 65532), no shell.
# Both bases are pinned by digest; bump them together with a PR (the digest of the multi-arch index, not one arch).
#
#   docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=v0.27.0 -t ghcr.io/jfillman/clearance:v0.27.0 .
#   container build --build-arg VERSION=dev -t clearance:dev .        # Apple's container CLI, local checks
#
# Reproducible: -trimpath, no VCS stamp, an empty build id, and no clock in the binary; the release workflow sets
# SOURCE_DATE_EPOCH (the tagged commit's time) and rewrites layer timestamps to it.
#
# The `installtest` target is the chart's install-test client (tools/installtest), not a release artifact.

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
COPY cmd/ cmd/
COPY internal/ internal/
COPY client/ client/
COPY schemas/ schemas/
COPY tools/installtest/ tools/installtest/
COPY tools/webui/ tools/webui/
COPY web-ui.lock ./
# The pinned clearance-ui bundle replaces the placeholder `clearance web` would embed: downloaded over https, refused
# unless its sha256 is the pin in web-ui.lock, then proven to be the UI and not the placeholder.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go run ./tools/webui && CLEARANCE_REQUIRE_UI_BUNDLE=1 go test -count=1 -run TestReleaseBundleIsTheUI ./internal/web
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o /out/clearance ./cmd/clearance && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid=" -o /out/installtest ./tools/installtest

FROM ${BASE_IMAGE} AS installtest
COPY --from=build /out/installtest /installtest
USER 65532:65532
ENTRYPOINT ["/installtest"]

FROM ${BASE_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="clearance" \
      org.opencontainers.image.description="Clearance: change assurance in the path of every change (core, api, CLI)" \
      org.opencontainers.image.source="https://github.com/jfillman/clearance" \
      org.opencontainers.image.licenses="NOASSERTION" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/clearance /clearance
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/clearance"]
CMD ["core"]
