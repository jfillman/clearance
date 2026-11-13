# syntax=docker/dockerfile:1.7
# Clearance's Slack surface (docs/slack.md): the static `clearance-slack` binary on distroless, nonroot, no shell. A
# different image from Clearance's on purpose: the websocket client and the Slack code are not in the core's image, and
# the service holds no signing key. Build from the repository root:
#   container build -f cmd/clearance-slack/Dockerfile --build-arg VERSION=dev -t clearance-slack:dev .
# Pinned and reproducible like the core's image (the digests are bumped together with it).

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
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X main.version=${VERSION}" \
      -o /out/clearance-slack ./cmd/clearance-slack

FROM ${BASE_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="clearance-slack" \
      org.opencontainers.image.description="Clearance's Slack surface: notifications, and clear and deny for linked people" \
      org.opencontainers.image.source="https://github.com/jfillman/clearance" \
      org.opencontainers.image.licenses="NOASSERTION" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/clearance-slack /clearance-slack
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/clearance-slack"]
