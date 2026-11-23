# The test double the Argo CD conformance job (tools/cmp-conformance.sh) runs in its kind cluster: tools/cmpsmoke as
# the plugin's Clearance core, and as the git host (smart HTTP, read-only) Argo CD and the plugin fetch the fixture
# repositories from. Never published. The build context is a directory the script fills:
#   cmpsmoke   the stub, built for linux (CGO_ENABLED=0)
#   repos/     the bare fixture repositories
FROM alpine:3.22
# git-http-backend is in git-daemon.
RUN apk add --no-cache git git-daemon
COPY cmpsmoke /usr/local/bin/cmpsmoke
COPY repos /srv/git
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/cmpsmoke"]
