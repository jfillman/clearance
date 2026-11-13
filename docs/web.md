# The web UI server (`clearance web`)

`clearance web` is the backend-for-frontend of Clearance's standalone web UI. It serves the UI bundle, signs a person
in at the people IdP, keeps the session in memory, and forwards the page's calls to clearance-api (reads), the core
(writes) and, if configured, the Autopilot gateway's person controls, with the **person's own ID token** as the bearer.
It is a subcommand of the one binary. It adds no authority: it decides nothing, holds no Clearance credential for
people, and caches no answer. Whatever Clearance answers (401, 403, a refusal) the page shows.

Status: WEB-4, with the Helm chart (WEB-5, below). The bundle itself (WEB-2/WEB-3) is a separate package; until the bundle is
built in, the binary serves a placeholder page and sign-in works.

## What it guards

| Property | Where it is enforced |
|---|---|
| The IdP's ID token is the only identity; the person's allowlist, roles and who-may-clear rules apply unchanged | `proxy.go` sets `Authorization: Bearer <person's ID token>`; the core and clearance-api verify it as for the CLI |
| Authorization code with PKCE (S256), `state` and `nonce` checked, confidential client | `server.go` (`login`, `callback`), `oidc.go` |
| ID token verified (signature from the issuer's JWKS, iss, aud, exp, iat) by the code the core uses | `authn.VerifyIDToken` (`internal/authn`), called from `oidc.go` `checkIDToken`; nonce, `azp` and `auth_time` checked there |
| Login CSRF and state replay | a `__Host-clearance_login` cookie binds the state to the browser; a state works once (`session.go` `flows.take`) |
| Sessions in memory only, bounded, evicted | `session.go` `Store`: nothing is written to disk or a database; the map is keyed by a hash of the id |
| Session cookie | `__Host-clearance_session`, 256-bit random id, HttpOnly, Secure, SameSite=Strict, Path=/, no Domain (`server.go` `setCookie`); a new id on every sign-in; ids are parsed strictly (`parseID`, fuzzed) |
| Lifetime | the earliest of the token's `exp`, one hour after `iat`, and `CLEARANCE_WEB_SESSION_TTL` (never over 1 h), plus an idle timeout (`callback`, `Store.live`) |
| CSRF | every non-GET needs `Origin` equal to the public origin and the session's synchronizer token in `X-CSRF-Token` (`checkCSRF`); the token comes from `GET /auth/session` |
| Header stripping | the outbound request is built from scratch with an allowlist (`forwardHeaders`: Accept, Accept-Language, Content-Type, Last-Event-ID, Idempotency-Key); inbound Authorization, Cookie, Forwarded and the rest are dropped; upstream Set-Cookie, Location and CORS headers are dropped (`proxy.go`) |
| No answer caching | `Cache-Control: no-store` on every forwarded answer; nothing stored |
| Limits | request body (`MAX_BODY_BYTES`, 1 MiB), answer size (32 MiB, the connection is cut rather than truncated), call deadline (60 s); a stream ends when the session does |
| Paths | dot segments, empty segments, backslashes, control characters and encoded `/`, `\`, `.` are refused (`upstreamPath`, fuzzed); redirects from upstream are not followed or passed on |
| Browser hardening | CSP `default-src 'self'; script-src 'self'; ... frame-ancestors 'none'`, nosniff, `Referrer-Policy: no-referrer`, X-Frame-Options, COOP/CORP, HSTS when the public URL is https (`securityHeaders`) |
| Egress | only the IdP and the three configured upstreams; the HTTP client ignores `HTTP(S)_PROXY` |
| Secrets | the client secret is read from a file, never logged; ID tokens are never logged or returned to the page |
| `via` | every write carries `X-Clearance-Via: web` (see below) |

The CSP allows inline *styles* (the UI's CSS-in-JS injects style elements) and no inline script.

## Step-up (a fresh login)

When the core refuses a write because the sign-in is too old, it answers **401** with
`{"error", "rule": "DG-AUTH-NOT-FRESH", "hint", "max_age": "<Go duration>", "age": "<Go duration>"}` (CLEARANCE_FRESH_AUTH_*,
[core.md](core.md)). The server matches exactly that (status 401, top-level `rule`), passes the answer through unchanged
and adds `X-Clearance-Reauth: /auth/login?reauth=1&max_age=<seconds>&return=<page>`. The UI navigates there; the server
then asks the IdP with `prompt=login&max_age=<n>`, checks the returned token's `auth_time` is within `max_age` (an IdP that
ignores the request does not satisfy it), replaces the session under a new id, and returns the person to the page. The
refused write is not replayed: the person repeats it. The web tier never decides what needs freshness; the core does. Any
other 401 (a bad token) carries no such header, and the page treats it as "sign in".

## Configuration

Flags override the environment.

| Env | Flag | Meaning |
|---|---|---|
| `CLEARANCE_WEB_LISTEN` | `--listen` | listen address, default `:8080` |
| `CLEARANCE_WEB_PUBLIC_URL` | `--public-url` | the origin people use (https; `http://localhost` for development); the redirect URI is `<url>/auth/callback` |
| `CLEARANCE_WEB_ISSUER` | `--issuer` | the people IdP (discovery is `<issuer>/.well-known/openid-configuration`) |
| `CLEARANCE_WEB_CLIENT_ID` | `--client-id` | the confidential OIDC client |
| `CLEARANCE_WEB_CLIENT_SECRET_FILE` | `--client-secret-file` | file with the client secret |
| `CLEARANCE_WEB_UPSTREAM_AUDIENCE` | `--upstream-audience` | optional: the audience the core and clearance-api require (e.g. `clearance`); see below |
| `CLEARANCE_WEB_API_URL` | `--api-url` | clearance-api |
| `CLEARANCE_WEB_CORE_URL` | `--core-url` | the core |
| `CLEARANCE_WEB_GATEWAY_URL` | `--gateway-url` | optional: the Autopilot gateway; `/api/gateway/*` exists only when set |
| `CLEARANCE_WEB_SESSION_TTL` | `--session-ttl` | at most 1 h (default 1 h) |
| `CLEARANCE_WEB_IDLE_TIMEOUT` | `--idle-timeout` | default 15 m |
| `CLEARANCE_WEB_MAX_SESSIONS` | | default 10000 |
| `CLEARANCE_WEB_FRESH_MAX_AGE` | `--fresh-max-age` | default 5 m |
| `CLEARANCE_WEB_MAX_BODY_BYTES`, `_MAX_RESPONSE_BYTES`, `_REQUEST_TIMEOUT` | | 1 MiB, 32 MiB, 60 s |
| `CLEARANCE_WEB_TLS_CERT`, `_TLS_KEY` | | serve TLS here; otherwise a gateway terminates it |

Endpoints: `/healthz` (process up), `/readyz` (the IdP is reachable; discovery is lazy and retried, so the server starts
while the IdP is down), `/auth/login`, `/auth/callback`, `/auth/session` (who, the CSRF token, expiry; never the ID
token), `POST /auth/logout`, `/api/read/*`, `/api/write/*`, `/api/gateway/*`, and the bundle at `/`.

The IdP client: confidential, authorization-code grant, PKCE, redirect URI `<public-url>/auth/callback`, scopes
`openid email profile`, `client_secret_basic`, `auth_time` in the ID token. The access and refresh tokens the IdP
returns are dropped unread.

## The token the core accepts (Dex cross-client trust)

The web's OIDC client has its own id (`clearance-web`), so by default its ID token has `aud: clearance-web`, which the core and
clearance-api (they require `oidc.audience`, `clearance`) refuse: sign-in would work and every forwarded call would be a 401. With
`CLEARANCE_WEB_UPSTREAM_AUDIENCE=clearance` the login adds the scope `audience:server:client_id:clearance` and Dex issues the
token with `aud: ["clearance", "clearance-web"]` and `azp: "clearance-web"` (Dex `getAudience`: the peers asked for, then the
requester). Dex does this only if the peer client lists the requester under `trustedPeers`: the `clearance` static client needs
`trustedPeers: [clearance-web]`. This does not change the CLI's device flow (trustedPeers is consulted only for that scope).
The server's check is strict: it still verifies the token for its own client (its id is in `aud`) and then requires the upstream
audience in `aud` AND `azp` equal to its own client id; a token issued to another client that merely lists the audience, or
one without `azp`, is refused. Unset (the default), nothing changes.

## Building the bundle in

The UI is the standalone [clearance-ui](https://github.com/jfillman/clearance-ui) shell, embedded from
`internal/web/static/` (`embed.FS`, `static.go`). The committed `index.html` there is a placeholder, so a plain
`go build ./cmd/clearance` and `go test ./...` work with no network. Released images carry the real UI.

**The pin** is `web-ui.lock`: the clearance-ui repo, a version, and the sha256 of that release's
`clearance-ui-web-<version>.tar.gz`. To bump the UI, change `version` and `sha256` in one PR (the release's
`.sha256` asset has the value; confirm it against your own download).

**The step** is `make web-ui` (`go run ./tools/webui`):

1. Download the tarball from the release over https (a redirect off https is refused; downloads are cached by the pinned
   sha256 under the user cache dir, `$WEBUI_CACHE` overrides).
2. Refuse unless its sha256 equals the one in `web-ui.lock`. The `.sha256` asset beside the tarball is never read: whoever
   could swap the tarball could swap that too.
3. Extract into a staging directory: only regular files and directories, no absolute or `..` paths, no symlinks, hard
   links or devices, no duplicates, size and entry caps, and an `index.html` at the root. Only then does it replace the
   contents of `internal/web/static/` (a refused archive changes nothing).

The extracted files are not committed: `assets/` is gitignored, and `index.html` shows as modified until
`make web-ui-clean` restores the placeholder. `make web-ui-verify` checks the pin without extracting;
`make build-release` is the step, the embed test and `go build`.

**Where it runs.** The `Dockerfile`'s build stage runs `go run ./tools/webui` before `go build`, then
`TestReleaseBundleIsTheUI` with `CLEARANCE_REQUIRE_UI_BUNDLE=1`, which fails the build if the embedded `index.html` is
still the placeholder or the bundle has no `assets/`. The release workflow builds the image from that Dockerfile, so every
released `clearance` image carries the pinned UI. CI's `web-ui` job does the same on every push (verify the pin, extract,
run that test, `go build`), so a bad pin or a broken bundle fails the PR and not the release.

The contract with the bundle: `index.html` is the entry; files under `assets/` have content-hashed names (cached for a
year, immutable); everything else is revalidated; an unknown path without an extension serves `index.html` for the
client router. The entry page needs a session (a person without one is redirected to sign in); assets are public. The
page reads `/auth/session` for the CSRF token and sends it as `X-CSRF-Token` on every non-GET.

## Deploy (the chart, WEB-5)

`charts/clearance` runs it behind `web.enabled: false` (default off; [install.md](install.md) has the values table):

- **A Deployment of ONE replica** (`web.replicas`, the chart refuses more): sessions are in memory, so more replicas would
  need sticky sessions, and a restart (or a rollout, which is `Recreate`) signs everyone out. Non-root (65532), read-only
  root filesystem, all capabilities dropped, RuntimeDefault seccomp, no service-account token mounted (the web tier holds no
  Kubernetes credential), probes `/healthz` (startup, liveness) and `/readyz` (readiness; the IdP must be reachable).
- **A Service** (`<release>-web`, port 8080) and an optional **HTTPRoute** (`httpRoutes.web`: `parentRefs`, `hostnames`,
  every path to the pod, since it serves the UI, `/auth/*` and `/api/*`).
- **The client secret is a file**: `web.clientSecret.existingSecret` (and `key`, default `client-secret`) names a Secret you
  manage or an ExternalSecret creates; it is mounted read-only (0400) at `/etc/clearance/web/client-secret` and
  `CLEARANCE_WEB_CLIENT_SECRET_FILE` points there. The chart never takes the value.
- **Environment**: `web.publicURL`, `web.issuer`, `web.clientID` (default `clearance-web`); the API and core URLs default to this
  release's `<release>-api` and `<release>-core` Services (`web.apiURL`, `web.coreURL` override); `web.gatewayURL` turns on
  `/api/gateway/*`; `web.sessionTTL`, `idleTimeout`, `freshMaxAge`, `requestTimeout`, `maxSessions`, `maxBodyBytes`,
  `maxResponseBytes` are optional. TLS is the Gateway's: the chart sets no `CLEARANCE_WEB_TLS_*`.
- **NetworkPolicy** (`networkPolicy.enabled`): ingress only from `networkPolicy.web.from` (your Gateway); egress only DNS, the
  api and the core pods, the IdP (`networkPolicy.web.idp.to` and `.ports`, an `ipBlock` or the in-cluster IdP's pods;
  NetworkPolicy has no host names), the gateway (`networkPolicy.web.gateway`, when `web.gatewayURL` is set) and
  `networkPolicy.web.extraEgress`. No Postgres, no Kubernetes API server. The core's and the api's policies admit the web pod
  on 8080 automatically.

**https only.** The server refuses an `http` public URL or issuer (except `http://localhost` for development) and its cookies are
`__Host-`/Secure, so the web UI is for clusters whose Gateway serves https (such as eks-dev); a lab Gateway that serves http
cannot run it.

The owner creates the confidential client in the people IdP (redirect URI `<publicURL>/auth/callback`) and the Secret.

## `via` and freshness

The server sends `X-Clearance-Via: web` on every write; `web` is one of the core's built-in surfaces (`cli`, `web`,
`slack`, `api`), so the core accepts it and records the claimed `surface`. Both this and the freshness refusal are in the
core since v0.46.0 (CLI phase 2). The server's tests run the step-up against the real core handler.
