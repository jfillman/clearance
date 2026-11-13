# The person CLI (`clearance`, alias `clr`)

Phase 1 of using Clearance without Backstage: sign in, and read. It is the existing `clearance` binary
([core.md](core.md)); the person commands call [clearance-api](clearance-api.md) with **your own ID token**, so the api
sees `user:<you>` (never a delegate) and shows you exactly what the Clearance pages in Tower show you. Writes (clear,
deny, resolve, break-glass) are a later phase and go to the core.

## `clr`

`clr` is the same binary under another name. Install it as a symlink; messages then say `clr`:

```
ln -s "$(command -v clearance)" ~/bin/clr
```

Nothing dispatches on the name beyond that, so a copy or a hard link works too. The release publishes the one image
(`ghcr.io/jfillman/clearance`, distroless, no shell); it ships no CLI archive yet, so the symlink is yours to make
where you install the binary.

## Configuration

Precedence: flags, then environment, then a small config file.

| Setting | Flag | Environment | Config file key |
|---|---|---|---|
| clearance-api URL | `--api` | `CLEARANCE_API_URL` | `api_url` |
| core URL (the write phase) | `--url` | `CLEARANCE_URL` | `url` |
| people IdP issuer | | `CLEARANCE_OIDC_ISSUER` | `oidc_issuer` |
| IdP public client id | | `CLEARANCE_OIDC_CLIENT_ID` | `oidc_client_id` |
| scopes (default `openid profile email`) | | `CLEARANCE_OIDC_SCOPES` | `oidc_scopes` |

The file is `$XDG_CONFIG_HOME/clearance/config.yaml`, else `~/.config/clearance/config.yaml`, and holds URLs and the
issuer only:

```yaml
api_url: https://clearance-api.hangar-dev.example
oidc_issuer: https://dex.hangar-dev.example/dex
oidc_client_id: clearance
```

Any other key (a `token`, a `client_secret`) is refused, so a secret pasted there fails loudly instead of being kept.
URLs are `https`; plain `http` is accepted for `localhost` only, because a token must not cross a network in the clear.
Redirects are never followed.

## Signing in

`clearance login` runs the OIDC **device-code** flow against the people IdP (people-dex in the lab; any IdP with
discovery and the device flow in production). Nothing listens on your machine, so it works over SSH.

```
$ clearance login
To sign in, open  https://dex.hangar-dev.example/dex/device
and enter the code  ABCD-EFGH
Waiting for you to approve...
signed in as user:erin; the token is kept in the OS keychain and used until 2026-11-13T13:00:00Z (at most 1 hour)
```

The client is **public**: the CLI has no client secret and sends none.

### Where the token lives and how it is used

- Only the **ID token** is kept, in the **OS keychain** (macOS Keychain, Windows Credential Manager, the Secret Service
  on Linux; service `clearance-cli`). The access token and any refresh token the IdP returns are dropped unread;
  the people IdP issues no refresh token.
- **Never a file.** On a machine with no keychain `login` fails and says so; use `--token-stdin`.
- **At most an hour.** A token stops being used at its `exp`, or an hour after it was issued or saved, whichever is
  first; an expired one is deleted from the keychain and the command says `run clearance login`.
- `--token-stdin` reads one token from stdin and keeps it in memory for that invocation only (automation, or a machine
  with no keychain). `CLEARANCE_TOKEN` does the same from the environment; it warns on a terminal because it can end up
  in a process listing or shell history. Neither touches the keychain.
- The CLI never prints or logs a token or an `Authorization` header. It does not verify the token's signature (the IdP
  gave it to it over TLS, and clearance-api verifies it on every call); it reads `exp` and `iat` to enforce the hour.
- `clearance logout` removes the keychain entry. The IdP has no revocation here, so the token stays valid at the api
  until its `exp`; it is just no longer held.
- On macOS the keychain library hands the entry to the `security` tool, so the token is briefly on that process's
  command line (visible to the same user's `ps`); it is an hour-long ID token, which is why it is the only thing kept.

### The IdP side (people-dex)

Nothing to change in the lab: apron's `55-identity/people-dex/dex.yaml` already enables
`urn:ietf:params:oauth:grant-type:device_code`, defines the public static client `clearance` (`public: true`,
`redirectURIs: ["/dex/device/callback"]`) and issues 1 hour ID tokens with no refresh grant. Point the CLI at it:
`CLEARANCE_OIDC_ISSUER=https://dex.<cluster-domain>/dex`, `CLEARANCE_OIDC_CLIENT_ID=clearance`. The ID token's audience
is the client id, which is what clearance-api's OIDC settings accept. For another IdP: enable the device authorization
grant for a public client, allow the `openid` scope, and issue ID tokens of an hour or less. The CLI trusts your system's
CA store for the IdP and the api; a lab CA must be in it.

## Commands

Every command takes `--api`, `-o table|json|jsonl|yaml` and `--token-stdin`. Output defaults to a table on a terminal
and JSON otherwise. JSON is the api's answer verbatim; `jsonl` is one line per item of a list. Flags and positional
arguments may be mixed (`changes show c-1 -o json`).

| Command | What it reads |
|---|---|
| `login`, `logout`, `whoami` | sign-in (above); `whoami` is `GET /v1/whoami` |
| `inbox` | the holding changes you may clear now: `GET /v1/clearances?awaiting=me` |
| `changes list [--app --env --state --tier --since --limit --all]` | `GET /v1/clearances` |
| `changes show <id>` | one change: why this tier, what it needs and the approvals so far, what it binds to, the outcome, the attestation summary |
| `changes history <id>` | the change's `deploy.*` records in chain order: `GET /v1/clearances/{id}/records` |
| `attest get <id>` | the attestation's summary (digest, backend, Rekor index, record seqs) |
| `attest download <id> -o <file>` | the Sigstore bundle as the api serves it (`-o -` for stdout; `--force` overwrites). Here `-o` is the file |
| `attest verify <id>` | the api verifies the stored bundle (`GET /v1/clearances/{id}/attestation/verify`, with the trust **the api** holds) |
| `attest verify <id> --trust-root ... --identity ... --issuer ...` (or `--key ...`) | downloads the bundle and verifies it **here, offline**, with the same code as `attest verify --file` and **your** trust inputs; nothing the api says is trusted |
| `exceptions list [--scope --kind --tool --app --since --until]` | `GET /v1/exceptions`; `--scope` matches an exception's app, target, cluster or environment here, after the read |
| `coverage [scope] [--from --to]` | `GET /v1/coverage` |
| `evidence [--tool --app --coverage --since --until --principal --agent --limit --all]` | `GET /v1/evidence` |
| `watch [--types --app --change --tool --count --after]` | `GET /v1/stream` (server-sent events) |

`--since` takes an RFC 3339 time, a date, or a span back from now (`30m`, `24h`, `7d`). `--limit` is 1 to 200 per page;
`--all` follows the cursor (at most 2000 items).

`attest verify <id>` is this command; `attest verify --file <bundle> ...` (no change id) is the original offline file
verifier, unchanged. `--change <id>` is accepted in place of the leading id.

`watch` reconnects with `Last-Event-ID` when the server ends the stream (it does every 10 minutes) or the connection
drops, drops events it already showed, and stops (exit 4) when the token runs out; `--after <seq>` resumes from a seq you
noted. Events print as lines (`-o table`), or as the event's JSON per line.

`changes history` and `attest verify` (server-side) need a clearance-api with the change-history and attestation reads;
against one without them the command says so (exit 6) instead of failing obscurely. `inbox` and `whoami` need the api
release that carries `awaiting=me` and `/v1/whoami`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | failed: a refused request (400), a verification that did not verify, an unexpected error |
| 2 | usage error |
| 4 | not signed in, token expired or refused (401): `run clearance login` |
| 5 | forbidden (403) |
| 6 | not found (404, or an api without that route) |
| 7 | clearance-api unreachable, rate limited, or 5xx |

**`coverage`** is for scripts and on-call, and uses its own codes for the statement: **0** covered (every feed
healthy), **2** degraded, **3** blind, or unavailable (the api could not be read, or no scope has any coverage at all).
With no scope it takes the worst of all scopes. A sign-in or permission failure is still 4 or 5. `clean` (nothing seen
uncleared) is shown but does not change the code: coverage is about whether Clearance could see.

## Examples

```
$ clearance inbox
ID      APP       ENV   TIER  STATE    PROPOSER    UPDATED              NEEDS
c-7f3a  gate-api  prod  3     holding  user:alice  2026-11-12 10:00:00  owner 0/1, outside 0/1

$ clearance coverage aws-prod; echo $?
aws-prod: degraded
...
2

$ clearance changes show c-7f3a        # why this tier, approvals, binds-to, outcome, attestation
$ clearance attest verify c-7f3a --trust-root trusted-root.json --identity core@example --issuer https://oidc.example
$ clearance watch --app gate-api -o jsonl | jq -c .
```

## The server side (clearance-api)

Two reads were added for the CLI ([clearance-api.md](clearance-api.md#reads-for-the-person-cli)): `GET /v1/whoami` and
`awaiting=me` on `GET /v1/clearances`.
