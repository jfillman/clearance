# The person CLI (`clearance`, alias `clr`)

Using Clearance without Backstage: sign in, read, and write. It is the existing `clearance` binary
([core.md](core.md)); the person commands call [clearance-api](clearance-api.md) with **your own ID token**, so the api
sees `user:<you>` (never a delegate) and shows you exactly what the Clearance pages in Tower show you. The
[writes](#writes) (clear, deny, resolve, break-glass) go to the core with the same token.

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
- On macOS the keychain library runs `/usr/bin/security -i` and writes the save command to its standard input, so
  the token is in a pipe and in no process's argument list (not visible to `ps`; checked by polling `ps` through
  repeated saves). Reads use `security find-generic-password -w`, which prints to a pipe. Phase 1 documented the
  token as briefly on the command line; that was wrong for this library version (go-keyring v0.2.8) and is corrected
  here. No cgo binding is used or needed: the release is a static `CGO_ENABLED=0` binary on distroless and a cgo
  Keychain library would break it. One limit: a macOS entry holds about 4 KiB, so an ID token over roughly 2.5 KB
  (many group claims) cannot be saved and `login` says so; use `--token-stdin` then.

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
| 4 | not signed in, token expired or refused (401): `run clearance login`; or the sign-in is too old for the action (`DG-AUTH-NOT-FRESH`): sign in again |
| 5 | forbidden (403) |
| 6 | not found (404, or an api without that route) |
| 7 | clearance-api (or the core, for a write) unreachable, rate limited, or 5xx |

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

## Writes

`changes clear`, `changes deny`, `exceptions resolve` and `breakglass` send to the **core** (`--url`, `CLEARANCE_URL`,
`url` in the config file) with your own ID token and `X-Clearance-Via: cli`, which the core records as the claimed
`surface` of the evidence record ([evidence.md](evidence.md#the-surface-of-a-persons-write-revision-7-g4)). The core
decides everything (who may clear, the tier, admins, how fresh your sign-in must be); the CLI shows, asks, and sends
**once**: a write is never retried. Clear and deny also read the change from clearance-api to show it, so they need both
URLs.

| Command | What it does |
|---|---|
| `changes clear <id> [--reason R] [--yes]` | `POST /v1/clearances/{id}/clear`: your approval, in the role you qualify for. `--reason` is a note recorded with it |
| `changes deny <id> --reason R [--yes]` | `POST /v1/clearances/{id}/deny`; the reason is required and recorded |
| `exceptions resolve <seq>... --as STATE [--cause C] [--note N]` | one seq: `POST /v1/observations/{seq}/resolution` |
| `exceptions resolve --from-file F --as ...` | the seqs in a file: one per line, a JSON array, or `exceptions list -o jsonl` output; `-` is stdin |
| `exceptions resolve --all-matching [--scope --kind --tool --app --since --until] --as ...` | every exception the exceptions-list filters match (resolvable kinds; at most 2000) |
| `packet publish <dir>` | `POST /v1/packets` (admin): publish a `clearance packet` directory ([assurance.md](assurance.md)) |
| `packet deliver <pk-id> --recipient R --for 168h` | `POST /v1/packets/{id}/deliveries` (admin): prints the recipient's credential once |
| `receipt pull`, `receipt sign`, `receipt submit` | the recipient's side, no account: read a packet under a credential, sign a receipt with your own key, send it |
| `receipt sample --packet pk-.. [--n --seed --stratify] --out F` | the recipient's side: `GET /v1/packets/{id}/sample`, a sample of the packet's cleared changes with an inclusion proof per record ([sampling.md](sampling.md)); check it with `clearance verify --sample F --packet <dir>` |
| `breakglass open --cluster C --env E [--app A] --ttl 30m --reason R` | `POST /v1/breakglass` (admin) |
| `breakglass close <id> [--yes]`, `breakglass list` | close a window early; the windows open now (admin) |

`STATE` is `still-live`, `reverted` (needs `--cause`: `agent-caused`, `policy-triggered`, `human-initiated`,
`automated-remediation`, `requirement-changed`, `external-dependency`, `unattributed`), `ratified` or
`declared-break-glass`. More than one seq goes through the bulk endpoint in calls of at most 200 (each call is one
transaction with its own batch id; the first failed call stops the run and the CLI says how many were already
recorded). The core skips what is not resolvable and says why.

**Before a write** the CLI prints what it will act on (to stderr, so `-o json` stays clean): for clear and deny the
change as `changes show` prints it (tier and why, what it needs, the approvals so far, what it binds to), for resolve
the count, state, cause, note and seqs. Then it asks `[y/N]`. Rules:

- `--yes` skips the question (scripts). With no terminal and no `--yes` the command refuses (exit 2).
- A **tier 3** clear never goes without a terminal: `--yes` is not honored there, and neither is `--token-stdin` (it
  takes stdin). A script cannot clear a tier 3 change.
- **Break-glass open is always interactive**: no `--yes`; it shows the scope, ttl and the reason it will record, and you
  type the `cluster/env` back.
- `exceptions resolve --plan` prints the exact requests it would send (`-o json` for a document) and sends nothing; it
  needs no core URL.
- A change that is not holding is refused before anything is sent.

**A stale sign-in.** A deployment can require a recent sign-in for tier 2 and tier 3 clears and for break-glass
([core.md](core.md#fresh-sign-in-and-the-surface-g3-g4)). The core answers `401` `DG-AUTH-NOT-FRESH`; the CLI exits 4
with `sign in again (clearance login): your sign-in is 22m0s old; this action needs one at most 15m0s old`. The CLI
holds the token for up to an hour, so run `clearance login` and repeat the command.

```
$ clearance changes clear c-7f3a --reason "diff reviewed, replicas only"
change       c-7f3a
...
Clear c-7f3a (gate-api / prod, tier 2) as yourself?
Your note: diff reviewed, replicas only [y/N] y
approved c-7f3a: the change is cleared, owner 1/1 (record 4821)

$ clearance changes deny c-7f3a --reason "wrong tree; rebase and push again" --yes
$ clearance exceptions list --kind drift --scope hangar-prod -o jsonl > drift.jsonl
$ clearance exceptions resolve --from-file drift.jsonl --as ratified --note "reviewed 2026-11-13" --plan
$ clearance exceptions resolve --all-matching --kind drift --scope hangar-prod --as reverted --cause human-initiated --yes
$ clearance breakglass open --cluster hangar-prod --env prod --ttl 30m --reason "prod is down, INC-123"
```

## The server side (clearance-api)

Two reads were added for the CLI ([clearance-api.md](clearance-api.md#reads-for-the-person-cli)): `GET /v1/whoami` and
`awaiting=me` on `GET /v1/clearances`.
