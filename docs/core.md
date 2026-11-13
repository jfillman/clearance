# The Go core (`clearance`)

**Status: Built and deployed.** The Go core is the only Clearance there is. It was written in this repository (R-1
of the Clearance and Autopilot build) and has served the decision and record path on hangar-dev since the cutover of
2026-11-03 (v0.29.0, Deployments `clearance-core` and `clearance-api` in `autopilot-system`). The Python package
that came before it (`src/clearance`) is gone from v0.30.0: the gateway half moved to Autopilot (R-3), and the core
half is this module. [CHANGELOG.md](https://github.com/jfillman/clearance/blob/main/CHANGELOG.md) (0.30.0) says
where each module went.

The core decides and records. A gateway (Autopilot's) or a gate provider (the Argo CD sync, the GitHub App, `clearance
register`) asks it for a decision and writes its records through it; the core enforces nothing itself and holds no
session. It is one Go module, `github.com/jfillman/clearance`, built as one static binary.

## The binary

`clearance <subcommand>`. Each subcommand is one file under `cmd/clearance` that registers itself (`internal/cli`).

| Subcommand | What it does | Status |
|---|---|---|
| `clearance core` | Serves the core over HTTP (the API below) from the environment. `--memory` runs it on an in-memory store (tests and local runs; nothing is kept). `--insecure-dev-auth`, with `--memory` only, accepts `Bearer <principal>` as that principal and serves the chain at `GET /v1/dev/records` (below). `--listen` overrides `CLEARANCE_LISTEN`. `--max-clock-skew` overrides `CLEARANCE_MAX_CLOCK_SKEW`; `0` (off) is accepted only with `--memory`. SIGTERM shuts it down gracefully (20 s for requests in flight). | Built |
| `clearance attest verify` | Verifies a change attestation bundle offline ([Change attestations](#change-attestations)): `--file` (the bundle, or `-` for stdin), `--subject <alg>:<hex>` (repeatable: digests the statement must name), and either `--key` (a static key's public half, PEM, or the core's JWKS) or `--trust-root`, `--identity`, `--issuer` and `--rekor-key` (keyless; `--trust-root` may be a Sigstore TrustedRoot JSON, which carries Rekor's keys, so no `--rekor-key`). Exit 0 verified, 1 not. | Built |
| `clearance trust-root build` | Builds the Sigstore TrustedRoot JSON from public PEM chains and Rekor public keys, each with its validity window: `--fulcio <chain.pem>[,start=..,end=..,uri=..]` and `--rekor <key.pem>[,start=..,end=..,url=..]`, repeatable, `--out`. Checks each chain (one chain, ends self-signed) and orders it, so the same inputs give the same bytes. See [Trusted root](#trusted-root-c-2a). | Built |
| `clearance chain verify` | Verifies an evidence chain from genesis, from a JSONL dump (`--file`, `-` for stdin) or a read-only Postgres connection (`--dsn`, default `$CLEARANCE_DSN`). `--anchor <count>:<head>` checks that a checkpoint taken elsewhere is still held, which catches truncation. | Built |
| `clearance packet` | The evidence packet job (C-5): a date range and scope to canonical JSON, CSV projections and a PDF, with the originals an offline verifier needs (the records as hashed, an inclusion proof for each under the witnessed checkpoint, the checkpoint with its countersignatures, the attestation bundles). `--dsn` (read-only) or `--file`, `--out`, `--from`/`--to`/`--days`, `--scope`, `--view packet\|freeze\|incident`. `clearance packet oscal` writes the control mappings as a (signed) OSCAL component definition. See [packet.md](packet.md). | Built (C-5) |
| `clearance ledger keygen` | Makes a signing key for the evidence ledger's log (`--name <origin>`) or a witness (`--witness`): the secret key goes to `--out` (a new file, mode 0600; an existing file is never replaced) and only the public key is printed. See [The evidence ledger](#the-evidence-ledger-c-3). | Built (C-3) |
| `clearance register` | A customer's CI registers what it deploys with the deployment gate (the diff of two rendered manifest directories), authenticated by the workflow's GitHub Actions OIDC token or `--token-file`. The flags of the Python command it replaced (v0.29.0 and before), except that `--paths-from-git` with a base is refused, because the binary does not shell out. The `register/action.yml` GitHub Action builds this binary at its own ref. Without it, the paths are the files that differ between `--before` and `--after`. | Built |
| `clearance conformance` | `--provider <url> --role runtime\|deployment`: starts an in-memory core and a fake target, drives the provider through a fake call or a fake change, and proves hold, clear, release and an outcome whose digest matches the cleared subject, one PASS or FAIL line per rule ([provider-protocol.md](provider-protocol.md)). | Built (R-1f) |
| `clearance version` | Prints the build version (`-ldflags "-X main.version=vX.Y.Z"`, else the module version). | Built |

## The API

The contract is [`contract/clearance-core.json`](https://github.com/jfillman/clearance/blob/main/contract/clearance-core.json)
(OpenAPI 3.1). It is generated from the server's route table and its Go request and response types
(`internal/server`, `tools/contract`), and a test fails when the committed file drifts.

| Route | Who may call | What it does |
|---|---|---|
| `POST /access/v1/evaluation` | a registered provider | Decide one AuthZEN 1.0 access evaluation (`tool.call`, `session.spawn`, `session.open`, `model.call`) and record the decision, sealed by the core. |
| `POST /v1/decisions/{id}/outcome` | the provider that asked for the decision | The call's result, effect (a pull request's receipt) and receipt, once per allowed decision. |
| `POST /v1/records` | a registered provider | One of the provider's own records: `session.open`, `run.launch`, `run.delete`, `run.finish`, `human.answer`, `session.freeze`, `session.end`, `trigger.hold`, `trigger.release`, `tool.call` (an outage read, `coverage-unavailable`), `deploy.outcome` (with `release: {id}`, and the gate sets the named change's `outcome`: [gate.md](gate.md#the-release-record-join-g-argo-6-built)), `deploy.exception`, `deploy.degraded` (the last two checked and acted on by the gate, C-6: [gate.md](gate.md#protected-environments-the-outage-policy-states-exceptions-and-break-glass-c-6-built)), `federated.decision` (another gateway's PDP decision, observed by a federated source such as the [Traefik Hub adapter](federate-traefik-hub.md); Unverified), and, for a provider registered for them, the observation kinds `observation`, `assessment`, `resolution`, `observation.health` ([evidence.md](evidence.md#observations-clearanceevidencev11-o-1)). A record that names its own event (`source.event_id`) is de-duplicated: a repeat answers `200` with the first record's reference and `duplicate: true`. |
| `PUT /v1/definitions` | the provider registered with `definitions: true` | The provider's whole set of cluster-pinned agent definitions replaces the core's; its optional `bundled` list is the definitions that ship with the provider itself. The core decides each pin and records each change once (`definition.load`, `definition.unload`, `definition.reject`). |
| `POST /v1/clearances`, `/v1/clearances/{change_id}/clear`, `/v1/clearances/{change_id}/deny` | a verifier; a person or a delegate | The deployment gate ([gate.md](gate.md)), at the Python core's paths. |
| `GET /v1/clearances/{change_id}` | a registered provider, or the verifier that registered the change | The change's state and its live [clearance token](#the-clearance-token) (`null` when it has none). A token with under half its life left is re-issued first. People read changes through clearance-api. |
| `POST /v1/clearances/{change_id}/outcome` | the principal that registered the change | G-TF-2: a cleared terraform-plan change's apply result, once: `deploy.outcome` with `matched` (verified), and `deploy.exception` (digest-mismatch) when the applied plan is not the cleared one. A second is `DG-STATE` ([gate.md](gate.md#hold-release-and-outcome-for-a-plan-g-tf-2-built)). Go client `ChangeOutcome`, Python `record_change_outcome`. |
| `GET /v1/clearances/{change_id}/wait` | the same callers | Long-poll (C-10): the same answer plus `changed`, as soon as the change's state is not `state` (default: its state when the call arrived), or after `timeout` seconds (1 to 60, default 30) with `changed: false`. Subject-kind neutral: the Terraform run task (G-TF-2) and the PreSync hook (G-ARGO-5) wait on it. The gate is the one writer, so an in-process notifier wakes the call on the commit itself; nothing polls the database. At most 512 waits open at once (503 past it); this route alone gets a deadline past the server's write timeout. Go client `Wait`. |
| `POST /v1/breakglass`, `POST /v1/breakglass/{id}/close` | an admin (`CLEARANCE_ADMINS`), or a delegate naming one | Open (or close early) a break-glass window on one protected environment, recorded before the answer; reconciled at its TTL ([gate.md](gate.md#break-glass)). |
| `GET /v1/breakglass` | a registered provider, or an admin | The break-glass windows open now (`?cluster=`). |
| `GET /v1/keys` | anyone (no token) | The token verification keys, a JWKS: the key in use and keys retired in the last 24 hours. |
| `PUT /v1/targets/{source}` | a provider registered with `targets` naming the source | The targets one source (a cluster's gitops render, an account's bootstrap) declares for the Map: the whole set replaces what the core holds for that source. Validated strictly; a changed set is one `targets.load` record with its digest. [Below](#publishing-declared-targets). |
| `POST /v1/definitions/review` | a verifier, a person, or a delegate naming one | Would Clearance load this agent definition, and how much more may its agent do (the definition-change tier). Stateless, unrecorded. |
| `POST /v1/provenance` | a verifier | The agent-identity and agent-scope verdicts for a pull request, recorded as `provenance.verify`. |
| `POST /v1/github/webhook` | GitHub (HMAC signature, no bearer token) | The Clearance GitHub App ([provenance-app.md](provenance-app.md)). |
| `GET /healthz`, `GET /readyz` | anyone | Up; the store answers and the policy is loaded. |

Every request has a body cap per route (`Content-Length` checked first, then `MaxBytesReader`; 8 MiB for an
evaluation, 64 KiB by default). The core's own routes decode JSON strictly (unknown fields and trailing data are
errors). Errors are `{"error": ...}`. The access log line carries no bodies, headers or tokens, and a panic answers a
bare 500. The server sets read-header, read, write and idle timeouts, and each handler is cut off at 25 s.

### Registered providers (`CLEARANCE_PROVIDERS`)

A JSON array (at most 64 KiB), strictly decoded. Without it no caller may evaluate or record.

```json
[{"name": "autopilot-gateway", "version": "0.3.27", "principals": ["autopilot-system/clearance"],
  "definitions": true},
 {"name": "argo-gate", "version": "0.1.0", "principals": ["hangar-prod/argocd/clearance-sync"],
  "kinds": ["deploy.outcome", "deploy.exception"]}]
```

- `name` is the record's `provider.name` (the evidence schema's pattern). It may not be `clearance`, which is the
  core's own name.
- `version` is `provider.version`, 1 to 64 characters.
- `principals` are fnmatch globs on the authenticated principal. A caller is the first provider whose globs match.
- `kinds` narrows which `POST /v1/records` kinds the provider may write. Absent, it is all of them but the observation kinds, which a provider writes only when it names them. `"kinds": []` is none: the spelling for a provider that only publishes `targets` (or `definitions`) and must write no record; such an entry needs `targets` or `definitions`, else the config is refused. An entry with `targets` and no `kinds` is still every kind: absence is never read as none, so an entry registered before `[]` existed keeps what it had.
- `intent_capture` is `redacted` (the default) or `full`, for its records' intent text.
- `definitions: true` lets the provider publish its cluster-pinned agent definitions (`PUT /v1/definitions`). At
  most one provider has it, because a publish replaces the whole set: two publishers would undo each other.
- `targets` is a list of source names (fnmatch globs) whose declared targets the provider may publish
  (`PUT /v1/targets/{source}`): `["hangar-prod"]`, or `["*"]`. A publish replaces only its own source's set, so several
  providers may publish; a source belongs to the first provider that lists it.
- `conformance` is the conformance suite the provider passed and when, as `<suite>/v<n>[@YYYY-MM-DD]`
  (`clearance-conformance/v1@2026-11-03`; `clearance conformance` prints the suite). The core stamps it on every
  record the provider writes as `provider.conformance`, the field the v1 schema reserved. Records written before
  the field was set, and the core's own records, have none. The registration says it; the core does not run the
  suite.

### Decisions, outcomes and records

- **Decision id.** A recorded decision's id is its evidence record's `seq`, as a decimal string. It is unique and
  stable, and one indexed read finds it again. The answer carries `decision_id` and `record` (`seq`, `hash`). A
  decision with no record (a model call to a deployment without model routes) has `decision_id: null` and takes no
  outcome.
- **The decision record** names its `caller` (`{provider, principal}`), and that field is verified because the
  core authenticated it. Its `ts` is the evaluation's `context.now`, which must be within 5 minutes of the core's
  clock (`CLEARANCE_MAX_CLOCK_SKEW`, `--max-clock-skew`). A caller cannot move it.
- **A person's run.** A `session.open` with `run: true` is Gateway.run_agent: a person (Tower's Run, or their own
  token) opens a session to launch a task agent. It asks for no limits and is not triggered. `via` names the
  delegate the person acted through. The record is the Python gateway's: `args_sha256` of `{"via": <delegate or
  null>}` and result `opened to run`, or `opened to run via <delegate>`. The delegate is the provider's word: the
  core verifies the provider, not the delegate.
- **Outcome.** Only the provider that asked for the decision may report its outcome, once, and only for an allowed
  decision. It is recorded as the decision's tool and linked by `outcome_of`. The identity fields are copied from the
  decision record (verified); what the provider reports is claimed. A second outcome is refused without a chain scan:
  the server indexes `outcome_of` at start and keeps the index while it is the one writer. A handler that refused
  the call after the core allowed it (the gateway's launch R004 and R001, the inbox's HR-*, artifacts' ART-*) sends
  `refusal: {rule, message}`. The record keeps the decision's `decision` and `rule` (verified) and adds `refusal`
  (claimed), so the handler's rule is in the chain as the Python deny record had it. A refusal carries no effect.
  A model call's outcome may carry `model_version` (the model that answered) and `usage` (the provider's token
  counts and `charged_tokens`, the call's weighted charge; A-4), both claimed and refused on any other
  tool's outcome ([evidence.md](evidence.md#the-flight-recorder-fields-revision-3-ap-c1-ap-c2)).
- **Provider records.** Sealed with the provider's name and version. Only `provider` and `ts` are verified;
  everything else is claimed. Each kind has its required fields and its boundary (`internal/server/records.go`;
  [provider-protocol.md](provider-protocol.md#record-kinds) lists them). A `tool.call` record is the outage
  policy's replay of a T0 read the provider ran while the core was unreachable: its `tool` is the tool called (a T0
  tool the core knows), its coverage is `coverage-unavailable`, and it carries no rule, effect or outcome. Its
  subject is the tool-call digest, claimed. It is never a decision. A run's records (`session.open`, `run.launch`,
  `run.finish`, `run.delete`) may carry `model_version` and `preflight`, and `run.finish` its `cost` (A-4).
- **Publishing declared targets.** `PUT /v1/targets/{source}` takes the targets a source declares for the Map
  (`{"targets": [...]}`; each target's `id`, `name`, `kind`, `group`, `env`, `app`, `owner`, `registry`, `scope`, `gates`
  and `observers`: [clearance-api.md](clearance-api.md#the-coverage-map-and-the-target-registry)). The provider must be
  registered with `targets` naming the source. The core validates strictly (names, kinds, modes, the sizes: at most 2000
  targets per source, 32 gates and 16 observers per target, 4 MiB), sorts the set by id and addresses it by the sha256 of its
  canonical JSON. A set with the digest the core already holds changes and records nothing; a different one replaces the
  source's row in `clearance_targets` and is one `targets.load` record, in one transaction, whose `result` carries
  `sha256:<digest>` (and the digest it replaced) and whose `target` is `targets:<source>`. An empty list withdraws the source.
  The core records what was declared, never that it is true: the Map reconciles the declaration with the records.
- **Published definitions.** `PUT /v1/definitions` takes the provider's Agent XR loader's pins (each with its
  document, source and XR owner) and rejections. The core decides every pin itself with its own schema
  (`definitions.FromPin`, `internal/profile`): the agent-definition schema, the name is the XR's, the owner is the
  XR's, a workload identity is `autopilot-runs/<name>`, the name is not a bundled one. A pin it refuses becomes a
  rejection with the core's reason. The set then replaces the stored one (`definitions.Service.Apply`, one
  transaction), and each change is one record: `definition.load` (new or re-pinned), `definition.unload`,
  `definition.reject`, sealed by the core with `caller`. The pin's own fields (principal `pin:<ns>/<xr>`, agent,
  target, args_sha256) are claimed, because the core did not fetch the file. Publishing the same set records
  nothing. Provenance (AS002 to AS004) reads the published set at once, and a restarted core reads it back from
  `clearance_definitions`. The core is the only writer of `definition.*` records; `POST /v1/records` refuses them.
  The same request may carry `bundled`, the definitions that ship with the provider itself (name, build version,
  document; Autopilot's gateway image `agents/`): decided with the same schema, held beside the pins as source kind
  `provider` (never shadowed by a pin), recorded the same way (principal `provider:<provider>`), and read by
  provenance and the read API. Absent keeps the provider's earlier set. Without it, an agent that is not pinned and
  not in `CLEARANCE_AGENTS_DIR` fails `Clearance / agent-scope` with AS004 ("not in this deployment").
- **The dev chain read.** `clearance core --memory --insecure-dev-auth` also serves `GET /v1/dev/records?from=<seq>&limit=<n>`
  (at most 10,000, a bearer token required): the in-memory chain, so another package's tests (autopilot's) read what
  the core recorded from the unmodified binary. It is not in the contract, and `core.Build` refuses it on a kept
  store; clearance-api is the reader of a kept chain.

### Clients

`client` (Go, the standard library only) and `clients/python` (generated from the contract, released with each tag)
call this API. Both report an unreachable core as a distinct error (`client.ErrCoreUnavailable`) that the caller's
outage policy acts on: by default, fail closed. The Python client (`clearance_client.CoreClient`) is what the
Autopilot gateway calls (R-3); in tests, `clearance core --memory` stands in for a deployed core (R-1e).

Record fields and the verified and claimed tags are the clearance.evidence/v1 shape ([evidence.md](evidence.md)).
Arguments are stored only as a hash (`args_sha256`, `canon.ArgsDigest`).

## Configuration

All configuration comes from the environment. An empty variable counts as unset.

| Variable | Meaning |
|---|---|
| `CLEARANCE_DSN` | The Postgres DSN. Required unless `--memory`. |
| `CLEARANCE_LISTEN` | Listen address (default `:8080`). |
| `CLEARANCE_PROVIDERS` | The registered providers (above). |
| `CLEARANCE_BUNDLES` | Comma-separated [policy bundle](#policy-bundles) files. Default none: the core rules only. (`CLEARANCE_PACKS` is gone; setting it is an error.) |
| `CLEARANCE_BUNDLE_SOURCES` | JSON object, source name to `{"url": "http(s)://...", "tokenFile": "..."}` or `{"file": "..."}`: where each source a bundle names is read at start. |
| `CLEARANCE_BUNDLE_SOURCE_WAIT` | How long the start keeps retrying a source that does not answer before it goes on with that bundle degraded (Go duration, default `10s`). |
| `CLEARANCE_ENV_LOWER_NAMES`, `CLEARANCE_ENV_LOWER_PREFIXES`, `CLEARANCE_ENV_LOWER_PROJECT_SUFFIXES`, `CLEARANCE_ENV_UPPER_REPO_PREFIXES` | How arguments name an environment tier, for R012 (below). Defaults: lower names `dev,development,sandbox,scratch`, no prefixes or suffixes. |
| `CLEARANCE_VERIFIERS` | Principal globs that may register changes and ask for provenance. |
| `CLEARANCE_DELEGATES` | Principal globs that may act for a person they name (in `CLEARANCE_ON_BEHALF_OF_HEADER`). |
| `CLEARANCE_ADMINS` | Principal globs (`user:<login>`) that may deny any held change and break glass. |
| `CLEARANCE_PROTECTED_ENVIRONMENTS` | Comma-separated `<cluster glob>/<env glob>` entries: the environments the gate protects. **Unset: every environment is protected** (fail closed). A change to any other is cleared at tier 0, reason `unprotected` ([gate.md](gate.md#protected-environments)). |
| `CLEARANCE_BREAKGLASS_MAX_TTL` | The longest break-glass window, a Go duration from `1m` to `4h` (default `4h`, the ceiling). |
| `CLEARANCE_FRESH_AUTH_TIER2` | The longest sign-in age that may clear a tier 2 change, a Go duration from `1m` to `24h`. **Unset (the product default): no requirement.** [Fresh sign-in](#fresh-sign-in-and-the-surface-g3-g4). |
| `CLEARANCE_FRESH_AUTH_TIER3_BREAKGLASS` | The same limit for clearing a tier 3 change and for opening or closing break-glass. Recommended `15m` where tier 3 or break-glass is used. Unset: a tier 3 clear uses the tier 2 limit; break-glass has none. |
| `CLEARANCE_FRESH_AUTH_DELEGATES` | `exempt` (default) or `require`: whether a delegate-named person's write must forward the sign-in time (`X-Clearance-Auth-Time`, unix seconds). |
| `CLEARANCE_VIAS_EXTRA` | Surface names a person's write may claim in `X-Clearance-Via` beside `cli`, `web`, `slack` and `api`: the deployment's portal (comma-separated lowercase words). |
| `CLEARANCE_DELEGATE_PERSON_ALLOWED` | Globs (`user:<login>`) a person a delegate names must match, the delegate path's counterpart of `CLEARANCE_OIDC_ALLOWED_USERS`. Unset: any `user:<name>` the delegate says (the behaviour before it existed). |
| `CLEARANCE_EXPIRE_SECONDS` | How often holding changes past their TTL are expired (default 60, at most 86400). |
| `CLEARANCE_MAX_CLOCK_SKEW` | How far an evaluation's `context.now` may be from the core's clock, a Go duration (default `5m`, at most `24h`). `0` turns the check off, and `clearance core` refuses that without `--memory`: a decision record's `ts` is the evaluation's `now` and is verified, so a kept chain never takes an unbounded one. A test core on a fixed clock runs `clearance core --memory --insecure-dev-auth --max-clock-skew 0`. |
| `CLEARANCE_AGENTS_DIR` | Bundled agent definitions (`*.yaml`). Default none. |
| `AGENT_LOGINS` | GitHub logins agents open PRs as. Default none: an agent PR is known by its Clearance record or its trailers. |
| `MODEL_ROUTES` | `alias=upstream,...`: the model aliases a definition release may name. When unset they are not checked. |
| `RUNTIME_IMAGES_EXTRA` | Globs a definition's `runtime.image` may match. |
| `CLEARANCE_TRUSTED_REGISTRIES` | Comma-separated image prefixes, each ending in `/`, that a tier-1 image bump may come from; an image bump from anywhere else is tier 2 (`image:not-trusted-registry`) and held for the owner group. Unset: any registry (the product default). Hangar sets `ghcr.io/riley-roooo/` (decided 2026-11-03, live from the R-4 cutover). |
| `CLEARANCE_GATE_UNBOUND_TREE` | `flag` (default) or `refuse`. A manifest-tree registration whose `treeDigest` is a placeholder (64 copies of one hex digit, or sha256 of nothing) is registered and flagged (`tree:unbound`, `subject.flags: ["unbound-tree"]`, the record's subject carries the commit only), or refused `DG-UNBOUND` (400). Planned: `refuse` becomes the default one release after this flag ships ([gate.md](gate.md#the-manifest-tree-digest-built)). |
| `CLEARANCE_SIGNING_KEY_FILE` | The [clearance token](#the-clearance-token) signing key: a PEM ECDSA P-256 private key (SEC 1 `EC PRIVATE KEY` or PKCS #8 `PRIVATE KEY`), read once at start. Unset: no tokens are issued, and the core logs a warning. |
| `CLEARANCE_SIGNING_KMS` | A KMS key reference. Reserved: the KMS signer is not built, and the core refuses to start with it set. |
| `CLEARANCE_TOKEN_TTL` | Each token's life, a Go duration (default `15m`; `1m` to `24h`, and at least four times `CLEARANCE_EXPIRE_SECONDS`, the refresh interval). |
| `CLEARANCE_TOKEN_ISSUER` | The tokens' `iss`, which verifiers check (default `clearance`). |
| `CLEARANCE_GITHUB_APP_ID`, `CLEARANCE_GITHUB_APP_KEY_FILE`, `CLEARANCE_GITHUB_APP_WEBHOOK_SECRET_FILE` | The Clearance GitHub App. Set all three or none. The key and secret are read from files. |
| `CLEARANCE_HCP_RUN_TASK_CONFIG_FILE` | The HCP Terraform run task (G-TF-6): a JSON file of installations `{organization, host, hmacKeyFile, environment}` ([docs/terraform-gate.md](terraform-gate.md#the-hcp-terraform-run-task-g-tf-6-built-not-live-verified)). Unset: `POST /v1/terraform/run-task` answers 404. Needs `hcp-run-task:*` in `CLEARANCE_VERIFIERS`. |
| `CLEARANCE_GITHUB_APP_COMMENTS` | `off` (default) or `agent-failures`. |
| `CLEARANCE_GITHUB_API` | The GitHub API base (default `https://api.github.com`). |
| `CLEARANCE_AUDIENCE` | The TokenReview audience for this cluster's workloads, and the audience of the foreign cluster's tokens (default `clearance`). |
| `CLEARANCE_OIDC_ISSUER`, `CLEARANCE_OIDC_AUDIENCE` | People's OIDC issuer and their ID tokens' audience. Set both or neither. |
| `CLEARANCE_OIDC_JWKS_URL` | Default `<issuer>/keys`. |
| `CLEARANCE_OIDC_USER_CLAIM` | Default `email`. |
| `CLEARANCE_OIDC_ALLOWED_USERS` | Comma-separated globs on that claim. Required with an issuer, because a valid token from an issuer that federates GitHub could belong to anyone with a GitHub account. |
| `CLEARANCE_FOREIGN_ISSUER`, `CLEARANCE_FOREIGN_CLUSTER`, `CLEARANCE_FOREIGN_SERVICE_ACCOUNTS`, `CLEARANCE_FOREIGN_JWKS_URL` | Another cluster's service-account issuer, its name, the `<namespace>/<sa>` globs it may use, and its JWKS (default `<issuer>/jwks.json`). These were `TOWER_*` before v0.29.0. |
| `CLEARANCE_GITHUB_OIDC_AUDIENCE` | GitHub Actions tokens' audience. GitHub Actions callers are off when it is unset. |
| `CLEARANCE_GITHUB_OIDC_ALLOWED` | Comma-separated globs on the token's `sub` (default `repo:*`). |

The deployment's vocabulary: names that belong to the platform Clearance is deployed in, each with a
product-neutral default (`internal/vocab`).

| Variable | Meaning | Default |
|---|---|---|
| `CLEARANCE_ON_BEHALF_OF_HEADER` | The header a delegate names a person in. | `X-Clearance-On-Behalf-Of` |
| `CLEARANCE_TRAILER_PREFIX` | The prefix of the commit trailers an agent's commit carries (`<prefix>Task:`, `Session:`, `Run:`, `Agent:`). | `Clearance-` |
| `CLEARANCE_RUN_IDENTITY_NAMESPACE` | The namespace a workload agent's service account must live in (`<ns>/<agent>`). | `agent-runs` |
| `CLEARANCE_BASELINE_DENY_PATHS` | Path globs every agent is denied, whatever its definition says. | `CODEOWNERS,**/CODEOWNERS,.github/**` |
| `CLEARANCE_BASELINE_DENY_FIELDS` | JSON pointers every agent is denied. | none |
| `CLEARANCE_GATE_OUTSIDE_GROUPS` | The gate baseline's outside groups (group refs). | none |
| `CLEARANCE_GATE_OWNER_FALLBACK` | The owner group of a change nobody names an owner for, when there is no outside group. | none |
| `CLEARANCE_V0_PROVIDER` | `name/version` that rows written before providers were recorded are projected with. | `unrecorded/unrecorded` |
| `CLEARANCE_ATTEST_KEY_FILE` | Change attestations, **static** backend (tests, labs): a PEM ECDSA P-256 private key, read once at start. Never with `CLEARANCE_ATTEST_FULCIO_URL`. | unset |
| `CLEARANCE_ATTEST_FULCIO_URL` | Change attestations, **keyless** backend: the Fulcio base URL (https; http only for loopback or an in-cluster Service name, `<svc>.<ns>.svc`). Needs `CLEARANCE_ATTEST_REKOR_URL`. | unset |
| `CLEARANCE_ATTEST_REKOR_URL` | The Rekor v1 log: required with Fulcio, optional with a static key (unlogged without). | unset |
| `CLEARANCE_ATTEST_OIDC_TOKEN_FILE` | Keyless: the core's OIDC identity token, re-read on every signing and never cached. | `/var/run/clearance/attest-oidc-token` |
| `CLEARANCE_AUTOMATION_SUBJECTS` | Comma-separated patterns (`*` the only wildcard, case-insensitive) on an approver's name or subject that mark automation: a bot account, a service or agent identity. A match is refused `DG-APPROVER-AUTOMATION` ([gate.md](gate.md#tier-3-approvers-are-people-c-14-built)). `none` empties the list. | `*[bot]`, `*-bot`, `bot-*`, `agent:*`, `system:*`, `svc-*`, ... (see gate.md) |
| `CLEARANCE_AUTOMATION_ISSUERS` | The same on an approver's issuer when they sign in themselves. | Kubernetes, GitHub Actions and ID-JAG issuers |
| `CLEARANCE_APPROVER_ALIASES` | Groups of names that are one person, `a=b=c;d=e`. Two approvals resolving to one group are `DG-APPROVER-SAME`. | none |
| `CLEARANCE_AI_COAUTHORS` | Comma-separated matchers, `<email>` or `Name <email>` (case-insensitive), on the `Co-Authored-By`, `Assisted-by` and `Generated-by` trailers an AI coding agent outside Clearance leaves. A PR with no record and no other agent signal where any of its commits carries one is `unattested`, a warning that never fails a check ([provenance-app.md](provenance-app.md#ai-co-author-trailers-agent-unattested-built)). `none` turns it off. | Claude Code, OpenAI Codex, Copilot CLI, Cursor, aider (by email) |

The evidence ledger is **off unless `CLEARANCE_LEDGER_DIR` is set** ([The evidence ledger](#the-evidence-ledger-c-3)):

| Variable | Meaning | Default |
|---|---|---|
| `CLEARANCE_LEDGER_DIR` | The Tessera volume: a mounted, writable, single-writer directory. Setting it turns the ledger on and requires the next two. Any other `CLEARANCE_LEDGER_*` variable without it is refused (it would silently do nothing). | unset: off |
| `CLEARANCE_LEDGER_KEY_FILE` | The log's signing key: a signed-note Ed25519 secret key, read from the file at start and never printed. Its name is the log's origin. | required |
| `CLEARANCE_LEDGER_WITNESS_POLICY_FILE` | The witness policy: `witness <name> <vkey> <url>` per witness (the vkey is the witness's cosignature key, type 0x04), `group <name> <n\|any\|all> <members...>`, and `quorum <name>`. At least one witness; `quorum none` is refused. | required |
| `CLEARANCE_LEDGER_RETIRED_KEYS_FILE` | vkeys of the log's retired signing keys (same name, other keys), one per line. | none |
| `CLEARANCE_LEDGER_CHECKPOINT_INTERVAL` | A Go duration, 1s to 1h: how often a grown log is checkpointed and sent to the witnesses, and how often the witnesses are asked again when it has not grown. | `1m` |
| `CLEARANCE_LEDGER_TIER3_WAIT` | `true` or `false`: a tier 3 change waits while evidence cannot be checkpointed. | `true` |
| `CLEARANCE_LEDGER_STALL_AFTER` | A Go duration: how long records may wait for a witnessed checkpoint before the ledger counts as stalled. | three intervals plus the 20 s witness timeout |

The source of truth is the package documentation of `internal/core`, `internal/bundles`, `internal/vocab` and
`authn.EnvVars`. `clearance register`
reads `CLEARANCE_URL` and GitHub Actions' `GITHUB_EVENT_PATH`, `GITHUB_REPOSITORY`, `GITHUB_SHA` and
`GITHUB_ACTOR`.

## Fresh sign-in and the surface (G3, G4)

Two additions to every **person write** (clear, deny, resolution and bulk resolution, break-glass open and close).

### Fresh sign-in (G3)

A person's write may be refused when the sign-in behind it is too old. The core evaluates it from the ID token it
verified, so it holds from every surface (the CLI, Tower, a Slack action) and cannot be skipped by a client.

- **The sign-in time** is the token's `auth_time` when the IdP sends it (the moment the person authenticated), else its
  `iat` (people-dex sends no `auth_time`; its `iat` is the sign-in, and a CLI token is never refreshed). Both are
  verified by the authenticator. A token with neither integer, or one dated in the future beyond the 30 s leeway, is not
  fresh.
- **The limits**, per action class, each a Go duration from `1m` to `24h`, **unset by default: no requirement** (a
  deployment that has not chosen sees no change):

| Variable | Applies to |
|---|---|
| `CLEARANCE_FRESH_AUTH_TIER2` | clearing a tier 2 change |
| `CLEARANCE_FRESH_AUTH_TIER3_BREAKGLASS` | clearing a tier 3 change, and opening or closing break-glass. **Recommended `15m`.** When unset, a tier 3 clear falls back to the tier 2 limit (a higher tier is never less strict than a lower one) and break-glass has none |

  Deny, resolutions, and clearing tier 0 and 1 (by policy) have no class. The check runs after the person is identified
  and the admin check (break-glass) has passed, before any state is read for the write, so a refused write records
  nothing.
- **The refusal** is `401`, `{"error": "your sign-in is 22m0s old; this action needs one at most 15m0s old", "rule":
  "DG-AUTH-NOT-FRESH", "max_age": "15m0s", "age": "22m0s", "hint": ...}`. The CLI turns it into "sign in again
  (`clearance login`)" and exit 4; the person signs in again and repeats the action.
- **Delegates.** A delegate (Tower's backend) names the person; it holds the person's session, not their ID token, so it
  cannot prove their `auth_time`. By default (`CLEARANCE_FRESH_AUTH_DELEGATES=exempt`) a delegate-named write is **not**
  checked: the limits apply to direct person tokens only, and nothing about the delegate path is weakened. With
  `require`, the delegate must forward the person's sign-in time in `X-Clearance-Auth-Time` (unix seconds) and it is
  checked against the same limits; a write without it is refused the same way (no `age` in the answer). That time is the
  delegate's word, trusted exactly as far as the delegate already is for naming the person. Tower's backend does not send
  it yet; turning `require` on before it does would refuse every delegated tier 2/3 clear.
- `core --memory --insecure-dev-auth` tokens have no age: a dev person token just signed in, so the limits never refuse it.

### Who a delegate may name (G8)

The core applies its **admin check** (`CLEARANCE_ADMINS`) to the person a delegate names, for break-glass and
resolutions, and the approver rules (owner or outside group from the directory, not the proposer, not twice) for clears,
exactly as for a person who signs in themselves (`TestG8TheCoreChecksThePersonADelegateNames`). It did **not** apply the
OIDC allowlist (`CLEARANCE_OIDC_ALLOWED_USERS`): that runs in the authenticator, on a token, and a delegate-named person
never presents one. `CLEARANCE_DELEGATE_PERSON_ALLOWED` closes that: globs (`user:<login>`) the named person must match,
else `403 DG-PERSON-ALLOWED`. It is **unset by default** (any `user:<name>` a delegate says, as before) because the name a
delegate sends (a Backstage user entity) need not have the shape of the OIDC claim the allowlist matches (an email), and
turning it on blindly could lock Tower out. Set it to the names Tower actually sends.

### The surface (G4)

Any person write may say where it came from, in two headers: `X-Clearance-Via` (`cli`, `web`, `slack`, `api`, or a name in
`CLEARANCE_VIAS_EXTRA`; else `400 DG-VIA`) and `X-Clearance-Surface-Ref` (printable text, at most 512 bytes, such as a Slack permalink; needs a
`via`, else `400 DG-SURFACE-REF`). The core records them as a **claimed** `surface` {`via`, `ref`} on the evidence record
([evidence.md](evidence.md#the-surface-of-a-persons-write-revision-7-g4)): `deploy.clear`, `deploy.deny`, every
`resolution` of a call, `breakglass.open` and an early `breakglass.close`. Nothing verifies it; the verified identity is
the person. The CLI sends `cli`; a portal's backend (on Hangar, Tower's, a separate repo) names itself in `CLEARANCE_VIAS_EXTRA` and
sends that name for the person it names; a Slack service sends `slack` with the message permalink.

A clear may also carry `{"reason": "..."}` (at most 4000 characters), recorded as the claimed `reason` of `deploy.clear`.

## The clearance token

**Status: Built** (C-1). Not yet deployed: hangar-dev runs v0.30.0 until a release carries it and the lab key
exists ([install.md](install.md#the-clearance-token-signing-key)). Nothing consumes a token yet: the Argo CD grant
sync (G-ARGO-3), the Config Management Plugin (G-ARGO-4), the PreSync wait (G-ARGO-5) and the Terraform gate
(G-TF-2) are the consumers.

When the deployment gate clears a change (`deploy.clear`, by policy or when the last person needed approves), the
core signs a short-lived token that says so and what it is bound to. Package `internal/token`; the gate's side is
`internal/gate/token.go`.

### Format: a DSSE envelope, with a JWT projection

Decided in the build spec (section 14, C-1) and kept here: one set of claims, signed twice with one key.

- **The DSSE envelope** (`payloadType` `application/vnd.clearance.token.v1+json`): the payload is the claims JSON,
  the signature is ECDSA over SHA-256 of DSSE's pre-authentication encoding, ASN.1 DER, as Sigstore writes it. This
  is the format the attestation signer (C-2) uses, so one signing path serves tokens and attestations, and any
  DSSE verifier checks it.
- **The JWT projection**: a compact JWS, header `{"alg": "ES256", "kid": <key id>, "typ": "clearance-token+jwt"}`,
  the same claims as its payload. For the PreSync hook and anything else that speaks JWT.

Both carry the same claims. A verifier may check either one and gets the same answer.

### Claims

| Claim | What it is |
|---|---|
| `_type` | `clearance.token/v1` |
| `iss` | `CLEARANCE_TOKEN_ISSUER` |
| `sub` | the clearance (change) id |
| `iat`, `exp` | NumericDate seconds. `exp` is at most `iat` + `CLEARANCE_TOKEN_TTL`, never past the change's horizon (below), and never more than 24 hours after `iat`, whoever signed it |
| `nonce` | 128 random bits, base64url: this clearance's issuance (below) |
| `clearance` | `{id, cleared_by: "policy" \| "people", decided_at}` |
| `subjects` | `{kind: "manifest-tree", repo, pr, commit, base, tree_root, images}`: the binding is `tree_root` (a Terraform change's is `plan_digest`, from G-TF-1); `commit` and `images` (every image the objects name, sorted) are cross-references |
| `objects` | each object the change touches: `{apiVersion, kind, namespace, name, rendered, changed, op}`; `rendered` is its rendered hash as the verifier reported it |
| `target` | `{cluster, env, app}` |
| `tier` | 0 to 3 |
| `policy` | `{ref, version, engine, verdict, bundle}`: the deploy.* record's `policy` group, field for field, so the token attests what the record says ([gate.md](gate.md) "The policy in the record"). `ref` is the tier policy (`clearance.yaml@<commit>`, `clearance.yaml@sha256:<digest>` or `baseline`); `version` the gate baseline plus the `clearance.yaml` digest; `engine`, `verdict` and `bundle` the offline admission result the verifier sent (`kyverno/<version>`, `pass` \| `warn` \| `fail` \| `skipped` \| `error`, and the rule set `<repo>//<path>@<commit>`), or `none` and `not-evaluated` (no `bundle`). The gate's own decision is `clearance.cleared_by` and `tier` |
| `provenance` | `{level, check, proposer, proposer_kind, agent, task_id}`: `level` is the evidence schema's (`confirmed-agent` for an agent PR the agent gates confirmed, `probable-agent` for another agent PR, `confirmed-human` for a person's PR the gates found no agent in, else `unknown`); `task_id` is the run's, when the registration names it (`taskId`) |
| `approvals` | each person: `{sub, iss, person, via, role, at}` (below); empty when policy cleared it |

A decoded payload (a tier-2 change one person cleared through Tower):

```json
{
  "_type": "clearance.token/v1",
  "iss": "clearance",
  "sub": "ch-5f0c2a9e1d3b7a41",
  "iat": 1793707200,
  "exp": 1793708100,
  "nonce": "q0bUo8m1V3m6l2b0kJ8m3A",
  "clearance": {"id": "ch-5f0c2a9e1d3b7a41", "cleared_by": "people", "decided_at": "2026-11-03T12:00:00+00:00"},
  "subjects": {"kind": "manifest-tree", "repo": "jfillman/gitops-gate-api", "pr": 7,
               "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "base": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
               "tree_root": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "images": []},
  "objects": [{"apiVersion": "argoproj.io/v1alpha1", "kind": "Rollout", "namespace": "app-gate-api-prod",
               "name": "gate-api", "rendered": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
               "changed": true, "op": "changed"}],
  "target": {"cluster": "hangar-prod", "env": "prod", "app": "gate-api"},
  "tier": 2,
  "policy": {"ref": "clearance.yaml@9f2c00000000000000000000000000000000e1e1", "version": "baseline-2026-10-31+sha256:3905e6096876f604915034458c354e7c01ca4266dde97b4fcd23efdfe3eee3e5",
             "engine": "kyverno/1.19.0", "verdict": "pass",
             "bundle": "https://github.com/jfillman/gitops-hangar-prod.git//30-policy@4b1d00000000000000000000000000000000a7a7"},
  "provenance": {"level": "confirmed-human", "check": "not-agent", "proposer": "user:dana", "proposer_kind": "person"},
  "approvals": [{"sub": "user:erin", "iss": "delegate:hangar-prod/app-backstage-prod/backstage", "person": "user:erin",
                 "via": "hangar-prod/app-backstage-prod/backstage", "role": "owner", "at": "2026-11-03T12:00:00Z"}]
}
```

### Approvals name the person

An approval names the person at their identity provider, and the delegate it came through, never only the service
that relayed it:

- **A person signed in themselves** (their OIDC ID token at the core): `sub` and `iss` are the token's subject and
  the configured issuer, as signed.
- **Through a delegate** (Tower's Backstage, naming the person in the on-behalf-of header): `sub` is the person as
  the delegate named them, `iss` is `delegate:<the delegate's principal>`, and `via` names the delegate. The core
  verified the delegate, not the person: the delegate is the issuer of that assertion. When a delegate forwards the
  person's own ID token instead, the approval will carry the IdP's subject and issuer (the token-forwarding work).
- **Policy**: no person. `approvals` is empty and `cleared_by` is `policy`.

The change view's approvals (`GET /v1/clearances/{id}`, both APIs) carry `sub` and `iss`; approvals recorded before
C-1 have neither, and the token names them `sub: <person>`, `iss: unattested`. The `deploy.clear` record carries
`approvals` (the schema's `{sub, iss, via, at}`, plus `person` and `role`), `cleared_by`, and `token` (the nonce)
when it issued one. The GitHub App's `deploy.request` and `deploy.answer` records, written as `app:<installation>`,
carry the same `approvals` and `cleared_by` once the change is cleared, so a record of the App approving a
deployment names who cleared it, or says `policy`.

### Nonce, replay and a new head

- **Issue.** A token is issued in the transaction that clears the change; its row (`clearance_tokens`) holds the
  nonce. If signing fails, the clear rolls back: a change is never cleared without its token.
- **Refresh.** While the change stays cleared, the core re-issues the token before it expires (when under half its
  life is left: on the expiry loop's tick, `CLEARANCE_EXPIRE_SECONDS`, and on a read through the core), with the
  same nonce. A token signed by a key the core no longer uses is re-issued at once.
- **Horizon.** A change's tokens are valid until its horizon: as long after it was cleared as it could have held
  (the gate TTL, 7 days by default, or the repo's tighter `ttlDays`). Past it the token lapses and is revoked, and
  the change must be registered again on a new head to deploy.
- **A new head invalidates it.** Registering a new head on the same pull request (for a pushed commit, `pr` 0: the
  same app, environment and cluster) revokes the older head's token, recorded as `deploy.revoke` (`token`: the
  nonce, result `token revoked: superseded by <head>`). The grant feed stops listing it at once.
- **The signed grant feed** (C-10). In the same transaction as any write to a cluster's tokens, and at least every
  2 minutes, the core signs that cluster's feed: a DSSE envelope over every token live there, with a per-cluster
  `seq`, a 5-minute `exp` and each token's payload digest (`token.Feed`, `token.SignFeed`, `token.VerifyFeed`,
  `Feed.Match`; [gate.md](gate.md#the-signed-grant-feed-c-10-built)). Stored in `clearance_feeds`, served by
  clearance-api. `FuzzVerifyFeed` fuzzes its parser.
- **Replay.** A token is acted on only while its nonce is the clearance's live one: the core's check
  (`gate.Service.CheckNonce`) refuses a token whose clearance has another nonce, a revoked one, or no longer
  cleared. A one-shot consumer (the PreSync hook) keeps `token.NonceCache`, which accepts a nonce once until its
  token expires and fails closed when full. An offline grant sync verifies signature, expiry and binding, and relies
  on the feed for revocation.

### Verifying

`token.Verify` (the envelope) and `token.VerifyJWT` check: the key (`GET /v1/keys`), the signature, strict
decoding of what was signed (an unknown claim is refused), `iss`, `exp` and `iat` (30 s leeway), the lifetime cap,
the binding the caller expects (`Expect`: clearance id, tree root, plan digest, commit, cluster), and the nonce
when a checker is given. `Claims.Covers(apiVersion, kind, namespace, name, rendered)` is admission's question: is
this object listed with this rendered hash. The parsers are fuzzed (`FuzzVerifyEnvelope`, `FuzzVerifyJWT`,
`FuzzParseJWKS`).

### The key

**ECDSA P-256 (ES256), from a file.** Chosen over Ed25519 because every consumer and signer in the path takes it:
ES256 is the JWS algorithm every JWT library and Kubernetes' own OIDC verification support (the core already accepts
it for people's ID tokens); Sigstore's DSSE tooling and cosign keys default to ECDSA P-256; and every KMS a customer
might hold the key in signs ECDSA P-256 with SHA-256 and returns DER (AWS KMS `ECC_NIST_P256`, Google Cloud KMS
`EC_SIGN_P256_SHA256`, Azure Key Vault `ES256`, Vault transit `ecdsa-p256`), while Ed25519 support across them is
uneven. The signature code is the standard library's (`crypto/ecdsa`); there is no custom crypto.

- **The lab**: a PEM file from a Secret the deployment names (`signing.existingSecret`), mounted read-only for the
  core only. The chart never creates it, the api never mounts it, and it is never logged.
- **Publication**: at start the core writes the public key to `clearance_signing_keys` and retires the one it used
  before. `GET /v1/keys` (the core and clearance-api) serves the key in use and keys retired in the last 24 hours,
  each `kid` its RFC 7638 thumbprint, so verifiers check tokens offline and a rotation does not strand tokens in
  flight.
- **Rotation**: replace the Secret's key and restart the core. Its first refresh re-signs every live token with the
  new key; verifiers that cache keys refetch on an unknown `kid`.
- **KMS**: `signing.kms` (`CLEARANCE_SIGNING_KMS`) is the chart's reference for a KMS-held key. The KMS signer is
  not built: the core refuses to start with it set. The interface it implements is `token.Signer` (`KeyID()`,
  `Public()`, `Sign(ctx, sha256 digest) -> DER`), which is what the KMS signing APIs above take and return; the
  token code does not change for it. A hosted Clearance (C-13) needs it.

## Change attestations

**Status: Built** (C-2), **tested against fakes**. The static backend and the whole path (outcome, statement, DSSE,
Rekor, the record, the bundle, offline verify) run in tests against a fake Rekor and a fake Fulcio. The keyless backend
has **not** run against a real Fulcio or Rekor: it waits for the Hangar signing PKI and the core's OIDC identity
(C-2a, [below](#what-keyless-needs-from-c-2a)). Unverified live: the Fulcio v2 request shape and Rekor v1's `dsse` entry,
which are written from their published APIs.

After a deploy provider reports a change's outcome, the core signs an **in-toto Statement v1** about the change and
keeps it with the change. Anyone with the bundle, the trust root and the change's digests can check, offline, that
Clearance cleared this change and a deploy applied it.

**When.** One attestation per change, for the first `deploy.outcome` that *applied* what was cleared:

- from a provider's `POST /v1/records` (an Argo CD agent's sync), or
- from `POST /v1/clearances/{id}/outcome` (a terraform apply that matched).

**When not.** A change gets **no attestation** when it was never cleared; when its outcome says nothing was applied
(`applied` false: an approved change that never synced); when the applied digest is not the cleared one (that is a
`deploy.exception`, and the change leaves `cleared`); or when it is in `exception` or `denied`. Nothing is recorded
for these. An outcome with no digest is attested with `matched: null` and a limitation that says so.

**Where.** The signer is the core's `internal/attest`, never a provider or a CMP. A provider's POST is answered
before signing starts: the outcome is queued after its commit and signed off the request path, retried with a
doubling delay (5 s to 5 min, 12 attempts) when Fulcio or Rekor is down (a bundle already signed and logged whose storing failed is kept in memory and stored on the retry, not signed and logged again; a restart between the log and the store costs one extra Rekor entry), and found again after a restart (the core
looks back over the last 2000 records for outcomes with no attestation). A signing failure never fails or delays an
outcome.

**The statement.** `_type` `https://in-toto.io/Statement/v1`; `predicateType`
`https://clearance.hangarplatform.dev/change-attestation/v1`; the schema is
[`schemas/change-attestation.schema.json`](../schemas/change-attestation.schema.json).

| Part | Carries |
|---|---|
| `subject[0]` | the cleared binding: `manifest-tree:<repo>/<app>/<env>` with the tree root's `sha256`, or `terraform-plan:<repo>/<app>/<env>` with the plan's |
| `subject[...]` | `commit:<repo>` with `gitCommit`; each image the change names **with a digest** (`<ref without digest>`, `sha256`) |
| `predicate.clearance` | `id`, `cleared_by` (`policy` or `people`), `decided_at` |
| `predicate.target`, `tier` | cluster, env, app; the tier |
| `predicate.policy` | `ref`, `version`, `engine`, `verdict`, `bundle`: the policy the change was decided under, the same group the `deploy.*` records carry |
| `predicate.approvals` | each approval: IdP `sub` and `iss`, `person`, `via`, `role`, `at` |
| `predicate.provenance` | `level` (confirmed-agent, probable-agent, confirmed-human, unknown), the check, the proposer, the agent and task |
| `predicate.cleared` | what the clearance bound: kind, repo, PR, commit, base, tree root or plan digest, images (the clearance token's subjects) |
| `predicate.outcome` | the `deploy.outcome` it rests on: `seq`, `provider`, `applied` (always true), `matched` (the applied digest is the cleared one; null when none was reported), `digest`, `observed_revision`, `at` |
| `predicate.release` | `id`, when the outcome record names a release (copied, not interpreted) |
| `predicate.coverage` | the outcome record's coverage |
| `predicate.limitations` | what this does **not** establish; never empty. Always: it attests the decision and the provider's own recorded outcome, not the live state of the target after the deploy, and the core did not observe the target. Added: a non-verified coverage, an outcome with no digest, images with no digest |

**Signing.** The statement is the payload of a DSSE envelope (`payloadType` `application/vnd.in-toto+json`, the PAE
and ES256 signature of [the clearance token](#the-clearance-token), one signing path), stored in a **Sigstore bundle**
(`application/vnd.dev.sigstore.bundle+json;version=0.2`) with its verification material. Postgres keeps the bundle
(`clearance_attestations`, one row per change) and so does the memory store. The backend is an interface
(`attest.Backend`); config selects it:

| Backend | Selected by | What it does |
|---|---|---|
| **keyless** | `CLEARANCE_ATTEST_FULCIO_URL` + `CLEARANCE_ATTEST_REKOR_URL` | per attestation: an ephemeral P-256 key (memory only, never stored), a proof of possession over the OIDC token's `sub`, Fulcio's short-lived certificate for it, the signature, a Rekor `dsse` entry (verifier: the certificate), the key discarded. The bundle carries the certificate chain and the Rekor entry |
| **static** | `CLEARANCE_ATTEST_KEY_FILE` (+ optional `CLEARANCE_ATTEST_REKOR_URL`) | a key file mounted like the clearance token's (`internal/token.LoadKeyFile`), for tests and labs. The bundle names the key by its RFC 7638 thumbprint (`kid`); Rekor entries are optional |
| off | neither set | attestations are not made and `GET /readyz` says so: `"attestation": {"enabled": false, "detail": "off: set ..."}`. Nothing else changes. Both set, or Fulcio without Rekor, stops the start |

`/readyz` reports `attestation: {enabled, backend, detail}`; off is not unready.

**The record.** The signer appends **`deploy.attestation`** to the chain (principal `policy`, `boundary: deployment`,
the change named): `attestation: {digest, backend, outcome_seq, rekor_log_index, rekor_uuid, key_id}`. `digest` is
`sha256:` of the DSSE envelope as `attest.EnvelopeDigest` serializes it (`payloadType`, `payload`, `signatures`), so the
chain ties the stored bundle to the moment the core signed it. The record and the stored bundle commit in one
transaction.

**Reading it** (clearance-api, same visibility as the change):

- `GET /v1/clearances/{id}` adds `attestation`: `{digest, backend, key_id, rekor_log_index, rekor_uuid, outcome_seq,
  record_seq, created_at}`, or `null`.
- `GET /v1/clearances/{id}/attestation` is the bundle (404 until the change has one).
- `GET /v1/clearances/{id}/attestation/verify` verifies the stored bundle server-side with `attest.Verify`, against the
  trust clearance-api is configured with, and `GET /v1/attestations` lists them ([clearance-api.md](clearance-api.md#change-history-and-attestations)).

**Verifying.** `clearance attest verify` checks, offline: the payload type; the signature (static: a key in `--key`;
keyless: the leaf certificate chains to `--trust-root` at **Rekor's integrated time**, with `--identity` as its SAN and
`--issuer` as its OIDC issuer extension); Rekor's signed entry timestamp against `--rekor-key`, and that the entry
logs this payload and signature; the statement's shape (the predicate is closed: unknown fields are refused); and
each `--subject` among the statement's subjects. A keyless bundle is refused without a trust root, an identity, an
issuer and Rekor's key, because a certificate that lives ten minutes proves nothing without the log's time. It does
**not** check Rekor's inclusion proof or checkpoint (the bundle keeps them); the signed entry timestamp is what it
relies on. `cosign verify-blob-attestation`-style tools read the same bundle.

### Trusted root (C-2a)

`clearance trust-root build` writes the document verifiers read: a Sigstore TrustedRoot (`application/vnd.dev.sigstore.trustedroot+json;version=0.1`)
with every Fulcio chain (intermediate first, root last) and every Rekor key, each with its `validFor` window. Cosign,
Glidepath's verify tasks and `clearance attest verify --trust-root` all read it.

```sh
clearance trust-root build \
  --fulcio hangar-fulcio-hangar-dev-chain.pem,start=2026-11-10T00:00:00Z \
  --fulcio legacy-hangar-dev-fulcio-root.pem,end=2026-11-10T00:00:00Z \
  --rekor rekor-hangar-dev.pub,start=2026-11-10T00:00:00Z --rekor rekor-hangar-dev-legacy.pub,end=2026-11-10T00:00:00Z \
  --fulcio-uri http://fulcio-server.fulcio-system.svc --rekor-url http://rekor-server.rekor-system.svc --out trusted-root.json
```

With a TrustedRoot, `attest verify` takes the Rekor key from the entry's log id (the SHA-256 of the key's DER), requires
the entry's signed time inside that key's window, and verifies the certificate against each chain whose window holds
that time. A bundle signed under a retired root therefore verifies while its window was open and not after. Identity and
issuer are still pinned. A chain root is trusted only as the self-signed certificate of its chain. Everything in the
input is public material.

### What keyless needs from C-2a

The keyless backend goes live when the Hangar signing platform provides all of these. Nothing here is in this repo.

| Need | Detail |
|---|---|
| **Fulcio** | the URL for `CLEARANCE_ATTEST_FULCIO_URL` (chart `attestation.keyless.fulcioUrl`): the "Hangar Fulcio `<cluster>`" whose CA is ECDSA P-256, signed by the root from the owner's key ceremony. The core calls `POST <url>/api/v2/signingCert`; the Fulcio must serve v2 and issue code-signing certificates |
| **OIDC issuer** | an issuer Fulcio trusts, configured in its `config.oidc-issuers`: the cluster's Kubernetes service account issuer (or the one that mints the core's token), with a type whose certificate identity is the token's **`sub`** (the core's proof of possession signs `sub`). The core's identity is `clearance-recorder@hangar-dev` (C-2a); verifiers pin it with `--identity` and the issuer with `--issuer` |
| **OIDC audience** | the audience Fulcio's issuer config expects (`sigstore` by default). Chart `attestation.keyless.audience` sets the projected service account token's audience (mounted at `/var/run/clearance-attest/oidc-token`, 10 minutes, rotated by the kubelet); the core re-reads it per signing |
| **Rekor** | the URL for `CLEARANCE_ATTEST_REKOR_URL` (chart `attestation.rekorUrl`): a Rekor v1 API (`POST /api/v1/log/entries`, `dsse` entries) |
| **Trust root** | for verifiers: the Fulcio root and intermediate certificates (PEM, `--trust-root`) and **Rekor's public key** (PEM, `--rekor-key`), or one [TrustedRoot JSON](#trusted-root-c-2a) holding both with their windows (`--trust-root`). They are public and belong in the repo or the cluster's trust bundle, not in the core's config: the core does not verify its own bundles |
| **Network** | the core's NetworkPolicy egress to Fulcio and Rekor (chart `networkPolicy.extraEgress`) |
| **Env and chart values** | `CLEARANCE_ATTEST_FULCIO_URL`, `CLEARANCE_ATTEST_REKOR_URL`, `CLEARANCE_ATTEST_OIDC_TOKEN_FILE` (set by the chart to the projected path); chart `attestation.keyless.fulcioUrl`, `attestation.keyless.audience`, `attestation.keyless.tokenExpirationSeconds`, `attestation.rekorUrl`. No Secret: the keyless backend holds no key |
| **autopilot** | after a clearance release carries this, the autopilot version bump that pins it |

## The evidence ledger (C-3)

Status: **Built**, off unless configured. A transparency log of the evidence chain's record hashes and nothing else,
checkpointed on a cadence, countersigned by a witness Clearance does not operate, and the assurance state that follows
from it (`internal/ledger`). It answers one question the chain cannot answer about itself: has anyone with write access
to the database cut the chain short or rewritten it and re-hashed the rest? The chain's own hashing catches an edited
row; only a party outside the database catches a chain that was rebuilt consistently.

### What it is made of

- **The log** is a [Tessera](https://github.com/transparency-dev/tessera) v1 log (`github.com/transparency-dev/tessera`,
  the POSIX driver). One entry per chain record: its 32-byte hash. Entry `i` is chain record `seq i`. The log learns
  nothing the hashes do not already publish. Records are added by the core's own loop, a second or so after they are
  written, never on the request path.
- **Checkpoints** are [C2SP tlog-checkpoints](https://c2sp.org/tlog-checkpoint) signed by the log key (a signed-note
  Ed25519 key; its name is the log's *origin*). Tessera signs one when the log has grown and its interval
  (`CLEARANCE_LEDGER_CHECKPOINT_INTERVAL`, default a minute) has passed, and asks the witnesses again at the same cadence
  when it has not, which is how an idle outage is noticed. A checkpoint is published only after the witness policy is
  satisfied; the core additionally refuses to record one that is not.
- **The witness** (`clearance-witness`, below) cosigns ([tlog-cosignature](https://c2sp.org/tlog-cosignature)) a
  checkpoint only when it is consistent with the last one it cosigned. Clearance's witness client is Tessera's: it sends
  `old <size>`, the consistency proof and the checkpoint, collects the countersignatures the policy asks for, and
  **refuses to publish a checkpoint a witness rejected**: nothing is published and the ledger says why. A checkpoint of a
  log that was truncated (a witness already cosigned more), rewritten (the same size, another root) or forked (an
  inconsistent proof) is rejected however the log signed it.
- **The assurance state** of a record, beside it and never hashed (`clearance_evidence.assurance`), moves from
  `recorded-not-checkpointed` to `checkpointed` when its hash is under a witnessed checkpoint. The checkpoint is stored
  in `clearance_ledger_checkpoints` and the rows under it are updated in one transaction. clearance-api and the record
  views already read the column, so they show it.
- **The outage knob** (`CLEARANCE_LEDGER_TIER3_WAIT`, default on): while evidence cannot be checkpointed, a **tier 3**
  change whose approvals are all in does not clear. It stays `holding` with `evidence_wait` on the change
  (`assurance: waiting-for-checkpoint` and the ledger's reason), its `deploy.clear` record says so, and the core's
  expiry loop clears it (`deploy.clear` by policy, token issued) once the ledger can checkpoint again. A change that
  reaches its TTL while waiting expires as any holding change does. Tiers 0 to 2 are not held by the ledger. Turn the knob
  off and a tier 3 change clears whatever the ledger says; the ledger still reports.

"Cannot be checkpointed" is: every witness's last answer was a failure (down, timing out, 5xx), or a witness rejected the
log's checkpoint, or records have waited longer than `CLEARANCE_LEDGER_STALL_AFTER` for a witnessed checkpoint. With
several witnesses and a quorum below all of them, one witness down does not hold anything unless checkpoints stop
advancing (the stall clock).

### The state, in `GET /readyz`

`ledger` is absent when the ledger is off, and never makes the core unready (a witness outage holds tier 3 changes, it
does not take the core out of service):

```json
"ledger": {"enabled": true, "origin": "clearance-ledger", "state": "witness-unavailable",
  "detail": "no witness answered the log's last checkpoint request",
  "chain": 9120, "ledger": 9120, "witnessed": 9087, "tier3_wait": true, "holding": true,
  "witnesses": [{"url": "https://witness.example/add-checkpoint", "state": "unavailable", "detail": "HTTP 503"}]}
```

`state` is `current` (every record is under a witnessed checkpoint), `checkpointing`, `witness-unavailable`,
`witness-rejected` or `stalled`. `holding` is whether a tier 3 change would wait right now.

### The volume, and rebuilding it

Tessera has no PostgreSQL driver, so the log's tiles are files on a volume. **The chain in PostgreSQL stays the source
of truth and the volume is a rebuildable copy of its hashes.** On start (`ledger.Open`) the core:

1. refuses if the chain holds fewer records than the last checkpoint a witness signed (the chain was truncated or restored
   from an older copy: `ErrChainBehind`), or fewer than the volume holds;
2. compares every entry the volume holds with the chain's record hash of the same seq and **names the first altered row**
   (`*AlteredRow`: seq, the hash the chain holds, the hash the ledger committed to);
3. writes the chain's record hashes the volume lacks to it, in seq order, until it matches the chain: an empty or lost
   volume is rebuilt entirely, a stale one is caught up. The root the volume computes must equal the root computed from
   the chain independently;
4. computes the root of the chain's first *N* records, where *N* is the last witnessed checkpoint's size, and **refuses to
   serve if it disagrees with that checkpoint's root** (`ErrRootMismatch`): a rebuilt volume reaches the same root, so the
   checkpoint a witness already signed still matches; a chain that was rewritten does not.

The core does not start with an inconsistent ledger. A witness that is merely down does not stop a start (the checkpoint
of the rebuilt tree is sent when it returns; the witness answers with its own size and the log sends the proof from there).
The checkpoints in `clearance_ledger_checkpoints` are what lets a lost volume be checked: they live with the chain.

The core is one replica on a ReadWriteOnce claim, so the chart's Deployment is `Recreate` (it always was: the chain's
single writer). With `ledger.enabled=false` the chart renders exactly what it did before: no claim, no variable, no mount.

### Keys

Never generated by the core and never printed. `clearance ledger keygen --name <origin> --out <file>` writes the log key
(mode 0600, never over an existing file) and prints the public key; the chart mounts the Secret read-only. **Rotating the
log key** keeps the name and changes the key: put the old vkey in `CLEARANCE_LEDGER_RETIRED_KEYS_FILE`, add the new vkey
to every witness's logs file *first*, then switch `CLEARANCE_LEDGER_KEY_FILE`. Checkpoints the old key signed still verify
(the retired vkey), the witnesses accept both, and every old entry is provable against a checkpoint the new key signed
(`Log.Prove`, `ledger.VerifyProof`): the entries and the tree do not change, only who signs the head.

### The witness (`clearance-witness`)

A C2SP tlog-witness in its own binary and image (`ghcr.io/jfillman/clearance-witness`, `cmd/clearance-witness`), because
it is worth something only run by someone the log's operator does not control. It holds, per log it knows, the latest
checkpoint it cosigned (a state file on a volume, written atomically; a witness that forgets can be rolled back) and
answers `POST /add-checkpoint`: 200 with the cosignature when the checkpoint extends the one it holds (a valid
consistency proof) or repeats it; 409 with its size (`text/x.tlog.size`) when the sender's idea of that size is wrong,
or plain 409 for another tree of a size it already cosigned; 400 for a checkpoint older than the sender claims to hold;
403 when no log signature under a trusted key verifies; 404 for an unknown log; 422 for a bad proof. Its signing key is
a signed-note secret key in a mounted file (`--key-file`); `--logs-file` lists the logs' vkeys, `--state-file` the
state. The chart is `charts/clearance-witness`. For the lab: one witness on hangar-prod, with its own key, run from the
apron prod profile; the policy on hangar-dev lists it as `witness <name> <its cosignature vkey> https://<host>`.

### The local anchored checkpoint

`evidence.Checkpoint` (count and head) is **not retired**: it is the chain verifier's own state, and
`clearance chain verify --anchor <count>:<head>` and `evidence.VerifyAgainst` are the only defence against truncation
while the ledger is off, which is the default. Removing them with the ledger off would remove a protection from a running
deployment. With the ledger on they are superseded (the witness anchors the chain from outside the database) and still
work. Retiring them is a decision for a release after the ledger has been on in the lab.

### What is not built

- **No "every N records" trigger.** Tessera's checkpoint cadence is a time interval; a checkpoint is signed when the log
  has grown and the interval has passed. The brief's "every N records or every minute" is the minute.
- **A `clearance ledger verify` command** (an offline audit of a volume against a database). The audit runs at start, and
  `Log.Audit` is the same check in process.
- **One witness protocol only**: the add-checkpoint form Tessera's client speaks. A witness network's other protocol
  versions are not implemented.
- **The log is not served.** The tiles are on the volume; nothing publishes them over HTTP yet, so a third party cannot
  fetch a proof from Clearance (`Log.Prove` is in process). The evidence packet ([packet.md](packet.md)) gets round this
  without serving the log: entry *i* is chain record *i*'s hash, so `ledger.Tree` builds the same inclusion proof from the
  chain's hashes alone (tested equal to `Log.Prove`), and `ledger.ParseCheckpointNote` verifies a checkpoint without a log.

## The decision engine (`internal/decide`)

The runtime decision is a pure function. It takes an AuthZEN evaluation to a decision with its rule id, name,
message, hint, tier, the spend the caller must apply, and the record fields to write. The request's context carries
every piece of state the decision reads, and `now`, so `Decide` does no I/O and reads no clock. The package
documentation (`internal/decide/doc.go`) has the request and response shapes and the four actions.

- **Rules are data.** The core's live in `internal/decide/core.json`, exported from the Python rule set (by
  `tools/golden/export_bundle.py`, at v0.29.0 and before), so rule text and hints match the Python character for
  character. It is now the source: a change to a core rule is an edit to `core.json`. A deployment's
  own rules are a [policy bundle](#policy-bundles) it loads. They are compiled once at load with cel-go against typed variables. A rule that does not
  compile, is not a bool, reads an undeclared field, or has a worst-case cost over `MaxRuleCost` (100,000) fails the
  load. Each evaluation is also cut off at that cost. Anything that fails to evaluate denies with R000.
- **Python semantics are reproduced exactly** where a decision depends on them: dict order and key equality,
  `True == 1 == 1.0`, `repr` in messages, `str.lower`, `strip` and `len`, `$` in `re.match`, fnmatch,
  `posixpath.normpath`, PyYAML's YAML 1.1 `safe_load`, and `json.dumps` lengths. They live in `internal/pycompat` (one
  home for every Python behaviour the core reproduces), `internal/pyyaml` (the core's one YAML loader, also used by
  `clearance register` and the definition loader) and `internal/scope` (`scope.py`). Each has vectors that Python
  generated (`tools/golden/gen_vectors.py`, standard library and PyYAML only, so it still runs: `python3 -I
  tools/golden/gen_vectors.py` with PyYAML installed).
- **Where cel-python and cel-go differ** is listed in
  [`internal/decide/CEL_DIFFERENCES.md`](https://github.com/jfillman/clearance/blob/main/internal/decide/CEL_DIFFERENCES.md).
  No rule evaluates differently for a request the API can carry. The only differences are for ill-typed contexts
  that a typed request cannot reach, and for inputs where the Python engine raises and the Go engine fails closed.
- **The golden corpus.** `testdata/golden/corpus.jsonl` was recorded from the Python engine over the whole Python
  test suite plus the fixture agents' calls (`tools/golden/test_fixture_calls.py`). It replays through the Go engine
  (`internal/decide/golden`), with the policy bundle the corpus deployment loads (`testdata/bundles/hangar`, or the
  file `CLEARANCE_GOLDEN_BUNDLE` names), with identical decisions, rule ids, names, messages, hints, tiers, problems, spend,
  grants and record fields. The same package benchmarks the decide path against its budget of 2 ms p99 in-process.

The corpus is frozen: the Python engine it was recorded from left the repository in v0.30.0, and its recorders
(`tools/golden/export_bundle.py`, `record.py`, `golden_recorder.py`, `test_fixture_calls.py`) went with it. They are
at the v0.29.0 tag, with the package they import, for anyone who needs to re-record against that engine. The corpus
is now a regression fixture for the Go engine: the replay fails if the embedded core rules, or the fixture bundle's
tools and rules, drift from the export on the corpus's first line, so a deliberate rule change updates the corpus
lines it changes in the same PR.

## Policy bundles

Built (v0.29.0). A deployment's policy is a **policy bundle**: a JSON file (`apiVersion: clearance.policy/v1`) that
the core and clearance-api load from configuration (`CLEARANCE_BUNDLES`) and name, with its version, in every
decision. Nothing about any deployment is compiled into Clearance: the core's source carries no platform's names
(`internal/boundary` checks every string literal and identifier of the Go core and every line of its embedded
data). A bundle holds:

| Field | What it is |
|---|---|
| `name`, `version`, `description` | The bundle's identity. Decisions name it as `clearance-core+<name>`, and `policy.bundles` lists `{name, version, digest, sources}`. |
| `tools` | The tools its rules govern (name, tier, required args, GitHub cost, target, propose-only, writes files, reads repo, receipt). The gateway's tool registry names the same tools; the core needs them to tier and type-check. |
| `pr_tools` | Tools whose receipt is a pull request (provenance looks them up by PR). |
| `profile_sections` | Definition profile sections whose `apps` list scopes an agent (a definition review reads them). |
| `sources` | Documents read at load, each `{name, version_pointer, compatible}`: the version at `version_pointer` must be one of `compatible`, or the load fails. Where each is read from is the deployment's `CLEARANCE_BUNDLE_SOURCES`. |
| `vars` | `ctx.<name>` variables, `{name, type: bool or int, expr}`, CEL over the call, in order. |
| `arg_checks` | `{when, checks}`: for a call `when` selects, each check that is true is one bad argument (R008). |
| `documents` | Field scope over a file a file-writing tool carries (`internal/docscope`): the file name, pointer rules (inline, or from a source at a JSON pointer; scopes `open`, `tighten`, `human` and `propose`, the last optionally only for some kinds of change, `proposeOn`), the rule id and hint of each finding class (`whole_file`, `human`, `loosened`, and `propose`, required when a rule is propose: a change to a propose field is one only a person's merge may land, which a file-writing tool cannot mark, so the check refuses it and its hint names the tool that can), and structural invariants (a keyed collection whose attribute may not change and whose protected items may not change at all; counted items per entry that may not decrease). `ctx.<name>` is its finding count. |
| `app` | CEL string over the call alone (no `ctx.*`): the application a call acts on, recorded as `app`. |
| `rules` | Deny-if rules (`id, name, expr, message, hint, order`, optional `problems` naming a document) placed among the core's by `order`. A rule with `problems` decides with that document's findings: the first finding's rule id and hint, every message, all of them as `problems`. |

**Context expressions** (vars, arg checks, app) are CEL, compiled and type-checked once at load like the rules,
over `tool.name`, `tool.known`, `tool.tier`, `tool.writes_files`, `tool.reads_repo`, `args` (the call's
arguments as sent) and `profile` (the definition's profile as written), with cel-go's strings extension and a
small library of total functions: `py.get`, `py.strlist`, `py.strip`, `py.len`, `py.utf8len`, `py.json_len`,
`py.trim_prefix`, `path.norm`, `path.base`, `glob.match`, `glob.any` (`internal/decide/celctx.go`). None of them fails
on a value of the wrong shape, so an expression with `type()` guards decides on any input. An integer outside int64
is neither `int` nor `double`. Each evaluation is cut off at `MaxContextCost`; an error is R000.

**Why the context is in the bundle, not in the caller.** The gateway sends the call as it is, and the core
computes everything the rules read: the argument checks, the app allowlists, the document scope. The decision
stays the core's, and a deployment changes it with a bundle, not a Clearance release. A context the gateway
computed would put part of the policy in the enforcement point. A compiled-in pack selected by configuration would
keep the deployment's names in the core.

**Sources are read live, at start.** A source such as a CI system's published contract (`GET /v1/contract`) is
fetched over HTTP(S) with the pod's projected service-account token (`tokenFile`), or read from a file. There is
no fallback copy.

- **A source that does not answer** (no connection, a timeout, a non-200 status, an unreadable token file) is
  retried every 2 s for `CLEARANCE_BUNDLE_SOURCE_WAIT` (default 10 s). Then the core starts with that bundle
  **degraded** (decided 2026-11-03):
  - Every call to one of the bundle's tools is denied **R000** with "policy bundle `<name>` is unavailable: its
    source `<source>` could not be read".
  - So is any call carrying a file one of the bundle's documents checks with rules from that source (an agent's
    cicd.yaml).
  - These denials charge nothing: no denial is counted and no breaker trips. It is a platform fault, not the
    agent's.
  - Every other call decides as usual. Records, the deployment gate, provenance, the GitHub App and clearance-api
    keep working.
  - The degraded bundle is named in every decision (`policy.bundles[].status: "unavailable"`, with the reason in
    `unavailable`) and in `/readyz` (`degraded`). The core and the api still answer **200**, deliberately: the core
    is one replica that also serves the gate, records and the webhook, and a 503 would take all of that out of its
    Service. Monitor `degraded` instead.
- **Meanwhile** the loader keeps fetching in the background (`bundles.Watch`), with backoff from 2 s doubling to
  60 s. When the source answers, it loads the bundle whole and swaps the policy in at once. Each load is logged
  (`policy bundle loaded`, with each source's location, version and digest), and later decisions name it
  (`status: "loaded"` and a new policy version).
- **A source that answers with a document that does not parse, or a version the bundle does not list** in
  `compatible`, is a configuration error, not an outage. At start it fails the start. Found later by the
  background loader, it is logged and the bundle stays degraded.

A changed source document (a new scope rule) changes the policy version in every decision after the next start
or load.

**Environments.** R012 (a lower-target tool pointed at an upper environment) reads the deployment's naming:
`project` ending in a `CLEARANCE_ENV_LOWER_PROJECT_SUFFIXES` entry is lower (any other project upper); else an
`env` in `CLEARANCE_ENV_LOWER_NAMES` or starting with a `CLEARANCE_ENV_LOWER_PREFIXES` entry is lower (any other env
upper); else a `repo` whose name starts with a `CLEARANCE_ENV_UPPER_REPO_PREFIXES` entry is upper (any other repo
lower).

**Records.** Each decision record carries `policy: {ref, version, engine}`: `ref` is `clearance-core` plus
`+<bundle>@<version>` for each bundle, `version` the digest over the core rules, the bundles, their source documents
and the environment naming, `engine` is `cel-go`.

The chart mounts each bundle from a ConfigMap (`policy.bundles`), configures its sources (`policy.sources`, with a
projected token and `policy.egress` for the NetworkPolicy), the environment naming (`policy.environments`) and the
vocabulary (`vocabulary.*`): see [install.md](install.md).

## The store (`internal/store`)

- **Same tables.** The core keeps `clearance_evidence`, `clearance_changes` and `clearance_definitions`, with the
  columns, indexes and jsonb shapes the Python core created (`pg.py` SCHEMA, verbatim, `CREATE ... IF NOT EXISTS`
  only). So the Go core can take over the live hangar-dev database at cutover without a migration. C-1 adds two
  tables of its own, created the same way on the next start: `clearance_tokens` (one row per cleared change: the
  cluster, nonce, key id, validity, revocation, the DSSE envelope and the JWT; indexed for the grant feed by
  `(cluster, expires_at)` and for the refresh by `expires_at`, both where not revoked) and `clearance_signing_keys`
  (the public keys the core has signed with). C-10 adds `clearance_feeds` (one row per cluster: the signed grant
  feed and the tokens it lists) and the index `clearance_evidence_app` (`((record->>'principal'), seq)` where the
  principal is `app:%`: the GitHub App installations' records, for clearance-api). The chart's reader role reads them through its default privileges. The gateway's
  tables (sessions, artifacts, inbox, events, holds, results) are not the core's and are left alone.
- **One writer.** Opening a writable store takes the advisory lock the Python core takes (`LockKey`, pg.py's
  `"clr0"`) on a dedicated connection and holds it for the store's life. Every write runs on that connection, and a
  second writer, Python or Go, fails to open, because two writers would fork the chain.
- **Verified on open.** The chain is verified from genesis, streamed in batches, so an edited, deleted or reordered
  row stops the core from starting instead of being extended. The hash is the Python one byte for byte
  (`internal/canon`: `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`).
- **Read-only mode** (`pg.OpenReader`) is for clearance-api and `clearance chain verify --dsn`: no lock, no
  migration, every session read-only. Every statement runs under a statement timeout and a context deadline.
- **The ledger's checkpoints** (C-3) are `clearance_ledger_checkpoints` (size, origin, root, the signed note, time), created
  the same way; `store.Ledger` is the interface, implemented by `store/pg` and `store/memory`
  (`PutLedgerCheckpoint` also sets `assurance = 'checkpointed'` on the rows under it, in one transaction, and refuses
  a checkpoint that would shrink or fork the one held).
- `store/memory` is the same interface in memory, for `clearance core --memory` and tests.

## Building and testing

```shell
go build ./cmd/clearance
go test -race ./...          # the Postgres tests need CLEARANCE_TEST_DSN and skip without it
tools/fuzz-all.sh 10s        # every Fuzz* target, as CI runs them
```

CI (`.github/workflows/go.yaml`) runs vet, gofmt, the race tests, the fuzz targets and govulncheck; it checks out
Autopilot's agent-definition schema so `internal/profile` can prove its embedded copy is byte for byte the same
(`CLEARANCE_AGENT_SCHEMA`; the test skips without it), and builds and dry-runs the `register` action. The contract is
regenerated with `go generate ./internal/server`. The release version is the `VERSION` file (`internal/release`):
`tools/pyclient` writes it into the Python client, and the release workflow checks the tag against it
(`go run ./tools/releasenotes -check-tag vX.Y.Z`).

### The boundary (`internal/boundary`)

What the core is not, as tests over its non-test source (`internal/`, `cmd/`, `client/`) and the Python client:

- **No session store, MCP server or tool dispatch.** `go list -deps` of the core names no MCP SDK and no model
  provider's SDK; no package is named for a gateway part (sessions, dispatch, MCP, the model proxy, the inbox,
  runtimes, triggers); no identifier is a session store, dispatcher, MCP handler, tool registry, model proxy or
  inbox; no string literal is the `/mcp` endpoint, an MCP method or a model API route. `SessionState` (a session as
  the gateway reports it in a decision request) and the actions `session.open` and `session.spawn` are decision
  vocabulary and stay. Those are Autopilot's (R-3).
- **No Hangar vocabulary** (R-5): no string literal or identifier, and no line of an embedded data file, names Hangar
  or one of its products, with one recorded exception (the embedded agent-definition schema).

Comments are not checked: they may say where a port came from. Each check has a test that it finds what it should. The image (`Dockerfile`) and the Helm chart (`charts/clearance`) are
in [install.md](install.md); every variable above is a chart value, and `tools/charttest` fails when one is not.
