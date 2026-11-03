# The Go core (`clearance`)

**Status: Built, not deployed.** The Go core is written and tested in this repository (R-1 of the Clearance and
Autopilot build). Nothing runs it yet: the live hangar-dev gateway still runs the Python core (`src/clearance`)
until W1 switches the decision and record path over. The Python modules stay in the repository, and stay true, until
R-3 moves the gateway to `autopilot`.

The core decides and records. A gateway (Autopilot's) or a gate provider (the Argo CD sync, the GitHub App, `clearance
register`) asks it for a decision and writes its records through it; the core enforces nothing itself and holds no
session. It is one Go module, `github.com/jfillman/clearance`, built as one static binary.

## The binary

`clearance <subcommand>`. Each subcommand is one file under `cmd/clearance` that registers itself (`internal/cli`).

| Subcommand | What it does | Status |
|---|---|---|
| `clearance core` | Serves the core over HTTP (the API below) from the environment. `--memory` runs it on an in-memory store (tests and local runs; nothing is kept). `--insecure-dev-auth`, with `--memory` only, accepts `Bearer <principal>` as that principal and serves the chain at `GET /v1/dev/records` (below). `--listen` overrides `CLEARANCE_LISTEN`. `--max-clock-skew` overrides `CLEARANCE_MAX_CLOCK_SKEW`; `0` (off) is accepted only with `--memory`. SIGTERM shuts it down gracefully (20 s for requests in flight). | Built |
| `clearance chain verify` | Verifies an evidence chain from genesis, from a JSONL dump (`--file`, `-` for stdin) or a read-only Postgres connection (`--dsn`, default `$CLEARANCE_DSN`). `--anchor <count>:<head>` checks that a checkpoint taken elsewhere is still held, which catches truncation. | Built |
| `clearance register` | The Go port of `register.py`: a customer's CI registers what it deploys with the deployment gate (the diff of two rendered manifest directories), authenticated by the workflow's GitHub Actions OIDC token or `--token-file`. Same flags as the Python command, except that `--paths-from-git` with a base is refused, because the binary does not shell out. Without it, the paths are the files that differ between `--before` and `--after`. | Built |
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
| `POST /v1/records` | a registered provider | One of the provider's own records: `session.open`, `run.launch`, `run.delete`, `run.finish`, `human.answer`, `session.freeze`, `session.end`, `trigger.hold`, `trigger.release`, `tool.call` (an outage read, `coverage-unavailable`), `deploy.outcome`, `deploy.exception`. |
| `PUT /v1/definitions` | the provider registered with `definitions: true` | The provider's whole set of cluster-pinned agent definitions replaces the core's. The core decides each pin and records each change once (`definition.load`, `definition.unload`, `definition.reject`). |
| `POST /v1/clearances`, `/v1/clearances/{change_id}/clear`, `/v1/clearances/{change_id}/deny` | a verifier; a person or a delegate | The deployment gate ([gate.md](gate.md)), at the Python core's paths. |
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
- `kinds` narrows which `POST /v1/records` kinds the provider may write (default: all of them).
- `intent_capture` is `redacted` (the default) or `full`, for its records' intent text.
- `definitions: true` lets the provider publish its cluster-pinned agent definitions (`PUT /v1/definitions`). At
  most one provider has it, because a publish replaces the whole set: two publishers would undo each other.

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
- **Provider records.** Sealed with the provider's name and version. Only `provider` and `ts` are verified;
  everything else is claimed. Each kind has its required fields and its boundary (`internal/server/records.go`;
  [provider-protocol.md](provider-protocol.md#record-kinds) lists them). A `tool.call` record is the outage
  policy's replay of a T0 read the provider ran while the core was unreachable: its `tool` is the tool called (a T0
  tool the core knows), its coverage is `coverage-unavailable`, and it carries no rule, effect or outcome. Its
  subject is the tool-call digest, claimed. It is never a decision.
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
- **The dev chain read.** `clearance core --memory --insecure-dev-auth` also serves `GET /v1/dev/records?from=<seq>&limit=<n>`
  (at most 10,000, a bearer token required): the in-memory chain, so another package's tests (autopilot's) read what
  the core recorded from the unmodified binary. It is not in the contract, and `core.Build` refuses it on a kept
  store; clearance-api is the reader of a kept chain.

### Clients

`client` (Go, the standard library only) and `clients/python` (generated from the contract, released with each tag)
call this API. Both report an unreachable core as a distinct error (`client.ErrCoreUnavailable`) that the caller's
outage policy acts on: by default, fail closed. The Python client (`clearance_client.CoreClient`) is what the
Autopilot gateway calls once R-3 moves it; in tests, `clearance core --memory` stands in for a deployed core (R-1e).

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
| `CLEARANCE_BUNDLE_SOURCE_WAIT` | How long the start keeps retrying a source it cannot fetch (Go duration, default `60s`). Then the process exits. |
| `CLEARANCE_ENV_LOWER_NAMES`, `CLEARANCE_ENV_LOWER_PREFIXES`, `CLEARANCE_ENV_LOWER_PROJECT_SUFFIXES`, `CLEARANCE_ENV_UPPER_REPO_PREFIXES` | How arguments name an environment tier, for R012 (below). Defaults: lower names `dev,development,sandbox,scratch`, no prefixes or suffixes. |
| `CLEARANCE_VERIFIERS` | Principal globs that may register changes and ask for provenance. |
| `CLEARANCE_DELEGATES` | Principal globs that may act for a person they name (in `CLEARANCE_ON_BEHALF_OF_HEADER`). |
| `CLEARANCE_ADMINS` | Principal globs (`user:<login>`) that may deny any held change. |
| `CLEARANCE_EXPIRE_SECONDS` | How often holding changes past their TTL are expired (default 60, at most 86400). |
| `CLEARANCE_MAX_CLOCK_SKEW` | How far an evaluation's `context.now` may be from the core's clock, a Go duration (default `5m`, at most `24h`). `0` turns the check off, and `clearance core` refuses that without `--memory`: a decision record's `ts` is the evaluation's `now` and is verified, so a kept chain never takes an unbounded one. A test core on a fixed clock runs `clearance core --memory --insecure-dev-auth --max-clock-skew 0`. |
| `CLEARANCE_AGENTS_DIR` | Bundled agent definitions (`*.yaml`). Default none. |
| `AGENT_LOGINS` | GitHub logins agents open PRs as. Default none: an agent PR is known by its Clearance record or its trailers. |
| `MODEL_ROUTES` | `alias=upstream,...`: the model aliases a definition release may name. When unset they are not checked. |
| `RUNTIME_IMAGES_EXTRA` | Globs a definition's `runtime.image` may match. |
| `CLEARANCE_TRUSTED_REGISTRIES` | Comma-separated image prefixes, each ending in `/`, that a tier-1 image bump may come from; an image bump from anywhere else is tier 2 (`image:not-trusted-registry`) and held for the owner group. Unset: any registry (the product default). Hangar sets `ghcr.io/riley-roooo/` (decided 2026-11-03, live from the R-4 cutover). |
| `CLEARANCE_GITHUB_APP_ID`, `CLEARANCE_GITHUB_APP_KEY_FILE`, `CLEARANCE_GITHUB_APP_WEBHOOK_SECRET_FILE` | The Clearance GitHub App. Set all three or none. The key and secret are read from files. |
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

The source of truth is the package documentation of `internal/core`, `internal/bundles`, `internal/vocab` and
`authn.EnvVars`. `clearance register`
reads `CLEARANCE_URL` and GitHub Actions' `GITHUB_EVENT_PATH`, `GITHUB_REPOSITORY`, `GITHUB_SHA` and
`GITHUB_ACTOR`.

## The decision engine (`internal/decide`)

The runtime decision is a pure function. It takes an AuthZEN evaluation to a decision with its rule id, name,
message, hint, tier, the spend the caller must apply, and the record fields to write. The request's context carries
every piece of state the decision reads, and `now`, so `Decide` does no I/O and reads no clock. The package
documentation (`internal/decide/doc.go`) has the request and response shapes and the four actions.

- **Rules are data.** The core's live in `internal/decide/core.json`, exported from the Python rule set by
  `tools/golden/export_bundle.py`, so rule text and hints match the Python character for character. A deployment's
  own rules are a [policy bundle](#policy-bundles) it loads. They are compiled once at load with cel-go against typed variables. A rule that does not
  compile, is not a bool, reads an undeclared field, or has a worst-case cost over `MaxRuleCost` (100,000) fails the
  load. Each evaluation is also cut off at that cost. Anything that fails to evaluate denies with R000.
- **Python semantics are reproduced exactly** where a decision depends on them: dict order and key equality,
  `True == 1 == 1.0`, `repr` in messages, `str.lower`, `strip` and `len`, `$` in `re.match`, fnmatch,
  `posixpath.normpath`, PyYAML's YAML 1.1 `safe_load`, and `json.dumps` lengths. They live in `internal/pycompat` (one
  home for every Python behaviour the core reproduces), `internal/pyyaml` (the core's one YAML loader, also used by
  `clearance register` and the definition loader) and `internal/scope` (`scope.py`). Each has vectors that Python
  generated (`tools/golden/gen_vectors.py`).
- **Where cel-python and cel-go differ** is listed in
  [`internal/decide/CEL_DIFFERENCES.md`](https://github.com/jfillman/clearance/blob/main/internal/decide/CEL_DIFFERENCES.md).
  No rule evaluates differently for a request the API can carry. The only differences are for ill-typed contexts
  that a typed request cannot reach, and for inputs where the Python engine raises and the Go engine fails closed.
- **The golden corpus.** `testdata/golden/corpus.jsonl` is recorded from the Python engine over the whole Python
  test suite plus the fixture agents' calls (`tools/golden/test_fixture_calls.py`). It replays through the Go engine
  (`internal/decide/golden`), with the policy bundle the corpus deployment loads (`testdata/bundles/hangar`, or the
  file `CLEARANCE_GOLDEN_BUNDLE` names), with identical decisions, rule ids, names, messages, hints, tiers, problems, spend,
  grants and record fields. The same package benchmarks the decide path against its budget of 2 ms p99 in-process.

To re-record after a change to the Python rules or engine (from the repository root, with the Python test extras
installed):

```shell
PYTHONPATH=src .venv/bin/python tools/golden/export_bundle.py   # the Go engine's embedded core rules
.venv/bin/python tools/golden/record.py                         # testdata/golden/corpus.jsonl (HANGAR_TECH defaults to ../)
PYTHONPATH=src .venv/bin/python tools/golden/gen_vectors.py     # pycompat and pyyaml reference vectors
go test ./internal/decide/... ./internal/pycompat ./internal/pyyaml
```

The replay fails if the embedded core rules, or the fixture bundle's tools and rules, drift from the export on the
corpus's first line.

## Policy bundles

Built (v0.29.0). A deployment's policy is a **policy bundle**: a JSON file (`apiVersion: clearance.policy/v1`) that
the core and clearance-api load from configuration (`CLEARANCE_BUNDLES`) and name, with its version, in every
decision. Nothing about any deployment is compiled into Clearance: the core's source carries no platform's names
(`tests/test_boundary.py` checks every string literal and identifier of the Go core and every line of its embedded
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
| `documents` | Field scope over a file a file-writing tool carries (`internal/docscope`): the file name, pointer rules (inline, or from a source at a JSON pointer), the rule id and hint of each finding class, and structural invariants (a keyed collection whose attribute may not change and whose protected items may not change at all; counted items per entry that may not decrease). `ctx.<name>` is its finding count. |
| `app` | CEL string: the application a call acts on, recorded as `app`. |
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
fetched over HTTP(S) with the pod's projected service-account token (`tokenFile`), or read from a file. When it
cannot be read, the loader retries every 2 s until `CLEARANCE_BUNDLE_SOURCE_WAIT` (default 60 s) runs out, and then
the process exits non-zero. There is no fallback copy: the core does not decide on a policy it could not load, and
Kubernetes restarts it until the source answers. While it is down, every evaluation fails at the caller (the
gateway's outage policy), and the deployment gate, provenance and the GitHub App webhook are down too. A changed
source document (a new scope rule) changes the policy version in every decision after the next start; a source
version the bundle is not written for stops the start until the bundle is updated.

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
  only). So the Go core can take over the live hangar-dev database at cutover without a migration. The gateway's
  tables (sessions, artifacts, inbox, events, holds, results) are not the core's and are left alone.
- **One writer.** Opening a writable store takes the advisory lock the Python core takes (`LockKey`, pg.py's
  `"clr0"`) on a dedicated connection and holds it for the store's life. Every write runs on that connection, and a
  second writer, Python or Go, fails to open, because two writers would fork the chain.
- **Verified on open.** The chain is verified from genesis, streamed in batches, so an edited, deleted or reordered
  row stops the core from starting instead of being extended. The hash is the Python one byte for byte
  (`internal/canon`: `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`).
- **Read-only mode** (`pg.OpenReader`) is for clearance-api and `clearance chain verify --dsn`: no lock, no
  migration, every session read-only. Every statement runs under a statement timeout and a context deadline.
- `store/memory` is the same interface in memory, for `clearance core --memory` and tests.

## Building and testing

```shell
go build ./cmd/clearance
go test -race ./...          # the Postgres tests need CLEARANCE_TEST_DSN and skip without it
tools/fuzz-all.sh 10s        # every Fuzz* target, as CI runs them
```

CI (`.github/workflows/go.yaml`) runs vet, gofmt, the race tests, the fuzz targets and govulncheck. The contract is
regenerated with `go generate ./internal/server`. The image (`Dockerfile`) and the Helm chart (`charts/clearance`) are
in [install.md](install.md); every variable above is a chart value, and `tools/charttest` fails when one is not.
