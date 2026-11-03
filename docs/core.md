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
| `clearance core` | Serves the core over HTTP (the API below) from the environment. `--memory` runs it on an in-memory store (tests and local runs; nothing is kept). `--insecure-dev-auth`, with `--memory` only, accepts `Bearer <principal>` as that principal. `--listen` overrides `CLEARANCE_LISTEN`. SIGTERM shuts it down gracefully (20 s for requests in flight). | Built |
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
| `POST /v1/records` | a registered provider | One of the provider's own records: `session.open`, `run.launch`, `run.delete`, `human.answer`, `session.freeze`, `trigger.hold`, `deploy.outcome`, `deploy.exception`. |
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
[{"name": "autopilot-gateway", "version": "0.3.27", "principals": ["autopilot-system/clearance"]},
 {"name": "argo-gate", "version": "0.1.0", "principals": ["hangar-prod/argocd/clearance-sync"],
  "kinds": ["deploy.outcome", "deploy.exception"]}]
```

- `name` is the record's `provider.name` (the evidence schema's pattern). It may not be `clearance`, which is the
  core's own name.
- `version` is `provider.version`, 1 to 64 characters.
- `principals` are fnmatch globs on the authenticated principal. A caller is the first provider whose globs match.
- `kinds` narrows which `POST /v1/records` kinds the provider may write (default: all of them).
- `intent_capture` is `redacted` (the default) or `full`, for its records' intent text.

### Decisions, outcomes and records

- **Decision id.** A recorded decision's id is its evidence record's `seq`, as a decimal string. It is unique and
  stable, and one indexed read finds it again. The answer carries `decision_id` and `record` (`seq`, `hash`). A
  decision with no record (a model call to a deployment without model routes) has `decision_id: null` and takes no
  outcome.
- **The decision record** names its `caller` (`{provider, principal}`), and that field is verified because the
  core authenticated it. Its `ts` is the evaluation's `context.now`, which must be within 5 minutes of the core's
  clock (`server.Options.MaxClockSkew`). A caller cannot move it.
- **Outcome.** Only the provider that asked for the decision may report its outcome, once, and only for an allowed
  decision. It is recorded as the decision's tool and linked by `outcome_of`. The identity fields are copied from the
  decision record (verified); what the provider reports is claimed. A second outcome is refused without a chain scan:
  the server indexes `outcome_of` at start and keeps the index while it is the one writer.
- **Provider records.** Sealed with the provider's name and version. Only `provider` and `ts` are verified;
  everything else is claimed. Each kind has its required fields and its boundary (`internal/server/records.go`).

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
| `CLEARANCE_PACKS` | Comma-separated policy packs. `hangar` loads the Hangar pack. Default none; any other name is an error. |
| `CLEARANCE_VERIFIERS` | Principal globs that may register changes and ask for provenance. |
| `CLEARANCE_DELEGATES` | Principal globs that may act for a person they name (`X-Hangar-On-Behalf-Of`). |
| `CLEARANCE_ADMINS` | Principal globs (`user:<login>`) that may deny any held change. |
| `CLEARANCE_EXPIRE_SECONDS` | How often holding changes past their TTL are expired (default 60, at most 86400). |
| `CLEARANCE_AGENTS_DIR` | Bundled agent definitions (`*.yaml`). Default none. |
| `AGENT_LOGINS` | GitHub logins agents open PRs as (default `hangar-autopilot-agents[bot]`). |
| `MODEL_ROUTES` | `alias=upstream,...`: the model aliases a definition release may name. When unset they are not checked. |
| `RUNTIME_IMAGES_EXTRA` | Globs a definition's `runtime.image` may match. |
| `CLEARANCE_FLIGHT_REGISTRIES` | Comma-separated image prefixes, each ending in `/`, that a tier-1 image bump may come from; an image bump from anywhere else is tier 2 (`image:not-flight-registry`) and held for the owner group. Unset: any registry (the product default). Hangar sets `ghcr.io/riley-roooo/` (decided 2026-11-03, live from the R-4 cutover). |
| `CLEARANCE_GITHUB_APP_ID`, `CLEARANCE_GITHUB_APP_KEY_FILE`, `CLEARANCE_GITHUB_APP_WEBHOOK_SECRET_FILE` | The Clearance GitHub App. Set all three or none. The key and secret are read from files. |
| `CLEARANCE_GITHUB_APP_COMMENTS` | `off` (default) or `agent-failures`. |
| `CLEARANCE_GITHUB_API` | The GitHub API base (default `https://api.github.com`). |
| `CLEARANCE_AUDIENCE` | The TokenReview audience for this cluster's workloads, and the audience of the Tower cluster's tokens (default `clearance`). |
| `CLEARANCE_OIDC_ISSUER`, `CLEARANCE_OIDC_AUDIENCE` | People's OIDC issuer and their ID tokens' audience. Set both or neither. |
| `CLEARANCE_OIDC_JWKS_URL` | Default `<issuer>/keys`. |
| `CLEARANCE_OIDC_USER_CLAIM` | Default `email`. |
| `CLEARANCE_OIDC_ALLOWED_USERS` | Comma-separated globs on that claim. Required with an issuer, because a valid token from an issuer that federates GitHub could belong to anyone with a GitHub account. |
| `TOWER_ISSUER`, `TOWER_CLUSTER`, `TOWER_SERVICE_ACCOUNTS`, `TOWER_JWKS_URL` | Another cluster's service-account issuer, its name, the `<namespace>/<sa>` globs it may use, and its JWKS (default `<issuer>/jwks.json`). |
| `CLEARANCE_GITHUB_OIDC_AUDIENCE` | GitHub Actions tokens' audience. GitHub Actions callers are off when it is unset. |
| `CLEARANCE_GITHUB_OIDC_ALLOWED` | Comma-separated globs on the token's `sub` (default `repo:*`). |

The source of truth is the package documentation of `internal/core` and `authn.EnvVars`. `clearance register`
reads `CLEARANCE_URL` and GitHub Actions' `GITHUB_EVENT_PATH`, `GITHUB_REPOSITORY`, `GITHUB_SHA` and
`GITHUB_ACTOR`.

## The decision engine (`internal/decide`)

The runtime decision is a pure function. It takes an AuthZEN evaluation to a decision with its rule id, name,
message, hint, tier, the spend the caller must apply, and the record fields to write. The request's context carries
every piece of state the decision reads, and `now`, so `Decide` does no I/O and reads no clock. The package
documentation (`internal/decide/doc.go`) has the request and response shapes and the four actions.

- **Rules are data.** They live in `internal/decide/core.json` and each pack's file (`packs/hangar/hangar.json`),
  exported from the Python rule set by `tools/golden/export_bundle.py`, so rule text and hints match the Python
  character for character. They are compiled once at load with cel-go against typed variables. A rule that does not
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
  (`internal/decide/golden`) with identical decisions, rule ids, names, messages, hints, tiers, problems, spend,
  grants and record fields. The same package benchmarks the decide path against its budget of 2 ms p99 in-process.

To re-record after a change to the Python rules or engine (from the repository root, with the Python test extras
installed):

```shell
PYTHONPATH=src .venv/bin/python tools/golden/export_bundle.py   # the Go engine's embedded bundles
.venv/bin/python tools/golden/record.py                         # testdata/golden/corpus.jsonl (HANGAR_TECH defaults to ../)
PYTHONPATH=src .venv/bin/python tools/golden/gen_vectors.py     # pycompat and pyyaml reference vectors
go test ./internal/decide/... ./internal/pycompat ./internal/pyyaml
```

The replay fails if the embedded bundles drift from the export on the corpus's first line.

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
