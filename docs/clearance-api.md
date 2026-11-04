# clearance-api: Clearance's read API

Status: **Built and deployed** in Go (R-2b, `clearance api`, `internal/api`): the `clearance-api` Deployment on
hangar-dev runs it since the cutover of 2026-11-03. The Python `api.py` it replaced left the repository in v0.30.0
(the runtime's reads moved to Autopilot's gateway API). This page's first section is the Go API; the sections after it
are the design as built in Python (v0.13.0 to v0.25.0), kept for the record and because every route the Go API kept
has the same path, parameters, answer and status codes.

## The Go clearance-api (R-2b)

`clearance api` is a subcommand of the one `clearance` binary and the chart's `api` Deployment (two replicas). It
reads what the core committed through `pg.OpenReader`: its own read-only DSN, no writer lock, no migration, every
session `default_transaction_read_only`, `statement_timeout` 5 s, a pool of `CLEARANCE_API_POOL` (5) connections.
It writes nothing. After R-3 the Autopilot gateway serves its own read API for the runtime (sessions, runs, agents,
the inbox, trigger history, results), so the Go API serves only Clearance's own reads.

### What you get

- Evidence: list (filters, `seq` cursor), one record, the chain check, counts by rule, tool, agent, app or decision.
  Every record goes through `evidence.Project` (v0-draft rows gain `provider` and `subject`, named in `projected`)
  with `assurance` beside it ([evidence.md](evidence.md)).
- PR receipts and the agent-gate verdicts (`provenance.verify` records) for a repo or a PR.
- The deployment gate: changes, counts, one change (with its live clearance token, C-1), the grant feed (a
  cluster's cleared changes with their tokens), and the gate's baseline policy.
- The clearance token verification keys (`GET /v1/keys`, public): what a verifier checks tokens with offline.
- The decision policy as data (rules in evaluation order with the bundle each came from as `pack`, the tool registry, and `core` plus the loaded bundles as `packs`) and the
  dry-run explainer, which runs the real engine (`decide.(*Engine).Decide` and the new `decide.(*Engine).Trace`, the
  port of `Policy.trace`) on a fresh session of a definition. Records nothing, spends nothing.
- The agent definitions Clearance decides with (`GET /v1/definitions`): the bundled set and the cluster pins the core
  stored in `clearance_definitions`, each with its `source`; the pins that did not load under `rejected`.

### Guardrails

- GET only; a request with a body is 413, another method on a known path 405, an unknown path 404 (JSON errors).
- Every query parameter is checked against the route's list: an unknown or a repeated one is 400 (api.py ignored
  them). `limit` is capped at 200 (not refused); `since`/`until` must look like ISO times.
- Every route but `/healthz`, `/readyz`, `/v1/keys` and `/v1/contract` needs a bearer token (`internal/authn.FromEnv`: TokenReview,
  people's OIDC, the Tower cluster's foreign workloads). Roles exactly as api.py (Who sees what, below).
- Server timeouts: read-header 5 s, read 10 s, write 30 s, idle 120 s, a 25 s deadline on every handler, 64 KiB of
  headers (the explainer's `args` are capped at 16 KiB).
- One access-log line per request: method, path, status, bytes, duration, principal. Never the query (the
  explainer's `args` are in it), a header or a token. A store failure is 503 `read failed`, the cause logged only.

### Routes: every api.py route, and where it went

| api.py operation | Path | Go `clearance api` |
|---|---|---|
| listEvidence | `GET /v1/evidence` | **ported**; adds `outcomes` (below) and `installation` (C-10) |
| getEvidence | `GET /v1/evidence/{seq}` | **ported** |
| verifyEvidence | `GET /v1/evidence/verify` | **ported** (auditors) |
| countEvidence | `GET /v1/evidence/counts` | **ported**; takes every list filter, adds `outcomes` and `installation`; `by=cost` (A-4, below) |
| getPolicy | `GET /v1/policy` | **ported** |
| explainPolicy | `GET /v1/policy/explain` | **ported** (`decide.(*Engine).Trace`) |
| listReceipts | `GET /v1/receipts` | **ported**; adds `installation` (C-10) |
| listProvenance | `GET /v1/provenance` | **ported**; adds `installation` (C-10) |
| listClearances | `GET /v1/clearances` | **ported**; adds `cluster`, and `cluster=<c>&state=cleared` is the grant feed (C-1, below) |
| countClearances | `GET /v1/clearances/counts` | **ported** |
| getClearance | `GET /v1/clearances/{id}` | **ported**; adds `token` (C-1) |
| getClearancePolicy | `GET /v1/clearance-policy` | **ported** |
| getContract | `GET /v1/contract` | **ported**; an OpenAPI 3.1 document since C-10, naming `x-clearance-core` (`CLEARANCE_CORE_URL`) and `x-clearance-gateway` |
| (healthz, readyz) | `GET /healthz`, `/readyz` | **ported**; readyz checks the database |
| (new) listDefinitions | `GET /v1/definitions` | **new**: the definitions Clearance holds, api.py's agent view without the gateway's `hold` |
| (new) listExceptions | `GET /v1/exceptions` | **new** (C-6): the packet's exceptions: every `deploy.exception` (`kind=` out-of-band, drift, untraced-apply, digest-mismatch), `deploy.degraded`, `breakglass.open`, `breakglass.close`, and every `coverage-unavailable` record; `tool`, `kind`, `app`, `since`, `until`, `limit`, `after`; newest first, cursor `seq`, scoped like the evidence list ([gate.md](gate.md#the-packets-exceptions)) |
| (new) getKeys | `GET /v1/keys` | **new** (C-1): the clearance token verification keys, a JWKS, from `clearance_signing_keys`; public |
| (new) getGrantFeed | `GET /v1/grant-feeds/{cluster}` | **new** (C-10): the cluster's **signed** grant feed, for grant-sync (below) |
| (new) listInstallations | `GET /v1/github/installations` | **new** (C-10): the GitHub App's installations as the records name them |
| (new) streamEvents | `GET /v1/stream` | **new** (C-10): server-sent events of new records and gate state changes |

### The grant feed and the token (C-1)

- `GET /v1/clearances/{id}` adds `token` beside the change: the live clearance token (`{nonce, key_id, issued_at,
  expires_at, dsse, jwt}`), or `null` when the change has none (not cleared, revoked by a new head, lapsed, or a
  core without a signing key). Anyone who may read the change gets it.
- `GET /v1/clearances?cluster=<c>&state=cleared` is the **grant feed** the grant-sync agent (G-ARGO-3) reads: the
  cluster's cleared changes whose token is live now, each with `token`, newest first, paged by `updated_at` like
  the list. Any other list carries no tokens. `cluster` alone filters the list.
- **Feed readers** (`CLEARANCE_API_FEED_READERS`, `<principal glob>=<cluster>` pairs; chart `api.feedReaders`) are a
  role of their own: a grant-sync agent on a protected cluster (on Hangar, `hangar-prod/<ns>/<sa>` through the
  foreign-cluster issuer). A feed reader may read only the feed of its own clusters and the changes on them, one at
  a time; any other route or cluster is 403.
- clearance-api never holds the signing key: tokens are signed and refreshed by the core and read here from
  `clearance_tokens`; the keys from `clearance_signing_keys`. The feed is indexed by
  `clearance_tokens_feed (cluster, expires_at) WHERE revoked_at IS NULL` and the token's primary key.
| listAgents, getAgent | `GET /v1/agents`, `/v1/agents/{name}` | **left for the gateway (R-3)**: they carry the trigger hold (control.py) and are the runtime's view; `/v1/definitions` is Clearance's part of them |
| listSessions, getSession | `GET /v1/sessions`, `/v1/sessions/{id}` | **left for the gateway (R-3)**: sessions are runtime state |
| getSessionResult | `GET /v1/sessions/{id}/result` | **left for the gateway (R-3)**: run results |
| getTask | `GET /v1/tasks/{task_id}` | **left for the gateway (R-3)**: the run tree |
| listHumanRequests | `GET /v1/human/requests` | **left for the gateway (R-3)**: the human inbox and its notifier feed |
| listEvents | `GET /v1/events` | **left for the gateway (R-3)**: trigger history |
| listRuntimes | `GET /v1/runtimes` | **left for the gateway (R-3)**: the runtime catalog is Autopilot's |

Nothing was dropped. Of the Backstage plugins' reads (backstage `plugins/clearance`, `plugins/clearance-react`,
`plugins/autopilot` on main), the Go API serves `/v1/evidence`, `/v1/evidence/counts`, `/v1/evidence/verify`,
`/v1/policy`, `/v1/policy/explain`, `/v1/receipts`, `/v1/clearances`, `/v1/clearances/{id}`, `/v1/clearances/counts`;
`/v1/agents`, `/v1/agents/{name}`, `/v1/sessions`, `/v1/sessions/{id}`, `/v1/sessions/{id}/result`, `/v1/events`,
`/v1/human/requests` and `/v1/runtimes` move to the gateway's read API with R-3. The Clearance backend's proxy forwards
only the operations in its vendored contract, so its copy is refreshed with R-3/R-4.

### Cost counts (`by=cost`)

Built (A-4, AP-C2). `GET /v1/evidence/counts?by=cost[&per=task|session|agent|principal]` with any of the list's
filters (`task`, `session`, `agent`, `tool`, `principal`, `decision`, `rule`, `app`, `since`, `until`), scoped like
every read. It sums the `model.call` outcome records that carry `usage` and the `run.finish` records that carry
`cost` ([evidence.md](evidence.md#the-flight-recorder-fields-revision-3-ap-c1-ap-c2)); `outcomes` does not apply and
is refused, and `per` is refused with any other `by`. The answer is the counts shape plus `per` and the summed
`cost`; `total` (model calls) and `cost` are over every matching group, not only the page of items; each item's `count` is its model calls and its `cost` is:

```json
{"by": "cost", "per": "task", "total": 4,
 "cost": {"charged_tokens": 215, "input_tokens": 170, "output_tokens": 35, "cache_creation_input_tokens": 0,
          "cache_read_input_tokens": 100, "model_calls": 4, "runs": 2, "wall_seconds": 90},
 "items": [{"key": "t-0", "count": 3, "cost": {"charged_tokens": 175, "...": "..."}}, "..."]}
```

`charged_tokens` is each call's weighted charge as the Autopilot gateway's model proxy metered it, so a task's sum is
what its run tree spent of its budget; a run that overran its budget (its breaker tripped) shows the whole cost,
more than the budget let it count. Items are ordered by `charged_tokens`, largest first, at most
200 (`MaxLimit`). `tool=model.call` leaves the runs out; `per=session&task=<id>` is one task tree's runs.

### The gates' reads (C-10, Built)

**The signed grant feed**, `GET /v1/grant-feeds/{cluster}` (roles `feed`, for its own clusters, and `auditor`). The C-1
feed above is a list of tokens, each verifiable on its own; nothing in it lets a reader tell a whole feed from one a
path in between trimmed or replayed. This route serves one document the core signed for the cluster:

```json
{"cluster": "hangar-prod", "seq": 41, "key_id": "<kid>", "issued_at": "...", "expires_at": "...",
 "feed": {"payloadType": "application/vnd.clearance.grant-feed.v1+json", "payload": "<base64>", "signatures": [...]},
 "tokens": [{"change_id": "ch-...", "nonce": "...", "key_id": "...", "issued_at": "...", "expires_at": "...",
             "dsse": {...}, "jwt": "..."}]}
```

The format, how the core keeps it fresh, and the reader's algorithm are in
[gate.md, The signed grant feed](gate.md#the-signed-grant-feed-c-10-built). clearance-api holds no key: it serves the
row the core wrote (`clearance_feeds`), the envelope and the tokens it lists side by side, so a reader never pairs a
feed with tokens re-issued after it. 404 until the core has signed a feed for the cluster (its first token there).

**GitHub App installations**, `GET /v1/github/installations` (person roles). What the App code records
(`internal/githubapp`, `internal/provenance`, `internal/gate/deploy.go`) names an installation as principal
`app:<installation id>`: `app.installation` (target the account, result `<action>: <n> repositories`),
`provenance.verify` (target `repo#pr`) and `deploy.request`. Each item: `id`, `principal`, `account` and `action` of
its last `app.installation` record (null when the chain has none), `status` (`active`, `suspended` after `suspend`,
`removed` after `deleted`), `first_seq`/`last_seq` and `first_ts`/`last_ts`, `records` by tool, and `repos` its checks
ran on (from `provenance.verify` targets). It is the deployment's operator view: every person may read it, as
`/v1/clearance-policy`.

**The installation filter**, `installation=<id>`: on `/v1/evidence` and `/v1/evidence/counts` it keeps the records
`app:<id>` wrote; on `/v1/provenance`, the verdicts it recorded; on `/v1/receipts` (receipts are written by the
gateway, never by the App), the receipts of pull requests that installation checked (a `provenance.verify` by
`app:<id>` targets their `repo#pr`). Viewer scoping applies first, as on every read.

**The stream**, `GET /v1/stream` (`text/event-stream`; person roles and `feed`):

- `event: record`, `data:` a record as `getEvidence` serves it; `event: clearance`, `data:` `{seq, tool, ts, change}`
  with the change summary the `deploy.*` record carried (id, app, env, cluster, head, tree, tier, state, objects): the
  state as of that record. Each has `id: <seq>`; a record and its clearance event share the seq and the id is on the
  second, so a reconnect at that id has both.
- Resume with `Last-Event-ID` (or `after=<seq>`); with neither the stream starts at the head. `types=records`,
  `types=clearances` or both (the default). Delivery is at least once: dedupe by seq.
- Scoping is the reads': records as `/v1/evidence` shows them to the viewer, clearance events for changes the
  viewer may read (`changeVisible`, on the change as stored). A **feed reader** gets clearance events of its clusters
  only (a cue to re-read its signed feed sooner than its interval; the feed stays the authority), and
  `types=records` is 403 for it.
- Cost and bounds: one poller per replica reads the chain's head every second while any stream is open (an indexed
  `ORDER BY seq DESC LIMIT 1`) and wakes the streams only when it moves; each stream then reads what is new for its
  viewer in batches of 200 by `seq`. At most 64 streams per replica and 8 per caller (503 with `Retry-After`), a
  10 s write deadline on every event (a reader that stops reading is dropped, never buffered for), a comment every
  15 s, and the server ends a stream after 10 minutes. The access log line is written when the stream ends.
- The Backstage proxy does not forward it (the contract marks it `x-clearance-stream`; the proxy buffers answers);
  Tower moving from polling to the stream is a follow-up.

### Differences from api.py on the ported routes

- **A person's own records** are found from the chain, not the gateway's `clearance_sessions` (which moves to the
  gateway's database): a record in a session is the person's when the first `session.open` record of its task names
  them. Every session spawned under a run shares its task and its principal, so this is the session row's
  principal; on the 612-record hangar-dev chain it gives exactly api.py's answers (Verifying, below).
- **Outcome records** (`outcomes`): the Go core writes two records per allowed call, the decision and then the
  outcome the provider reports (`outcome_of`), which copies the decision's tool, agent, rule and app. Counts default
  to `outcomes=exclude`, one per decision or event, and say so in the answer (`"outcomes": "exclude"`); `include`
  counts both, `only` the outcomes. The list defaults to `include` (every record; `exclude` and `only` filter).
  v0-draft rows have no outcomes, so every count over them is unchanged.
- **Counts take every list filter** (`task`, `session`, `principal`, `rule` too). api.py ignored them, so Tower's
  Evidence page total with a rule filter counted every rule; now it counts what the list shows.
- **Strict queries**: an unknown or repeated parameter is 400; `since`/`until` on evidence must be ISO times; `/v1/clearances` and `/v1/clearances/counts` both refuse an unknown `state` or a non-ISO `since` (api.py counted them as nothing).
  Comparison is still as text against the record's `ts`, as api.py, so a `ts` with no fraction sorts after every
  fraction of its own second (Tower's `toISOString` is second-granular here).
- **Receipts by repo** escape LIKE's `_` and `%` (api.py matched `a_b` as any character).
- **A change whose `requirement.outsideGroups` is JSON null** is scoped as having none (api.py's COALESCE did not
  catch a JSON null, and the query failed for a person).
- **verify** also checks the `seq`, `hash` and `prev_hash` columns against the record (`pg.Reader.Verify`);
  `bad_seq` is the position where the chain broke.
- **503 bodies** say `read failed` without the exception class.
- **notifier**: the role resolves as at api.py, but no Clearance read is a notifier's (the inbox feed is the gateway's).

### Environment (`internal/api` Config)

| Variable | Default | |
|---|---|---|
| `CLEARANCE_API_DSN` | (required) | the read-only role's DSN |
| `CLEARANCE_API_AUDITORS` | none | principal globs: every read, the chain check, `full=1` |
| `CLEARANCE_API_NOTIFIERS` | none | principal globs: the notifier role |
| `CLEARANCE_API_FEED_READERS` | none | `<principal glob>=<cluster>` pairs, comma-separated: the grant feed's readers (C-1) |
| `CLEARANCE_DELEGATES` | none | principal globs that may name a person in the on-behalf-of header (`CLEARANCE_ON_BEHALF_OF_HEADER`; Hangar sets `X-Hangar-On-Behalf-Of`) |
| `CLEARANCE_AGENTS_DIR` | none | the bundled definitions; cluster pins come from `clearance_definitions` |
| `CLEARANCE_API_DEFINITIONS_INTERVAL` | 30 | seconds between re-reads of the stored definitions |
| `CLEARANCE_API_POOL` | 5 | Postgres connections per replica (1 to 50) |
| `CLEARANCE_BUNDLES`, `CLEARANCE_BUNDLE_SOURCES`, `CLEARANCE_BUNDLE_SOURCE_WAIT`, `CLEARANCE_ENV_*` | none | the policy bundles the core runs ([core.md](core.md#policy-bundles)), for `/v1/policy` and the explainer; loaded as the core loads them: a source that does not answer leaves the bundle degraded (named in `/readyz` `degraded`, still 200) until it answers |
| `CLEARANCE_ON_BEHALF_OF_HEADER`, `CLEARANCE_V0_PROVIDER` and the rest of the vocabulary | core.md | the header a delegate names a person in, the provider v0-draft rows are projected with ([core.md](core.md#configuration)) |
| `CLEARANCE_CORE_URL` | none | where Clearance's writes go, named in `/v1/contract` as `core` |
| `CLEARANCE_GATEWAY_URL` | none | where the runtime's writes go, named in `/v1/contract` as `gateway` |
| `BACKSTAGE_URL`, `BACKSTAGE_TOKEN_FILE` | none, `/var/run/clearance/backstage-token` | a person's groups (memberOf) and the apps they own (Components by `spec.owner`, `backstage.Ownership`) |
| `CLEARANCE_LISTEN` | `:$PORT` | listen address; `PORT` defaults to 8080 |

plus the authenticator's (`authn.EnvVars`: `CLEARANCE_AUDIENCE`, `CLEARANCE_OIDC_*`, `CLEARANCE_FOREIGN_*`,
`CLEARANCE_GITHUB_OIDC_*`). The chart sets each (`api.*` values; `tools/charttest` fails when one is missing).

### Indexes

The schema has the primary key on `seq`, `clearance_evidence_receipt`, `clearance_evidence_app` (C-10: the App
installations' records, `((record->>'principal'), seq) WHERE principal LIKE 'app:%'`, behind
`/v1/github/installations` and the installation filter) and the `clearance_changes` indexes and (C-6)
`clearance_evidence_exceptions`, a partial index on `seq` whose predicate `GET /v1/exceptions` repeats word for word
(`TestExceptionsUseTheIndex`); this package adds none
(the core owns the schema). The stream reads the primary key's range above its cursor; the signed feed is one row
of `clearance_feeds` by its primary key. The list is paged by `seq DESC` on the primary key and every filter is
applied on the way; at the lab's size that is well inside the statement timeout. Before the chain is large, the
core's schema should gain (a migration, not done here):

- `clearance_evidence ((record->>'task_id'), seq) WHERE record->>'tool' = 'session.open'`: a person's own tasks
  (the `opened` CTE).
- `clearance_evidence ((record->>'agent'), seq)`, `((record->>'app'), seq)`, `((record->>'tool'), seq)`,
  `((record->>'session'))`, `((record->>'task_id'))`, `((record->>'ts'))`: the hot filters (the "Decided" list
  below named them for api.py too; they were never created).
- `clearance_evidence ((record->>'target')) WHERE record->>'tool' = 'provenance.verify'`: verdicts by PR.
- `clearance_changes ((record->>'updated_at'))`: the changes list's order and cursor (api.py orders by the record's
  `updated_at`, not the indexed column).

### Verifying against api.py

`internal/api` runs every HTTP test on an in-memory read adapter and on Postgres (`CLEARANCE_TEST_DSN`).
`tools/api-golden/golden_py.py` (at v0.29.0 and before; it imported the Python package) loaded a chain dump into a
scratch database (`clr_golden`, with a sessions table as the gateway wrote it), asked Python api.py a list of
requests as an auditor, a person, a delegate and a person with no records, and wrote the answers; `CLEARANCE_API_GOLDEN=<answers.json> go test ./internal/api -run Golden` serves
the same database through the Go API and compares every answer. On the 612-record hangar-dev dump (2026-11-03):
368 answers (evidence pages and filters, counts by every key, single records, verify, receipts and verdicts by repo
and PR, the policy, the gate policy, six dry runs), all identical.

## Why

Clearance today serves agents (MCP at `/mcp`) and two narrow routes (`POST /v1/provenance` for the agent gates,
`/v1/human/*` for the human inbox). Tower needs far more: sessions and runs, budgets, the evidence chain, receipts,
agent definitions, the inbox as a feed. Serving those reads from the gateway is wrong for two reasons:

1. **The gateway is single-writer.** Every gateway operation holds one lock (`SerializedGateway.lock`), and only
   one process may hold Postgres's writer lock (`pg.LOCK_KEY`). Reads from a busy Tower page would queue behind
   agents' tool calls, and the gateway cannot scale out.
2. **The people API has no feed.** Tower's notification poller asks once per catalog user per minute because there
   is no "what's new for anyone I can notify" call.

## Shape

- **Same package, separate process.** `clearance api` (a new entry point; on Hangar, `autopilot-gateway api`)
  serves HTTP only: no MCP, no tool handlers, no run backend, no model proxy.
- **Its own Deployment**, `clearance-api`, two or more replicas, behind its own Service and route
  (`clearance-api.<domain>`).
- **Read-only Postgres.** A CloudNativePG managed role `clearance_reader` with `SELECT` on the `clearance_*`
  tables and nothing else, via its own Secret. The API never takes the writer lock, never migrates, never
  writes. A gateway down (or restarting) does not take the API down.
- **Committed state only.** It reads what the gateway has committed (each gateway operation commits its evidence
  and sessions together), so it can lag the gateway by one in-flight operation, never show a half-written one.
- **Writes stay on the gateway.** Answering a human request (`POST /v1/human/requests/{id}/answer`) and any future
  operator write (close a session, trip or reset a breaker) go to the single writer, so the evidence chain has one
  author. The API documents the gateway URL for them.
- **Agent definitions** come from the same definitions directory the gateway loads (`CLEARANCE_AGENTS_DIR`, the
  same image), not from the database.

## Endpoints (v1, GET only)

All list endpoints are cursor-paginated (`limit`, max 200; `after`), newest first unless noted.

| Endpoint | Returns |
|---|---|
| `GET /v1/agents`, `/v1/agents/{name}` | definitions: `description` (one line, what it is for), `runsIn` (`cluster`: a runtime image runs it as an AgentRun; `client`: no image, a person's MCP client is the loop and Clearance enforces the envelope), kind, identity, owner, tier ceiling, tools, repos/apps scope, limits, triggers (never instructions' full text by default; `?full=1` for auditors) |
| `GET /v1/sessions` | sessions: `agent`, `principal`, `task`, `state` (`live`, `recent`, `closed`, `expired`), `since` filters; each with limits, budget used, breaker, run, parent, expiry |
| `GET /v1/sessions/{id}` | one session, with its children; `input` (v0.25.0: what an in-cluster run was asked, `{prompt, started_by}`) and `outcome` once it ended: `{status, finished_at, turns, tool_calls, not_ok, reason, result, via}`, where status is the runtime's `done`, `budget`, `expired` or `error`, or `no-result` (the run ended without handing one back; `run_phase` says how) or `expired` (the deadline came first), and `result` is the kept answer's `{bytes, sha256, truncated, expires_at}` |
| `GET /v1/sessions/{id}/result` (v0.25.0) | a finished in-cluster run's answer, kept **30 days**: `{status, final_text (at most 16 KiB, `truncated` if cut), turns, tool_calls: [{tool, ok, rule}], reason, written_at, expires_at}`; 404 before the run finishes, when it kept none, or after it expired. Scoped like the session |
| `GET /v1/tasks/{task_id}` | the run tree: every session in the task, parent links, totals |
| `GET /v1/evidence` | records filtered by `task`, `session`, `agent`, `tool`, `principal`, `decision`, `rule`, `app`, `since`, `until`; cursor is `seq` |
| `GET /v1/evidence/{seq}` | one record, with its hash and assurance state; every served record is in the clearance.evidence/v1 shape, a v0-draft row with the `provider` and `subject` the api derived named in `projected` ([evidence.md](evidence.md)) |
| `GET /v1/evidence/verify` | the chain checked from genesis (or `from`/`to`): `ok`, `count`, `head`, first bad `seq` |
| `GET /v1/evidence/counts` | records you may see counted by `by` (rule, tool, agent, app, decision), same filters as the list: the 7-day hits on the Policy page. `by=cost` sums what runs cost instead, `per` task tree (default), session, agent or principal ([cost counts](#cost-counts-bycost)) |
| `GET /v1/policy` | the policy in force: deny rules in evaluation order (id, name, CEL, message, hint, and the bundle it came from as `pack`), the tool registry with tiers, `core` plus the loaded bundles as `packs` |
| `GET /v1/policy/explain` | "would this be allowed?": `agent`, `tool`, `args` (JSON); the real policy on a fresh session of that definition, the decision and every rule's verdict in order (the path). Records nothing, spends nothing |
| `GET /v1/receipts` | PR receipts (`repo`, `pr`): what Clearance's agents opened, the commit, the paths |
| `GET /v1/provenance` | the agent-gate verdicts recorded for a PR (`provenance.verify` records) |
| `GET /v1/human/requests` | the inbox: for a person, what they may answer (as today); for a `notifier`, every pending request with who may answer it (owner and group), `since` for "new since" |
| `GET /v1/events` | the trigger bridge's history (v0.15.0): every event it received, newest first, with what it did per agent (`launched`, `deduped`, `braked`, `refused`, `launch-failed`, with the session and run); filters `app`, `agent`, `source`, `key` (routing key), `subject` (the event's subject id, e.g. a PipelineRun name), `since`, `until`; cursor is `received_at`. Kept 30 days. The trigger dry run, an agent's trigger statistics and Tower's run marks read it |
| `GET /v1/contract` | the API contract (below) |
| `GET /healthz` | liveness; `GET /readyz` checks the database |

Later (phase 3): `GET /v1/stream`, server-sent events of new evidence records and inbox changes (the same shape as
glidepath-api's `/v1/events`), so Tower stops polling. (`/v1/events` is the trigger bridge's history, above.)

Never returned: tool arguments (only their digest is stored), artifact contents, tokens, model prompts.

## Person controls: the write path (v0.17.0)

Decided 2026-10-31: people write through the **delegate model**, the same one the human inbox uses. A person
calls the gateway with their own sign-in, or Tower's backend calls as itself and names them in
`X-Hangar-On-Behalf-Of`. Clearance decides who may act: the agent's owner group (the definition's `owner`, resolved
by the catalog directory), a platform admin (`CLEARANCE_ADMINS`, principal globs), and for a session, the person whose
session it is. Every control is an evidence record naming the person and the delegate. These are gateway routes
(`clearance.hangar-dev.local`), not clearance-api's: the read API never writes.

| Route | Does | Record |
|---|---|---|
| `POST /v1/sessions/{id}/freeze` `{reason}` | trips the session's breaker (and its children's): every further call is refused, the run stays for a person to read | `session.freeze` |
| `POST /v1/sessions/{id}/end` `{reason}` | closes the session and its children; the budget is settled; the run's pod ends with its AgentRun's TTL | `session.end` |
| `POST /v1/agents/{name}/hold` `{reason, hours}` | holds the agent's triggers: `open_triggered` refuses with **R024** until `until` (24 h by default, 336 at most; renewing replaces the hold) | `trigger.hold` |
| `POST /v1/agents/{name}/runs` `{input?}` (v0.23.0) | starts an in-cluster run of a **task** agent with a runtime image, as the person: a session opened in their name, then the AgentRun with `input` (at most 2000 characters) as its task. The agent's owner group or a platform admin; **R001** for an agent that runs in the client or is not a task agent, **R024** while held. 201 `{agent, session, task_id, run, by, via}` | `session.open`, `run.launch` |
| `DELETE /v1/agents/{name}/hold` | lifts a hold early | `trigger.release` |

A hold is an emergency brake, not a policy: anything meant to last ("turn this agent off", "weekdays only") is a
definition PR. `GET /v1/agents` and `/v1/agents/{name}` carry the active hold as `hold` (`by`, `via`, `reason`,
`since`, `until`), or `null`. Refusals carry a `rule` (`CT-FORBIDDEN` 403, `CT-UNKNOWN` 404, `CT-CLOSED` /
`CT-TRIPPED` 409, `CT-REASON` / `CT-HOURS` 400, `CT-NOHOLD` 404, `CT-OFF` 404 when the deployment keeps no holds).

Not yet: replay a past event, launch a run by hand, open the definition PRs (A3).

## Definitions from the cluster (v0.18.0)

Autopilot M4: an agent definition no longer has to ship in the gateway's image. An **`Agent` XR** (airframe
`xrds/agent.yaml`, in the app's `tenants/<app>/xr-requests/`) pins one commit of a definition file in the app's own
repository (`agents/<name>.yaml`). The gateway's loader (autopilot `agent_xrs.py`) lists the XRs, fetches each pinned
file through the agents' GitHub App (the broker allows an onboarded app's own repositories only), and hands the
documents to `definitions.py`, which decides whether a pin becomes a definition:

- the file passes the schema, its `name` is the XR's name, its `owner` is the XR's `spec.owner`, and a workload identity
  is `autopilot-runs/<name>`;
- the name is not a bundled platform definition's (the image's `agents/` keep their names; a pin can never replace one);
- one name, one pin (two XRs naming the same agent load neither).

The live set is `definitions.Definitions`, the Mapping the gateway and this API hold: bundled first, cluster second.
Every change is evidence, once per change and never per poll: `definition.load` (a new or re-pinned definition, result
`loaded <repo>@<commit> <path>` or `re-pinned …`), `definition.unload` (a pin removed), `definition.reject` (decision
`deny`, rule `DF-PIN`, the reason as result). The principal is `pin:<namespace>/<name>`. The gateway persists the set
(`clearance_definitions`) and this API refreshes from it, so it never fetches anything.

A running session resolves its definition by name on every call, so a re-pin to a **tighter** definition applies to
runs in flight (lowering authority is immediate); raising it is the reviewed pin.

`GET /v1/agents` carries, per agent, `source`: `{kind: bundled}` or `{kind: cluster, repo, path, commit, namespace, xr,
loaded_at, pin}`; and a top-level `rejected`: the pins Clearance could not load, each with `name`, `source` and
`reason`, so the team sees why. `GET /v1/agents/{name}` carries `source` too. Whether a pin loaded is **this** record,
never the XR's status: Clearance writes no XR status (its one Kubernetes write stays AgentRun).

## The deployment gate (v0.19.0)

The second boundary ([gate.md](gate.md)). Writes are gateway routes: `POST /v1/clearances` registers or re-evaluates a
change (a **verifier's** token, like `/v1/provenance`: the `clearance-gate-` check), `POST /v1/clearances/{id}/clear`
and `POST /v1/clearances/{id}/deny` `{reason}` are people's, through the delegate model. Refusals carry `DG-*` rules
(`DG-PROPOSER` 403, `DG-TWICE` 409, `DG-FILLED` 409, `DG-FORBIDDEN` 403, `DG-STATE` 409, `DG-REASON` 400,
`DG-UNKNOWN` 404, `DG-OFF` 404; `DG-POLICY` and `DG-PROVENANCE` deny the change by policy).

Reads here: `GET /v1/clearances` (filters `app`, `env`, `state` holding|cleared|denied|expired|superseded, `repo`, `pr`,
`tier`, `since`; cursor `updated_at`), `GET /v1/clearances/counts?by=state|tier|app|env|cleared_by`,
`GET /v1/clearances/{id}` (objects, paths, every reason, requirement, approvals, checks), `GET /v1/clearance-policy`
(the baseline a repo's `clearance.yaml` may only tighten). A person sees changes on apps they own and changes whose
owner group or outside group is one of theirs: the people who may clear them. Every step is evidence in the
`deployment` boundary (`deploy.request`, `deploy.clear`, `deploy.deny`, `deploy.expire`, and `deploy.answer` when
the GitHub App's answer reached a waiting GitHub Actions deployment), listed by the evidence routes like any other
record. Since v0.23.0 a GitHub Actions workflow may register too, with its own OIDC ID token (principal `github:<sub>`,
listed in the verifiers), for its own repository only: any other repo is refused with `DG-REPO` (403); `clearance
register` builds the body ([provenance-app.md](provenance-app.md) phase 2b). Since v0.22.0 a change carries `deployments`, the GitHub Actions deployments waiting on it (run, environment,
answer, delivered; [provenance-app.md](provenance-app.md) phase 2a), and may have `pr: 0`, a pushed commit with no PR.

## Reviewing a definition, and its release (v0.20.0)

`review.py`, for the agent release flow (decided 2026-10-31): a definition is reviewed YAML in a repo, a pin makes
one commit live, and a CI check asks Clearance two questions on the gateway's `POST /v1/definitions/review`
`{doc, old?, name?, owner?, path?}` (a verifier's token, a person's, or a delegate naming one; stateless, nothing
recorded):

- **validate**: would Clearance load it, and could its agent use what it lists? `DF-SCHEMA`, `DF-NAME` (file and pin
  name), `DF-OWNER`, `DF-IDENTITY` (`autopilot-runs/<name>`), `DF-TOOL` (unregistered), `DF-TRIPWIRE`, `DF-CEILING`
  (a tool above the ceiling: R007 would deny every call), `DF-REPOS` (a repo tool with no allowlist: R014), `DF-MODEL`
  (not a route of this deployment), `DF-IMAGE` (not pinned by digest, or outside the deployment's `runtime_images`
  globs).
- **classify** `old` to `doc`: tier **0** no change in authority (instructions, framework label); **1** narrows only
  (fewer tools, lower ceiling, smaller limits, fewer repos, apps, models or triggers, smaller network or compute, the
  agent removed); **2** spends more or runs more (larger limits, a new trigger or higher cap, a new model or runtime
  image, larger compute, a new read tool); **3** touches more (a higher ceiling, a new writing tool, a new repo, app
  or API, wider network, fewer denied paths, sidecars, a different identity or owner, a new agent with a writing
  tool). Each reason names the field and the change.

Answer: `{ok, problems: [{rule, path, message, hint}], tier, changes: [{field, change, tier}]}` (no tier when not ok).

**The runtime catalog** (`runtimes.py`): the deployment hands Clearance the agent images it offers, each `{name, image (by
digest), kind runtime|base, framework, summary, status available|planned}`. An available `runtime` image is allowed
for `runtime.image` (beside the deployment's extra globs, for images built for an agent's own repo); a `base` image is a
FROM image for code agents, never run as is. clearance-api lists it at `GET /v1/runtimes` for the New agent picker,
with `custom_images` (v0.25.0): the globs an image built for an agent's own repo must match (empty = catalog runtimes only).

The release is a deployment-gate change: `POST /v1/clearances` with `definition: {name, path, old, new}` (the pin PR's
check). Its tier comes from `classify`; a new document with problems is denied (`DG-DEFINITION`); tiers 0 and 1 clear
by policy, 2 and 3 wait for the owner group (and an outside group), on the same Clearances page and records.

## Who sees what

Callers authenticate exactly as at the gateway: service-account tokens (TokenReview), people's OIDC ID tokens, and
foreign workloads by public issuer (Tower). Roles are principal globs in config:

| Role | Config | May |
|---|---|---|
| person | any authenticated `user:*` | their own sessions and evidence; sessions and evidence of agents whose `owner` group they are in (the deployment's Directory, as the inbox uses); evidence records that target an app they own (below); the inbox as today |
| `delegate` | `CLEARANCE_DELEGATES` (Tower) | everything a person may, for the person named in `X-Hangar-On-Behalf-Of` |
| `notifier` | `CLEARANCE_API_NOTIFIERS` (Tower) | the inbox feed across everyone (for notifications), nothing else |
| `auditor` | `CLEARANCE_API_AUDITORS` | every read, including definitions' full instructions and the chain check |
| `feed` | `CLEARANCE_API_FEED_READERS` (a grant-sync agent) | its clusters' grant feed and the changes on them, with their tokens; nothing else (C-1) |

A record's visibility is decided by its session's owner and agent, so a person never sees another team's agents'
sessions through a filter.

**App owners see what agents did to their app** (decided 2026-10-30). A person who owns an app in the catalog (the
Component's `spec.owner`, directly or through a group) sees every evidence record whose target is that app: its
repos (`<app>`, `gitops-<app>`), its Argo CD Applications, its Glidepath app. Records only, not the rest of the
session that made them, so another team's agent's work elsewhere stays theirs. The gateway records `app` on every
record whose call names an application (the pack's `app_of`: on Hangar `glidepath.*`, `airframe.*` and
`xr.request` by their `app` argument, `repo.*` by the repo, `<app>` or `gitops-<app>`; `argo.*` names an Argo CD
Application, not an app, so none yet). Records are hashed into the chain, so older ones cannot be backfilled: app
visibility starts with the release that records `app` (v0.13.0); the owner and team rules cover the rest. Tower's per-app tabs use it for an
"Agent activity" view (`GET /v1/evidence?app=<app>`). Reads are not themselves recorded as evidence (they change nothing); they are logged
and counted.

## The contract

`contract/clearance-api.json` is an **OpenAPI 3.1** document since C-10 (info.version 1.1.0), generated from the Go
route table and answer types (`go generate ./internal/api`, `tools/contract -api`; `TestTheCommittedContractIsCurrent`
fails when it drifts, and checks that every route is in it with its roles and query parameters and that every
`$ref` resolves). The route table stays the source. Each operation carries `x-clearance-roles` (the roles that may
call it; a portal's backend forwards by method, path and these), its path and query parameters, the statuses it
answers with their schemas (`components.schemas`, reflected from the Go types), and `security: []` when no token is
asked. `/v1/stream` answers `text/event-stream` and is marked `x-clearance-stream: true`. `GET /v1/contract` serves
the same document with `x-clearance-core` and `x-clearance-gateway` when the deployment names them. The pre-C-10
shape (`api`, `version`, `notes`, `operations`, `responses`, `schemas`; v0.27.0 to v0.30.x) is gone: a reader of it
moves to `paths` (the Backstage backend reads both). `/v1` changes are additive only; a breaking change is `/v2`.

## Hangar deployment (apron `55-autopilot/clearance`)

- `api.yaml`: the `clearance-api` Deployment (same image, `api` command, read-only root fs, no projected tokens
  except the catalog one for the Directory), Service, PodDisruptionBudget.
- `postgres.yaml`: the `clearance_reader` managed role and its Secret.
- NetworkPolicy: ingress to `clearance-api` from the Gateway namespace; egress to Postgres and the catalog.
- HTTPRoute `clearance-api.<domain>`. `clearance.<domain>/v1/human/` stays on the gateway for the answer POST.

## Phases

1. **Read API v1:** agents, sessions, tasks, evidence (with verify), the inbox feed, the contract; deployed;
   Tower's Agent requests poller switches to the feed (one call per minute, not one per user).
2. **Tower's Clearance plugin:** sessions and run trees, an evidence explorer, agent definitions, gate verdicts on
   a PR, on the API.
3. **Event history** (v0.15.0, done): `/v1/events`, what the trigger bridge received and did, kept 30 days; Gateway.record_event writes it from the bridge (autopilot event_bridge.py). Not evidence: not in the chain.
4. **Stream:** `/v1/stream` (SSE); Tower subscribes instead of polling.

## Decided (2026-10-30)

- **App-scoped visibility:** yes, at the record level: an app owner sees records that target their app, not
  whole sessions of agents scoped to it (Who sees what, above).
- **Read replica:** not in v1. The API reads the primary through its own DSN (`CLEARANCE_API_DSN`, the
  `clearance_reader` role) with guardrails: `statement_timeout` 5 s, a pool of 5 connections per replica, page size
  at most 200, and indexes for the hot filters (`session`, `task_id`, `tool`, `ts`, `app`). Moving to a
  replica is configuration: CloudNativePG publishes `<cluster>-ro`; add one instance and point the DSN at it.
  Trigger: API p95 over 300 ms, or the gateway's write latency rising while Tower is busy (both on Prometheus).
