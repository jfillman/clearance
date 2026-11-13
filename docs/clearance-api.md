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
| listEvidence | `GET /v1/evidence` | **ported**; adds `outcomes` (below), `installation` (C-10) and `coverage` (one state or a comma-separated list: `authorized-and-verified`, `observed-not-attributed`, `out-of-band-detected`, `coverage-unavailable`, `break-glass`, `attempted-refused`; unknown is 400) |
| getEvidence | `GET /v1/evidence/{seq}` | **ported** |
| verifyEvidence | `GET /v1/evidence/verify` | **ported** (auditors) |
| countEvidence | `GET /v1/evidence/counts` | **ported**; takes every list filter, adds `outcomes`, `installation` and `coverage`; `by=coverage` totals per state; `by=cost` (A-4, below) |
| getPolicy | `GET /v1/policy` | **ported** |
| explainPolicy | `GET /v1/policy/explain` | **ported** (`decide.(*Engine).Trace`) |
| listReceipts | `GET /v1/receipts` | **ported**; adds `installation` (C-10) |
| listProvenance | `GET /v1/provenance` | **ported**; adds `installation` (C-10) |
| listClearances | `GET /v1/clearances` | **ported**; adds `cluster`, and `cluster=<c>&state=cleared` is the grant feed (C-1, below); adds `awaiting=me` ([below](#reads-for-the-person-cli)) |
| countClearances | `GET /v1/clearances/counts` | **ported** |
| getClearance | `GET /v1/clearances/{id}` | **ported**; adds `token` (C-1) and `attestation` (C-2: the digest, backend and Rekor index of the signed change attestation, or `null`) |
| (new) getClearanceAttestation | `GET /v1/clearances/{id}/attestation` | **new** (C-2): the change's attestation as a Sigstore bundle, for `clearance attest verify`; 404 until a deploy reports an applied outcome ([core.md](core.md#change-attestations)) |
| (new) whoami | `GET /v1/whoami` | **new**: who the token is and what the api resolves it to ([below](#reads-for-the-person-cli)) |
| (new) verifyClearanceAttestation | `GET /v1/clearances/{id}/attestation/verify` | **new**: the stored bundle verified server-side ([below](#change-history-and-attestations)) |
| (new) listChangeRecords | `GET /v1/clearances/{id}/records` | **new**: one change's `deploy.*` records in chain order ([below](#change-history-and-attestations)) |
| (new) listAttestations | `GET /v1/attestations` | **new**: the signed attestations, newest first ([below](#change-history-and-attestations)) |
| (new) getAttestationConfig | `GET /v1/attestation-config` | **new**: Rekor's public URL, the keyless identity and issuer, the static key ids, the offline verify command |
| getClearancePolicy | `GET /v1/clearance-policy` | **ported** |
| getContract | `GET /v1/contract` | **ported**; an OpenAPI 3.1 document since C-10, naming `x-clearance-core` (`CLEARANCE_CORE_URL`) and `x-clearance-gateway` |
| (healthz, readyz) | `GET /healthz`, `/readyz` | **ported**; readyz checks the database |
| (new) listDefinitions | `GET /v1/definitions` | **new**: the definitions Clearance holds, api.py's agent view without the gateway's `hold` |
| (new) listExceptions | `GET /v1/exceptions` | **new** (C-6): the packet's exceptions: every `deploy.exception` (`kind=` out-of-band, drift, untraced-apply, digest-mismatch, attempted-refused, monitoring-protection), `deploy.degraded`, `breakglass.open`, `breakglass.close`, and every `coverage-unavailable` record; `tool`, `kind`, `app`, `since`, `until`, `limit`, `after`; newest first, cursor `seq`; (every signed-in person, a delegate for one, an auditor and an observation reader see every exception, O-5; redacted below) ([gate.md](gate.md#the-packets-exceptions)) |
| (new) listObservations | `GET /v1/observations` | **new** (O-1), any signed-in person, a delegate for one, or an auditor (O-5): a scope's `observation` records (`kind=assessment`, `resolution` (every edit of one is a record of its own: the history) or `observation.verification` for those); `scope` required, `source`, `since`, `until`, `limit`, `after`; newest first, cursor `seq` |
| (new) listObservationHealth | `GET /v1/observations/health` | **new** (O-1), any signed-in person, a delegate for one, or an auditor (O-5): a scope's `observation.health` and `observation.audit-gap` records, same parameters |
| (new) getCoverage | `GET /v1/coverage` | **new** (O-1), any signed-in person, a delegate for one, or an auditor (O-5): the three-part coverage statement of a scope and window ([below](#observations-and-the-coverage-statement-o-1)) |
| (new) listTargets | `GET /v1/targets` | **new** (the Map), any signed-in person, a delegate for one, or an auditor: the declared target registry, the union of every source's published set ([below](#the-coverage-map-and-the-target-registry)) |
| (new) getMap | `GET /v1/map` | **new** (the Map), same readers: the coverage map in one read, the registry joined with the records ([below](#the-coverage-map-and-the-target-registry)) |
| (new) getKeys | `GET /v1/keys` | **new** (C-1): the clearance token verification keys, a JWKS, from `clearance_signing_keys`; public |
| (new) getGrantFeed | `GET /v1/grant-feeds/{cluster}` | **new** (C-10): the cluster's **signed** grant feed, for grant-sync (below) |
| (new) listInstallations | `GET /v1/github/installations` | **new** (C-10): the GitHub App's installations as the records name them |
| (new) streamEvents | `GET /v1/stream` | **new** (C-10): server-sent events of new records and gate state changes |

### Observations and the coverage statement (O-1)

Built. Three reads over the observation kinds ([evidence.md](evidence.md#observations-clearanceevidencev11-o-1)).
Since O-5 (owner decision 2026-11-12) **any signed-in person** may read them (an OIDC user on
`CLEARANCE_OIDC_ALLOWED_USERS`, or a delegate such as Tower's Backstage proxy acting for one), and an auditor still may.
An observation is about an account or a cluster, not an agent or an app, so a person reads the whole scope rather than
the per-person evidence scope. A person is refused (403) only when the caller is not a person or a delegate acting for
one; no token, or a user the allowlist refuses, is 401. Resolving an observation stays admin-only: `POST
/v1/observations/{seq}/resolution` is on the core and is unchanged.

| Route | Before O-5 | After O-5 |
| --- | --- | --- |
| `GET /v1/coverage` | auditor | person, delegate, auditor, observer (machine reader) |
| `GET /v1/observations` | auditor | person, delegate, auditor, observer |
| `GET /v1/observations/health` | auditor | person, delegate, auditor, observer |
| `GET /v1/exceptions` | person, delegate, auditor (a person: only their own runs, agents and apps) | person, delegate, auditor, observer: every exception |
| `POST /v1/observations/{seq}/resolution` (core) | admin, or a delegate naming an admin | unchanged |
| `POST /v1/observations/resolutions` (core, bulk, up to 200; [gate.md](gate.md#bulk-resolution)) | n/a | admin, or a delegate naming an admin |

**What a person reads.** The coverage statement carries no record bodies. The observation lists return the records, and
a person gets each record's `state_change` with the value of every secret-bearing key (`password`, `secret*`, `token`,
`credentials`, `userdata`, `environment`, a `{name, value}` pair whose name is one, and so on) replaced by `[redacted]`,
naming the redacted fields in `redacted` (`["state_change"]`, and `["exception"]` on a `deploy.exception`, whose `objects` can be live objects); an auditor reads the record as stored (the stored hash covers the unredacted
record). The providers also keep secrets out at the source (observe-k8s records a Secret at Metadata with no
`state_change`, the core refuses a Secret observation that carries one, observe-aws strips request keys that carry
credentials), so the redaction is a second line, not the only one. It is by key name: a secret held under an innocuous
key in a non-Secret object is not recognised.

**No scope:** `GET /v1/coverage` (no `scope`) answers `{from, to, scopes: [statement, ...], truncated}`: the statement below for every scope with an observation, audit gap or health record, sorted by scope (each statement names its `scope`; at most 100 scopes, then `truncated`). The scope list is read as distinct names, not as records (`Store.Scopes`: observations and audit gaps in the window, or a health record before its end; at most 1000 names, then `truncated`), and a statement reads health bounded: the records in the window plus, per source, the records before it from the last one the collector wrote as healthy (`Store.HealthBefore`, the most that can still decide a state the window starts in, for instance a flip the core held), not the scope's whole health history; the statement is identical to one built from all of it. With a `scope` the answer is the single statement, unchanged.

**Names only:** `GET /v1/coverage?names=only` (no `scope`; `names` with a `scope`, or any value but `only`, is 400) answers `{from, to, scopes: [{scope: "<name>"}, ...], truncated, names_only: true}` straight from the one `Store.Scopes` read: no statement is built (no evidence or health read per scope), so it stays cheap however many scopes there are. It lists up to 1000 names (then `truncated`), not the 100 a full answer's statements are capped at. Use it to populate a scope picker. A Clearance older than this change answers `names=only` with 400 (an unknown parameter), the signal to fall back to the full scope-less call.

`GET /v1/coverage?scope=&from=&to=` (RFC 3339; `to` defaults to now and is never in the future, `from` to 24 hours
before it; at most 92 days) answers:

- `cleared_and_verified`: the observations whose latest assessment is `authorized-and-verified` (an operation on
  monitoring never is), with `count`, `by_coverage` and the first 200 `items`;
- `seen_not_cleared`: every other observation, by coverage (`out-of-band-detected`, `observed-not-attributed`,
  `break-glass`, `attempted-refused`, or `unassessed` when no assessment has arrived), each item with its latest
  resolution and cause;
- `could_not_see`: the `segments` of the window a feed was blind or degraded (`reason`: `reported`, `stale` or
  `never-seen`), the `audit_gaps`, and the seconds;
- `source_integrity`: how many of the window's observations had their source verified (`observations`, `verified`,
  `verified_by_record` (the observation's own integrity), `verified_later` (an `observation.verification` about it, O-5)
  and `unverified`); each item says `source_verified` and `verified_by` (`self` or `later`), and carries its newest
  resolution's `resolution_seq`, `resolved_by` (the person, or the provider) and `resolved_at`;
- `health`: per source, the worst `state` in the window, the state `now`, the last health record, whether it is `stale`
  and the checks that failed;
- `state` (`healthy`, `degraded` or `blind`: the worst of any source; `blind` when no feed has a health record at all),
  `clean` and `text` (the statement in words, what the packet prints).

A health record holds for twice its `interval_seconds` (default 900); after that the feed is blind until the next one.
`clean` is true only when `state` is `healthy` and nothing was seen uncleared and no read was truncated (10000 records
of a kind): **a clean exceptions list is never printed for a window without a healthy health record**, and a feed that
stops produces a blind window. A window that starts before the feed's first health record is blind (`never-seen`) for the
stretch before it. `TestCoverageIsBlindForAScopeWhoseHealthRecordIsStale` runs this on memory and on Postgres.

A person sets a resolution on the **core**, not here (clearance-api writes nothing):
`POST /v1/observations/{seq}/resolution` ([gate.md](gate.md#a-persons-resolution-of-an-observation-o-5)); the coverage
statement reads the newest resolution record about an observation. The same route resolves a gate `deploy.exception`
(out-of-band, drift, untraced-apply, digest-mismatch), scoped to its destination; `GET /v1/observations?kind=resolution`
lists those too, under the exception's cluster or workspace scope.

Indexes (the core's schema): `clearance_evidence_observed` on `((record->>'scope'), seq)` for the five kinds (and `clearance_evidence_verification` for `observation.verification`), and
`clearance_evidence_event` on provider, kind and `source.event_id` behind the core's de-duplication; `clearance_evidence_written` on `written_at` (the Map's lower bound: a record's `ts` is never before the time it was written).

### The coverage Map and the target registry

The Map answers "what should be protected, who guards and watches it, and does the evidence agree": the **declared**
registry joined with the **observed** records, so Tower makes one call however many gates and targets there are.

**The registry** is declared, never inferred from records. Each source that publishes (a cluster's gitops render, an
account's bootstrap) sends the whole set of targets it declares with `PUT /v1/targets/{source}` on the core
([core.md](core.md#publishing-declared-targets), [provider-protocol.md](provider-protocol.md#publishing-declared-targets));
the core validates it strictly, stores it per source (`clearance_targets`) and records a changed set once as
`targets.load` with the set's digest. `GET /v1/targets` serves the union (`source`, `group`, `kind`, `env`, `app`
filter; a target id two sources declare is a `conflicts` entry and the first source's by name is kept):

```json
{"items": [{"source": "hangar-prod", "id": "gate-api-prod", "name": "gate-api", "kind": "k8s-namespace",
            "group": "hangar-prod", "env": "prod", "app": "gate-api", "owner": "group:default/team-gate",
            "registry": "flight", "scope": "hangar-prod",
            "gates": [{"type": "glidepath", "instance": "gate-api-cicd", "mode": "enforce"},
                      {"type": "g-argo", "instance": "argo-gate", "mode": "flag"}],
            "observers": [{"provider": "observe-k8s", "source": "observe-k8s"}]}],
 "sources": [{"source": "hangar-prod", "digest": "9f2c...", "targets": 25, "updated_at": "2026-11-13T09:00:00Z"}],
 "conflicts": [], "invalid": []}
```

A gate's `instance` is the name its records carry: the registered provider's name (`provider.name`), or, for a gate that
registers changes (the clearance-gate check, Glidepath), the verifier principal that registered them. A target's `scope`
is the coverage scope its observations arrive under (what `GET /v1/coverage?scope=` and `GET /v1/observations/health?scope=`
take), and its `app` and `env` attribute the deployment gate's records to it.

**`GET /v1/map?from&to`** (RFC 3339, default the last 24 hours, at most 92 days; `group=<g>` narrows to one cluster or
account, `expand=<g>[,<g>]` adds an edge to each target of those groups, `target=<id>` is the one-target detail):

```json
{"from": "2026-11-12T12:00:00Z", "to": "2026-11-13T12:00:00Z",
 "registry": {"sources": [...], "conflicts": [], "targets": 25},
 "nodes": {
  "gate_types": [{"id": "gate:g-argo", "type": "g-argo", "instances": 8, "targets": 20,
                  "mix": {"enforce": 5, "flag": 3, "silent": 0}, "status": "attention",
                  "decisions": 412, "refused": 9, "exceptions": 2, "holding": 3,
                  "coverage": {"authorized-and-verified": 380, "out-of-band-detected": 2, "...": 0},
                  "lanes": {"requested": 120, "tiered": 120, "decided": 118, "applied": 110, "applied_matched": 109,
                            "observed": 530, "verified": 498}}],
  "groups": [{"id": "group:hangar-prod", "group": "hangar-prod", "targets": 12, "kinds": {"k8s-namespace": 12},
              "status": "down", "mix": {"enforce": 20, "flag": 3, "silent": 0}, "no_gate": 0, "holding": 3,
              "coverage": {"authorized-and-verified": 380, "observed-not-attributed": 4, "unassessed": 0, "...": 0},
              "verified_pct": 97.1, "observers": {"healthy": 12}}],
  "targets": [{"id": "gate-api-prod", "source": "hangar-prod", "name": "gate-api", "...": "the declared fields",
               "status": "attention", "coverage": {"...": 0}, "verified_pct": 97.1,
               "lanes": {"...": 0}, "holding": 1,
               "gates": [{"type": "g-argo", "instance": "argo-gate", "mode": "flag", "attributed": true, "silent": false,
                          "decisions": 31, "refused": 2, "exceptions": 1, "holding": 0, "coverage": {"...": 0}, "lanes": {"...": 0}}],
               "observers": [{"provider": "observe-k8s", "source": "observe-k8s", "state": "healthy",
                              "last_ts": "2026-11-13T11:59:30Z", "stale": false, "failed_checks": []}]}],
  "observers": [{"id": "observer:observe-k8s/observe-k8s", "provider": "observe-k8s", "source": "observe-k8s",
                 "targets": 12, "states": {"healthy": 12}, "status": "ok"}]},
 "edges": [{"from": "gate:g-argo", "to": "group:hangar-prod", "kind": "guards", "targets": 12, "volume": 412,
            "refused": 9, "holding": 3, "status": "attention"},
           {"from": "observer:observe-k8s/observe-k8s", "to": "group:hangar-prod", "kind": "watches", "targets": 12,
            "volume": 0, "refused": 0, "holding": 0, "status": "ok"}],
 "attention": [{"kind": "blind-observer", "severity": "down", "title": "...", "detail": "...", "count": 1,
                "targets": ["acct-prod"]}],
 "partial": [{"field": "lanes.observed,lanes.verified", "reason": "..."}],
 "truncated": false}
```

`status` is `ok`, `attention` or `down` everywhere (a node, an edge, an attention item; attention items also say `info`).
An edge's `volume` is its decisions (the line's width), its `status` the worst state on it (the line's colour). The detail
(`target=`) adds `"target": {"changes": [...], "exceptions": [...], "evidence": [...]}`: the changes moving through the target
(tier, state, age), its exceptions and its recent deployment records.

How each number is derived (all from existing evidence, in a fixed number of aggregate statements; nothing pages a history into Go):

| Metric | From |
|---|---|
| `coverage` mix of a target | the target's `scope`: its `assessment` records in the window by `coverage` (an observation re-assessed counts under each coverage it got), plus `unassessed` (observations no assessment is about). A group counts each of its scopes once. `verified_pct` is authorized-and-verified over the assessed |
| observer `state` | `observe.Build` over the scope's `observation.health` records at the window's end (the newest record per source, blind once a record is stale, the core's monitoring flip held): the `/v1/observations/health` logic. A declared observer with no record is `blind` (never seen); a target with no `scope` is `unknown` |
| `decisions`, `refused` | the deployment gate's `deploy.clear`, `deploy.deny` and `deploy.expire`, and each runtime decision (a core record with a `policy` that is not an outcome); refused is `decision: deny` or coverage `attempted-refused` |
| `exceptions` | `deploy.exception` and `deploy.degraded` |
| `holding` | `clearance_changes` in state `holding` now (not windowed), by the registrant, app and env |
| attribution to a gate | a record belongs to a gate instance when its `provider.name` is the instance, or the change it names was registered by it (`registered_by`); to a target when the record's `app` is the target's `app` and its change `env` is the target's `env` |
| `lanes.requested/tiered/decided/applied` | distinct changes with `deploy.request` (tiered equals requested: the tier is decided at registration), `deploy.clear`/`deny`/`expire`, and `deploy.outcome` (`applied_matched`: its `matched`) |
| `lanes.observed/verified` | observations of the target's scope, and the ones assessed authorized-and-verified (a gate type sums its targets' scopes, each once) |

Declared and observed are reconciled, never an error: `no-gate` (a target no gate is declared for), `blind-observer` and
`degraded-observer`, `flag-mode` (a gate type with instances in flag mode), `holding` (changes waiting on a person, by tier),
`gate-silent` (a declared instance no record of the window names; `mix.silent`) and `undeclared-gate` (a registrant or
provider whose records no target declares). The last two are whole-registry facts and are left out of a `group=` or `target=` view.

`partial` says what the records cannot yet say, instead of faking it: `lanes.observed,lanes.verified` are counted from the
target's scope, not joined to each change (a `deploy.outcome` does not yet name the observation that matched it, G-ARGO-3);
targets that declare no `app` have no decisions, holds or lanes (`targets.attribution`); targets that declare no `scope` have
no coverage mix or observer health (`targets.coverage`).

Who sees what: observations and health are whole-scope for every reader (O-5, as `/v1/coverage`); gate decisions, holds
and the detail's changes and evidence are the records the viewer may see (the evidence and change scoping of every other
read), and the detail's exceptions are every exception (as `/v1/exceptions`, redacted below an auditor).

**Counts for the Map.** `GET /v1/evidence/counts` also groups by `provider` (the registered provider or gate that wrote the
record) and `boundary`, takes `scope=<scope>` (one observed scope's records, read whole as the observation reads are) and
`bucket=1m|5m|15m|1h|6h|1d` (needs `since`; `until` defaults to now; at most 1500 buckets): each item is then a bucket
(`bucket`, its epoch-aligned start) and a key, in time order, at most 10000 items.

**Budget.** The Map is one `GateActivity` statement over the window's gate records (bounded below by the first record
written at or after `from`, `clearance_evidence_written`), one over the declared scopes' observations (on
`clearance_evidence_observed`, its predicate repeated word for word), one for their health, and one for the holding changes.
`TestMapStaysUnderABudgetOnALargeChain` holds `GET /v1/map` under a second on 25 000 records (about 50 ms) and, with
`CLEARANCE_MAP_PERF=1`, on 250 000 (about 0.5 s).

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

### Reads for the person CLI

Built for `clearance` / `clr` ([cli.md](cli.md)); the Tower and Slack surfaces can use them too. Both are reads, as visible as
the caller's own view; neither returns a secret.

**`GET /v1/whoami`** (any authenticated caller): who the token is and what the api resolves it to, from the same
viewer resolution every read uses.

```json
{
  "principal": "user:erin",
  "kind": "person",
  "roles": ["person"],
  "role": "person",
  "person": "user:erin",
  "via": null,
  "admin": false,
  "auditor": false,
  "groups": ["group:default/team-gate"],
  "apps": ["gate-api"],
  "agents": [],
  "issuer": "https://dex.example/dex",
  "expires_at": "2026-11-13T13:00:00+00:00"
}
```

`roles` is every role the principal holds; `role` is the one this read resolved to. For a delegate that names a person,
`principal` is the delegate, `person` is who the reads are as and `via` names the delegate. `admin` is whether `person`
matches `CLEARANCE_ADMINS`. `groups`, `apps` and `agents` come from the Directory and catalog (empty without
`BACKSTAGE_URL`). `issuer` and `expires_at` are the token's `iss` and `exp` when it carried them; no subject claim, no
token, no key.

**`GET /v1/clearances?awaiting=me`**: the holding changes the caller may clear now, newest first, with the list's other
filters (`app`, `env`, `tier`, `since`, `limit`, `after`; `state`, if given, must be `holding`). The question is the gate's
own: each change the viewer can see is put through `gate.RoleFor`, the function `POST /v1/clearances/{id}/clear` uses to
say which requirement a person satisfies, so a change is listed exactly when that call would not refuse the person for
`DG-PROPOSER` (they proposed it), `DG-TWICE` (they already cleared it), `DG-FILLED` (their side of the requirement is met)
or `DG-FORBIDDEN` (in neither the owner group nor an outside group). The api re-implements none of it. The check is by the
principal and their groups; the gate's session and subject checks (`DG-APPROVER-SAME`) need the approval request itself
and still apply when they act. An admin is listed only if they also qualify as a group member: admins may deny any held
change, but clearing is the groups'. A person's token, or a delegate naming one, is needed (an auditor or a machine is
400). `next` pages as the list does; the filter reads the holding changes the viewer sees a page at a time (at most 2000
per request, and holding changes are few), so it is the same on the in-memory and Postgres stores.

```json
{"items": [{"id": "c-7f3a", "app": "gate-api", "env": "prod", "tier": 3, "state": "holding", "proposer": "user:alice", "...": "..."}], "next": null}
```

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
| `CLEARANCE_API_OBSERVATION_READERS` | none | principal globs: the `observer` role, machine pollers that read `GET /v1/coverage`, `/v1/observations`, `/v1/observations/health` and `/v1/exceptions` (whole scope, redacted like a person) and nothing else (O-5) |
| `CLEARANCE_API_FEED_READERS` | none | `<principal glob>=<cluster>` pairs, comma-separated: the grant feed's readers (C-1) |
| `CLEARANCE_ADMINS` | none | principal globs (`user:<login>`), the core's own list: `GET /v1/whoami` reports `admin` from it (the chart sets it for both) |
| `CLEARANCE_DELEGATES` | none | principal globs that may name a person in the on-behalf-of header (`CLEARANCE_ON_BEHALF_OF_HEADER`; Hangar sets `X-Hangar-On-Behalf-Of`) |
| `CLEARANCE_AGENTS_DIR` | none | the bundled definitions; cluster pins come from `clearance_definitions` |
| `CLEARANCE_API_DEFINITIONS_INTERVAL` | 30 | seconds between re-reads of the stored definitions |
| `CLEARANCE_API_POOL` | 5 | Postgres connections per replica (1 to 50) |
| `CLEARANCE_BUNDLES`, `CLEARANCE_BUNDLE_SOURCES`, `CLEARANCE_BUNDLE_SOURCE_WAIT`, `CLEARANCE_ENV_*` | none | the policy bundles the core runs ([core.md](core.md#policy-bundles)), for `/v1/policy` and the explainer; loaded as the core loads them: a source that does not answer leaves the bundle degraded (named in `/readyz` `degraded`, still 200) until it answers |
| `CLEARANCE_ON_BEHALF_OF_HEADER`, `CLEARANCE_V0_PROVIDER` and the rest of the vocabulary | core.md | the header a delegate names a person in, the provider v0-draft rows are projected with ([core.md](core.md#configuration)) |
| `CLEARANCE_API_ATTEST_KEY` | none | the attestation signing key's **public** half (PEM) or the core's JWKS: verifies static-key attestations |
| `CLEARANCE_API_ATTEST_TRUST_ROOT`, `CLEARANCE_API_ATTEST_IDENTITY`, `CLEARANCE_API_ATTEST_ISSUER` | none | keyless: a Sigstore `trusted-root.json` (or Fulcio's root and intermediates as PEM, with `CLEARANCE_API_ATTEST_REKOR_KEY`) and the identity and OIDC issuer the certificate must name; the same inputs as `clearance attest verify` |
| `CLEARANCE_API_ATTEST_REKOR_URL` | none | Rekor's public URL, for "open in Rekor" links (`/v1/attestation-config`). The chart: `api.attest.*`, files in an existing ConfigMap mounted at `/etc/clearance/attest-trust` |
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
(`TestExceptionsUseTheIndex`), and, for the change history, `clearance_evidence_change`
(`((record->'change'->>'id'), seq) WHERE record->>'tool' LIKE 'deploy.%'`, behind `GET /v1/clearances/{id}/records` and
the `request` reference) and `clearance_attestations_seq` (`record_seq DESC`, behind `GET /v1/attestations`); both are
in the core's schema (`CREATE INDEX IF NOT EXISTS`), and this package's queries repeat the predicate as written; this
package adds none of its own (the core owns the schema). The stream reads the primary key's range above its cursor; the signed feed is one row
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

### Change history and attestations

Built for the Tower change detail and Attestations boards. All reads; every one is as visible as the change.

- `GET /v1/clearances/{id}/records[?limit&after]`: the change's `deploy.*` records (request, clear, answer, revoke,
  outcome, attestation, exception, ...) in chain order, found by the record's `change.id`. Each item is `{seq, hash,
  tool, ts, principal, record}` (the record as `GET /v1/evidence/{seq}` serves it); `next` is the last `seq` when the page
  is full, pass it as `after`. A person reads them redacted like an exception (secret-bearing `state_change` keys); an
  auditor as stored.
- `GET /v1/clearances/{id}` gains `request: {seq, hash}`, the change's first `deploy.request` (the record
  `POST /v1/clearances` wrote when it registered the change; the `request` the release log carries, [gate.md](gate.md#the-release-record-join-g-argo-6-built)),
  or `null`.
- `GET /v1/attestations[?app&env&since&until&limit&after]`: the attestations of the changes you may see, newest first,
  `since`/`until` bounding when they were signed, cursor `record_seq`. An item: `change_id, app, env, cluster, release_id`
  (the change's `outcome.release`), `tree_digest, signed_at, digest, backend, key_id, rekor_log_index, rekor_uuid,
  outcome_seq, record_seq` (the `deploy.attestation` record's seq) and `verification`.
- `GET /v1/clearances` rows gain `attested` and `attestation` (the reference `GET /v1/clearances/{id}` shows, null for
  none) on every list but the grant feed.
- `GET /v1/clearances/counts?by=attestation`: `attested` (a signed attestation is stored), `pending` (the deploy
  reported an applied outcome and none is stored: the signer is waiting or retrying, or attestation is off) and `none`
  (no applied outcome). The stat tile "applied, not attested" is `pending`. Same `app`, `env`, `state`, `since` filters.
- `GET /v1/attestation-config`: `{verifiable, modes, rekor_url, rekor_entry_url, identity, issuer, key_ids,
  verify_commands}`. Public values only (the keyless identity and issuer, the static keys' ids, Rekor's URL, a
  `rekor_entry_url` with `{log_index}` to fill); no key material. `verifiable` is false when no trust is configured.

**Server-side verification**, `GET /v1/clearances/{id}/attestation/verify`: a pure read (clearance-api has no write
path). It runs `attest.Verify`, the code `clearance attest verify` runs, on the stored bundle, with the trust the api
was started with (`CLEARANCE_API_ATTEST_*`) and the change's cleared digest as the required subject (the tree digest,
or the plan digest for a terraform change). It then holds the bundle to the change: the envelope's digest is the stored
one, and the statement is about this change id. The answer is `{verified, cached, checked_at, digest, subject, mode,
key_id, identity, issuer, rekor: {log_index, integrated_time, verified}, errors}`. A bundle that fails is a 200 with
`verified: false` and the reason in `errors`; 404 is no such change, no attestation, or no trust configured. What it
trusts: only the configured keys, trust root, identity and issuer; the database is not trusted (a stored bundle that
does not verify, or whose digest is not the recorded one, fails). What it does not do is what the CLI does not: it
checks Rekor's signed entry timestamp, not an inclusion proof. A portal says "verified" **only** when this answers
`verified: true`; the lists' `verification` is the last such answer (`{verified, checked_at}`, null if never checked).

The answer is remembered per replica, in memory, by change id and envelope digest (at most 5000, the oldest half
dropped when full), until the replica restarts; `cached: true` says it was not re-run. Verification is offline
cryptography (no Rekor call), so re-running it is cheap, but the list never re-verifies rows. A replica that has not
been asked shows `verification: null`.

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
| `GET /v1/evidence/counts` | records you may see counted by `by` (rule, tool, agent, app, decision, coverage), same filters as the list: the 7-day hits on the Policy page. `by=cost` sums what runs cost instead, `per` task tree (default), session, agent or principal ([cost counts](#cost-counts-bycost)) |
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
`DG-APPROVER-AUTOMATION` 403 and `DG-APPROVER-SAME` 409 (the approver is automation, or the same subject as another approval: [gate.md](gate.md#tier-3-approvers-are-people-c-14-built)), `DG-UNKNOWN` 404, `DG-OFF` 404; `DG-POLICY` and `DG-PROVENANCE` deny the change by policy).

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
| `observer` | `CLEARANCE_API_OBSERVATION_READERS` (a machine poller) | `GET /v1/coverage`, `/v1/observations`, `/v1/observations/health`, `/v1/exceptions`, whole scope, redacted like a person; nothing else (O-5) |
| `feed` | `CLEARANCE_API_FEED_READERS` (a grant-sync agent) | its clusters' grant feed and the changes on them, with their tokens; nothing else (C-1) |

A machine principal may hold more than one machine role (Tower's backend is a `notifier` and an `observer`). Each
route takes the first role it admits, in the order `auditor`, `feed`, `notifier`, `observer`; a route that admits none
of them refuses the principal by its first (0.41.3).

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
