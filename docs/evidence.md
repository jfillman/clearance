# The evidence record: clearance.evidence/v1

Every decision Clearance makes, and every event a registered provider reports, is one evidence record in one
hash-chained log. This page is the record's contract: the schema, the versioning rule, how the rows written before
the schema froze are read, and the record check on real hangar-dev records.

Status: **Built** (R-6). The schema is published at
[`schemas/evidence.schema.json`](../schemas/evidence.schema.json) (`$id`
`https://clearance.hangarplatform.dev/schemas/evidence/v1.json`, embedded in the Go binary as
`github.com/jfillman/clearance/schemas.EvidenceV1`). The Go core is the one writer
(`internal/evidence.Seal`, used by `store/memory` and `store/pg`). Until v0.29.0 the Python gateway (`audit.py`
`seal`) wrote the same v1 envelope; that package left the repository in v0.30.0, and its fixtures below are frozen. The api projects v0-draft rows. Signing, the Tessera ledger and assurance states
other than `recorded-not-checkpointed` are later packages (C-series); this page says where they attach.

## What you get

- **One record shape for both boundaries.** A tool call, a model call, a session open, a gate clearance and a
  provider's deployment outcome are the same record: the event's own fields plus one envelope.
- **Every field tagged.** `verified` lists the fields the writer established itself, `claimed` the fields something
  else asserted. A control assertion may rest only on verified fields.
- **Who wrote it.** `provider` names the registered provider and its version. The writer sets it from its own
  registration; an event cannot.
- **What it is about.** `subject` is the thing the record binds to, in in-toto style: a kind (`tool-call`,
  `manifest-tree`, `terraform-plan`, `definition`) and digests keyed by algorithm (`sha256`, `gitCommit`).
- **Intent redacted by default.** Free text an agent or a change gives as its reason is stored only as a SHA-256;
  the text is kept only where the deployment opts in (`Writer.intent_capture = "full"`).
- **One chain across versions.** The chain rule did not change, so the 612 v0-draft rows on hangar-dev and every v1
  record after them verify as one chain, in Python and in Go.

## The chain rule (unchanged since v0-draft)

- `seq` counts from 0 with no gaps.
- `prev_hash` is the previous record's `hash` (64 zeros for seq 0).
- `hash` is SHA-256 over the canonical JSON of the record without `hash`: keys sorted by code point, no
  whitespace, UTF-8, only `"`, `\` and control characters escaped, floats in Python's repr
  (`internal/canon`, byte for byte `audit.canonical`).
- The assurance state is **not** in the record. It is a column beside it (`clearance_evidence.assurance`), because
  it changes after the record is written (`recorded-not-checkpointed` until a witnessed checkpoint covers it).

## The record

A v1 record is **flat**: every field is a top-level key, so every existing query (`record->>'tool'`, the receipt
index on `record->'effect'`) works on v0-draft and v1 rows alike, and `verified`/`claimed` name fields by key. The
architecture's field groups are a property of each key (`x-clearance-group` in the schema). Fields not in the
schema are allowed and are claimed unless the writer verified them.

| Group | Fields | Notes |
| --- | --- | --- |
| Identities | `provider`, `principal`, `agent`, `session`, `parent`, `task_id`, `initiator`, `model_version` | `provider` {name, version[, conformance]} is required (`conformance` from the provider's registration, C-1); `initiator` {sub, iss} optional; `model_version` reserved for AP-C1 |
| Source | `subject`, `tool`, `args_sha256`, `change`, `source` | `subject` required (null when there is none); `tool` is the operation or event type; arguments are never stored, only their digest |
| Target | `boundary`, `target`, `app`, `destination` | `boundary` is `runtime` or `deployment`; `destination` {cluster, environment, application} optional |
| Provenance | `provenance` | optional {level, signals[{name, tag}]} |
| Decision | `decision`, `tier`, `rule`, `rules`, `reason`, `policy`, `approvals`, `token`, `preflight` | verdict, tier, rule fired; `policy` {ref, engine, version}, filled by R-5 for runtime decisions (engine `cel-go`) and by C-8 for deployment decisions (plus `verdict` and `bundle`: the offline admission engine's result and rule set; [gate.md](gate.md) "The policy in the record"); `approvals` [{sub, iss, via, at}] (C-1: on `deploy.clear`, with `person` and `role`, and on the App's `deploy.request` and `deploy.answer` once cleared); `token` the clearance token's nonce (C-1: `deploy.clear`, `deploy.revoke`); `preflight` reserved for AP-C1 |
| Outcome | `result`, `effect`, `refusal`, `outcome` | `result` keeps its v0 meaning (the result line, or a deny's reason); `effect` is the receipt of a write the writer made; `refusal` {rule, message} optional (revision 2): a handler's refusal on an outcome, after the core allowed; `outcome` {applied, observed_revision, digests, health, rollback} optional |
| Coverage state | `coverage` | `authorized-and-verified` (default), `observed-not-attributed`, `out-of-band-detected`, `coverage-unavailable` |
| Assurance state | `assurance` | beside the record, never hashed: `checkpointed`, `recorded-not-checkpointed`, `not-recorded`; a reader adds it |
| Intent | `intent` | {capture: redacted\|full, sha256[, text]}; only when the event has an intent |
| Integrity | `schema`, `seq`, `ts`, `prev_hash`, `hash`, `verified`, `claimed`, `projected` | `projected` is read-only, added by a reader (below). A signature and a checkpoint reference attach beside the record when the ledger exists, like `assurance` |

Required in every v1 record: `schema`, `seq`, `ts`, `prev_hash`, `hash`, `boundary`, `coverage`, `provider`,
`subject`, `tool`, `verified`, `claimed`.

### How the envelope is built

One function builds it. The Python writer built the same bytes for the same event and Writer:
`internal/evidence/testdata/python-v1.jsonl` is what it wrote (by `python_chain.py`, at v0.29.0 and before), and
Go's `TestPythonV1Identical` must reproduce it byte for byte:

- An event may set `boundary`, `coverage`, `subject` and `intent`. It may not set `seq`, `schema`, `verified`,
  `claimed`, `prev_hash`, `hash` or `provider`. Unknown `boundary` or `coverage` values are refused (v0-draft
  accepted any string).
- `subject`, when the event does not give one, is derived: a gate record's `change` with a tree digest gives
  `manifest-tree` (`sha256` = the tree, `gitCommit` = the head, name `app/env`); a `definition.*` record gives
  `definition` (the digest of the pin); any other runtime record gives `tool-call` (name = tool, `sha256` =
  `args_sha256`); a deployment record with no tree has `null`. A derived subject is verified when the fields it came
  from are; an event's own subject is claimed unless the writer verifies `subject`.
- Since G-TF-1 the deployment gate gives every `deploy.*` record its subject itself, from the change's `subject`
  ([gate.md](gate.md#the-terraform-plan-subject-g-tf-1)): `manifest-tree` (name `app/env`, `sha256` = the
  manifest-tree digest, `gitCommit`), `definition` for an agent definition's release (name = the agent), or
  `terraform-plan` (name `app/env`; `sha256` = the saved plan, `planJson` = the redacted plan JSON, `variableSet` =
  the variable-set hash, `gitCommit`). A placeholder tree is left out: the subject then carries `gitCommit` only. The
  subject is claimed (the verifier described the change).
- `verified` and `claimed` together name every field outside the chain's own (`seq`, `schema`, `boundary`,
  `coverage`, `verified`, `claimed`, `prev_hash`, `hash`).

### The writer (what R-1d calls)

The Go core's routes do not build records; they call `store.Tx.Append(ctx, event, evidence.Writer)`, which seals
through `evidence.Seal`:

```go
type Provider struct{ Name, Version string }
type Writer struct {
    Provider      Provider        // from CLEARANCE_PROVIDERS, after the caller authenticated
    IntentCapture string          // "redacted" (default, also "") or "full"
    Verified      map[string]bool // nil = evidence.GatewayVerified
}
func Seal(head Checkpoint, event map[string]any, w Writer) (record map[string]any, canonical []byte, err error)
func DeriveSubject(r map[string]any) (subject map[string]any, sources []string)
func Project(r map[string]any) map[string]any
func Stored(r map[string]any) map[string]any
```

- The core's own decision records (POST /access/v1/evaluation, the gate routes): the core's provider and
  `GatewayVerified` (the v0 verified set plus `provider`).
- A registered provider's own records (POST /v1/records: session.open, run.launch, run.finish, deploy.outcome,
  ...): that provider's name and version, and `evidence.ProviderVerified` (only `provider` is verified; everything
  the provider says is claimed). Pass the provider's `subject` in the event. A `tool.call` record from a provider is
  an outage read (`coverage: coverage-unavailable`): a T0 read the provider ran while the core was unreachable,
  posted on recovery. Its `tool` is the tool called and its subject the derived tool-call digest, both claimed. It
  is not a decision, and it carries no `rule`, `effect` or `outcome`.
- Definitions a provider publishes (PUT /v1/definitions): `definition.load`, `definition.unload` and
  `definition.reject`, sealed by the core with `caller`. Verified: `provider`, `ts`, `caller`, `tool`, `decision`,
  `rule` (and the null session fields). Claimed: the pin's `principal` (`pin:<ns>/<xr>`), `agent`, `target`,
  `args_sha256`, `result` and so the subject, because the core decided the pin but did not fetch the file. The
  Python gateway's loader, which fetched it, wrote the same fields verified; the Go core's are tagged for what it
  knows.
- Errors: `ErrEnvelopeField` (an event set a reserved field), `ErrInvalid` (a value outside the schema),
  `ErrNotStorable` (a value Postgres jsonb would change).

The Python equivalents are `audit.Writer`, `audit.Provider`, `audit.seal`, `audit.derive_subject`,
`audit.project` and `audit.stored`; the gateway's writer is `audit.gateway_writer()`
(`autopilot-gateway` at the package version).

## Versioning rule

- The `schema` string names the record shape a writer emitted. It changes only for a breaking change: a field
  removed or renamed, a meaning changed, a field moved between verified and claimed for an existing writer, a new
  required field, an enum value removed.
- Additive changes inside v1 (a new optional field, a new optional property inside an optional object, a new enum
  value for a reserved field) bump `x-clearance-revision` in the schema file and are listed in the changelog. No
  stored record changes.
- Rows are never migrated. A row stays exactly as written, because its bytes are hashed; readers project old
  versions into the current shape.
- The chain rule is version independent, so one chain holds every version.

## v0-draft rows: the projection

hangar-dev seq 0 to 611 were written as `clearance.evidence/v0-draft`. They are not rewritten (that would break
every hash after them). clearance-api serves every record through `audit.project`:

- A v0-draft row is returned as written, plus `provider` = `{"name": "autopilot-gateway", "version":
  "unrecorded"}` (every v0 row was written by the Python gateway process, which named no version) and `subject`
  (derived as above), and `projected: ["provider", "subject"]`.
- A v1 record is returned as written plus `projected: []`.
- `assurance` is added beside every record, as before.
- `schema` is never rewritten: a projected row still says `clearance.evidence/v0-draft`.
- To re-check a served record's hash, drop `assurance`, `projected` and every field `projected` names
  (`audit.stored`, `evidence.Stored`).

The routes that serve records (`GET /v1/evidence`, `GET /v1/evidence/{seq}`, `GET /v1/receipts`,
`GET /v1/provenance`) project; filters and counts read the stored fields, which both versions share. The contract
(`contract/clearance-api.json`) is unchanged.

The Go clearance-api (R-2b, `internal/api`) does the same: it runs every served record through `evidence.Project` and adds `assurance`
beside it; `evidence.Project` is byte-identical to `audit.project` on all 612 hangar-dev rows (below).

## The record check (hangar-dev, 2026-11-03)

The architecture (chapter 01) asks for one real record held against the six questions an auditor asks of every
sampled change. It was run on a dump of the live hangar-dev chain: 612 records, seq 0 to 611, all
`clearance.evidence/v0-draft`, `clearance chain verify --file` `ok 612 head
08cf40674262c1d5e7b7d236dd991c9c6d11cbb4c114f6508bb7058ab1d2a918`. Records of each kind:

| seq | kind | what it says |
| --- | --- | --- |
| 0 | session.open | nightly-reviewer, principal `autopilot-runs/nightly-reviewer`, task `t-fbd9fbf5728a`, allow |
| 3 | tool call (deny) | repo.pr.open, tier 1, target `lower`, deny R006 "tool is not permitted for this session" |
| 139 | tool call (write) | repo.pr.open by triage-agent, tier 1, allow; `effect` {repo jfillman/gate-api, pr 32, commit 5348e71, paths [app.js]} |
| 141 | provenance verdict | provenance.verify of jfillman/gate-api#32: `identity:confirmed scope:in-scope`, same task `t-59cf28628f59` as 139 |
| 16 | model call | model.call, target `claude-sonnet-5-5`, allow, result ok |
| 236 | human.answer | principal `user:jfillman` answered h-01b274e4bd90 for coding-agent |
| 335, 336 | deploy.request, deploy.clear | checks-only-scratch to agents on hangar-dev, tier 0 cleared by policy; `change` with head 25216f9 and tree 8b191d0c… |
| 397 | deploy.request | DG-UNREGISTERED: deployment run 41274084765 to prod rejected, no change registered |
| 405 | deploy.answer | the App's answer, deployment run 41274084765 approved; change tree is 64 zeros |

The six questions against those records:

| # | Question | v0-draft record today | v1 field that answers it | Who fills it |
| --- | --- | --- | --- | --- |
| 1 | What changed: rendered manifest digest, diff, repos and clusters touched | **Runtime: no.** A tool call has only `args_sha256` (seq 3, 139) and the PR it opened (139 `effect`); no manifest. **Deployment: partly.** 335/336 carry the tree digest and head in `change`, claimed; 402 to 405 have a zero tree (a hand-made registration by a pipeline service account on 2026-11-01, not `clearance register`, whose own registrations, 468 to 474 and 641, carry a real tree; since G-TF-1 a placeholder tree is flagged `tree:unbound` or refused `DG-UNBOUND`), and 397 has no change at all | `subject` (manifest-tree: sha256 + gitCommit), `source`, `destination` | the deployment gate; `clearance register` must send a tree |
| 2 | Who or what initiated it, with confidence | **Yes, strongest at runtime.** principal + agent + session + task_id are verified on every record (seq 0, 3, 16, 139); 141 adds a provenance level for the PR, as a result string | `principal`, `agent`, `task_id`, `initiator`, `provenance` {level, signals} | both; the gateway has the strongest signal |
| 3 | Was it authorized before it went live: policy, tier, approver, approver is not author | **Partly.** decision, rule and tier are verified (seq 3: deny R006, tier 1); 336 says "cleared by policy" in `result`. No policy version, no approver identity (405's principal is `app:177375213`, the App, not a person) | `policy` {ref, engine, version}, `rules`, `reason`, `approvals` [{sub, iss}], `token` | both; the shared core |
| 4 | Was it tested: CI run and results | **No.** Nothing in any record | a provider's claimed `outcome`/`source` from the PR and pipeline (CI attestation reference) | the deployment gate, from the PR and pipeline |
| 5 | What actually deployed: sync result with a digest matching the cleared one | **No.** 405 says the GitHub deployment was approved, not what landed | `outcome` {applied, observed_revision, digests, health} on deploy.outcome, compared with the cleared `subject` | the deployment gate (R-1d deploy.outcome, G-ARGO) |
| 6 | Rollback available and whether it was used | **No** | `outcome.rollback` {available, used, to} | the deployment gate |

Result, as the architecture predicted: the runtime record answers 2 well and 3 in part, and has nothing for 1, 4,
5 and 6. It is a decision record. Two findings beyond the prediction: question 3's approver half is missing even on
deployment records (405 names the App installation, not the person who approved), and question 1 is unanswered for
the `clearance register` changes (402 to 405 carry a zero tree), so a GitHub deployment cleared that way binds to
the commit only. v1 adds the fields for every question; filling them is the work of R-1d (decision and outcome
records), R-5 (`policy`), G-ARGO and G-TF (`subject`, `outcome`) and A-4 (`model_version`, `preflight`).

Projected, the 612 rows have subjects `tool-call` 576, `definition` 17, `manifest-tree` 14 and none for 5
(397, 402, 403, 404, 405, the findings above); every projected row is valid against the v1 schema.

## Across the v0 to v1 boundary (on a copy of the lab chain)

Run on 2026-11-03 against copies of the dump; the dump itself is not in the repo.

| Check | Result |
| --- | --- |
| Python `AuditLog` over a copy, two v1 records appended by the gateway writer, Python `audit.verify` | `(True, None)` 614, head `3dbfdd49…7f`; seq 610-611 v0-draft, 612-613 v1 |
| Go `clearance chain verify --file` on that file | `ok 614 head 3dbfdd4904533104dfeb067c1a4d178c06e01b0ca332dcbcde9bba903384d77f` |
| Go `store/memory` loaded with the copy, two v1 records appended (`TestV0ChainExtendedWithV1` with `CLEARANCE_LIVE_CHAIN`) | `clearance chain verify --file`: `ok 614 head 2cfdce964d9b490180e066101ff59eb7086af1e3d16e93a0bcc2eab59359ae74`; `python_chain.py verify --schema`: `ok schema-valid-v1 2 614` |
| Postgres: the 612 rows inserted into a scratch database, Python `PgAuditLog` opened (verified) and appended two v1 records, then Go `store/pg` opened as writer (verified) and appended two more (one as a registered provider) | Go `clearance chain verify --dsn`: `ok 616 head 3cb43a52d1899d7edf0feccb05ba3a27486bd81b6f286214b897964d8e5b437c`; Python `PgAuditLog` reopen: `(True, None) 616`, same head, providers autopilot-gateway, autopilot-gateway, clearance, argo-gate |
| Projection of all 612 rows | Python `audit.project` and Go `evidence.Project` byte-identical on 612 of 612; `stored(project(r))` re-verifies the chain; 0 schema errors |

In CI the same boundary runs on the four-record v0-draft fixture (`internal/evidence/testdata/python-chain.jsonl`):
`TestPythonV1Identical`, `TestExtendPythonChain`, `TestV0ChainExtendedWithV1` and the store conformance suite. (The
Python checks in the table, and `python_chain.py`, ran at v0.29.0; they left with the Python package in v0.30.0.)

To repeat it on a fresh dump:

```sh
psql "$CLEARANCE_DSN" -Atc "select record::text from clearance_evidence order by seq" > chain.jsonl
CLEARANCE_LIVE_CHAIN=$PWD/chain.jsonl CLEARANCE_LIVE_OUT=$PWD/extended.jsonl \
  go test -count=1 -run TestV0ChainExtendedWithV1 ./internal/store/memory/
go run ./cmd/clearance chain verify --file extended.jsonl
```
