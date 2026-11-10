# The evidence packet (C-5)

An auditor asks one question about a period: what changed, who or what cleared it, what landed that nobody cleared,
and how do I know you would have seen it. The packet is the answer for a date range and scope, built from the evidence
chain and nothing else, in three forms and with the originals needed to check it without asking Clearance.

Status: **Built** (C-5; the offline verifier is C-4, built: [verify.md](verify.md)). Run it as a job: `clearance packet`.

## What you get

- **One canonical JSON document** (`packet.json`, keys sorted, the same bytes for the same records) that is the
  packet; the CSV files and the PDF are projections of it and print its numbers and its sentences, nothing more.
- **A coverage statement that cannot lose a state.** Total records, every coverage state (all six, at zero too), every
  assurance state, the degraded windows, and each observed scope's health. A state with no records is listed with a 0,
  because a state left out reads as "none".
- **No clean list on a blind window.** The sentence "No exceptions detected" is printed only beside a window in which
  every observed scope had a collector whose feed was healthy for the whole of it. A feed that stops makes a blind
  window; a scope with no collector prints **blind**; no scope at all is blind. Otherwise the empty list says why it is
  not a clean one.
- **Assertions that rest on verified fields only.** Control mappings are data; a record that supports an assertion only
  through a field the writer merely claimed is counted as `claimed_only` and is not support.
- **Argo CD and Terraform side by side.** A change's subject is a rendered manifest tree or a saved plan; the packet
  prints the kind and the digest of each in the same table, and an outcome names who reported it (the registered
  provider and its `conformance`, or `clearance` when the core wrote the record itself).
- **Verifiable offline.** The packet carries the stored records as they were hashed, an inclusion proof for each record
  under the witnessed checkpoint, the checkpoint with its witness countersignatures, the public keys it is checked
  with, and the change attestation bundles. When the ledger is off, it says so in so many words.

## Running it

```sh
clearance packet --dsn "$CLEARANCE_DSN" --out ./packet-2026-10 \
  --from 2026-10-10 --to 2026-11-09 \
  --scope aws-111 --scope k8s-prod \
  --ledger-log-keys log-vkeys.txt --ledger-witness-policy witness-policy.txt \
  --signing-key oscal-signing-key.pem
```

It opens the database read-only, reads the chain from genesis (**verifying it as it goes**: a chain that does not
verify makes no packet), and writes the directory, which must not exist or be empty. `--file chain.jsonl` reads a dump
instead of a database (the lab, the tests). Flags:

| Flag | Meaning |
| --- | --- |
| `--from`, `--to`, `--days` | The window, RFC 3339 or a date; `to` is exclusive, defaults to now and is never in the future; `from` defaults to `--days` (30) before `to`; at most 366 days |
| `--scope` | An observed scope (account, cluster or workspace), repeatable. None: every scope the chain holds an observation or health record for. A scope you name that has no collector is printed blind |
| `--view` | `packet` (default), `freeze` or `incident`: [the scoped views](#freeze-and-incident-reports) |
| `--title` | The freeze's or incident's name |
| `--app`, `--env`, `--cluster` | Narrow the gate's records (changes, exceptions, break-glass) to one place |
| `--mapping` | A control mapping, `framework/version` (repeatable; default all) |
| `--format` | `json,csv,pdf` (default all three). The originals for offline verification are always written |
| `--ledger-log-keys`, `--ledger-witness-policy` | The ledger's **public** material: the log's vkeys (one per line, key in use first) and the witness policy file. With them the job checks the checkpoint's signatures and copies them into the packet. Without them the packet says the signatures were not checked here |
| `--signing-key` | An ECDSA P-256 PEM key: signs the OSCAL component definition |

`clearance packet oscal --out <dir> [--signing-key <pem>]` writes the control mappings alone, as the published
component definition.

## The directory

| File | What it is |
| --- | --- |
| `packet.json` | The canonical packet |
| `packet.pdf` | The PDF presentation |
| `csv/*.csv` | `coverage`, `coverage-scopes`, `observed-changes` (freeze and incident views), `degraded-windows`, `assertions`, `changes`, `human-cleared`, `ai-identities`, `exceptions`, `policy-changes`, `acceptances`. A cell a spreadsheet would read as a formula is prefixed so it stays text |
| `evidence/records.jsonl` | The originals: every record from the first to the last in the window, plus the context records the statements read (a feed's last health record before the window; the assessments and resolutions of the window's observations), one canonical record per line **with its `hash`**. Drop `hash`, canonicalize, SHA-256: that is the hash |
| `evidence/proofs.json` | An inclusion proof (RFC 6962 audit path) for each carried record the checkpoint covers |
| `ledger/checkpoint.txt` | The latest witnessed checkpoint as published: a C2SP signed note with the log's signature and the witnesses' countersignatures |
| `ledger/log-keys.txt`, `ledger/witness-policy.txt` | The public keys and policy it is checked with, when the job was given them |
| `attestations/<change>.json` | The Sigstore bundle of each change attestation in the packet |
| `oscal/component-definition.json` (and `.dsse.json`) | The control mappings as an OSCAL component definition, signed when a key was given |
| `MANIFEST.json` | The SHA-256 of every other file |

The packet is deterministic: the same chain, window and parameters give the same bytes (no clock in the PDF, none in the
OSCAL document), so a re-run is a check.

## Sections

**Header.** The view, the window, the scopes and filter, the mappings, and the chain it was read from (count, head,
verified from genesis, the seq range carried).

**Coverage statement.** Total records; records by coverage state (`authorized-and-verified`, `observed-not-attributed`,
`out-of-band-detected`, `coverage-unavailable`, `break-glass`, `attempted-refused`) and by assurance state
(`checkpointed`, `recorded-not-checkpointed`, `not-recorded`), and the cross of the two; **degraded windows** (the core
unreachable, from a provider's `deploy.degraded` outage window; a feed blind or degraded; a break-glass window); and the
**observation health** of each scope: the same three-part statement `GET /v1/coverage` answers
([clearance-api.md](clearance-api.md#observations-and-the-coverage-statement-o-1)), built from the same function over
the same records, with `window_verified` true only when there is at least one scope and every one had a collector and a
healthy feed throughout. Each scope prints the statement's **three parts**: (1) *cleared and verified* (the
observations whose latest assessment is `authorized-and-verified`), (2) *seen, not cleared* (by coverage state) and (3)
*could not see* (every stretch a feed was blind or degraded, with its source, reason and seconds, and the audit gaps), then
the **health summary** per source (worst state in the window, state now, blind and degraded seconds, whether it went
stale) and **source integrity**: how many of the window's observations had their source verified, by the delivery's own
verification or by a later `observation.verification` of the same event (the S3 trail's proof of an event EventBridge
delivered first, [observe-aws.md](observe-aws.md)), each counted once. A collector that was stopped is a blind window
for its scope, a collector that kept reporting is a clean one, side by side in the same packet, and a scope with no
collector is printed blind. The numbers are `observe.Build`'s, the function `GET /v1/coverage` runs, so the two cannot
disagree about the same records; the offline verifier rebuilds them ([verify.md](verify.md)).

**Control assertions.** For each mapping, each control's assertions with a status: `met` (every record in the
population supports it), `met-with-exceptions`, `claimed-only` (everything in the population rests on a claimed field),
`not-met`, or `not-evidenced` (nothing to test, or a window whose feeds could not be verified: an absence of exceptions
supports nothing there). Each carries the population, how many records support it, how many only claim it, how many fail,
and the seqs behind the failures. The evaluators (named in the mapping data) are:

| Evaluator | Population and rule |
| --- | --- |
| `deploy-cleared-before-apply` | Changes with an applied outcome: a clearance, with a verified decision and tier, earlier than the outcome |
| `approvals-distinct-people` | Human-cleared changes: [`token.ApproversStatement`](gate.md) holds (all approvals kind `person`, distinct subjects) |
| `outcome-matches-cleared` | Applied outcomes: only a comparison the core made itself (a plan's verified `matched`) counts; a provider's own claim is `claimed_only` |
| `failures-rolled-back` | Failed changes: a rollback is the deploying provider's claim, so it is `claimed_only`, never support |
| `no-unauthorized-changes`, `monitoring-protected` | No out-of-band (monitoring-protection) exception; `not-evidenced` unless the window was verified |
| `records-checkpointed` | The packet's records under a witnessed checkpoint |
| `observation-coverage-healthy` | Observed scopes with a collector and a healthy feed throughout |
| `exceptions-resolved` | Observations seen and not cleared that have a recorded resolution |

**Changes.** One row per change from its `deploy.*` records: app, environment, cluster or Terraform workspace, the
subject (`manifest-tree` or `terraform-plan`, with the digest, and a plan's variable-set hash), tier, the I-1
**operational class** (printed only when the records carry it), state (`applied`, `failed`, `rolled-back`, `denied`,
`revoked`, ...), the request and clearance seqs, the outcome (applied, matched and whether the core compared it, the
health, the error, the claimed rollback) with **who reported it**, and the attestation. A change that failed stays listed
as failed after a rollback.

**Human-cleared changes.** The approvals on each `deploy.clear`: person, subject, issuer, role, delegate, time and the
**kind** the approval route recorded (C-14). The line "approvers: distinct subjects, none automation" is printed by
`token.ApproversStatement` and only when it holds; an approval recorded before the kind existed prints "not provable
from the records".

**AI identities.** Each agent that appears on a record in the window: principals, records, allowed and denied, the
changes it proposed, the provenance levels, and the model versions (claimed by the runtime provider).

**Exceptions.** One row per exception, in seven classes, each class always listed with its count:

| Class | Rows |
| --- | --- |
| `out-of-band` | `deploy.exception` of kind out-of-band, drift, untraced-apply or digest-mismatch, and observations seen and not cleared: actor, the diff (expected and observed digests, objects or addresses, the state or the operation), and the resolution (inside a break-glass window, re-cleared at a seq, an observation's or a person's `reverted`/`ratified`/... with its cause, or "none recorded"). A person's resolution of a gate exception (`POST /v1/observations/{seq}/resolution`, newest wins) is the row's resolution, with `cause`, `resolved_by`, `resolution_seq` and `resolution_note` as an observation row has; a break-glass window still shows in `window` |
| `break-glass` | One row per window: who opened it, until when, and how it closed (`breakglass.close`'s report) |
| `attempted-refused` | An operation something tried and a control refused: nothing landed |
| `monitoring-protection` | An operation on the controls that watch the environment, whether or not it succeeded |
| `degraded-mode-auto-clear` | `deploy.degraded` (a provider that let a change land, or held it, while the core was unreachable, with the outage policy it was held to) and the runtime reads posted on recovery |
| `invalidated-token` | `deploy.revoke`: a clearance token that stopped being good |
| `provider-correlation-failure` | An observation whose provider named a grant, plan, task or run and was still left uncleared, and a federated decision that could not be tied to a task. This is a second row for an observation already listed under its own class |

When the list is empty the section prints "No exceptions detected" **only** if the coverage statement's
`window_verified` is true, else it says the list is not a clean one and why.

**Policy changes.** `definition.load/unload/reject` records, and each time the policy in force on the gate's records
(`policy.ref`, `policy.version`) changed.

**Verification.** What an offline verifier will find: the chain (verified from genesis by the job), the ledger state, the
checkpoint (origin, size, root, who cosigned, whether the witness policy was satisfied and whether the job checked the
signatures), how many carried records are under it, the proofs, the attestation bundles carried (and any that could not
be read), and the OSCAL file. If the store holds no witnessed checkpoint the section begins "NOT CHECKPOINTED" and says
what that does and does not show.

**Acceptances.** The signed acceptance receipts assurance recipients return for a packet (package P-1): packet id,
engagement, framework and mapping versions, checkpoint, verdict and per-control notes; later packets carry the prior
receipts. P-1 does not exist yet, so the section prints that no receipt has been recorded and nothing else: no content
is inferred from the chain. `acceptances` in the JSON is `{status, statement, receipts[]}` (`status` is `none-recorded`
until receipts exist, and `packet.Params.Receipts` is where P-1 will hand them in), and `csv/acceptances.csv` has the
receipt columns, empty for now. A `ratified` or `declared-break-glass` resolution and each break-glass window are
**Exceptions** rows (the resolution column, and the `break-glass` class). An observation row shows its **newest**
resolution with the person (or provider) who wrote it (`resolved_by`, `resolution_seq`, the cause, and the person's note as `resolution_note`: in full in `packet.json`, cut to 200 characters in the CSV and the PDF): a person's edit
in Tower is a newer record about the same seq and replaces the collector's in the packet, the earlier records staying
in the evidence. A row also says whether its source was verified.

## Freeze and incident reports

Two scoped views of the same records, not new data: `--view freeze --title "Q4 freeze" --env prod` and
`--view incident --title INC-42 --cluster hangar-prod --from ... --to ...`. A view narrows the gate's records to the
place named and keeps the sections that answer its question: **freeze** carries the coverage statement, changes,
exceptions, acceptances (receipts) and verification (what changed or tried to change inside the freeze, and whether it was
cleared); **incident** adds AI identities, policy changes and a **timeline** of the changes, exceptions and break-glass
events in scope in time order. Both always carry the full coverage statement, and both add an **observed changes** section (`observed_changes`, CSV
`observed-changes.csv`): every observation inside the window and scope, cleared or not, in time order, with the actor, what
changed, the coverage the latest assessment gave it, how it was resolved and by whom, and whether its source was verified
(the exceptions section lists only what was not cleared; a freeze or an incident also asks what *did* change). At most
2000 rows are listed (`truncated` says so, `count` is the whole count).

## Control mappings and the OSCAL component definition

Mappings are data in `internal/packet/mappings/`, one file per framework and version, keyed by control, naming for each
assertion the evaluator that tests it. Two ship, in this order: `soc2/2017` (CC8.1, change management) and
`soc2/2027-draft` (CC7.1, detection and monitoring; the draft's wording is not reproduced, the control title is
paraphrased). Adding a framework is adding a file.

They are published as an **OSCAL component definition** (v1.2.3, the current release): one component, Clearance, a
control implementation per mapping, an implemented requirement per control, a statement per assertion carrying its
evaluator. The document is canonical and dated by the mappings' own revisions, so it is reproducible. Signed, it is a
DSSE envelope (`application/vnd.oscal.component-definition+json`, ECDSA P-256 over the SHA-256 of the pre-authentication
encoding, the signature the clearance token and the change attestation use).

## What a verifier can and cannot do offline

The ledger's Tessera volume is a cache of the chain: `Log.Prove` builds a proof only in the process that has it open, and
the log is not served over HTTP. So the packet builds the proofs from the chain's record hashes, which is the same
tree (entry *i* is record *i*'s hash): `internal/ledger.Tree` produces, for every seq, the same audit path the log gives
(tested against `Log.Prove`), and the job refuses to issue a packet whose chain does not hash to the checkpoint's root or
whose proof does not verify. A verifier needs only the packet: recompute each hash from `records.jsonl`, check the
`prev_hash` links where seqs are adjacent, check each proof against the checkpoint's root, and check the checkpoint's
signatures under keys it trusts (`ledger.ParseCheckpointNote`). `clearance verify` does exactly this and more ([verify.md](verify.md)).

What it cannot do: a record **after** the checkpoint is `recorded-not-checkpointed` and has no proof; with the ledger off
nothing is checkpointed and the packet says the records show consistency, not that the chain was not rewritten as a
whole; the signatures are checked in the job only if it was given the public keys, so the packet records whether it did;
a record's *claimed* fields are what their writers said and are labelled so.

## Not yet

- A scheduled job in the chart: the command is a batch job (it exits), but no `CronJob` template ships yet.
- Fields the records do not carry: who proposed a change and whether the approver is its author (the gate's change view
  has it; the records do not), tests run (CI results), and the Terraform provider's `conformance` where it is not
  registered (the record then names `clearance`).
- Text is written in the standard Courier fonts as WinAnsi: Latin-1 is exact and any other character prints as `?` in the
  PDF (the JSON and CSV are UTF-8).
