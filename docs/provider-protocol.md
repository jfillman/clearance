# The provider protocol and the conformance harness

A **provider** is an enforcement point: the thing that actually does a tool call or lands a change, and that asks
Clearance first. Clearance's core decides and records; it never acts on anything itself. This page is the contract
a provider implements, written from the routes the Go core serves today (`internal/server`, `internal/gate`,
`contract/clearance-core.json`), and the conformance suite that proves a provider keeps it.

Status: **Built** (R-1f) for everything the core serves today: the two roles, the conformance control interface,
`clearance conformance`, and the reference fakes. The wait route, the change-bound outcome route and the signed
clearance token are **Proposal** (C-1, C-10, G-TF-2); the section [Not served yet](#not-served-yet) says how a
provider works without them.

## What you get

- **One contract for every enforcement point.** The Autopilot gateway, the Argo CD gate, the Terraform gate, the
  GitHub App's deployment protection rule and `clearance register` all speak to the same small API.
- **A test that a provider keeps it.** `clearance conformance --provider <url> --role runtime|deployment` starts an
  in-memory core and a fake target, drives the provider through a fake call or a fake change, and prints one PASS or
  FAIL line per rule. Exit 0 means every rule held.
- **Proof from the record, not from the provider.** The harness checks what the core recorded and what the fake
  target received, and verifies the evidence chain at the end. Nothing the provider says about itself is taken as
  proof.

## Guardrails every provider keeps

| Rule | Runtime | Deployment |
| --- | --- | --- |
| Ask first | Every action is evaluated before it runs | Every change is registered before it lands |
| Act only on yes | Only on `decision: true` | Only on `state: cleared`, only the cleared digest |
| Fail closed | No answer, a timeout or a 5xx is a deny | No answer leaves the change held; nothing lands |
| Exactly once | One action per allowed decision | One apply per cleared change |
| Report what happened | One outcome per allowed decision | One `deploy.outcome` per applied change, with the applied digest |
| Identify yourself | Authenticate as a registered provider principal | The same, and be a verifier |

## Who implements which role

| Provider | Role | Status |
| --- | --- | --- |
| Autopilot gateway (`autopilot-gateway`) | runtime | Built in Python, deciding in-process today; it calls the Go core from R-3 and is tested then, and again as the Go port (A-9) |
| Argo CD gate: CMP, grant-sync agent, PreSync wait (G-ARGO-3, -4, -5) | deployment | Proposal; G-ARGO-9 requires conformance |
| Terraform gate: `clearance hold`, `release`, `report` (G-TF-3) | deployment | Proposal |
| Clearance GitHub App, deployment protection rule | deployment | Built inside the core (`internal/githubapp`); it answers GitHub's callback rather than applying, so it is not driven by this suite |
| `clearance register` (a workflow registering its change) | deployment, register step only | Built (`cmd/clearance/register.go`) |

## Registering a provider

The core knows its providers from `CLEARANCE_PROVIDERS` (`server.Provider`):

```json
[{"name": "argo-gate", "version": "0.1.0", "principals": ["hangar-prod/argocd/clearance-sync"],
  "kinds": ["deploy.outcome", "deploy.exception"]}]
```

- `name` and `version` are what every record the provider writes carries as `provider` (verified: the core sets
  it from the registration, never from the request). `clearance` is the core's own name and is refused.
- `principals` are globs on the authenticated principal. A caller is the first provider whose globs match it.
- `kinds` narrows which `POST /v1/records` kinds it may write (default: all).
- A deployment provider registers changes, so its principal must also match `CLEARANCE_VERIFIERS`.

Every call carries `Authorization: Bearer <token>`: in a cluster an audience-bound projected service-account token,
from a workflow a GitHub Actions OIDC token. A provider never logs it.

## The runtime role

The gateway's loop, for every tool call, model call, session open and spawn:

1. **Evaluate.** `POST /access/v1/evaluation` with the AuthZEN request (`decide.EvaluationRequest`): `subject`
   (the principal and its tier ceiling), `action` (`tool.call`, `model.call`, `session.open`, `session.spawn`, with
   the arguments), `resource` (the tool, model or agent), `context` (the session state the provider holds: limits,
   budgets used and reserved, breaker, scope, `now`). The core holds no session. The answer
   (`server.EvaluationResult`):

   ```json
   {"decision": true,
    "context": {"rule": "", "message": "allowed", "tier": 1,
                "spend": {"tool_calls": 1, "github_calls": 4, "open_prs": 1},
                "policy": {"bundle": "clearance-core", "version": "..."}},
    "decision_id": "1", "record": {"seq": 1, "hash": "..."}}
   ```

   The decision is recorded before it is answered. A 503 means the core could not record it, which is no decision.
2. **Apply the spend**, allow or deny. `context.spend` is what the provider must do to the session the request
   named: add `tool_calls`, `github_calls`, `open_prs`, `children`; reserve `reserve` on the parent (a spawn); count
   one denial when `denial` is set; trip the breaker with `trip`, and the descendants with `trip_tree`. A provider
   that ignores the spend lets a session run past its budgets.
3. **Act only on `decision: true`.** On a deny, return `context.message` and `context.hint` to the caller and do
   nothing else. On `session.open` and `session.spawn`, `context.grant` is the session to create.
4. **Report the outcome.** `POST /v1/decisions/{decision_id}/outcome` once the call ran, allowed decisions only:

   ```json
   {"result": "ok", "effect": {"repo": "o/r", "pr": 7, "commit": "5348e71", "branch": "agent/t-1", "paths": ["app.js"]},
    "receipt": {"backend_id": "..."}}
   ```

   `result` is the call's result line (`ok`, `error:<Kind>`, a handler's refusal). `effect` is only for a tool with a
   receipt or that writes files (it is what provenance later reads). `receipt` is flat scalars. The core links the
   record to the decision with `outcome_of {seq, hash}` and copies the decision's identity fields (verified). It
   refuses a second outcome (409), an outcome for a deny (409), and an outcome for another provider's decision (403).
5. **Write the runtime records** the provider owns: `POST /v1/records` with
   `{"provider": "<name>", "kind": "<kind>", "record": {...}}`. Kinds and what each must carry:

   | Kind | Must carry |
   | --- | --- |
   | `session.open` | session, task_id, principal, agent, result |
   | `run.launch`, `run.delete`, `session.freeze` | session, principal, agent, result |
   | `human.answer` | principal, target, result |
   | `trigger.hold` | principal, agent, target, result |

   Only `provider` and `ts` are verified on these; everything else is claimed.
6. **Fail closed.** A connection error, a timeout or a 5xx from the core is a deny for the call in hand. The one
   exception is the recorded switch in R-3's outage policy; until it exists there is none.

## The deployment role

For every change to a protected environment:

1. **Register the change with its subject.** `POST /v1/clearances` with the change (`gate.ChangeRequest`,
   [docs/gate.md](gate.md)): app, env, cluster, repo, pr, head, proposer, owner, objects, paths, checks, and
   `treeDigest`, the sha256 of the canonical rendered tree (for Terraform, the saved plan's digest, G-TF-1). That
   digest is the subject the clearance binds to. Registration is idempotent by repo, PR and head; a new head on the
   same PR supersedes the old one. The answer is the change as recorded: `id`, `tier`, `reasons`, `requirement`,
   `state`, `tree_digest`, `target`, `expires_at`.
2. **Hold while `state` is `holding`.** Tiers 0 and 1 clear by policy at once; tier 2 waits for one person from the
   owner group, tier 3 for one owner and one outside, never the proposer. Nothing is applied while the change holds.
   Today the provider learns the state by sending the same registration again (see
   [Not served yet](#not-served-yet)).
3. **Release on `cleared`, once, and only the cleared digest.** Re-hash what is about to be applied and compare it
   with `tree_digest`; if they differ, do not apply (a push after clearing is a new head, so a new change). Apply
   exactly once.
4. **Refuse on `denied`, `expired` or `superseded`.** Never apply. A change the core never answered for is not
   cleared either.
5. **Report the outcome.** `POST /v1/records`, kind `deploy.outcome` (must carry `app`, `target`, `outcome`):

   ```json
   {"provider": "argo-gate", "kind": "deploy.outcome", "record": {
     "app": "gate-api", "target": "jfillman/gitops-gate-api#12@25216f9", "result": "applied",
     "change": {"id": "ch-0123456789abcdef", "tree": "sha256:8b19...", "head": "25216f9..."},
     "subject": {"kind": "manifest-tree", "name": "gate-api/prod", "digests": {"sha256": "8b19...", "gitCommit": "25216f9..."}},
     "destination": {"cluster": "hangar-prod", "environment": "prod", "application": "gate-api-prod"},
     "outcome": {"applied": true, "observed_revision": "25216f9...", "digests": {"sha256": "8b19..."}, "health": "Healthy"}}}
   ```

   `change.id` names the change, and `outcome.digests.sha256` is the digest the provider actually applied: the
   auditor's question 5 ("what deployed, and does it match what was cleared") is answered by comparing it with the
   cleared change's `tree_digest` (docs/evidence.md). The core does not compare them yet; the harness does.
6. **Report exceptions.** A break-glass apply, or a change seen in the environment that no clearance covers, is a
   `deploy.exception` record (must carry `principal`, `target`, `result`; set `coverage: out-of-band-detected`).
   It is a finding, never a way around the hold.

## Not served yet

| What | Route or piece | Why a provider needs it | Interim |
| --- | --- | --- | --- |
| Wait for a decision | `GET /v1/clearances/{id}/wait?timeout=` (G-TF-2, shared with G-ARGO-5) | A held change can wait days; the PreSync hook and `clearance hold` need to block on it | Re-send the registration (`POST /v1/clearances`, same body) every few seconds; it answers the change as it stands. Each poll takes the gate's lock and rewrites the change row (`updated_at`), so keep the interval at 5 s or more in production |
| Read a change | `GET /v1/clearances/{id}` on the core | A provider that did not register the change (the grant-sync agent, a reconciler) cannot learn its state from the core | clearance-api serves `GET /v1/clearances/{id}` (`getClearance`) to people, delegates, notifiers and auditors only, so a provider needs a role there or a core route; the Go clearance-api is R-2 |
| Change-bound outcome | `POST /v1/clearances/{id}/outcome` (G-TF-2) | The core should compare the applied digest with the cleared one, write `matched`, and file `deploy.exception` on a mismatch | `deploy.outcome` through `POST /v1/records`, which is all claimed: the core checks neither that `change.id` exists nor that the digest matches |
| Signed clearance token | issued on `deploy.clear` (C-1) | Lets a provider (and admission) verify offline that a release binds this digest, without trusting the poll answer | Release on the polled `state` and compare the digest yourself |
| A group directory in the Go core | `gate.Service.Directory` (nil from `core.Build`) | Without it nobody is in any group, so no person can clear a tier-2 or tier-3 change on `clearance core` | The harness sets its own directory on the built core; a deployment needs R-2 to wire one (the Python core reads Tower's catalog) |
| Conformance in records | `provider.conformance` (reserved in the v1 schema) | A record could say which suite its writer passed | `CLEARANCE_PROVIDERS` has no field for it yet; the report's `suite` is the value to stamp |

## The conformance control interface (test only)

To be tested, a provider exposes three routes that make it perform its normal flow against a core and a target the
harness names. **This interface is for testing only and is off by default.** A provider:

- serves it only behind an explicit switch (a flag such as `--conformance-control` or an environment variable),
  never in a production profile or chart default;
- binds it to loopback or a test namespace, on its own port, apart from its real API;
- while it is on, sends its normal traffic to the core and target URLs it is given, with the bearer tokens it is
  given, and still runs every check it runs in production (it does not skip a decision because it is under test).

Routes, on the control address:

| Route | Body | Answer |
| --- | --- | --- |
| `GET /conformance/v1/info` | | `{"name", "version", "roles": ["runtime" \| "deployment"]}`: the harness registers the provider in its core under this name and version |
| `POST /conformance/v1/apply` | `conformance.ApplyRequest` (below) | `202 {"id"}`; the flow runs in the background |
| `GET /conformance/v1/applies/{id}` | | `conformance.Status`: `{id, state, reason, decision_id, spend, change_id, outcome {seq, hash}}` |

`ApplyRequest`, strictly decoded (unknown fields refused, 1 MiB cap, `conformance.DecodeApply`):

```json
{"id": "dp-held", "role": "deployment", "provider": "argo-gate",
 "core": {"url": "http://127.0.0.1:53001", "bearer": "<minted for this run>"},
 "target": {"url": "http://127.0.0.1:53002", "bearer": "<minted for this run>"},
 "poll_interval_ms": 50,
 "change": {"app": "...", "treeDigest": "sha256:...", "...": "..."},
 "manifest": "apiVersion: apps/v1\n..."}
```

A runtime apply carries `evaluation` (the AuthZEN request to send, exactly) instead of `change` and `manifest`; the
tool's arguments are what it sends the target when it acts. States: `accepted` and `holding` are in flight;
`applied`, `refused` (deliberately did not act: a deny, an expiry, an unreachable core) and `failed` (tried and the
target refused) are final. `spend` is the spend the provider applied for the decision.

The fake target takes `POST /v1/apply {"id", "content"}` with the target bearer, records the sha256 of what it
received and when, and answers `{"seq", "sha256"}`. A real provider's adapter for the test maps that onto its own
action (a sync, an apply, a tool backend).

## What the harness drives and asserts

`clearance conformance` builds a core with `core.Build` on an in-memory store and serves it on loopback. It registers
the provider under the name from `info`, as principal `conformance/provider` (also a verifier), and mints random
bearer tokens for this run: one for the provider, one for the approver `user:conformance-approver` (in the owner
group `group:default/conformance-owners`), one for the target. The change's proposer is
`user:conformance-proposer`. The core's clock is the harness's, so it can move a change past its TTL. A proxy in front
of the core notes each decision's spend and can make the core answer 503 or drop the connection.

Assertion ids are pinned in [`testdata/conformance/assertions.json`](../testdata/conformance/assertions.json)
(suite `clearance-conformance/v1`).

### Runtime

| Assertion | The harness | Passes when |
| --- | --- | --- |
| `control.info` | `GET /conformance/v1/info` | the provider answers and lists the role |
| `runtime.deny-not-acted` | a `repo.pr.open` call whose session does not permit the tool (the core denies it, R006) | state `refused`, the target received nothing, no outcome record |
| `runtime.allow-acted-once` | the same call, permitted | state `applied`, the target received it exactly once (after a hold window for duplicates) |
| `runtime.outcome-references-decision` | reads the chain | exactly one outcome record whose `outcome_of` is the decision's seq and hash, written as the provider, and named in the status |
| `runtime.spend-applied` | compares the status's `spend` with what the core answered | equal for both the deny (`denial`) and the allow (budgets) |
| `runtime.outage-fails-closed` | the core answers 503, then drops the connection | `refused` both times, the target received nothing |
| `chain.verify` | `evidence.Verify` over every record | the chain verifies from genesis and is not empty |

### Deployment

| Assertion | The harness | Passes when |
| --- | --- | --- |
| `control.info` | `GET /conformance/v1/info` | the provider answers and lists the role |
| `deployment.register-subject` | a tier-2 change (a Deployment's replicas) | the core holds a change registered by the provider whose `tree_digest` is the manifest's sha256, and the status names its id |
| `deployment.hold` | waits for `holding`, then a hold window | still `holding`, the target received nothing |
| `deployment.clear` | the approver clears it (`POST /v1/clearances/{id}/clear`) | the change is `cleared` by that person |
| `deployment.release-once` | waits for the provider | `applied`, the target received it exactly once, after the clear, with the cleared digest |
| `deployment.outcome-digest` | reads the chain | exactly one `deploy.outcome` for the change, by the provider, `outcome.applied: true`, `outcome.digests.sha256` equal to the cleared `tree_digest` and to what the target observed (and `subject.digests.sha256`, when given) |
| `deployment.policy-clear` | a tier-0 change (a docs path) | cleared by policy, applied once, with a matching outcome |
| `deployment.deny-never-applied` | a tier-2 change the approver denies | `refused`, the target received nothing, no applied outcome |
| `deployment.expiry-never-applied` | a tier-2 change; the clock moves past the TTL and the gate's expiry runs | `refused`, the target received nothing, no applied outcome |
| `chain.verify` | `evidence.Verify` over every record | the chain verifies from genesis and is not empty |

### Running it

```sh
clearance conformance --provider http://127.0.0.1:9090 --role deployment --report conformance.json
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--provider` | | the provider's control address |
| `--role` | | `runtime` or `deployment` |
| `--report` | | write the JSON report (`conformance.Report`: suite, role, provider, every assertion, the chain head); it never contains a token |
| `--timeout` | 15s | the wait for the provider at each step |
| `--hold-window` | 500ms | how long a held change must stay unapplied, and the wait for a late or duplicate apply |
| `--poll-interval` | 50ms | the poll hint handed to a deployment provider |
| `--listen-host`, `--advertise-host` | 127.0.0.1 | where the core and the target listen, and the host the provider is told |
| `--verbose` | off | log the in-memory core to stderr |

Exit 0 when every assertion passes, 1 when one fails, 2 on a usage or harness error. A provider that does not
answer `info` is one failed assertion, not an error.

## The reference fakes

`internal/conformance/fakes` holds a runtime provider (`fakes.NewRuntime`) and a deployment provider
(`fakes.NewDeployment`) that follow this page, and two broken variants: `Runtime.ActOnDeny` acts on whatever the core
answered, `Deployment.ApplyBeforeClear` applies as soon as it has registered. `go test ./internal/conformance/` runs
the suite against all four: the good fakes pass every assertion; the runtime break fails `runtime.deny-not-acted`;
the deployment break fails `deployment.hold`, `deployment.release-once`, `deployment.deny-never-applied` and
`deployment.expiry-never-applied`. The chain verifies at the end of every run. They are the smallest readable
providers of each role, a starting point for the gateway's and the gates' own adapters.
