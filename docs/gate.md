# The deployment gate (Clearances): design pass, 2026-10-31

Clearance has two boundaries. The **runtime boundary** is built: every tool call an agent makes goes through the
gateway, is decided by policy and recorded as evidence. The **deployment boundary** is this document: may a change
land in a protected environment, and can we prove afterwards that it did so under policy? The product site names the
screen **Clearances**; the UI design doc calls it board C1 and the Tower panels T1. This is the design pass the owner
asked for before anything is built (decision 2026-10-31). It proposes; it decides nothing the owner has not.

## What exists, and what the gate adds

| Today | Gap the gate closes |
|---|---|
| Glidepath opens a **release PR** per Flight environment; a person merges it (Assisted), or one owner signs off first (Hand-flown, a soft `hangar/release-signoff` commit status from Tower). Argo CD syncs the merge. | Nothing looks at **what** the change is. A one-line image bump and a secret-reference rotation are the same PR to GitHub. There is no tiering, no "two people for secrets", and no record that a *change* was cleared, only that a PR was merged. |
| The **agent gates** (`agent-gates-` check) prove whether a PR is the one an agent opened, and that it stayed inside the agent's scope; Clearance records the verdict (`provenance.verify`). ADR-0027 verifies the promoted commit's signature. | Provenance of the *proposer* is known; nothing ties it to a decision about the *change*. |
| Kyverno admits only Flight-registry images on upper clusters (ADR-0029). | Admission knows images, not changes. A `kubectl apply` into prod is invisible to every record. |
| Clearance's runtime record already carries receipts: which agent opened which PR, commit, paths. | The deployment record would be the other half: who let it in, under which policy, bound to which tree. |

The gate adds one thing: a **grant**, Clearance's recorded decision that a specific change may land in a specific
environment, by policy or by named people, bound to exactly what was reviewed. Everything else (tiers, approvals,
the queue, the panels, the marks, admission) is how grants are made and checked.

## Vocabulary

- **Change**: a commit to a gitops repo that Argo CD syncs to a protected environment (today: the merge of a release
  PR to `gitops-<app>` or `gitops-infra-<name>` for an environment with `production: true`, later any protected
  environment). Identified by repo, PR, head commit; described by the **rendered manifest tree** (what Argo would
  apply) and the **objects** in it.
- **Tier** (0 to 3): how much a change can hurt, decided from what it touches, on its own merits at the deployment
  boundary, whoever proposed it (design.md: a T2 runtime proposal is tiered again here).
- **Grant** (a *clearance*): the decision for one change in one environment: cleared by policy, cleared by people, or
  denied. Bound to commit, manifest-tree digest, object list and policy version. An evidence record; in phase 2 also a
  signed attestation.
- **Exception**: a change seen in the environment that no grant covers (an out-of-band apply, a push after clearing).
  Not a decision; a finding that the record keeps and the queue shows.

## Tiers at the deployment boundary

Computed from the rendered diff (objects, not only paths), as the maximum over everything the change touches. The
baseline is platform-owned; a repo's `clearance.yaml` can only **tighten** (add paths to a higher tier, require more
people), never loosen, the way `cicd.yaml`'s `governance` fields work.

| Tier | What it covers (baseline) | Cleared by |
|---|---|---|
| **0** | Docs, tests, comments, labels and annotations without effect, anything outside a runtime path | policy, at once |
| **1** | An image bump on a Flight-registry image (`release.yaml`, the Rollout's image) with CI green, provenance confirmed, under 400 changed lines; ConfigMap data a Rollout does not mount as config of a tier-2 object | policy, at once, when every check holds; else it becomes tier 2 |
| **2** | Runtime shape: replicas, resources, Rollout strategy, `values-<env>.yaml`, NetworkPolicy, HTTPRoute, environment variables, probes | **one** person from the app's owner group, not the proposer |
| **3** | Secrets and their references (Secret, ExternalSecret, SecretStore), RBAC (Role, RoleBinding, ServiceAccount), AppProject, migrations/jobs that write data, anything in `clearance.yaml` itself | **two** people: one from the owner group, one from outside it (a group `clearance.yaml` names: platform-leads, security), neither the proposer |

Tier is a floor: a change touching a tier-3 object is tier 3 however small the edit ("Secrets are tier 3 however
small"). The classifier explains itself: every grant carries **why this tier** (the objects and rules that set it),
which is what the Tower callout and the C1 detail show.

Provenance from the agent gates feeds the tier: a change whose PR is a **confirmed agent** PR is never tier 0 or 1
by policy alone (it is at least tier 1 with every check, so a person sees agent output land); a PR that looks like an
agent's but has no receipt (`unknown → agent`) is **denied** outright, as the agent gates already fail it.

## Who clears, and how

- **By policy**: tiers 0 and 1, when the checks hold: CI green on the PR, provenance confirmed (agent or human, per
  ADR-0027 and the agent gates), the tree renders, admission policies pass offline (ADR-0028). Recorded as
  `deploy.clear` with `principal: policy`.
- **By people**: the delegate model, as every person write in Clearance (decision 2026-10-31): the person clears
  from Tower, Backstage's backend calls the gateway as itself naming them, Clearance checks the person against the
  requirement (owner group, the outside group, not the proposer, not the same person twice) and records
  `deploy.clear` naming person and delegate. `Deny` is `deploy.deny` with a reason. The proposer of a change (the PR's
  author, or the person whose session an agent acted in) **cannot clear it**; the UI hides Clear from them rather than
  letting the gate refuse it.
- A grant **expires**: a change holding for people expires after its TTL (proposed: 7 days, with the PR; Tower
  re-asks on a new push). Expired is a state the queue shows, not a decision.
- Hand-flown release mode becomes a case of the gate: its "one owner, not the merger, approves" is tier 2's rule. Phase
  1 keeps Tower's `hangar/release-signoff` status working beside the gate; the owner decides whether the gate replaces
  it (open question 2).

## Enforcement: soft at merge, hard at admission

**Phase 1, soft (merge time).** A Glidepath check, `clearance-gate-`, on every release PR to a protected environment
(like `agent-gates-`): it renders the tree for the PR head, asks Clearance to register and evaluate the change
(`POST /v1/clearances`, idempotent by repo, PR, head), and reports: cleared by policy (green), holding for N people
(pending, with who may clear and the Tower link), denied (red, with the rule). GitHub Free cannot require a check on a
private repo, so this is a soft gate exactly like today's sign-off status: Tower shows it, the release record keeps
it, a merge past it is a high-severity notification and an **exception** in the record. It is also a release
guardrail (`releaseGuardrails`), so the promotion fan-in waits on it.

**Phase 2, hard (admission time).** The board's promise, "a push after clearing produces a new tree that no grant
covers, so the sync is refused at admission", needs the cluster to know the grants. Three ways, for the owner to pick
(open question 1):

| Option | How | For | Against |
|---|---|---|---|
| **A. Grant-match admission** (recommended) | Clearance publishes each grant to the target cluster as a `Clearance` resource (one CRD, cluster-scoped, named by app and environment) holding the granted objects' specs. A Kyverno ValidatingPolicy on protected namespaces, matching Argo CD's service account, looks the grant up and admits an object only when its spec equals the granted one. Anything else (a drifted push, a `kubectl apply`) is refused and recorded as an exception by the policy's own report. | Enforcement is in the cluster, independent of GitHub and Argo; exceptions are caught by construction; same containment pattern as AgentRun (one kind, the composition decides). | Clearance gains a cluster write (publishing grants) per protected cluster, the same departure D3 already accepted for AgentRun; deep-equality on specs needs care with defaults and mutating webhooks (compare the rendered, server-side-dry-run-normalised spec). |
| **B. Sync by grant** | Protected Argo Applications get a manual sync policy; Clearance's controller calls Argo's sync API with the granted revision once a grant exists. | No admission policy to write; Argo's own UI shows what is pending. | Clearance holds an Argo write credential; a `kubectl apply` is still invisible; a rogue push is only prevented until someone syncs by hand. |
| **C. Protected branch** | Argo syncs a `prod` branch that only the gate fast-forwards to a granted commit. | Pure git; easy to audit. | Clearance holds a git write credential on every gitops repo; `kubectl apply` invisible; two branches to reason about. |

Phase 2 also brings the **attestation**: each grant signed (Fulcio/Rekor like the release signing policy), so the
"clearance attestation ✓" mark on a release is a verifiable statement, and the ledger and packet (SOC 2 CC8.1 first)
read from it.

## The record

Evidence records, in the existing chain, `boundary: deployment`:

| Tool | When | Carries |
|---|---|---|
| `deploy.request` | the check registers a change | app, env, repo, pr, commit, tree digest, objects, tier and why, provenance, requirement |
| `deploy.clear` | policy or a person clears | principal (policy or the person), via, which requirement it satisfies |
| `deploy.deny` | a person denies, or the classifier denies (unknown agent) | reason, rule |
| `deploy.expire` | the TTL passes | — |
| `deploy.exception` | admission or the controller sees a change no grant covers | object, who applied it (the admission request's user) |

Apps' owners see their apps' records (the existing `app` scoping); the C1 queue is for everyone who may clear
something; auditors see all. The run that drafted the change links by `task_id` through the PR receipt.

## API

Gateway (writes, delegate model): `POST /v1/clearances` (the check: register or re-evaluate a change; the caller is a
verifier, like `/v1/provenance`), `POST /v1/clearances/{id}/clear`, `POST /v1/clearances/{id}/deny` `{reason}`.
clearance-api (reads): `GET /v1/clearances?app&env&state&since`, `GET /v1/clearances/{id}`, `GET /v1/clearances/counts`,
and the policy in force per environment `GET /v1/clearance-policy?app&env` (the tiers and approvers that apply).

## Screens

- **Clearance › Clearances** (C1): stats (holding for a person, cleared by policy and by a person in 24 h, exceptions,
  coverage: protected environments with the gate on); change traffic by tier with provenance and state; the detail
  with why-this-tier, approvals (cleared, needed, and whether *you* qualify), what the grant binds to, provenance
  verified versus claimed, the runtime task; **Clear as <you>**, **Deny…**, the rendered diff. Tabs Active, Cleared
  today, Denied, Exceptions.
- **Tower › app › Clearance** (T1): the needs-you callout for a change holding on this app; the change policy per
  environment (protected, coverage, 24 h counts, the tiers for this app); the existing agent panels stay.
- **Marks**: Pull requests "tier 2 · holding" on the release PR; Releases "clearance attestation ✓" once signed;
  the agent-request-style chip and toast for a change holding for *you*.

## Phases

1. **Dec 2026, soft gate**: classifier (rendered diff, baseline tiers, `clearance.yaml` tighten-only), `deploy.*`
   records, grants in Postgres, gateway and read API, the `clearance-gate-` check and release guardrail, C1 page, T1
   panels and the PR mark, Slack/PR comment through the check. Hand-flown's sign-off runs beside it.
2. **Jan 2027, hard gate**: grants published to the cluster, grant-match admission (option A unless decided
   otherwise), exceptions from admission, signed attestations, the "clearance attestation ✓" mark, ledger and packet.
3. **Later**: AgentRun claims gated at admission (roadmap phase 5, the native entry point); the gate as an AuthZEN PDP
   behind a proxy (D17) if Hangar ever runs one.

## Open questions for the owner

1. Phase 2 enforcement: A (grant-match admission, recommended), B or C.
2. Does the gate **replace** Tower's Hand-flown sign-off (one rule, one record), or run beside it for a release?
3. Where `clearance.yaml` lives: in each gitops repo beside the environments it governs (recommended: it changes with
   the environment, it is tier 3 itself, and the platform baseline lives in the catalog like `releaseSigning`), or
   centrally in the platform's catalog only.
4. The outside group for tier 3: `group:default/admins` today (it exists), or new `platform-leads` / `security`
   groups.
5. Holding TTL: with the PR (7 days) or shorter (the board shows an hour); and whether a new push re-asks (recommended:
   yes, a new head is a new change).
