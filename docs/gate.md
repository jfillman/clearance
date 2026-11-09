# The deployment gate (Clearances): design pass, 2026-10-31

Status (v0.30.0): **phase 1a built** (the gate's core, v0.19.0; in Go since R-1c), fed by Glidepath's
`clearance-gate-` check (advisory on Hangar) and `clearance register` (v0.23.0), and answered to GitHub Actions
deployments by the App's protection rule (v0.22.0; [provenance-app.md](provenance-app.md)). **Not built**: phase 2
admission (the pulled grant and the admission policy), `deploy.exception` and outcome records. **Phase 2's shapes are
chosen** ([Phase 2 design pass](#phase-2-design-pass-g-argo-1-2026-11-03), Draft, spiked on hangar-dev 2026-11-03):
the admission policy is a native ValidatingAdmissionPolicy, not the Kyverno policy the first draft below names. The
design below is as reviewed; the Built sections at the end say what exists.
G-TF-1 adds a second subject beside the manifest tree, a saved Terraform plan, with its
own tier table ([The terraform-plan subject](#the-terraform-plan-subject-g-tf-1)), and defines the digest a manifest
change binds to ([The manifest-tree digest](#the-manifest-tree-digest-built)).

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

Which registries count as Flight is deployment configuration, `CLEARANCE_TRUSTED_REGISTRIES` (prefixes ending in `/`). Unset, the product default, any registry counts and the `image:not-trusted-registry` rule never fires. Hangar sets `ghcr.io/riley-roooo/` from the R-4 cutover (decided 2026-11-03): a bump to any other image, the third-party images Kyverno allows included, is tier 2 and waits for one owner.

Tier is a floor: a change touching a tier-3 object is tier 3 however small the edit ("Secrets are tier 3 however
small"). The classifier explains itself: every grant carries **why this tier** (the objects and rules that set it),
which is what the Tower callout and the C1 detail show.

Provenance from the agent gates feeds the tier: a change whose PR is a **confirmed agent** PR is never tier 0 or 1
by policy alone (it is at least tier 1 with every check, so a person sees agent output land); a PR that looks like an
agent's but has no receipt (`unknown → agent`) is **denied** outright, as the agent gates already fail it.

## Who clears, and how

- **By policy**: tiers 0 and 1, when the checks hold: CI green on the PR, provenance confirmed (agent or human, per
  ADR-0027 and the agent gates; `unattested`, AI-co-authored work outside Clearance, counts as `not-agent`: a warning,
  never a tier, [provenance-app.md](provenance-app.md#ai-co-author-trailers-agent-unattested-built)), the tree renders, admission policies pass offline (ADR-0028). Recorded as
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
| `deploy.clear` | policy or a person clears | principal (policy or the person), via, which requirement it satisfies; `approvals` (each person's IdP `sub` and `iss`, `via`, `role`, `at`), `cleared_by`, and `token` (the clearance token's nonce) when it cleared the change (C-1) |
| `deploy.revoke` | a new head supersedes a cleared change | the revoked token's nonce and the head that superseded it (C-1) |
| `deploy.attestation` | the core signed the change's attestation after an applied `deploy.outcome` (C-2) | `attestation` {digest (sha256 of the DSSE envelope), backend, outcome_seq, rekor_log_index, rekor_uuid, key_id}; [core.md](core.md#change-attestations) |
| `deploy.deny` | a person denies, or the classifier denies (unknown agent) | reason, rule |
| `deploy.expire` | the TTL passes | — |
| `deploy.exception` | admission or the controller sees a change no grant covers | object, who applied it (the admission request's user) |

Every `deploy.*` record also carries a `policy` group naming the policy that decided and the policy engine's
verdict (C-8, "The policy in the record" below).

Apps' owners see their apps' records (the existing `app` scoping); the C1 queue is for everyone who may clear
something; auditors see all. The run that drafted the change links by `task_id` through the PR receipt.

## API

Gateway (writes, delegate model): `POST /v1/clearances` (the check: register or re-evaluate a change; the caller is a
verifier, like `/v1/provenance`), `POST /v1/clearances/{id}/clear`, `POST /v1/clearances/{id}/deny` `{reason}`.
The core also answers `GET /v1/clearances/{id}` (C-1) to a registered provider and to the verifier that registered
the change: the state and the live clearance token, the read a gate provider waits on (and its long-poll,
`.../{id}/wait`, C-10), and `POST /v1/clearances/{id}/outcome` (G-TF-2): a terraform-plan change's apply result, from
its registrant.
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

## Decided 2026-10-31

The owner answered all five questions below (the first on 2026-10-31 after the expansion that follows the table).

| # | Question | Decision |
|---|---|---|
| 1 | Phase 2 enforcement | **A, grant-match admission, with the grant pulled** by a sync on the protected cluster ("A without a remote write" below). Clearance keeps no credential for any other cluster; the upper cluster reads clearance-api as Tower already does. B and C are not pursued. |
| 2 | Hand-flown sign-off | **The gate replaces it.** Tier 2's rule ("one owner, not the proposer") is Hand-flown's rule, so the `clearance-gate-` check becomes the thing Tower shows and the release guardrail waits on; the `hangar/release-signoff` status retires when the check ships (phase 1). One rule, one record. |
| 3 | Where `clearance.yaml` lives | **In each gitops repo**, beside the environments it governs, tighten-only; the platform baseline (the tier table above) lives in the catalog like `releaseSigning`, never in `cicd.yaml`. |
| 4 | The outside group for tier 3 | **`group:default/admins`** for now, because it exists; a `security` group when there are people to put in it. The requirement reads "one from the owner group, one from the outside group, neither the proposer"; a person in both counts once. |
| 5 | Holding TTL | **7 days, with the PR.** A new push is a new change: the check re-registers it (new tree digest), the old grant request expires as `deploy.expire`, and the people are asked again. |

### Question 1, expanded: how the hard gate enforces (phase 2)

The soft gate (phase 1) is the same whichever option is chosen; the question is what stops a change that no grant
covers from reaching a protected cluster. What each option actually protects against, on Hangar as it is:

| | A. Grant-match admission | B. Sync by grant (Argo) | C. Protected branch |
|---|---|---|---|
| A push to the gitops repo after clearing (the tree changed) | Refused at admission: the object's spec is not the granted one | Prevented until someone syncs by hand; a manual sync in the Argo UI applies it | Prevented: the branch Argo watches moves only to granted commits |
| A `kubectl apply` into prod | Refused (Argo's service account is matched; anyone else is refused by the same policy on protected namespaces) | Invisible | Invisible |
| Argo auto-sync of an ungranted commit | Refused per object | Off by design (manual sync policy) | Not possible: the branch is the grant |
| What Clearance must hold | **Nothing on the protected cluster.** The grant is *pulled*: a small grant sync on the upper cluster reads clearance-api (as Tower on hangar-prod already does) and writes the `Clearance` objects itself; Clearance keeps no credential for any other cluster (see "A without a remote write" below) | An Argo CD API credential on the protected cluster: a remote write, which breaks the rule, unless a prod-side syncer pulls the granted revision and triggers the sync | A git credential able to push to every gitops repo's protected branch; no cluster write at all |
| How an exception is caught | By construction: the admission refusal is the record (`deploy.exception` from the policy report, with the requester) | Not caught: nothing watches what was applied by hand | Not caught for `kubectl apply`; a push to the watched branch is impossible, so there is nothing to catch |
| Blast radius of a mistake in the mechanism | A Kyverno `ValidatingPolicy` with `failurePolicy: Fail` on protected namespaces: a CEL error refuses every matching admission cluster-wide (the lesson of the fail-closed webhooks: `has()`-guard every `matchConditions` expression, match only Argo's service account and the protected namespaces, keep Kyverno itself out of scope). A broken grant publish blocks syncs, not running workloads | A stuck controller means no syncs; a bad one syncs the wrong revision | A bad fast-forward moves prod; recovery is a revert commit |
| Spec equality | Needs care: compare the server-side-dry-run-normalised rendered object (defaults, mutating webhooks, Argo's tracking labels), not the raw manifest | Not needed | Not needed |
| Effort | The CRD, the publisher in the gateway, the policy, the normaliser, the report-to-exception bridge; the most new code | A controller calling Argo's sync API; the least new code | The fast-forward step in the check; small, but a second branch per gitops repo and Argo repointed |

#### A without a remote write: the grant is pulled

Hangar's rule is that nothing on the control plane writes to a protected cluster: durable changes reach it as commits
that its own Argo CD pulls, and Clearance's one Kubernetes write (AgentRun) is on the control-plane cluster only. The
first draft of A said "Clearance publishes each grant to the target cluster", which would break that rule. It does
not have to. Grants travel the way everything else reaches an upper cluster: the cluster **pulls** them.

- **The grant lives in Clearance** (Postgres, `deploy.clear` evidence, in phase 2 a signed attestation), and
  clearance-api serves it: `GET /v1/clearances?cluster=<name>&state=cleared`.
- **A grant sync runs on the protected cluster** (`clearance-grant-sync`, part of the cluster repo's Autopilot layer
  for upper clusters). Every 30 s it reads clearance-api as its own identity, the same foreign-workload path Tower's
  backend on hangar-prod uses today (verified against the cluster's public issuer, read-only), verifies each grant's
  attestation against Clearance's public key, and creates, updates or removes the local `Clearance` objects. It is the
  only identity that may write that kind: a second admission rule refuses everyone else.
- **The admission policy reads only local objects.** Kyverno's ValidatingPolicy on protected namespaces matches Argo's
  service account and admits an object when its normalised spec is in the local grant. No network call at admission
  time, nothing to time out.
- **Exceptions flow outward, not inward.** The sync reads the policy reports and posts them to the gateway as
  `deploy.exception` (an API call with its own identity, like `/v1/provenance` from the agent gates), so the record
  is complete without Clearance ever reaching into the cluster.
- **Failure mode.** clearance-api unreachable: grants stop updating, so *new* changes cannot land until it is back
  (fail closed at the gate, nothing running is touched); existing grants stay. A broken sync is the same. This is the
  cost of a hard gate and the behaviour the design wants.

Where the credentials sit, then: the upper cluster holds a read token for clearance-api (it already does), Clearance
holds nothing for the upper cluster, and the only writer on the upper cluster is still Argo CD plus one in-cluster
sync writing one kind. Option B, read the same way, would need a prod-side syncer to trigger the Argo sync for the
granted revision; a control-plane call to prod's Argo API would be the remote write the rule forbids. Option C never
touches the cluster.

Why A is still the recommendation: pulled, it writes nothing to the cluster from outside; it is the only option whose promise matches the board's ("a push after clearing
produces a new tree that no grant covers, so the sync is refused at admission"), the only one that sees
`kubectl apply`, and the one whose record is produced by the thing that enforces. Its two costs are real: Clearance
writes to the cluster (as it already does for AgentRun, narrowly), and spec equality is engineering, not a lookup.
B is a good interim if phase 2 must land quickly: it needs no admission policy and Argo shows what waits, but it
protects only against auto-sync, and it hands Clearance an Argo credential. C is the cheapest to reason about and the
weakest: it moves the trust to whoever can push the protected branch, and Clearance becomes that someone.

A middle path worth considering: ship **B first as phase 2a** (weeks, not months: Applications of protected
environments go manual, the gateway syncs on `deploy.clear`), and **A as phase 2b** once the normaliser exists,
keeping B's manual sync policy as defence in depth. The record is the same either way.

## Phase 2 design pass (G-ARGO-1, 2026-11-03)

Status: **Draft** as a design record; the shapes below are chosen, and since then built (the admission policy and
grant, G-ARGO-2; the agent, G-ARGO-3; the plugin and the PreSync wait, G-ARGO-4 and G-ARGO-5; the release join,
G-ARGO-6: each section says its own status). Each was spiked on hangar-dev (Argo CD 3.5.0,
Kubernetes 1.36.5, Kyverno 1.19.0) in scratch namespaces created and deleted for the purpose, in Warn mode only. The
two measurements that only mean something on hangar-prod (Kyverno's failure modes under prod load, the cross-cluster
path) are prepared for the user in [spikes/g-argo-1/prod-plan.md](spikes/g-argo-1/prod-plan.md) and are
**Unverified** until the user runs them. The spike code and manifests are in [spikes/g-argo-1/](spikes/g-argo-1/).
The hangar decisions D25 to D29 record the choices.

### The chosen shapes

| Question | Chosen | Why, in one line |
| --- | --- | --- |
| (a) Where the CMP sits in a tenant Application | **The plugin replaces the Helm source.** The plugin source is the gitops (values) repo; the CMP fetches the airframe chart at the pinned tag and renders it with those values. The Application keeps no other generating source | A plugin source is handed only its own repository: `$appsrc` never reaches it (a1), and objects from any other source are not stamped |
| (b) What a grant matches | **The `clearance.hangar.io/rendered` annotation the CMP stamps**, keyed by group/kind/name, never the live spec | The stamp survived Argo's tracking annotation, a mutating policy and API-server defaulting byte for byte; the live object's canonical hash differed from the render for every object |
| (c) The admission engine | **A native ValidatingAdmissionPolicy**, `paramKind: ClearanceGrant`, one binding, `paramRef` by selector with **exactly one active grant per protected namespace**, objects as a map | In-process (about 1 ms, no webhook to time out); Kyverno's webhook refused Argo's writes in Audit/Warn mode while its controller was down on hangar-dev |
| (d) The outcome source | **The agent watches Application status** | The watch saw every operation within a second, including one Notifications lost for good when its receiver was down for 30 s |
| (e) How prod reaches the core | **Two more hangar-prod foreign workloads** on the existing path (prod issuer, Traefik route, hostAlias): the CMP as `argocd-apps/argocd-apps-repo-server`, the agent as its own service account | The core's foreign authenticator already takes a list of service accounts; three config lists and one route change, no code |

### (a) The Config Management Plugin on a multi-source Application

Hangar's tenant Applications are multi-source: on hangar-prod the airframe chart (a Helm source whose value files
are `$appsrc/hangar-prod/...`) and the `gitops-<app>` repo as `ref: appsrc`; on hangar-dev a third source,
`charts/glidepath-env`. The spike ran three shapes on a namespaced Argo CD 3.5.0 with a spike plugin
([spikes/g-argo-1/cmp](spikes/g-argo-1/cmp/main.go)), against the real airframe chart at v0.3.168 and a values file in
this repository standing in for the gitops repo:

| Shape | Result |
| --- | --- |
| control: today's Helm source with `$appsrc` value files | renders the values (4 objects) |
| a1: the plugin source **is** the chart; its parameters name `$appsrc/...` value files | the plugin gets the chart directory only (22 files), no `ref` variable in its environment and no `$appsrc` path anywhere; it rendered the chart's **defaults** (2 objects, empty names) **without any error**. A plugin cannot read a ref source |
| a2: the plugin **replaces** the Helm source: it sits on the values repo and clones the chart at the pinned tag (`v0.3.168`, peeled to commit `c7e846a`) | renders the values (4 objects plus a ConfigMap from a plain directory source beside it); the stamps on the 4 chart objects matched a render of the same inputs on a laptop, so the render is deterministic across machines |
| deny: the plugin exits 1 | `ComparisonError: ... CMP processing failed ... tier 3 change denied by policy (spike): DG-POLICY; nothing syncs`, as G-ARGO-4 wants |

What follows for G-ARGO-4 and the ApplicationSet template:

- The protected Application has **one generating source**, the plugin on `gitops-<app>`; the chart's repo, tag and
  path are plugin parameters set by the tenant-onboarding template (`#@if clearance.gate.enabled`). The `ref: appsrc`
  source can stay for the template's other environments but means nothing to the plugin. Any other generating source
  (hangar-dev's `glidepath-env`) must be rendered by the CMP too or left out of protected apps: an object from a
  non-plugin source carries no stamp and admission refuses it (seen in a2: the directory source's ConfigMap was the
  one object the policy flagged as unstamped).
- The CMP fetches the chart itself. On Hangar the airframe repo is public, so a shallow clone at the tag works; the
  CMP records the **peeled commit**, not the tag, in the change subject. A customer's private chart means an OCI
  chart pulled by digest with a registry credential mounted into the sidecar only. The gitops repo stays Argo's to
  fetch with its own repository credentials, which the CMP never sees.
- The render is `helm template <Application name> <chart> --namespace <destination>`: the release name and the
  namespace are part of what is hashed (the chart stamps `app.kubernetes.io/instance`), so the Tekton
  `clearance-gate` render must use the same two values for the parity test (G-ARGO-8).
- The CMP computes the tree root as [The manifest-tree digest](#the-manifest-tree-digest-built) defines it (G-TF-1);
  the spike plugin's own line format predates that definition and is not the one to build.
- The CMP must set `metadata.namespace` to the destination on every namespaced object **before** hashing. Argo adds
  it to objects that lack it (the chart's `extraManifests` do), and without it the agent cannot reproduce the stamp
  (see b).
- **The merge commit is not the PR head.** The clearance-gate check registers the PR head; Argo syncs the merge
  commit on `main`. The rendered tree is the same, the commit is not, so the CMP must find the cleared change by
  **tree digest** (app, env, tree), not by repo, PR and head. G-ARGO-4 and C-10 gain that lookup: a registration
  without `pr` answers the cleared change for the same app, environment and tree, and otherwise registers a new one.
- The CMP renders tenant input while holding a verifier token. Helm templates cannot execute code and the CMP runs no
  Kustomize exec plugins, but a CMP compromise would be a gate bypass (it chooses what it registers and stamps), so
  the sidecar is its own minimal image, mounts the clearance token in its container only, and the G-ARGO-8 parity
  render on the control plane is the second opinion.

### (b) Grant matching on the stamped annotation

The question was whether the `clearance.hangar.io/rendered` annotation survives to admission and the live object,
and whether normalised spec equality is workable instead. a2 was synced into a protected scratch namespace with a
`MutatingAdmissionPolicy` that adds a label and an annotation to Deployments, under the spike's admission policy in
Warn.

- **The stamp survived** on every object, unchanged and equal to the CMP's hash: Argo added
  `argocd.argoproj.io/tracking-id` and `kubectl.kubernetes.io/last-applied-configuration`, the mutating policy
  added its label and annotation, and the API server defaulted the Deployment (`strategy`, `revisionHistoryLimit`,
  `progressDeadlineSeconds`, `imagePullPolicy`, `terminationMessagePath`, `dnsPolicy`).
- **Spec equality fails without a normaliser that knows every defaulter.** The canonical hash of the live object
  differed from the stamp for all four objects, the plain ConfigMap included (Argo's own annotations are enough).
- **The agent can still check content.** Argo applies client-side, and its `last-applied-configuration` is the
  rendered object plus the tracking id: hashing it with the tracking id removed reproduced the stamp for the
  ConfigMap, the ServiceAccount and the NetworkPolicy, and for the Deployment once the CMP's missing namespace was
  accounted for. That is the exception scan G-ARGO-3 needs ("a hash no grant lists"), without a normaliser. A sync
  with `ServerSideApply=true` has no last-applied annotation; protected apps stay on client-side apply until the
  agent reads Argo's managed fields instead.
- What the stamp does not do: admission cannot hash content (Kubernetes CEL has no digest function). A writer that
  copies a valid stamp onto other content is admitted, which is why the policy matches only Argo's controller (any
  other writer is the agent's exception, by construction), the CMP alone computes stamps, and the agent's scan
  compares the stamp with the last-applied content.

### (c) The native ValidatingAdmissionPolicy against a Kyverno ValidatingPolicy

Both policies were written for the same rule ([30-vap.yaml](spikes/g-argo-1/manifests/30-vap.yaml),
[31-kyverno.yaml](spikes/g-argo-1/manifests/31-kyverno.yaml)): match only Argo's application-controller, only
CREATE and UPDATE of main resources (`!has(request.subResource) || request.subResource == ''`), only namespaces
labelled `clearance.hangar.io/protected=true`; admit when the stamped object is listed in a valid grant at that hash.
Each case below was a server-side dry run impersonating the controller ([run-c.sh](spikes/g-argo-1/run-c.sh)):

| Case | Native VAP (Warn) | Kyverno ValidatingPolicy (Audit, Warn) |
| --- | --- | --- |
| listed, stamped hash | admitted | admitted (when Kyverno was up) |
| stamp changed | warned: does not list ... at sha256:00 | warned |
| unlisted object | warned | warned |
| no stamp | warned | warned |
| another writer (cluster admin) | not matched | not matched |
| the `scale` subresource as the controller | not matched | not matched |
| grant marked invalid (`status.valid: false`) | warned | not checked: Kyverno has a clock, so it checks `expiresAt` instead (warned: expired) |
| grant named by the stamp does not exist | n/a (selector) | warned: not found |
| two active grants, the object in one | **warned by the other**: `paramRef` by selector evaluates every matching grant and each must pass | admitted (the stamp names the grant, `resource.Get` reads that one) |
| no grant at all, `parameterNotFoundAction: Deny` | **refused, in Warn**: a missing param is a binding error, not a validation result, so `validationActions: [Warn]` does not soften it. Argo's whole sync failed on it | n/a |
| no grant at all, `parameterNotFoundAction: Allow` | admitted silently (no warning, even with a bad stamp) | n/a |
| Kyverno's admission controller down (234 to 237 restarts on hangar-dev during the spike) | unaffected | **refused**: `failed calling webhook ... connection refused` or `context deadline exceeded` (10 s timeout), in Audit/Warn, because the policy is `failurePolicy: Fail`. Argo failed to sync the Deployment four times in a row; 16 of 30 webhook calls were rejected with 503 |
| the policy deleted while Kyverno is down | gone at once | its webhook stayed about 4 minutes, until the controller came back to reconcile it |

Cost and latency:

- **CEL cost**, measured with the API server's own admission CEL compiler and evaluator (k8s.io/apiserver v0.36.3,
  [celcost](spikes/g-argo-1/celcost/cost_test.go)): with the grant's objects as a **list** and `exists()`, a
  200-object grant costs 4,647 units (2,000 objects: 46,047); with a **map** keyed by group/kind/name, 52 units
  whatever the size. The budget is 10,000,000 per binding and 1,000,000 per expression, so neither shape is close,
  but the map is constant and is the one chosen. The API server type-checked the policy against the CRD's schema
  with no warnings.
- **Latency** (API server metrics on hangar-dev): the VAP's checks took 21 ms for 20 evaluations, about 1 ms each;
  the Kyverno webhook averaged 0.5 to 1.2 s per call when it answered.
- Kyverno's 1.19 webhook is fine-grained: it carried the policy's namespace selector and match condition, so its blast
  radius was the policy's scope. Inside that scope, though, its availability is the gate's.

What follows for G-ARGO-2:

- **Native VAP.** One policy, one binding, `paramRef` by selector `clearance.hangar.io/active=true` with no
  namespace (the grant is read from the admitted object's own namespace).
- **Exactly one active grant per protected namespace.** Because every selected grant must pass, the agent labels only
  the newest cleared grant active and that grant lists **every** object of its tree (with `changed` marking the diff),
  so unchanged objects stay admitted. Older grants stay for the record, unlabelled; what they list reaches admission only through `spec.carried` of the active
  one (see "The running tree and the active grant").
- **Expiry is the agent's.** Kubernetes CEL in admission has no clock; the agent sets `status.valid` (status
  subresource, written only by the agent) and removes the active label on expiry, and the policy checks
  `status.valid`.
- **The Warn to Deny toggle flips two fields**, `validationActions` and `parameterNotFoundAction` (Allow in Warn,
  Deny in Deny), and Warn has a gap the agent covers: with no grant, nothing warns.
- `auditAnnotations` must be typed: `string(params.metadata.name)` (an untyped `params.metadata.name` is refused at
  create).
- Kyverno is not used for the gate. It stays Hangar's Flight-registry policy engine; a Kyverno outage must not decide
  whether a protected sync can land.

### (d) The outcome source

The same Application was synced with Argo CD Notifications sending a webhook on every finished operation
([50-notifications.yaml](spikes/g-argo-1/manifests/50-notifications.yaml)) and a watch on the Application beside it
([run-d.sh](spikes/g-argo-1/run-d.sh)):

| | Watch on Application status | Notifications webhook |
| --- | --- | --- |
| receiver or agent up | saw `Running` and then `Succeeded` within a second of `finishedAt` | delivered once, about 3 s after `finishedAt` |
| receiver down for one sync (30 s) | saw it (a watch relists on reconnect, so a restarted agent catches up from state) | 4 attempts in 8 s, then `giving up`, and the trigger was marked sent: **the outcome was lost for good** |
| first start | the current state | it back-filled two operations that had finished 9 and 22 minutes earlier |
| multi-source | `status.sync.revisions` and `status.operationState.syncResult.revisions` (plural) | the template's `.app.status.sync.revision` was empty (`<no value>`) |
| credential | the agent's own read of Applications on its cluster | the notifications controller would hold a token for the core on the protected cluster |

Glidepath's relay already lives with this (its doc: Rollouts and Argo notifications are at-most-once and fail
silently; the 15-minute heartbeat is the retry). An outcome record cannot wait for a heartbeat: it is what C-2
signs. **The agent watches.** It keys each outcome by the operation's `finishedAt` and the Application's UID, posts
it once (`deploy.outcome` through `POST /v1/records`, or the change-bound route when C-10 has it), and on restart
reposts the last operation, which the core must answer idempotently. It reports only an Application whose destination
namespace is labelled protected: a project can hold an environment the gate doesn't protect, such as a staging beside a
gated prod, and the agent has no read there.

### (e) How the CMP on hangar-prod reaches the core on hangar-dev

The path exists: hangar-prod Backstage (service account `app-backstage-prod/backstage-ingestor`) holds a projected
token with audience `clearance`, reaches `clearance.hangar-dev.local` and `clearance-api.hangar-dev.local` through a
hostAlias to hangar-dev's ingress (192.168.1.72) and Traefik, and the core verifies the token against hangar-prod's
public issuer `https://hangarplatform.dev/oidc/hangar-prod` (`CLEARANCE_FOREIGN_*`, principal
`hangar-prod/<namespace>/<sa>`).

- **More than one service account: supported.** `CLEARANCE_FOREIGN_SERVICE_ACCOUNTS` is a comma-separated list of
  `<namespace>/<sa>` globs (`internal/authn`, `ForeignWorkloadAuthenticator.Allowed`). A new test,
  `TestSeveralServiceAccountsOfOneForeignCluster`, proves three prod accounts authenticate as three principals and a
  sibling account in the same namespace is refused. **Limit:** one foreign cluster per core (one issuer); a second
  protected cluster needs a list of issuers, a code change for later.
- **The CMP's identity** is the repo-server pod's service account, `argocd-apps/argocd-apps-repo-server`, with the
  projected `clearance` token mounted into the CMP sidecar only. **The agent** gets its own,
  `clearance-system/clearance-argocd-agent` (name to be fixed by G-ARGO-3).
- **Config changes, all apron values for hangar-dev, no code:**

  | Where | Change |
  | --- | --- |
  | `clearance-core` `CLEARANCE_FOREIGN_SERVICE_ACCOUNTS` | add `argocd-apps/argocd-apps-repo-server` and the agent's account |
  | `clearance-api` `CLEARANCE_FOREIGN_SERVICE_ACCOUNTS` (its own copy) | add the agent's account (the grant feed is read there) |
  | `CLEARANCE_VERIFIERS` | add `hangar-prod/argocd-apps/argocd-apps-repo-server` (the CMP registers changes) |
  | `CLEARANCE_PROVIDERS` | `argocd-cmp` for the repo-server principal; `argocd-agent` for the agent's, `kinds: [deploy.outcome, deploy.exception]` |
  | clearance-api roles | a grant-feed reader role for the agent's principal (today only auditors, notifiers, delegates and owners exist): C-10's work |
  | HTTPRoute `clearance-github-webhook` | add `Exact /v1/records` (probed from the laptop: `/v1/clearances` reaches the core, 401 without a token; `/v1/records` is a Traefik 404 today) |
  | hangar-prod, argocd-apps Helm values and the agent's chart | the hostAlias and an egress NetworkPolicy to 192.168.1.72:80 for the repo-server and the agent |
- **The route is plain HTTP across the LAN**, as Tower's is today (https on `*.hangar-dev.local` is a Traefik 404). A
  verifier token on that hop is a lab limitation the decision records; a real deployment terminates TLS at the route.
- **The grant feed's seq is not enough on its own.** C-10 (clearance#58) signs a grant feed per cluster whose seq
  restarts at 1 if the core's database is rebuilt. G-ARGO-3's grant sync must therefore keep a feed epoch beside the
  seq it last applied (the chain's genesis hash or a per-database id that the feed carries), so it can tell a rebuilt
  core (new epoch: start again at 1) from a replay (same epoch, lower seq: refuse) without an operator resetting its
  stored seq.

### G-ARGO-2: the grant and the admission policy (Built)

Status: **Built** (manifests in [`providers/argocd/crd/`](../providers/argocd/crd/), tested against a real
kube-apiserver); **not yet applied** anywhere. Apron renders them into an upper cluster
(`56-clearance-gate/`, `clearance.gate.enabled`), in Warn until `clearance.gate.enforce`.

- **`ClearanceGrant`** (`clearancegrants.clearance.hangar.io/v1`, namespaced in the protected namespace):
  `spec.subject` (`commit`, `tree`: the [manifest-tree digest](#the-manifest-tree-digest-built) root),
  `spec.objects` (a **map** keyed `<group>/<kind>/<name>`, core group empty, each `{rendered, changed}`: every object of the
  tree, not only the diff), `spec.expiresAt`, `spec.clearance` (`id`, `tier`, `policy.name`/`version`), `spec.signature`
  (the signed grant the agent verified; admission does not read it), and `status.valid` (with `reason`, `checkedAt`), a
  status subresource. This follows D27, not the card's `objects[]` list.
- **`clearance-protected-writes`** (ValidatingAdmissionPolicy, `paramKind: ClearanceGrant`) matches CREATE and UPDATE
  of namespaced main resources in namespaces labelled `clearance.hangar.io/protected=true`, and only when the writer is
  `system:serviceaccount:argocd-apps:argocd-application-controller` (every `matchConditions` term `has()`-guarded). It
  requires the object's `clearance.hangar.io/rendered` stamp, the namespace's active grant to be `status.valid`, and
  the grant to list the object's key at exactly that stamp. `auditAnnotations` carries `grant: <name>`. **One**
  binding, `paramRef` by selector `clearance.hangar.io/active=true` with no namespace: the grant is read from the
  object's own namespace, and the agent keeps exactly one active per namespace.
- **`clearance-grant-writer`** admits CREATE and UPDATE (and `/status`) of a ClearanceGrant only from
  `system:serviceaccount:clearance-system:clearance-argocd-agent`. DELETE is left alone so a namespace can be deleted.
- **Warn to Deny** flips two fields together on the first binding: `validationActions` `[Warn, Audit]` to `[Deny, Audit]`
  and `parameterNotFoundAction` `Allow` to `Deny`; the grant-writer binding follows `validationActions`.
- **Found while testing: a Deny binding with no active grant refuses every matched write in the namespace, from any
  user,** because the API server resolves the param before it evaluates `matchConditions`. The spike saw this only
  for Argo. Consequences: the agent must always leave one active grant on a protected namespace (the order is: create
  the grant, then label the namespace protected); the policy excludes what the agent needs to bootstrap and what the
  control plane writes on its own and Argo never applies (`clearancegrants`, events, endpoints, endpointslices,
  leases); and Deny with no grant freezes the namespace's controllers (a ReplicaSet cannot create Pods) until a grant
  is active. That is the fail-closed outcome the design wants, but it is why Warn uses `Allow`.
- **Envtest** (`providers/argocd/crd/test_admission.py`, CI `admission-policy`, 189 checks over both modes): admit (listed
  ConfigMap and Deployment, an update; a carried tree's hash, below); refuse (unlisted, wrong hash on create and update, no stamp, `generateName`
  with no name, expired grant, grant with no status, two active grants, no active grant); not matched (another
  writer, another service account, an unprotected namespace, a labelled Namespace object, the `scale` subresource);
  grant writes (agent only, status included, the CRD's schema); the audit annotation in the API server's audit log; no
  CEL error in any response.
- **The injected wait Job (G-ARGO-4).** The CMP adds an unstamped PreSync Job labelled
  `clearance.hangar.io/injected: wait`. The policy exempts only a Job that is **exactly what the CMP builds**
  (`providers/argocd/cmp/job.go`), as an **allowlist of fields**: any Job, pod or container field the CMP does not set
  is refused (probes, `lifecycle`, `dnsConfig`, `serviceAccountName`, `nodeName`, tolerations, init containers, host
  namespaces, ports, sysctls, `ttlSecondsAfterFinished`, ...), except the values the API server defaults before
  admission (`dnsPolicy: ClusterFirst`, `schedulerName: default-scheduler`, completions and parallelism 1, `suspend: false`,
  the generated selector, `terminationMessagePath`, the projected volume's `defaultMode`), each held to its default.
  The Job must have that label and the PreSync hook; one container on the pinned wait image (a digest reference
  Apron renders from `versions.clearance.waitImage`; empty means no exemption); `args` `[--change <id> --timeout
  <duration>]` (only the id and the duration vary); `env` exactly `CLEARANCE_URL=<the pinned core URL>` and
  `CLEARANCE_TOKEN_FILE=/var/run/secrets/tokens/clearance`; every `securityContext` value pinned to the CMP's (pod: `runAsNonRoot: true`, user and group 65532, seccomp
  `RuntimeDefault`; container: no privilege escalation, read-only root filesystem, `capabilities.drop: [ALL]`);
  `automountServiceAccountToken: false` and **no**
  `serviceAccountName` (the CMP has no setting for one, so the pod runs as the namespace's default account, and only the projected
  token with audience `clearance` is mounted); `hostAliases` exactly the pinned one (none when the pin is empty); one
  read-only mount of the one projected token volume. The waiter mounts a clearance token, so anything that could
  redirect it is refused. It still needs an active grant to exist under Deny (the param resolves first). Envtest: the CMP's
  Job is admitted; about 40 deviations (listed in `test_admission.py`) are each refused by the policy.
- **Not checked by admission:** the stamp's content (CEL has no digest function), expiry by time (the agent's
  `status.valid`), the signature. Those stay the CMP's, the agent's and G-ARGO-3's.

### Release records and the Clearance record (decided 2026-11-03)

The owner's decision (hangar D25): **Clearance's signed record is the authority for what was cleared and what
deployed; Glidepath's release record cross-references it by `releaseId` and the change id.** The release record is
a pointer, never evidence; when the two disagree, the signed record wins and the disagreement is a finding.

What each carries today:

| Record | Where, who writes | Carries |
| --- | --- | --- |
| `release.yaml` `releaseTracking` | the gitops repo, inside the rendered tree; `open-release-pr` | `releaseId` (`<chainId>:<cluster>/<env>`), `cluster`, `appNamespace`; the airframe chart renders `releaseId` onto the Rollout as `hangar.io/release-id` |
| `release-tracking-<chainId>` ConfigMap, served by glidepath-api `GET /v1/apps/{app}/releases/{chainId}` | hangar-dev; `open-release-pr`, `mark-release-merged`, the relay, the ITSM tasks | PR, image, state machine, facts, drift, the change request |
| the release log, `releases/<app>@<tag>.yaml` | the gitops repo, outside the tree; Tower, once final | guardrails (every check's result), change request, test evidence, promotion attestation (Rekor `logIndex`), release mode and sign-off, outcome |
| Clearance's change and `deploy.*` records | the core's chain | the change (repo, PR, head, tree digest, objects, tier and why, approvals), outcome, and from C-2 the signed attestation |

The overlap is the decision about the change (Tower's sign-off block, the guardrail list) and the outcome; the
release log already holds a promotion attestation by Rekor index, which is the pattern to follow.

**The fields.**

| Record | New fields | Written by, when |
| --- | --- | --- |
| Clearance change row and its `deploy.request` | `release: {id}`, the `releaseId` | the registering provider. The CMP reads it from the rendered Rollout's `hangar.io/release-id` (or the values file's `releaseTracking.releaseId` when the app has no Rollout); because it is inside the tree, it is bound by the tree digest, not only claimed. The clearance-gate check sends the same value from `release.yaml` |
| `deploy.outcome` | `release: {id}` beside `change: {id, tree}` (Built, G-ARGO-6) | the agent, from the objects' `clearance.hangar.io/release` stamp (else the Rollout's `hangar.io/release-id`) and the object's `clearance.hangar.io/grant` |
| the attestation predicate (C-2) | `release: {id}` | the core's signer, copied from the change |
| `release-tracking-<chainId>` ConfigMap | `clearanceId`, `clearanceTree`, `clearanceRequestSeq`, `clearanceRequestHash` | the `clearance-gate` task, right after `POST /v1/clearances` answers (the answer gains the `deploy.request` record's `seq` and `hash`) |
| glidepath-api `GET /v1/apps/{app}/releases/{chainId}` | `clearance: {id, tree, request: {seq, hash}}` | glidepath-api, from the ConfigMap |
| the release log `releases/<app>@<tag>.yaml` | `clearance: {id, tree, state, request: {seq, hash}, outcome: {seq, hash}, attestation: {digest, rekorLogIndex}}` | Tower, when it writes the final outcome, read from clearance-api `GET /v1/clearances/{id}` |
| `release.yaml` `releaseTracking` | **nothing new** | it is inside the rendered tree: a change id written there would change the tree it names, so it carries only `releaseId`, as today |

**Following the link.**

- *From Clearance to the release.* A `deploy.request` or `deploy.outcome` names `release.id`. The verifier splits it
  into the chain id and `<cluster>/<env>`, reads the release (glidepath-api `GET /v1/apps/{app}/releases/{chainId}`,
  or the release log file after the sweep), and checks that its `clearance.id` is this change and its `clearance.tree`
  is this tree digest.
- *From the release to Clearance.* The release log's `clearance.request.seq` and `hash` name a record: the verifier
  reads it (`GET /v1/evidence/{seq}` on clearance-api, or the packet offline), checks the hash, checks that the chain
  verifies through it, and checks that the record's `release.id` and tree are this release's. The attestation is
  checked with `cosign verify-attestation` against the tree digest and the Rekor index the log names.
- A pointer that does not round-trip is a finding (`deploy.exception`-style, raised by `clearance verify` and shown by
  Tower), never a reason to trust the release record over the chain.

**What changes where.**

- **G-ARGO-4 (CMP):** read `releaseId` from the rendered tree and send `release.id` with the registration.
- **G-ARGO-3 (agent):** put `release.id` and `change.id` on every `deploy.outcome`.
- **C-10 / G-ARGO-6 (core):** store `release_id` on the change; `GET /v1/clearances?release=<releaseId>`; return the
  `deploy.request` record's `seq` and `hash` in the registration answer and in `GET /v1/clearances/{id}`; the signer
  copies `release.id` into the predicate.
- **Glidepath `open-release-pr`:** nothing new in `release.yaml`, deliberately. It keeps writing
  `releaseTracking.releaseId` into the tree (that is how the CMP learns the release), and the release-tracking
  ConfigMap it creates gains the four `clearance*` keys, empty until the gate task fills them.
- **Glidepath `clearance-gate` task and glidepath-api:** the task sends `release.id` and writes the four keys; the API
  returns them (G-ARGO-6 already names `clearanceId` and `treeDigest`).
- **Tower:** writes the `clearance:` block into the release log with the final outcome; Hand-flown's `signoff` block
  retires with the sign-off status (decision 2 above), replaced by the clearance block.
- Clearance stays installable without Glidepath: `release` is an optional, opaque identifier on the change, and the
  annotation it is read from is deployment vocabulary (Hangar's `hangar.io/release-id`), not product code.

### The release-record join (G-ARGO-6, Built)

What is built of the design above, and the chain a test walks end to end (`internal/server/release_join_test.go`):
pull request, change, grant, outcome, attestation, release record, joined by ids and nothing else.

| Link | Carries | Where |
| --- | --- | --- |
| the PR's change | `id`, `tree_digest`, `pr`, `head` | `POST /v1/clearances`; the `clearance-gate` task |
| the release record | `clearanceId`, `clearanceTree` | glidepath's `release-tracking-<chainId>` ConfigMap, written by the `clearance-gate` task; glidepath-api returns `clearance: {id, tree}`; the release log has `clearance_id`, `clearance_tree` |
| the grant | the change id, in the cleared token and on every object as `clearance.hangar.io/grant` | the CMP, the agent |
| the outcome | `release: {id}` and `change: {id, tree}` | the agent's `deploy.outcome` on `POST /v1/records` |
| the change's view | `outcome: {seq, hash, applied, matched, digest, release, provider, at}` | `GET /v1/clearances/{id}` on the core and clearance-api |
| the attestation | `predicate.release.id`, `predicate.outcome.seq`; the row's Rekor log index | `GET /v1/clearances/{id}` (`attestation`), `GET /v1/clearances/{id}/attestation` |

- **One path for the release id.** A `deploy.outcome` names its release in the record's own `release {id}`
  (`ProviderEvent.release`; a non-empty string, `id` only, a `deploy.outcome` field). A provider that still sends
  `change.release.id` (the Argo CD agent before this change) is accepted: the core copies the id to `release` and
  keeps `change` as sent. The signer reads `release.id`, else `change.release.id`, so older outcome records still
  attest with their release. The agent now sends `release {id}` and no `change.release`.
- **The outcome on the change.** The core sets the change's `outcome` in the same transaction that appends the
  provider's `deploy.outcome` (`gate.Service.RecordOutcome`); the latest outcome stands, since an Application can sync
  more than once. Only a cleared change takes it, and only an outcome for the change's own destination (cluster, environment) and app: a registered provider naming another app's change, or an unknown change, is recorded with `unattached` saying so. Only a cleared change takes it: for a holding, denied, expired or otherwise not-cleared change the
  outcome is still recorded, with `unattached` saying why, and neither the change's `outcome` nor an attestation follows. `seq` and `hash` are the record's, so a reader finds it on the chain (`GET /v1/evidence/{seq}`) and
  checks the hash. `matched` is whether the applied digest is the cleared tree; a record with no digest is
  `matched: false`, with `digest` empty. Everything in it is the provider's claim; the core did not observe the target.
  A terraform-plan change keeps its own outcome route.
- **Which app and environment.** Changes are registered under the Glidepath app and environment names (`gate-api`, `prod`). A tenant-onboarded Application is named `<app>-<env>` and carries `hangar.io/app` and `hangar.io/env` labels, so the agent reports its outcomes (and refused-sync exceptions) under those labels, falling back to the Application's name and the namespace's environment; the outcome attaches only when they equal the change's.
- **The stamp.** The airframe chart renders `hangar.io/release-id` onto the Rollout, so that id is inside the tree and
  bound by the tree digest. An app with no Rollout has none, so the CMP now copies the release id to every object as
  `clearance.hangar.io/release`: the one the objects' `hangar.io/release-id` agree on, else `releaseTracking.releaseId`
  of the value files (not rendered output, so the digest does not bind that fallback: it is claimed). Two objects naming different releases get no stamp. It is a gate annotation: never hashed, removed
  before the agent recomputes an object's digest, and a tenant-written one is replaced or removed, never trusted. The
  agent reads the stamp first, then `hangar.io/release-id`; objects that disagree report no release and
  `mixed_stamps`.

Not built: registering the release id on the change (`GET /v1/clearances?release=<releaseId>`), and the
`deploy.request` record's `seq` and `hash` in the registration answer, with glidepath's `clearanceRequestSeq` and
`clearanceRequestHash` keys. The join above runs from the release record to the change by id, and from the outcome and
attestation back to the release by `release.id`.

**The live check on hangar-prod** (Unverified until run). For one real release of a protected app, with `<chainId>`
from its release PR and `<app>` its name:

1. `GET <glidepath-api>/v1/apps/<app>/releases/<chainId>`: `clearance.id` is `ch-...`, `clearance.tree` is the PR's tree
   digest.
2. `GET <clearance-api>/v1/clearances/<clearance.id>`: `state` is `cleared`; `outcome.release` is
   `<chainId>:<cluster>/<env>`, `outcome.applied` and `outcome.matched` are true, `outcome.digest` equals the tree
   digest from step 1; `attestation.outcome_seq` equals `outcome.seq` and `attestation.rekor_log_index` is set.
3. `GET <clearance-api>/v1/evidence/<outcome.seq>`: the record's `hash` equals `outcome.hash` and its `release.id`
   equals step 2's.
4. `GET <clearance-api>/v1/clearances/<id>/attestation | clearance attest verify --subject sha256:<tree digest>`:
   passes, and the statement's `predicate.release.id` is the same release id.
5. The live Rollout (`kubectl -n <ns> get rollout -o jsonpath='{.metadata.annotations}'`) carries
   `clearance.hangar.io/release` (needs the CMP of this change) and `clearance.hangar.io/grant` equal to the change id.

### Card changes this pass recommends

| Card | Change |
| --- | --- |
| G-ARGO-2 | objects as a map keyed `<group>/<kind>/<name>` (a list may stay for display); exactly one active grant per namespace; `status.valid` set by the agent; the Warn toggle also flips `parameterNotFoundAction`; typed `auditAnnotations` |
| G-ARGO-3 | the grant sync keeps a feed epoch with its seq (C-10's feed seq restarts on a rebuilt database); the outcome source is the watch, keyed by operation; expiry and the active label are the agent's; the exception scan hashes Argo's `last-applied-configuration` |
| G-ARGO-4 | the plugin replaces the Helm source; one generating source per protected app; chart fetched by tag and recorded by peeled commit; namespace set before hashing; lookup by tree digest for the merge commit; `release.id` from the tree |
| G-ARGO-6 | the release-record fields above, in both directions |
| C-10 | registration without `pr` (by app, env and tree); the grant-feed reader role on clearance-api; `release` on the change; record `seq`/`hash` in answers |
| G-ARGO-7 | the route's `Exact /v1/records`, the hostAlias and egress on hangar-prod, the three foreign-list entries |

### Reproducing the spikes (hangar-dev only)

`spikes/g-argo-1/up.sh` installs a namespaced Argo CD 3.5.0 with the spike plugin in `clearance-spike-argo`
(deploying into `clearance-spike-prot`), `kubectl apply -f manifests/40-apps.yaml` creates the four Applications,
`manifests/20-grant-crd.yaml`, `30-vap.yaml`, `31-kyverno.yaml` and `32-mutating.yaml` the CRD and policies (Warn),
`run-c.sh` and `run-d.sh` run spikes c and d, `celcost` (`go test -v ./...` in that directory) measures the CEL cost,
and `down.sh` removes everything. The scripts refuse any context but hangar-dev. The spike plugin is not G-ARGO-4:
it registers nothing and keeps no cache.

## Built, phase 1a (v0.19.0): the gate's core

What exists in Clearance now; the check, the release guardrail and the screens follow (1b, 1c).

- **`gate.py`**: `GatePolicy` (the baseline tier table: tier-3 kinds, field tokens and paths, non-runtime paths, the
  Flight registries, the 400-line cap, the outside groups, the 7-day TTL, approvers per tier) and `tightened()`, which
  applies a repo's `clearance.yaml` (add kinds, paths and field tokens to tiers 2 and 3; raise the people required;
  shorten the TTL; anything else, or anything looser, is `DG-POLICY` and the change is denied). `ChangeRequest`: what
  the check posts (app, env, cluster, repo, PR, head, base, proposer and its kind from the agent gates, the owner
  group when the check knows it, the tree digest, the changed paths and lines, each touched object with the JSON
  pointers of its changed fields and its new images, the checks' results, the repo's `clearance.yaml`). `classify()`:
  the tier as the maximum over paths and objects (`kind:Secret`, `field:secretKeyRef`, `path:clearance.yaml`,
  `image-bump`, `image:not-trusted-registry`, `metadata-only`, `release-stamp`, `non-runtime`, `lines>400`, `checks:ci,render`,
  `provenance:agent`), then the decision: tiers 0 and 1 clear by policy, 2 and 3 hold for a `Requirement`
  (owner-group people, outside-group people), an unknown proposer is denied (`DG-PROVENANCE`). `Change`: the record,
  with `role_for()` (owner first, then outside; `DG-PROPOSER`, `DG-TWICE`, `DG-FILLED`, `DG-FORBIDDEN`, `DG-STATE`; since C-14 also `DG-APPROVER-AUTOMATION` and `DG-APPROVER-SAME`, [rule GATE-APPROVER-001](#tier-3-approvers-are-people-c-14-built)).
- **Gateway**: `register_change` (a verifier's call; idempotent by repo, PR and head; a holding change is re-evaluated
  with the new check results and clears by policy once they hold; a new head supersedes the heads still holding),
  `clear_change` and `deny_change` (the delegate model; the owner group is the request's, or the catalog's through
  `AppOwners`, or the outside group when nobody knows), `expire_changes` in the expiry sweep. Records in the
  **deployment boundary**: `deploy.request` (the verifier; result = the tier and why), `deploy.clear` (`policy`, or the
  person with their role and delegate), `deploy.deny` (`DG-PROVENANCE`, `DG-POLICY`, or a person's `DG-DENIED` with the
  reason), `deploy.expire` (TTL, or `superseded by <head>`). Each carries `app`, the target `repo#pr@head` and a
  claimed `change` summary (id, env, tier, tree digest, state).
- **Routes**: gateway `POST /v1/clearances` (verifiers), `POST /v1/clearances/{id}/clear`, `POST /v1/clearances/{id}/deny`
  `{reason}`; clearance-api `GET /v1/clearances` (app, env, state, repo, pr, tier, since; a person sees their apps'
  changes and the ones their groups may clear), `GET /v1/clearances/counts?by=state|tier|app|env|cleared_by`,
  `GET /v1/clearances/{id}`, `GET /v1/clearance-policy`. Postgres `clearance_changes`.
- Not yet: the `clearance-gate-` check (1b: it renders the tree, diffs objects, posts here; the PaC check is red while
  holding and re-run after people clear), the release guardrail, the C1 page and T1 panels, the PR mark, retiring
  `hangar/release-signoff`, `deploy.exception` and the pulled grants (phase 2).

## Open questions for the owner (all decided 2026-10-31; kept for the record)

1. ~~Phase 2 enforcement: A (grant-match admission, recommended), B or C, or B then A.~~ Decided: A, pulled (see "Question 1, expanded").
2. ~~Does the gate **replace** Tower's Hand-flown sign-off (one rule, one record), or run beside it for a release?~~ Decided: replace.
3. ~~Where `clearance.yaml` lives~~ Decided: each gitops repo. Was: in each gitops repo beside the environments it governs (recommended: it changes with
   the environment, it is tier 3 itself, and the platform baseline lives in the catalog like `releaseSigning`), or
   centrally in the platform's catalog only.
4. ~~The outside group for tier 3~~ Decided: `group:default/admins`. Was: `group:default/admins` today (it exists), or new `platform-leads` / `security`
   groups.
5. ~~Holding TTL~~ Decided: 7 days with the PR, a new push re-asks. Was: with the PR (7 days) or shorter (the board shows an hour); and whether a new push re-asks (recommended:
   yes, a new head is a new change).

## The clearance token (C-1, Built)

On `deploy.clear` the core signs a short-lived token bound to what was cleared: the tree root, the commit and image
digests, each object's rendered hash, the target cluster and environment, the tier, the policy and its verdict,
provenance and the task, and the approvals naming each person at their identity provider. It is a DSSE envelope
with a JWT projection, signed with the core's ECDSA P-256 key; [core.md](core.md#the-clearance-token) has the
format, the claims, the key and the replay rules. In short:

- A token lives `CLEARANCE_TOKEN_TTL` (15 minutes) and is re-issued, with the same nonce, while its change stays
  cleared, up to the change's horizon (as long after the clear as the change could have held: 7 days).
- A new head on the same pull request revokes the older head's token (`deploy.revoke`); a token whose nonce is not
  the clearance's live one is a replay.
- The grant feed is clearance-api's `GET /v1/clearances?cluster=<c>&state=cleared`: the cluster's cleared changes
  whose token is live, each with it. Since C-10 the grant-sync agent (G-ARGO-3) reads the **signed** feed instead,
  `GET /v1/grant-feeds/{cluster}` ([below](#the-signed-grant-feed-c-10-built)), as a feed reader
  (`CLEARANCE_API_FEED_READERS`), verifies it whole and each token against `GET /v1/keys`, and writes the
  ClearanceGrants.
- `registerChange` takes an optional `taskId` (the run that proposed the change), kept on the change as `task_id`,
  carried in the token and on every `deploy.*` record's `task_id`.

`objects[].op` may be `unchanged` (Built): an object in the rendered tree that the diff does not touch. It is kept on the
change and in the token (`changed: false`) so a grant covers the whole tree, and it adds nothing to the tier. Glidepath's
clearance-gate lists every rendered object this way.

Not yet: admission on the grant (G-ARGO-2), the CMP that registers the whole rendered tree with unchanged objects
marked (G-ARGO-4), the PreSync wait
(G-ARGO-5), and the Terraform plan subject (G-TF-1, which adds `subjects.plan_digest`).

## Tier 3 approvers are people (C-14, Built)

**Rule `GATE-APPROVER-001`: the approvers of a change are distinct people, never automation.** The clear route
(`POST /v1/clearances/{id}/clear`) enforces it, on top of `DG-PROPOSER` (no self-clearance), `DG-TWICE`, `DG-FILLED` and
the outside-team rule, which are unchanged:

| Id | Status | Meaning |
| --- | --- | --- |
| `DG-APPROVER-AUTOMATION` | 403 | The approver is not a person: the principal is a service account (TokenReview or another cluster's), a GitHub Actions identity or any non-person principal; or the person's name, subject or issuer matches an automation pattern (a bot account such as `cicd-pac[bot]`, the agents' GitHub App, an ID-JAG agent identity such as `agent:triage`, a service-account subject, an agent-identity issuer) |
| `DG-APPROVER-SAME` | 409 | The approval resolves to the same subject as one already on the change: the same IdP subject under another name, the same IdP session (`sid`), or two names the deployment lists as one person |

How the check reads an approval:

- **Signed in directly**: the principal's name, the token's `sub` and its `iss` are tested. The issuer is tested only
  here: a Kubernetes or GitHub Actions issuer, or an ID-JAG issuer, never signs a person.
- **Through a delegate** (Tower clears as `hangar-prod/app-backstage-prod/backstage` naming `user:riley-roooo`, recorded as
  `iss: delegate:<delegate>`, `sub: user:riley-roooo`, `via: <delegate>`): the person named is the approver and is
  tested. The delegate is a service identity by design and is **not** refused; a delegate naming `user:cicd-pac[bot]`
  or an agent identity is.
- **Distinct**: an approval's keys are its person, its subject, its subject at its issuer (direct sign-ins only), its
  session and the alias group any of them belongs to. Two approvals that share a key are one approver.

The patterns are configuration, product-neutral by default, with platform names in the deployment's vocabulary
(`internal/vocab`, [core.md](core.md#configuration)): `CLEARANCE_AUTOMATION_SUBJECTS` (default `*[bot]`, `*-bot`,
`bot-*`, `bot:*`, `app/*`, `agent:*`, `agent-*`, `*-agent`, `system:*`, `serviceaccount:*`, `service-account:*`, `svc-*`,
`spiffe://*`, `*.iam.gserviceaccount.com`), `CLEARANCE_AUTOMATION_ISSUERS` (default `*kubernetes*`, `*.svc`, `*.svc.*`,
`*token.actions.githubusercontent.com*`, `*id-jag*`, `*idjag*`) and `CLEARANCE_APPROVER_ALIASES` (`a=b=c;d=e`, each
group one person; default none). `*` is the only wildcard, matching is case-insensitive, and `none` empties a pattern
list. A deployment whose bots or agents are named otherwise adds its names there.

An approval that passed the check records `kind: person` with its `sub` and `iss`, in the change, in the token's
`approvals` and in the `deploy.clear` record. The attestation predicate's approval items carry `kind` too (absent on
approvals recorded before C-14, which prove nothing about it). `token.ApproversStatement` turns verified approvals into
the line a packet or verification statement prints, "approvers: distinct subjects, none automation", and prints
nothing for a change with any approval lacking `kind: person`.

Limits, stated: an alias is only known if the deployment lists it, since the gate has no directory of a person's
other names; the patterns catch naming shapes, not an automation that signs in under a plain person-looking name at a
plain issuer (the allowlist at sign-in and the delegate list are the controls there); a break-glass window is not an
approval and is unchanged.

## Protected environments, the outage policy, states, exceptions and break-glass (C-6, Built)

C-6 makes the gate's edges explicit: which environments it protects, what a provider does when it cannot reach the
core, every state a change can be in, the records a provider files when something lands outside a clearance, and a
recorded break-glass path. Everything here is in the core (`internal/gate`: `protected.go`, `outage.go`,
`states.go`, `exception.go`, `breakglass.go`) and clearance-api; the providers that act on it are G-ARGO and G-TF.

### What you get

- **Protection is Clearance's decision.** The deployment lists the environments it protects; a caller cannot opt a
  change out (`protected: false` is refused, `DG-PROTECTED`). A change elsewhere is cleared at tier 0 with the reason
  `unprotected`, and recorded like any other.
- **Fail closed when unconfigured.** An empty list protects every environment.
- **An outage policy per tier**, tighten-only per repo: tiers 0 and 1 allow-and-record, 2 and 3 hold.
- **One state machine** with every edge listed and tested; a token is live only while its change is cleared, and
  every edge out of cleared revokes it in the same transaction.
- **Exceptions as first-class records** (`deploy.exception`, four kinds) and **degraded-mode reports**
  (`deploy.degraded`), both acting on the change they name, and both in the packet's exceptions
  (clearance-api `GET /v1/exceptions`).
- **Break-glass for admins only**, bounded (at most 4h), recorded before any effect, reconciled when it ends.

### Protected environments

`CLEARANCE_PROTECTED_ENVIRONMENTS` (chart `gate.protectedEnvironments`) is a comma-separated list of
`<cluster glob>/<env glob>` entries (fnmatch: `prod-*/*`, `*/prod`, `hangar-prod/*`).

| Configured | A change to `cluster/env` |
| --- | --- |
| **Empty (the default)** | **Every environment is protected.** A deployment that has not said which environments it protects fails closed: everything is tiered and held as before. |
| Listed and matching | Protected: tiered by the baseline and the repo's `clearance.yaml`, held or cleared as before. `protected: true` in the view. |
| Listed, not matching | **Cleared at tier 0**, one reason `{subject: "<cluster>/<env>", rule: "unprotected", tier: 0}`, `cleared_by: policy`, `protected: false`, a token issued, and recorded (`deploy.request`, `deploy.clear` "tier 0: cleared (<cluster>/<env> is not a protected environment)"). |

The caller's `protected` field: `true` (what Glidepath's clearance-gate task sends) or absent is accepted and decides
nothing; `false` is refused 400 `DG-PROTECTED`, so a caller cannot unprotect a change and nobody reads a stored
`protected: false` as the caller's say-so. The user's decision of 2026-11-03 left ignore-or-refuse to this
package; refusing was chosen because no caller sends `false` today (Glidepath sends `true`), so it breaks nothing and
makes a caller that tries visible.

### The outage policy

What a deployment-gate provider does with a change while it cannot reach the core:

| Tier | Platform baseline | `clearance.yaml` `outage:` may set |
| --- | --- | --- |
| 0 | `allow-and-record` | `hold` |
| 1 | `allow-and-record` | `hold` |
| 2 | `hold` | `hold` only |
| 3 | `hold` | `hold` only |

`allow-and-record`: the provider lets the change through and keeps what it did; once the core answers it posts a
`deploy.degraded` record (below). `hold`: nothing lands until the core is back. A tier the provider cannot know (it
never reached the core to classify the change) is held. The block is tighten-only like the rest of `clearance.yaml`:
`outage: {"1": "hold"}` is accepted, `outage: {"2": "allow-and-record"}` is `DG-POLICY`. The baseline is in
`GET /v1/clearance-policy` (`outage`), and each change carries its own action (`outage`, its tier under its
effective policy) so a provider that cached the change knows what to do with it.

This is the deployment boundary's outage policy. The runtime gateway's (R-3: fail closed, T0 reads only with
`GATEWAY_OUTAGE_ALLOW_READS`, replayed as `tool.call` `coverage-unavailable`) is unchanged.

### The state machine

| From | To | What moves it | Token |
| --- | --- | --- | --- |
| (new) | `holding` | register: tier 2 or 3, or tier 1 waiting on its checks | none |
| (new) | `cleared` | register: tier 0 or 1 cleared by policy, or an unprotected environment | issued |
| (new) | `denied` | register: denied by policy (`DG-PROVENANCE`, `DG-POLICY`, `DG-DEFINITION`) | none |
| `holding` | `cleared` | the requirement is met by people, or a re-registration clears by policy | issued |
| `holding` | `denied` | a person or an admin denies it, or a re-registration denies by policy | none |
| `holding` | `expired` | its TTL passes | none |
| `holding` | `superseded` | a new head registers (same PR; for a push, same app, env and cluster) | none |
| `holding` | `degraded` | a provider reports it let the change land during an outage (`deploy.degraded`, `allow`) | none |
| `holding` | `exception` | a `deploy.exception` names it | none |
| `cleared` | `superseded` | a new head registers | **revoked** (`deploy.revoke`) |
| `cleared` | `exception` | a `deploy.exception` names it (drift, a digest mismatch, out of band) | **revoked** (`deploy.revoke` "token revoked: exception: <kind>") |

`denied`, `expired`, `superseded`, `degraded` and `exception` are final: nothing moves a change out of them, and a new
head registers a new change. "Held" in the card is the state `holding`; a provider that held a change during an
outage (`deploy.degraded`, `deny`) leaves its state as it was. A cleared change a provider let through during an
outage stays cleared. `gate.Transitions` is the table; any other move is a bug the gate refuses to write (the
operation fails and nothing commits). The GitHub App's deployment answer for `degraded` and `exception` is
`rejected`, with the reason in the comment.

Two behaviour changes from C-1, both to keep the token consistent with the state: a new head now moves a **cleared**
older head to `superseded` (it stayed `cleared` with a revoked token), so a GitHub deployment of the old head is
rejected `DG-UNREGISTERED`; and a pushed commit (`pr` 0) supersedes only the holding and cleared changes of the same
app, environment and cluster (it superseded every holding pushed commit of the repository).

### Exceptions: `deploy.exception`

A registered provider posts it through `POST /v1/records` (kind `deploy.exception`; principal, target, result,
`exception` and `destination` required: {cluster, environment}, or for a Terraform plan, which has no cluster,
{workspace: {backend, key, name}}, never both). The `exception` object:

| `exception.kind` | Must carry | Coverage the core sets | Written by |
| --- | --- | --- | --- |
| `out-of-band` | `objects` [{apiVersion, kind, namespace, name, rendered?, grant?}] (at least one) | `out-of-band-detected` | the Argo agent (G-ARGO-3): objects with no grant, or a hash no grant lists |
| `drift` | `addresses` or `objects` (at least one) | `observed-not-attributed` | G-TF-5's scheduled `terraform plan -detailed-exitcode` (**Built**); live drift |
| `untraced-apply` | `actor` (the principal behind the write) | `out-of-band-detected` | G-TF-5's state-backend watch: S3 object versions and CloudTrail (**Built**) |
| `digest-mismatch` | `expected`, `observed` and `change.id` | `out-of-band-detected` | G-TF-2's outcome route; the CMP's applied-tree check |
| `attempted-refused` | `actor` and `detail` (the operation) | `attempted-refused` | O-1: an operation something tried and a control refused. Nothing landed, so a change it names (`change.id`) is **not** moved to exception |
| `monitoring-protection` | `actor` and `detail` (the operation) | `out-of-band-detected` | O-1: an operation on the controls that watch the environment (a trail, an audit policy, a recorder), tier 3 whether or not it succeeded ([evidence.md](evidence.md#observations-clearanceevidencev11-o-1)); moves a change it names to exception like any other |

Optional on every kind: `state` {backend, key, version}, `detected_at` (RFC 3339), `detail`. Unknown fields are
refused. A provider's `coverage` must be absent or the kind's. The core adds `breakglass` (verified) when an open
break-glass window covers the destination. When `change.id` names a holding or cleared change, the change moves to
`exception` (its `ended` names the record's seq, tool and kind), and a cleared change's token is revoked, in the same
transaction as the record.

```json
{"provider": "argo-gate", "kind": "deploy.exception", "record": {
  "principal": "kubernetes-admin", "target": "apps/v1/Deployment/app-gate-api-prod/gate-api",
  "result": "applied without a grant", "app": "gate-api",
  "destination": {"cluster": "hangar-prod", "environment": "prod"},
  "exception": {"kind": "out-of-band", "objects": [{"apiVersion": "apps/v1", "kind": "Deployment",
    "namespace": "app-gate-api-prod", "name": "gate-api"}]}}}
```

### Degraded-mode reports: `deploy.degraded`

When a provider could not reach the core and acted on the outage policy, it posts what it did once the core answers:
`POST /v1/records`, kind `deploy.degraded`, with principal, target, app, result, `decision` (`allow`: it let the
change land; `deny`: it held it), `coverage: coverage-unavailable`, `outage` {from, to} (RFC 3339, `to` not in the
future) and `destination`; optionally `tier` (what it believed), `change.id`, `subject`. No `rule`: the core decided
nothing. The core adds `outage_policy` (verified): `action` (the named change's `outage`, else the baseline for the
claimed tier, else `hold` for an unknown tier), `source` (`change`, `baseline`, `unknown-tier`) and `conforms`
(`decision` was `deny`, or the action was `allow-and-record`). A non-conforming report is still recorded; it is a
finding. An `allow` naming a holding change moves it to `degraded`.

### Break-glass

| Route | Who | What |
| --- | --- | --- |
| `POST /v1/breakglass` `{reason, ttl, cluster, env, app?}` | a person matching `CLEARANCE_ADMINS`, or a delegate (`CLEARANCE_DELEGATES`) naming one in the on-behalf-of header | Opens a window on one protected environment. `ttl` is a Go duration, 1m to `CLEARANCE_BREAKGLASS_MAX_TTL` (default and ceiling 4h). The named user is the authenticated admin (or the one the delegate names): never a free-text field (an unknown field is refused). The answer comes after `breakglass.open` and the window's row commit together, so the record precedes every change it covers. |
| `POST /v1/breakglass/{id}/close` | an admin (or a delegate naming one) | Closes the window early and reconciles it at once. |
| `GET /v1/breakglass[?cluster=]` | a registered provider, or an admin | The windows open now: what a provider that honours break-glass (the Argo agent's marker, G-ARGO-3) reads. |

Break-glass clears nothing and applies nothing: Clearance holds no write credential to a protected environment. A
change made in the window is still an exception when a provider sees it, and each `deploy.exception` and
`deploy.degraded` inside the window carries the window's id (`breakglass`) (a window that names an app tags only that app's reports; one
window per environment either way). When the TTL ends, the expiry loop
(`CLEARANCE_EXPIRE_SECONDS`) closes the window with a `breakglass.close` record: `window` {from, to}, `changes` (the
deployment records the store holds about that cluster and environment, and app when the window names one, written
while it was open: `deploy.exception`, `deploy.degraded`, `deploy.outcome`, `deploy.clear`; at most 200 listed),
`reported` (the full count), `truncated`, and `limitations`, the statement of what the store cannot know:

> Lists only what a provider reported to Clearance in the window. A change made directly (kubectl, a cloud console,
> a script) appears only if an exception detector watches this environment and reported it; a report that arrived
> after the window closed is not listed.

Refusals: `DG-BREAKGLASS` (403, not an admin), `DG-BREAKGLASS-TTL` (400), `DG-BREAKGLASS-SCOPE` (400: not names, or
an environment Clearance does not protect: there is no glass to break), `DG-BREAKGLASS-OPEN` (409, a window is
already open there), `DG-REASON`, `DG-DELEGATE`, `DG-PERSON`, `DG-UNKNOWN` and `DG-STATE` (close). A refused request
records nothing. Windows are kept in `clearance_breakglass`.

### The packet's exceptions

clearance-api `GET /v1/exceptions` is the list the packet's Exceptions section (C-5, [packet.md](packet.md)) is built from (the job reads the chain itself and applies the same rules): every
`deploy.exception`, `deploy.degraded`, `breakglass.open` and `breakglass.close`, and every record whose coverage is
`coverage-unavailable` (the runtime's outage reads too), newest first, scoped by viewer like the evidence list, on the
partial index `clearance_evidence_exceptions`. Filters: `tool`, `kind` (an exception kind), `app`, `since`, `until`,
`limit`, `after` ([clearance-api.md](clearance-api.md)).

### Rule ids and reasons added

| Id | Where | Meaning |
| --- | --- | --- |
| `DG-PROTECTED` | `POST /v1/clearances`, 400 | `protected: false` is refused: Clearance decides protection |
| `unprotected` | a change's reason (tier 0) | the environment is not on `CLEARANCE_PROTECTED_ENVIRONMENTS` |
| `DG-POLICY` (outage) | `clearance.yaml` | an `outage:` entry that loosens the baseline, or not a tier 0 to 3 |
| `DG-BREAKGLASS` | `POST /v1/breakglass`, `/close`, 403 | not an admin |
| `DG-BREAKGLASS-TTL` | `POST /v1/breakglass`, 400 | the TTL is not a Go duration from 1m to the deployment's maximum (at most 4h) |
| `DG-BREAKGLASS-SCOPE` | `POST /v1/breakglass`, 400 | cluster, env or app are not names, or the environment is not protected |
| `DG-BREAKGLASS-OPEN` | `POST /v1/breakglass`, 409 | a window is already open on that environment |

### Not yet

- The providers that file these records: the Argo agent's exceptions and break-glass marker (G-ARGO-3). Terraform
  drift and untraced-apply detection is **Built** (G-TF-5, [terraform-gate.md](terraform-gate.md#exception-detection-g-tf-5-built-not-deployed)).
  A report located by workspace is not tagged with a break-glass window (windows are per cluster and environment).
  The change-bound outcome route that writes `digest-mismatch` itself is
  **Built** (G-TF-2, [below](#hold-release-and-outcome-for-a-plan-g-tf-2-built)): it writes the record in this
  shape and moves the change to `exception` with the same edge.
- The packet itself (C-5) is **Built** ([packet.md](packet.md)), with its coverage statement (counts by coverage and assurance, degraded windows, per-scope observation health); its offline verifier (C-4) is not.
- A report that arrives after its break-glass window closed is not tagged with it.

## The signed grant feed (C-10, Built)

What the grant-sync agent (G-ARGO-3) reads, every 30 s, from clearance-api as a feed reader:
`GET /v1/grant-feeds/{cluster}`. The C-1 list (`GET /v1/clearances?cluster=<c>&state=cleared`) stays, but it is a
page of tokens, each good on its own: a reader cannot tell it the whole set from a page someone trimmed, nor today's
from last hour's replayed. A grant-sync that removes grants for what is missing needs both, so the core signs the
set.

**The document** (`internal/token/feed.go`, `token.Feed`): a DSSE envelope, payloadType
`application/vnd.clearance.grant-feed.v1+json`, signed with the token key (the same Signer, keyid and `GET /v1/keys`),
over

```json
{"_type": "clearance.grant-feed/v1", "iss": "clearance", "cluster": "hangar-prod",
 "epoch": "<hex: the hash of the chain's first record>", "seq": 41, "iat": 1762200000, "exp": 1762200300, "records_seq": 1093,
 "entries": [{"change_id": "ch-...", "nonce": "...", "exp": 1762200800, "payload_sha256": "<hex>"}]}
```

- `epoch`: names the database `seq` counts in, the hash of the evidence chain's first record (no two databases share
  it; a rebuilt or restored one has another). A reader keeps it beside the highest `seq` it accepted.
- `seq`: the cluster's feed number within the epoch, one more than the feed it replaces, never reused.
- `iat`, `exp`: NumericDate; `exp` is `iat` + 5 minutes (`gate.FeedTTL`; a feed may claim at most 15).
- `records_seq`: the evidence chain's last seq when it was signed; every `deploy.*` record at or below it is reflected.
- `entries`: every token live on the cluster at `iat`, by `change_id` ascending (at most 2000). `payload_sha256` is the
  SHA-256 of that token's DSSE payload (the claims bytes as signed), so it names one issuance: a refreshed or altered
  token does not match.

**When the core signs it.** In the same transaction as any write to one of the cluster's tokens (a clear issues one,
a refresh re-issues, a new head or the horizon revokes), so the stored feed always matches the stored tokens; and
at least every 2 minutes otherwise (`gate.FeedResign`, the core's own minute ticker, whatever
`CLEARANCE_EXPIRE_SECONDS` is), so a feed past its `exp` means the core, or the path to it, is down. A cluster gets
its first feed with its first token, and an empty feed (no entries) once its last token is revoked: that is how its
grants get removed. A cluster with more than 2000 live tokens is not re-signed (its feed goes stale and grant-sync
stops: fail closed), and the core logs it every minute. The row (`clearance_feeds`, one per cluster) keeps the
envelope and the tokens it lists side by side; clearance-api serves it as it is and holds no key.

**What grant-sync does with it** (in this order; any failure means: change nothing, keep the grants it has, and
let them expire on their own `exp`):

1. Keys: `GET /v1/keys` (cache it up to its `max-age`; refetch on an unknown keyid).
2. `token.VerifyFeed(feed, keys, {Issuer, Cluster: <its own>, MinSeq: <the highest seq it accepted>, Epoch: <the
   epoch that seq belongs to>})`: the signature, strict decoding, the issuer, this cluster (`ErrFeedCluster`), `seq`
   not below the last accepted **of the same epoch** (`ErrFeedReplay`; the same seq is the same feed read again; a
   new epoch is a rebuilt core and starts at 1), and fresh (`exp`, with 30 s leeway).
3. `feed.Match(tokens)`: the tokens beside it are exactly the entries, each the issuance named
   (`ErrFeedIncomplete` otherwise).
4. Each token: `token.Verify` with `Expect{Cluster}` (signature, expiry, binding). No nonce check is needed: the
   feed is the revocation list.
5. Then create or update a ClearanceGrant per entry, delete the grants no entry names, and remember `seq`.

A reader that persists its `MinSeq` survives restarts; one that does not accepts any fresh feed after a restart,
which is still bounded by `exp`. A restored or rebuilt core database starts `seq` again at 1 **with a new `epoch`**
(since G-ARGO-3): the agent takes the new epoch from seq 1 without an operator resetting anything, and still refuses
the same epoch's lower seq. What an epoch cannot tell is a rolled-back database that keeps its first record from a
rebuilt one that does not exist yet: a restored backup has its old epoch and a lower seq, which is refused until it
passes the stored seq. A feed older than the agent's last (another epoch, signed earlier) is bounded only by its `exp`
(5 minutes).

**Faster than 30 s.** `GET /v1/stream` gives a feed reader the clearance events of its clusters as they are
recorded; it is a cue to re-read the feed, never a substitute for it.

**For the gate providers that wait** (the Terraform run task, G-TF-2; the PreSync hook, G-ARGO-5): the core's
`GET /v1/clearances/{change_id}/wait?state=&timeout=` ([core.md](core.md#the-api)) holds the call until the change
leaves the state the caller knows, or up to 60 s, and answers the state and the token. It is the same for every
subject kind.

## The Argo CD agent (G-ARGO-3, Built)

Status: **Built**; tested against a fake Argo CD (`providers/argocd/agent`, `go test`) and **passing the provider
conformance suite** as `argocd-agent` (G-ARGO-9, with the plugin: `TestArgoConformance` in `providers/argocd/cmp`; see
[the provider protocol](provider-protocol.md#the-gates-adapters-g-tf-7-g-argo-9)). The gate is **live on hangar-prod in
Warn mode, not Deny** (reported by the owner, 2026-11-09): admission warns about what a grant does not list and refuses
nothing, so nothing here claims enforcement. The numbered proof below is **Unverified** by this repository (its steps were
not run for this change). One controller on the protected cluster, one replica, three loops. It holds no key and
decides nothing; its credential is the pod's projected service-account token (audience `clearance`), read fresh for
every request. Provider identity `argocd-agent/<version>` is in `source.provider` of every record it posts, and the core's verified
`provider` is `argocd-agent` with the registered version (live records name `argocd-agent`, owner, 2026-11-09).

| Loop | Every | Does |
| --- | --- | --- |
| **Grant sync** | 30 s | `GET /v1/keys` (cached 5 min, refetched on an unknown key id), `GET /v1/grant-feeds/<cluster>`; verifies the feed (signature, issuer, cluster, freshness, seq within its epoch), that the tokens beside it are exactly its entries, and each token (signature, expiry, cluster); then writes one `ClearanceGrant` (`clearance.hangar.io/v1`) per cleared change and namespace its objects name, whether or not the namespace is labelled protected yet; `spec.objects` is every object of the tree keyed `<group>/<kind>/<name>` (an empty group for core kinds) to `{rendered, changed}`; labels exactly the newest cleared grant of a namespace `clearance.hangar.io/active=true` and lists on it, in `spec.carried`, the namespace's other live cleared trees (the running tree stays admissible, [below](#the-running-tree-and-the-active-grant)); sets `status.valid` (with `reason`, `checkedAt`); and deletes the grants no entry names |
| **Outcomes** | a watch | Lists and watches Applications in the Argo CD namespace whose project is protected; for each finished operation (`Succeeded`, `Failed`, `Error`) posts one `deploy.outcome` keyed by `<Application UID>@<operation startedAt>` (`source.operation`), carrying the sync phase, `observed_revision` and `revisions`, health and sync status, and the applied tree digest (`outcome.digests.sha256`, `change.tree`), `change.id` and `change.release.id` read from the `clearance.hangar.io/tree`, `/grant` and `hangar.io/release-id` stamps of the live objects Argo tracks to the Application (`mixed_stamps: true` and no digest when they disagree) |
| **Exceptions** | 60 s | For every object of the scanned kinds in a protected namespace (not those a controller owns, nor `kube-root-ca.crt` and the `default` service account, nor the gate's own PreSync wait Job when it is exactly what the plugin injects: the same field allowlist as admission's exemption, against the pinned image, core URL and host alias of the chart's `waitJob` values; a Job that only copies its name is reported): no `clearance.hangar.io/rendered` stamp; a stamp no valid grant of the namespace lists for that object; or, when Argo CD's client-side apply left `last-applied-configuration`, content whose hash (without the tracking id and the gate's annotations) is not the stamp. Posts `deploy.exception` (`out-of-band`; `result` says which) once per finding, one record per namespace, reason and writer (the newest field manager); a finding that goes away is forgotten and reported again if it returns. A failed sync whose message is the admission policy's refusal (`ValidatingAdmissionPolicy` or `clearance.hangar.io` in the operation or a resource message) is reported once per operation with `result` "sync refused by the admission policy" |

**Fail closed.** With clearance-api unreachable, or a feed that fails any check (older seq in the same epoch, another
cluster, unknown key, stale, a token withheld or added, no epoch), the agent changes no grant, and keeps the epoch and
seq it had. Every pass it also expires, on its own clock, the grants whose `spec.expiresAt` has passed: `status.valid:
false` and the active label removed, the grant kept for the record. The agent never creates, updates or deletes a
workload, and its RBAC cannot (list on the scanned kinds, no Secret).

**Namespace invariants** (G-ARGO-2: with a Deny binding the API server resolves `paramRef` before `matchConditions`, so a
protected namespace with no active, valid grant refuses every matched write; a second active grant is refused). The
agent keeps them, and the tests hold it to them (`TestGrantSync`, `TestARotationThatFailsKeepsTheActiveGrant`):

1. **The grant comes before the label.** The agent writes a namespace's grant whether or not the namespace is labelled
   `clearance.hangar.io/protected=true`. An operator labels a namespace protected only after
   `kubectl get clearancegrants -n <ns> -l clearance.hangar.io/active=true` shows one with `status.valid` true; the agent
   never labels namespaces.
2. **Exactly one active grant per namespace; rotation in a fixed order.** (The active grant also carries the other live
   trees, `spec.carried`; the grant held active until the flip keeps its carried list, so the running tree is admitted right
   up to the flip.) Write the new grant (not active), mark it
   valid, then per namespace deactivate the old and at once activate the new, two consecutive calls with nothing
   between. A namespace is under two active grants never, and under none only between those two calls (the policy
   refuses writes there and Argo CD retries). If the new grant cannot be written or validated, the old stays active.
3. **Only revocation and expiry leave a namespace with none.** A grant whose token left the feed (revoked, superseded) is
   deleted and one past `spec.expiresAt` is marked invalid and deactivated: that is the gate closing, by design, and the
   namespace refuses until the next clearance.

### The running tree and the active grant

**The gap (seen on hangar-prod, 2026-11-09).** The agent makes a grant active as soon as its change clears on the pull
request, not when it merges or syncs, and the policy reads exactly one active grant. So between the clear and the merge
the tree prod still runs had no active grant: the Rollout was stamped with grant `ch-0a29f11f80f20359` while
`ch-212c050629a9d5d7` was active. If Argo CD re-applied the running tree in that gap (self-heal correcting drift), the
write failed the hash check. In Warn that is a warning; under Deny it is refused until the pull request merges, and a
change cleared and never merged would leave it blocked. A rollback or revert to a tree that was already cleared hit the
same refusal.

**The design: the active grant carries the other live trees.** `spec.carried` (on the active grant only; the CRD allows
16 entries) lists, for each other cleared change of the namespace, `{change, tree, expiresAt, objects}`, where `objects`
is the same `<group>/<kind>/<name>` map to `{rendered}` as `spec.objects`, trimmed to the objects whose hash differs from
the active grant's own. The policy's third check admits an object when its `rendered` stamp equals the hash in the
active grant's own `objects` **or** in any `carried[].objects` entry for that key. Everything else is as before: one
active grant (the policy still needs exactly one), the stamp required, `status.valid` required, each object bound to a
hash by its key, the injected wait Job's exemption unchanged. Warn behaves as before; a refusal is still a warning.

A carried entry lives only as long as its change's clearance:

- **Revoked, superseded, exception, or the horizon passed:** the change's token leaves the signed feed, and the next grant
  sync (30 s) writes the active grant without it. This is the same lag a revoked grant has today (its `ClearanceGrant` is
  deleted on the next pass).
- **Expired:** each entry has its own `expiresAt` (the token's), and the agent drops the entry on its own clock every
  pass, **whether or not the feed can be read**, so a carried tree cannot outlive its clearance because the active
  grant is still valid. The admission policy has no clock; it never reads `expiresAt`.
- The agent carries at most 16 changes (the newest by decision time); another namespace's trees are never carried.

What this admits, and what it does not: the running tree, a tree that was cleared and has not merged, and a tree
rolled back to (any of them still within its clearance, up to the 7 day horizon for a change cleared and not
revoked). It is not "any tree cleared before": an old tree is admissible exactly while its clearance is live, and each
object is still bound to a cleared rendered hash by its key. Because the carried trees were each cleared by policy and
approvals on their own, the set of hashes a protected namespace accepts is the union of live clearances, which is what
"this change is cleared for this cluster" already means; carrying them adds no clearance, it stops the active grant
from hiding the ones that still hold.

**Alternatives weighed.**

- *Activate at sync, not at clear.* The agent would flip the active label only once Argo has synced the tree. It has the
  smallest grant but the largest moving part: the sync itself needs the new tree's grant active (Argo's write is what the
  policy checks), so the agent must flip before the sync starts and cannot tell a sync from a self-heal; it would need to
  learn the intent from the PreSync wait Job or the Application operation, a new path from cluster state to
  authorisation. It also leaves the rollback and cleared-but-unmerged cases open.
- *Several active grants.* Refused by the API server's own semantics: `paramRef` by selector evaluates every matching
  param and each must pass (`test_admission.py`, "two active grants, each must pass"), so a second grant can only deny.
- *Carry only the running tree.* The agent could read the live objects' `clearance.hangar.io/grant` stamps and carry only
  those. It would admit less, but gives the agent a second input to trust and misses the rollback to a cleared tree
  that is not running. Not done; the carry set is bounded by the clearances themselves.

**Grant-writer restriction unchanged.** Only the agent's service account writes a `ClearanceGrant` (`spec.carried`
included); the list comes from the same verified signed feed as the grant's own objects.

**When the path to the hub is down.** `spec.expiresAt` of a grant is its token's expiry. The core re-issues each token
about every 7.5 minutes, and a token lives 15 minutes (`CLEARANCE_TOKEN_TTL`), so `expiresAt` rolls forward while
the agent can read the feed. With clearance-api or the path to it down the agent changes no grant (fail closed, above),
and on its own clock:

1. a carried entry is dropped at its own `expiresAt`, and the active grant is marked `status.valid: false` with its label
   removed at its own: between 7.5 and 15 minutes after the last successful refresh, and in any case 15 minutes after the
   last feed it read;
2. a feed older than 5 minutes is refused anyway, so a late or replayed feed does not extend anything.

Under **Warn** that changes nothing (a missing or invalid grant warns; `parameterNotFoundAction: Allow`). Under **Deny**
the namespace then refuses every matched write, and, because the API server resolves the param before the match
conditions, **from any user**: Argo's self-heal, and also the ReplicaSet controller creating pods (see "Found while
testing"). Running pods are not touched. Recovery:

- *The path returns:* the next grant sync (30 s) reads a fresh feed, rewrites the grants with new `expiresAt`, marks them
  valid and flips the active label back (`TestTheActiveGrantCarriesTheRunningTree`, "recovery"). No operator action.
- *The path does not return and the namespace must move:* a cluster admin sets the first binding back to Warn
  (`validationActions: [Warn, Audit]` and `parameterNotFoundAction: Allow`, in apron `clearance.gate.enforce`), or removes the
  `clearance.hangar.io/protected` label from the namespace. Either is a break-glass act: restore it and confirm one active, valid grant
  (`kubectl get clearancegrants -n <ns> -l clearance.hangar.io/active=true`) before enforcing again.

Apron renders the admission policy from `providers/argocd/crd/admission.yaml` and the CRD from
`clearancegrant-crd.yaml`; both changed here (the third validation and `spec.carried`), so apron's copies must be
re-rendered to match before the Deny flip, and the agent image must be at this version first (an older agent writes no
`carried`, so the policy behaves as before).

**Break-glass.** The agent reads `GET /v1/breakglass?cluster=<c>` (it is a registered provider). It reports exceptions
inside a window like any other, names the window in `exception.detail`, and the core tags the record with it
(`breakglass`, verified). Break-glass does not silence the scan: a change in the glass is still an exception.

**The outcome's key and the core.** The design says the core answers a repeated outcome idempotently. Since O-1 it does,
for a provider that names its own event (`source.event_id`, [evidence.md](evidence.md)); the agent does not send one yet,
so it still keeps what it posted in its state ConfigMap
(`clearance-argocd-agent-state`: the feed epoch and seq, the last operation posted per Application, the exceptions
reported), writes it only after the core answered, and a restart does not repost (`--repost-on-start` does, for a core
that de-duplicates by `source.operation`; the core now de-duplicates on `source.event_id`, which the agent does not send
yet). A crash between the core's answer
and the state write posts that one outcome twice; both carry the same `source.operation`.

**What the CMP and the CRD must agree with** (G-ARGO-2, G-ARGO-4; the agent holds them to nothing it cannot check):
the CRD G-ARGO-2 defines (`--grant-api`, default `clearance.hangar.io/v1`, `providers/argocd/crd`): `spec` as `subject`,
`expiresAt`, `clearance`, `objects` (a map); the active label; the stamps' names above; and that a stamp has the
value of the token's `objects[].rendered` for the object, which is the object's `render.ObjectDigest` (a `sha256:`
prefix is accepted when comparing, but the grant lists the token's value as it is, and admission compares it to the
stamp literally).

**Deploying it** (apron values the manager wires; hangar-dev):

| Where | Value |
| --- | --- |
| `clearance-core` `CLEARANCE_FOREIGN_SERVICE_ACCOUNTS` | add `clearance-system/clearance-argocd-agent` (the service account G-ARGO-2 settled on; Argo's is `argocd-apps/argocd-application-controller`) |
| `clearance-api` `CLEARANCE_FOREIGN_SERVICE_ACCOUNTS` | add `clearance-system/clearance-argocd-agent` |
| `clearance-api` `api.feedReaders` | `{principal: hangar-prod/clearance-system/clearance-argocd-agent, cluster: hangar-prod}` |
| `CLEARANCE_PROVIDERS` | `argocd-agent`, principal `hangar-prod/clearance-system/clearance-argocd-agent`, `kinds: [deploy.outcome, deploy.exception]` |
| HTTPRoute | `Exact /v1/records`, `/v1/breakglass` on the core's host; `/v1/keys` and `/v1/grant-feeds/*` on clearance-api's |

On hangar-prod: the chart `charts/clearance-argocd-agent` (values: `cluster`, `apiURL`, `coreURL`, `argocd.namespace`,
`argocd.projects`, `protectedNamespaces`, `hostAliases`, `networkPolicy`), the image `ghcr.io/jfillman/clearance-argocd-agent`.

**Proof on hangar-prod** (Unverified until run; the manager runs it, with the agent deployed, the namespace
`app-<x>-prod` labelled `clearance.hangar.io/protected=true`, G-ARGO-2's CRD and policy installed):

1. `kubectl -n clearance-system logs deploy/clearance-argocd-agent` shows a feed accepted, no `refused`.
2. Clear a change for the app (a tier 0/1 PR merged, or `clearance register` then clear). On hangar-prod within 30 s
   (plus the feed's re-sign): `kubectl get clearancegrants -A -l app.kubernetes.io/managed-by=clearance-argocd-agent
   -L clearance.hangar.io/active` lists `<change id>` active, `status.valid` true. Record the time of the clear
   (`GET /v1/clearances/<id>`, `decided_at`) and of the grant (`creationTimestamp`).
3. Argo CD syncs the app (the CMP stamps); after the operation finishes, `GET /v1/evidence?tool=deploy.outcome` (as an
   auditor) shows a record whose `source.provider` is `argocd-agent/<version>`, `outcome.phase` `Succeeded`,
   `outcome.digests.sha256` equal to the change's `tree_digest`, and `change.id` the change.
4. `kubectl -n app-<x>-prod create configmap by-hand --from-literal=a=b` (a writer that is not Argo CD). Within the scan
   interval (60 s) `GET /v1/exceptions` shows a `deploy.exception`, `result` "no grant annotation", object
   `v1/ConfigMap/by-hand`, `coverage: out-of-band-detected`. `kubectl delete configmap by-hand` afterwards.
5. Fail closed: scale the core's route down or block the agent's egress; the agent logs `grants stay as they are`,
   no grant changes, no workload restarts; restore, and it recovers on the next tick.

## The Go core (R-1c, Built, deployed on hangar-dev 2026-11-03)

The gate is ported to Go with behaviour unchanged: `internal/gate` (classification, the change record,
`POST /v1/clearances`, `.../{id}/clear`, `.../{id}/deny`, expiry and the GitHub deployment answers), `internal/review`
(`POST /v1/definitions/review`), `internal/definitions` (the pinned-definition set and its `definition.*` records) and
`internal/gate/render` (`clearance register`'s manifest diff, reading YAML the way PyYAML's SafeLoader does). Each gate
operation is one store transaction: the change row and its `deploy.*` records commit together. One tightening: an unknown
field in a request body is refused (400) where the Python core ignored it.

**Who is in a group (Built).** The Go core reads the owner group and people's groups from Tower's
Backstage catalog, as the Python deployment does (`internal/directory/backstage`, ported from autopilot `reads.py`
`BackstageDirectory` and `BackstageAppOwners`). A person `user:<login>`'s groups are the `memberOf` relations of
`user:default/<login>` (`GET /api/catalog/entities/by-name/user/default/<login>`), cached 60 s; a change registered
without an owner gets its app's Component `spec.owner` (`.../by-name/component/default/<app>`), a bare name read as
`group:default/<name>`, `<namespace>/<name>` as `group:<namespace>/<name>`, and a user owner ignored, cached 300 s. Configuration, the same variables as autopilot
`serve.py` so apron's values carry over:

| Variable | Meaning |
| --- | --- |
| `BACKSTAGE_URL` | Tower's Backstage (http or https). Unset: no directory and no owner lookup, so nobody is in any group and **no person can clear a tier-2 or tier-3 change**; the core logs this at startup |
| `BACKSTAGE_TOKEN_FILE` | the bearer token, re-read on every call (default `/var/run/clearance/backstage-token`, a projected service-account token for the `backstage` audience). Never logged |

It fails closed for clearing: Backstage down, refusing, slow (10 s deadline per call), redirecting, answering more
than 1 MiB or answering something that is not an entity is no groups and no owner, cached for the TTL like any
answer, so a person cannot clear until it answers again; an unknown owner falls back to the outside group, which
nobody is in either while Backstage is down. Differences from the Python transport: the per-call deadline is 10 s
(was 30 s; the Go gate asks inside its lock and the operation's transaction), redirects are not followed (the token
stays with the configured URL), the answer is capped at 1 MiB (was 16 MiB), a malformed answer is no groups where
Python raised, and each cache holds at most 4096 entries.

## The policy in the record (C-8, Built; live check pending)

Two policies stand behind a deployment decision: Clearance's own tier policy (the baseline, tightened by the repo's
`clearance.yaml`), which the core applies, and the target cluster's admission policies, which the verifier evaluates
offline over the rendered tree before it registers the change. Every `deploy.*` record about a change
(`deploy.request`, `deploy.clear`, `deploy.deny`, `deploy.expire`, a GitHub deployment's `deploy.request`) carries a
`policy` group, in the evidence schema's Decision group, that names both:

```json
"policy": {
  "ref": "clearance.yaml@9f2c...e1",
  "version": "baseline-2026-10-31+sha256:3905e609...e3e5",
  "engine": "kyverno/1.19.0",
  "verdict": "pass",
  "bundle": "https://github.com/jfillman/gitops-hangar-dev.git//30-policy@4b1d...07"
}
```

| Field | What it is | Where it comes from |
| --- | --- | --- |
| `ref` | `clearance.yaml@<commit>`: the commit that last changed the repo's `clearance.yaml` at the change's head. `clearance.yaml@sha256:<digest>` when the verifier sent the file without its commit; `baseline` when the repo has none | the request's `policyCommit` (else the digest of `policy`) |
| `version` | the gate baseline's version, plus `+sha256:<digest>` of the `clearance.yaml` that tightened it. With the core's baseline this reproduces the tier decision | the core |
| `engine` | the admission engine and its version, `kyverno/1.19.0`; `none` when no admission result was sent | the request's `admission.engine` |
| `verdict` | `pass`, `warn` (Audit/Warn findings only, or a rule offline evaluation could not decide), `fail` (a Deny/Enforce policy fails: the cluster would refuse the sync), `skipped` (no admission policy to evaluate), `error` (the evaluation could not run); `not-evaluated` when none was sent | the request's `admission.verdict` |
| `bundle` | the admission rule set it ran: `<repo>//<path>@<commit>`. With the rendered tree (`subject`) and `engine`, it reproduces the admission verdict | the request's `admission.bundle` |

A decision with no change on record (a GitHub deployment of an unregistered commit, `DG-UNREGISTERED`) records
`{ref: baseline, version: <baseline>, engine: none, verdict: not-evaluated}`. The group is **claimed**: the verifier
reports the commit and the verdict; the core fills `version` from what it applied. The runtime boundary's records keep
their own `policy` group (`clearance-core+<bundle>@<version>`, the bundle digest, `engine: cel-go`), unchanged. The clearance token signed on `deploy.clear` carries the same group as its `policy` claim, field for field ([core.md](core.md) "The clearance token"): the token attests what the record says.

**The request.** `POST /v1/clearances` takes two optional fields beside `policy` (all strictly decoded, unknown keys
refused):

- `policyCommit`: the 40-hex commit that last changed `clearance.yaml` at the head. Refused without `policy`.
- `admission`: `{engine, verdict, bundle, deny, warn}`; `engine` is `<name>/<version>` (lowercase name), `verdict` one
  of the five above, `bundle` at most 512 printable characters, `deny` and `warn` the blocking and warning finding
  counts. It is a check result: `checks.admission` becomes its verdict, and a request whose `checks.admission` says
  something else is refused (400).

The change keeps `policy_ref` and `admission` (clearance-api serves them on `GET /v1/clearances/{id}`; a change
registered before this release has neither, and its records name `clearance.yaml@sha256:<digest>` or `baseline`). A
re-registration of a holding change takes the new admission result, so the `deploy.clear` that follows records the
verdict it cleared on.

**Recorded, not enforced.** The tier rules do not read the verdict: on Hangar the `policy-validation-` check is the
required gate for an admission failure, and phase 2's grant-match admission is the hard one. Making a tier-1 clear by
policy wait for `admission` in (`pass`, `warn`, `skipped`) is a one-line change to the checks a tier-1 change needs,
left for the owner to decide (it would turn every verifier that sends no admission result into tier 2).

**Who sends it.** Glidepath's `clearance-gate-` task evaluates each protected environment's rendered head with the
Kyverno CLI against the target cluster's policy bundle, exactly as the `policy-validation-` gate does (glidepath
`docs/admin/policy-validation.md`; the two tasks share the evaluation), and sends `admission` and `policyCommit`.
Argo CD's config management plugin (G-ARGO) sends the same `admission` object from its own offline evaluation of the
tree it rendered; `clearance register` sends none today (`not-evaluated`).

## The operational class (I-1, Built)

The tier is the customer's policy: a tenant can tighten it, so tier 2 in one tenant is not tier 2 in another. The
**operational class** is what the change does, computed from the rendered diff or the plan with a fixed mapping. It is
the only axis a cross-tenant comparison may use. The packet's Changes section prints both (C-5, later); the field is
in the record now.

| Class | What it means | Examples |
|---|---|---|
| `availability` | can take a service down or change its capacity | a Deployment image bump, a Service, an HPA, `aws_instance`, `aws_lb` |
| `privilege` | changes who may do what | Role, RoleBinding, ServiceAccount, `aws_iam_*`, an agent definition's authority |
| `data-integrity` | can lose or corrupt stored data | PersistentVolumeClaim, StatefulSet, `aws_db_*`, `aws_s3_bucket` |
| `security-boundary` | moves a network, admission or trust boundary | NetworkPolicy, Ingress, webhook configs, security groups |
| `credential-exposure` | touches a secret or key | Secret, ExternalSecret, `aws_secretsmanager_*`, `aws_kms_*` |
| `none` | nothing operational changed (see below) | release stamps only, a plan that changes nothing |

A change carries one or more of the five, sorted, in `operational_class`; `class_mapping` is the mapping's version
(`opclass/1`). Both are in the Decision group of every `deploy.*` record about a registered change (the request, clear,
deny, expire, revoke, answer, outcome, exception and degraded records), verified (the core computes them from the diff
it holds) and stored on the change, so a record says which mapping computed it.

**The mapping is data**: `internal/gate/opclass.json`, embedded, versioned. It holds the Kubernetes kinds, field
pointers (`securityContext`, `secretKeyRef`, `volumeClaimTemplates`, ...), path globs and Terraform resource-type
globs, each with its classes. Changing it bumps `version`; the tier rules (classify.go, terraform.go) are untouched.
A changed or added or removed object of a kind the mapping does not name is `availability` (the fallback): a
change to a running thing is never classless. A field rule adds a class to the kind's (a Deployment whose
`envFrom` changed is `availability` and `credential-exposure`). A Terraform resource of an unmapped type that
changes is also `availability`.

**A change with no operational effect is `["none"]`, never empty**, and `none` never appears beside another class. That
covers: a change of only release stamps or other metadata fields (the `release-stamp` and `metadata-only` reasons), a
manifest change with no object changed (non-runtime paths only), a plan with no resource change, a tag-only or
description-only update of a type that is unmapped or only an availability concern (a tag on an IAM role or a database keeps
its class: a tag can drive access), and an agent definition whose reasons carry no change in
authority (provenance notes only). An agent definition that changes authority is `privilege`. `none` is a class a
reader can aggregate on; an empty list would read as "not classified".

**Not classified**: a deployment request with no change on record (`DG-UNREGISTERED`) has no diff, so its record
carries neither field. A change registered before I-1 has none stored; its records compute the classes from what the
change stores, under the baseline, so they are still present. The classes never move the tier, the requirement or any
verdict.

## The manifest-tree digest (Built)

A change binds to what will be applied through one digest, the **manifest-tree digest** of the rendered "after"
tree. `clearance register` computes it from `--after`, Glidepath's `clearance-gate-` check computes the same value
for the same render (it always has), and the Argo CD plugin (G-ARGO) is to stamp the same value; the core keeps it as
the change's `tree_digest` and `subject.digests.sha256`, and the provider protocol's outcome compares against it.

1. **Objects.** Every document in the directory's `*.yaml`, `*.yml` and `*.json` files (recursively, in path order)
   that has `apiVersion`, `kind` and `metadata.name`; a `*List`'s `items` count one by one. YAML is read as PyYAML's
   SafeLoader reads it (YAML 1.1 scalars; `internal/gate/render`). An object's identity is
   `(apiVersion, kind, metadata.namespace or "", metadata.name)`; a later document with the same identity replaces an
   earlier one.
2. **Object hash.** The lowercase hex sha256 of the object's canonical JSON: keys sorted by code point, separators
   `,` and `:` (no spaces), every character outside space to `~` escaped as `\uXXXX` (Python's
   `json.dumps(obj, sort_keys=True, separators=(",", ":"))`). This is also each object's `digest` in `objects`.
3. **Lines.** One per object: `apiVersion/kind/namespace/name:` followed by the object hash (an empty namespace
   leaves `//`, as in `rbac.authorization.k8s.io/v1/ClusterRole//shop-reader:2f89...`).
4. **Root.** The lines sorted byte-wise, joined with `\n` (no trailing newline), and the lowercase hex sha256 of
   that. It is sent as 64 hex digits (a `sha256:` prefix is accepted and dropped).

`internal/gate/render/testdata/parity` pins the definition: its three objects' hashes and the root
`27cbba8e2f2c...1238` were computed with Glidepath's own Python over the same file, and
`TestTreeDigestIsGlidepaths` holds the Go to them. Before G-TF-1, `clearance register` hashed the canonical
documents themselves (sha256 over each object's canonical JSON and a newline, in identity order), so its digest for a
render differed from Glidepath's; a change registered by a v0.30.0 or earlier `clearance register` keeps the digest it
was registered with.

**Placeholders.** A `treeDigest` of 64 copies of one hex digit, or sha256 of nothing (the tree of an empty render),
is a placeholder: it binds the change to no tree, only to its commit. (hangar-dev's records 402 to 405, on
2026-11-01, carry an all-zero tree; they were a hand-made registration by `app-gate-api-cicd/pipeline-runner`, not
`clearance register`, whose registrations there, 468 to 474 and 641, carry a real tree.) What the core does with one
is `CLEARANCE_GATE_UNBOUND_TREE` (chart `gate.unboundTree`):

- `flag`, the default for this release, for backward compatibility: the change is registered and tiered as before,
  with one more reason, `{"the tree", "tree:unbound", 0}`, `subject.flags: ["unbound-tree"]` and no
  `subject.digests.sha256`; its records' subject carries `gitCommit` only.
- `refuse`: `DG-UNBOUND` (400), nothing recorded. The plan is to make this the default one release later, once every
  registrar sends a real tree.

`clearance register` itself refuses an `--after` that holds no manifests (exit 2) rather than send the empty tree.

## The terraform-plan subject (G-TF-1)

Status: **Built** in the core (classification, the request and the record); the hold, release and outcome on the
core API are G-TF-2's (next section, Built). The CLI and CI step that post it are G-TF-3
([docs/terraform-gate.md](terraform-gate.md), Built); detection of applies that went around the gate (G-TF-5) come next; nothing in
Glidepath or the lab's `jfillman/hangar-infra` posts one yet.

A change's **subject** is what it binds to. Beside the Kubernetes object diff (kind `manifest-tree`, described by
`treeDigest` and `objects`) and an agent definition's release (kind `definition`), a change can now be a saved
Terraform plan. The verifier sends it as the request's `subject` (`schemas/change-request.schema.json`, the whole
request's schema; `POST /v1/clearances` from a verifier, `CLEARANCE_VERIFIERS`, or from a GitHub Actions workflow's
OIDC token, which registers for its own repository only, `DG-REPO`):

```json
"subject": {
  "kind": "terraform-plan",
  "planDigest": "<sha256 of the saved plan file, terraform plan -out>",
  "planJsonDigest": "<sha256 of the redacted plan JSON, terraform show -json with sensitive values replaced>",
  "workspace": {"backend": "s3", "key": "network/lab/terraform.tfstate", "name": "default"},
  "versions": {"terraform": "1.9.8", "providers": {"registry.terraform.io/hashicorp/aws": "5.70.0"}},
  "summary": {"create": 0, "update": 1, "replace": 0, "destroy": 1, "destroyedAddresses": ["aws_instance.bastion"]},
  "targeted": false,
  "variableSetDigest": "<sha256 of the variable set>",
  "resources": [
    {"address": "aws_vpc.lab", "type": "aws_vpc", "actions": ["update"], "fields": ["/tags/Owner"]},
    {"address": "aws_instance.bastion", "type": "aws_instance", "actions": ["delete"]}
  ]
}
```

- `resources` is one entry per `resource_changes[]` of the plan JSON: the address, the type (the address must name
  it), Terraform's action list (`no-op`, `create`, `read`, `update`, `delete`, `delete`+`create`,
  `create`+`delete`), the JSON pointers of the attributes an update changes, and Terraform's `action_reason`
  (`actionReason`; `replace_by_request` is a `-replace`). The card's shape names only the summary; the resources were
  added because the tier table needs each resource's type and attributes, and the classifier names their addresses.
- `summary` must be exactly what `resources` says (the counts, and `destroyedAddresses` = the addresses with
  `["delete"]`), or the request is refused; a verifier cannot show a destroy in one and hide it from the other.
- `targeted` says the plan was made with `-target`.
- With a plan subject, `cluster` and `treeDigest` may be omitted (a `treeDigest` that is not the plan's digest is
  refused), `objects` must be empty and `definition` absent. The change's `tree_digest` is `planDigest`, so the
  provider protocol's outcome check reads the same field for both kinds.
- Every digest is sha256 (bare hex or `sha256:`); a placeholder plan, plan-JSON or variable-set digest is refused
  `DG-UNBOUND`. **Secret variable values are never sent or stored:** the record carries the redacted plan JSON's
  digest and the variable set's hash; `fields` are attribute names, never values.

**The Terraform baseline** (`GatePolicy`: `TFTier3Types`, `TFTagFields`), the maximum over the plan's resource
changes (no-op and read entries are skipped) and its paths (the path rules apply: a `clearance.yaml` in the infra
repo is tier 3):

| Rule | Tier | Reason (subject, rule) |
|---|---|---|
| destroy (`["delete"]`) in a protected workspace | 3 | the address, `tf:destroy` |
| replace (`delete`+`create`, either order) in a protected workspace | 3 | the address, `tf:replace` |
| any change to an IAM, security-group, network-ACL, KMS or database type, a tag included | 3 | the address, `tf-type:iam` / `security-group` / `network-acl` / `kms` / `database` |
| an update whose every changed attribute is under `/tags`, `/tags_all`, `/labels` or `/description` | 1 | the address, `tf:tag-only` |
| everything else (create, other updates, destroy or replace in an unprotected workspace, an update naming no attributes) | 2 | the address, `tf:create` / `tf:update` / `tf:destroy` / `tf:replace` |
| a plan that changes nothing | 1 | `the plan`, `tf:no-change` |
| `-target` (`targeted`) or a `-replace` (`actionReason: replace_by_request`): one tier up, at least 2, at most 3 | +1, floor 2 | `the plan`, `tf:targeted`; the address, `tf:replace-requested` |

Then, as for manifests: an unknown proposer is denied (`DG-PROVENANCE`); a tier-1 plan clears by policy only with
`ci: pass` and `provenance` confirmed, not-agent or unattested (there is no `render` check for a plan), else it is tier 2
(`checks:...`); tier 2 holds for one owner, tier 3 for one owner and one outside person. Tier 3 is never cleared by
policy, so **a destroy in a protected workspace never clears by policy**. The decision's `result` names the
workspace and what set the tier: `tier 3: holding for 1 from group:... and 1 from outside (...) (s3:network/lab/
terraform.tfstate#default, protected; set by aws_instance.bastion)`.

The type globs (fnmatch on the resource type), by category: **iam** `aws_iam_*`, `aws_ssoadmin_*`,
`aws_organizations_policy*`, `aws_lambda_permission`, the S3, SQS, SNS, ECR and Secrets Manager resource policies,
`google_*_iam_*`, `google_service_account*`, `google_organization_policy`, `azurerm_role_assignment`,
`azurerm_role_definition`, `azurerm_user_assigned_identity`, `azuread_*`, `kubernetes_*role*`,
`kubernetes_service_account*`; **security-group** `aws_security_group`, `aws_security_group_rule`,
`aws_default_security_group`, `aws_vpc_security_group_*`, `google_compute_firewall*`,
`azurerm_network_security_group`, `azurerm_network_security_rule`; **network-acl** `aws_network_acl`,
`aws_network_acl_*`, `aws_default_network_acl`; **kms** `aws_kms_*`, `google_kms_*`, `azurerm_key_vault*`;
**database** `aws_db_*`, `aws_rds_*`, `aws_dynamodb_*`, `aws_docdb_*`, `aws_neptune_*`, `aws_redshift_*`,
`aws_elasticache_*`, `aws_memorydb_*`, `aws_dax_*`, `aws_keyspaces_*`, `aws_timestreamwrite_*`, `google_sql_*`,
`google_spanner_*`, `google_bigtable_*`, `google_firestore_*`, `google_alloydb_*`, `azurerm_*sql*`,
`azurerm_cosmosdb_*`, `azurerm_redis_*`. `GET /v1/clearance-policy` serves them under `terraform`.

**Protected workspaces.** A workspace is protected when the request says `protected` (the default, as for an
environment) or the repo's `clearance.yaml` names it. `clearance.yaml` gains a `workspaces:` block, tighten-only
like the gitops tiers:

```yaml
workspaces:
  protected: ["network/*", "prod"]        # globs on the state key or the workspace name: protect more, never fewer
  tiers:
    "3": {types: ["aws_route53_*"]}       # more tier-3 types (reason tf-type:clearance.yaml)
    "2": {types: ["aws_vpc"]}             # types whose tag-only update is still tier 2 (tf-type:tier2)
```

Anything else in the block (an `unprotected` list, `tiers` 0 or 1, a key other than `types`, a value that is not a
list of strings) is `DG-POLICY`, and, as for the gitops block, the change is denied by policy rather than the file
ignored. Approvers and the TTL are the file's top-level `approvers` and `ttlDays`, shared by both kinds.

**The record.** The change on record (`GET /v1/clearances`, `/v1/clearances/{id}`) carries `subject`: the request's
plan subject plus `digests` (`sha256` = the plan, `planJson`, `variableSet`, `gitCommit` = the head). Each
`deploy.*` record's subject is `{kind: terraform-plan, name: app/env, digests}` (claimed: the verifier described the
plan). A manifest change's subject is `{kind: manifest-tree, digests: {sha256, gitCommit}}`, a definition release's
`{kind: definition, name: <agent>, digests}`; a change stored before G-TF-1 reads back as `manifest-tree` from its
`tree_digest`. clearance-api returns the stored change as it is, so the list shows `subject.kind` for every change
registered from this release on (and for older ones once they are written again). A cleared plan's clearance token
(C-1) has `subjects.kind: terraform-plan` and binds the plan's digest as `subjects.plan_digest` (no `tree_root`).

## Hold, release and outcome for a plan (G-TF-2, Built)

Status: **Built** in the core (`internal/gate/outcome.go`, `terraform.go`, `request.go`); its caller is G-TF-3's
`clearance hold`, `release` and `report` ([docs/terraform-gate.md](terraform-gate.md), Built); the lab workflow is G-TF-4 ([terraform-gate.md](terraform-gate.md#the-lab-workflow-g-tf-4-draft), Draft).

**Registration is idempotent by repository, workspace and plan.** A terraform-plan change's id is `ch-` and the first
16 hex of sha256 over the JSON array `["terraform-plan", repo, backend, key, name, planDigest]`, not of
`repo#pr@head`. The same saved plan registered again (a re-run, another job, the merge commit) is the same change:
a holding one is re-evaluated with the new checks, a decided one returned as it stands, with one `deploy.request`.
Another workspace, state key or plan is another change, so two workspaces planned at one commit no longer collide.
Superseding is unchanged: a new head on the same pull request supersedes the heads still holding.

**The hold is 24 hours.** A plan goes stale as the state moves, so a terraform-plan change expires one day after it
is registered (`GatePolicy.PlanTTLDays`, `DefaultPlanTTLDays = 1`; `GET /v1/clearance-policy` serves
`terraform.ttlHours: 24`). A gitops change keeps the 7-day TTL. A `clearance.yaml` `ttlDays` still only shortens:
the plan's TTL is the shorter of the two. The expiry loop writes `deploy.expire` (`result: "not cleared within 24
hours"`, principal `policy`), and the token horizon (C-1) follows the same TTL after the clear.

**Waiting and release.** There is no plan-specific wait route: the provider long-polls C-10's
`GET /v1/clearances/{id}/wait?state=holding&timeout=60` as the registering principal, and on `cleared` the answer
carries the clearance token, whose `subjects.kind` is `terraform-plan` and `subjects.plan_digest` the plan's digest
(`token.Expect.PlanDigest` refuses a token for another plan). The release step re-hashes the saved plan and applies
only when it equals the cleared digest (G-TF-3).

**The outcome.** `POST /v1/clearances/{change_id}/outcome`, for the principal that registered the change only (the
same workflow's OIDC subject, or the same verifier), strictly decoded (unknown fields refused, 4 MiB cap):

```json
{"applied": true, "planDigest": "sha256:<the saved plan file that was applied>",
 "changes": [{"address": "aws_vpc.lab", "action": "update", "status": "complete"}],
 "startedAt": "2026-11-03T12:00:00Z", "finishedAt": "2026-11-03T12:00:09Z", "error": ""}
```

`changes` come from `terraform apply -json`'s apply hooks (address, `hook.action`: noop, create, read, update,
replace, delete, move, import, remove, forget; `status` complete or errored), at most 2000; no values. `error` is the
apply's error (at most 4 KiB), when it failed. `finishedAt` is not before `startedAt` nor more than 5 minutes ahead
of the core's clock.

The core compares `planDigest` with the digest the change was cleared for and, in one transaction:

- writes `deploy.outcome` (principal: the registrant; `decision` null) with **`matched`** (verified: the core's
  comparison), `outcome {applied, digests: {sha256: <applied>}, changes, started_at, finished_at, error}` (claimed:
  the reporter's), `destination {environment, cluster?}`, and the change summary whose `tree` is the cleared digest;
- on a mismatch also writes **`deploy.exception`** of kind `digest-mismatch`, in C-6's shape: `exception {kind,
  expected: "sha256:<cleared>", observed: "sha256:<applied>", detected_at, detail}` (the detail names the outcome's
  seq), `coverage: out-of-band-detected`, the change named by `change.id`;
- keeps the outcome on the change: `outcome {seq, applied, matched, plan_digest, at, exception}`;
- on a mismatch moves the change to `exception` and revokes its token (`deploy.revoke`), below.

The answer is `{change, matched, audit_seq, exception_seq}`. A failed apply is an outcome too (`applied: false`, its
error recorded).

**The outcome's state machine.** One outcome per change, and only for a cleared one:

| Situation | Answer |
| --- | --- |
| a cleared terraform-plan change, first outcome, from its registrant | 200; `deploy.outcome`; on a mismatch also `deploy.exception` and `deploy.revoke`, and the change is `exception` |
| a second outcome for the same change, matched or not | 409 `DG-STATE` ("already recorded (seq N)") |
| a holding, denied, expired or superseded change | 409 `DG-STATE` |
| a caller that did not register the change | 403 `DG-FORBIDDEN` |
| a manifest-tree or definition change | 400 `DG-SUBJECT` (its provider reports `deploy.outcome` through `POST /v1/records`) |
| no such change; the gate off | 404 `DG-UNKNOWN`; 404 `DG-OFF` |
| a malformed body | 400 |

Every refusal records nothing. Go client `ChangeOutcome`, Python client `record_change_outcome`.

**A mismatch takes the clearance away (C-6).** In the same transaction as the two records, the change moves from
`cleared` to `exception` along C-6's state machine (`gate.Transitions`), its `ended` names the `deploy.exception`
(seq, tool, kind `digest-mismatch`), and its token is revoked: a `deploy.revoke` record, "token revoked: exception:
digest-mismatch". A GitHub deployment of it is then rejected. A matched outcome leaves the change `cleared` with its
token live until its horizon. A second outcome is `DG-STATE` either way (the change has an outcome, and a mismatched
one is no longer cleared). The core writes this exception itself, so it is not checked by `gate.CheckReport` and is
not tagged with a break-glass window: a plan names no cluster.

## The Argo CD plugin and the PreSync wait (G-ARGO-4 and G-ARGO-5, Built)

Status: **Built** in `providers/argocd/cmp` and `providers/argocd/wait`, with unit tests, a parity test against a
recorded gate-api render, and the provider conformance suite (G-ARGO-9: the plugin's `Generate` with the agent behind a
fake Argo CD, `TestArgoConformance`: it holds a tree nobody cleared with the PreSync wait Job and applies nothing, stamps
and syncs once a person clears it, finds a tree a pull request's check cleared by policy, and refuses a denied or an
expired one); the lookup it needs is in the core (`gate.Service.clearedByTree`). The conformance run does not start the
Job's container (`clearance-wait` has its own tests). The owner reports the gate **live on hangar-prod in Warn mode, not
Deny** (2026-11-09); the steps [at the end](#checking-it-on-hangar-prod-steps-for-the-manager) were not run for this
change and stay **Unverified** here. The plugin writes no evidence record of its own: it registers changes as a verifier
(`proposer: system:argocd-cmp`), so the records that name the gate are the agent's.
Apron's half (the sidecar and the ApplicationSet's plugin source, off by default) is `clearance.gate.enabled` in
[apron](https://github.com/jfillman/apron) `README.md`. The shape is the Phase 2 design pass's (D26, (a) above): the
plugin replaces the Helm source.

### What `generate` does

`providers/argocd/cmp` is the `clearance-cmp` binary, run by Argo CD's CMP server in a sidecar of argocd-apps'
repo-server (`plugin.yaml`; an Application opts in with `spec.source.plugin.name: clearance`). For one Application:

1. **Render.** The chart is fetched at its pinned tag (`git clone --depth 1 --branch <tag>`) and the peeled commit is
   recorded, not the tag. Then `helm template <Application name> <chart> --namespace <destination>` with the
   gitops repository's value files (a missing one is skipped) and the platform-injected values last (`valuesJson`,
   what the Helm source's `valuesObject` was). A kustomize directory (`kustomizeDir`, the tenant's `configmap/`) is
   rendered with `kustomize build` beside it. The release name is the Application and the namespace is the destination.
2. **Canonicalise and hash.** Objects are read and hashed exactly as [The manifest-tree digest](#the-manifest-tree-digest-built)
   defines it (the same `internal/gate/render` code `clearance register` uses), after the destination namespace is
   set on every namespaced object that lacks one (Argo CD adds it on apply; the agent must be able to reproduce the
   stamp). Cluster-scoped kinds are a fixed list plus any kind named `Cluster*` plus the Application's
   `clusterScopedKinds` parameter (a plugin cannot ask the cluster's discovery).
3. **Cache.** A cleared tree is remembered for two minutes (per app, environment, cluster and tree) so a refresh of an
   unchanged render does not call the core.
4. **Register.** `POST /v1/clearances` as a verifier, the object shape the `clearance-gate` Tekton task posts, for a
   pushed commit: `pr: 0`, `head` the commit Argo CD syncs (`ARGOCD_APP_REVISION`), `repo` the gitops repository,
   `proposer: system:argocd-cmp`, every object `added` (there is no base render to diff), checks `ci`, `provenance`
   and `admission` unknown and `render` ok. A tree nobody has cleared is therefore never cleared by policy at tier 1
   (its checks are missing): it holds for people. The core answers with the **cleared change for the same app,
   environment, cluster and tree** when there is one (below), and otherwise registers a new one.

### The three outcomes

| The change is | The plugin | Argo CD shows |
| --- | --- | --- |
| `cleared` | emits every object stamped with `clearance.hangar.io/rendered` (the object's hash, bare hex), `clearance.hangar.io/tree` (the tree root) and `clearance.hangar.io/grant` (the change id) | a normal sync |
| `holding` | emits the objects stamped `rendered` and `tree` (no `grant`) **plus a PreSync Job**, `clearance-awaiting-approval`, carrying the change id | the sync waits at "PreSync: clearance awaiting approval" until a person clears it; the next render, now cleared, adds the grant annotation |
| `denied` (tier 3 policy, a person), `expired`, `superseded`, `exception`, `degraded`; or the core unreachable with no cleared allow-and-record entry (an outage hold); or a render that fails | exits 1 with the reason on stderr | `ComparisonError` on the Application; nothing syncs |

The outage policy is C-6's: while the core is unreachable a tree that was cleared (within its own expiry) and whose
tier's action is `allow-and-record` is served from the cache; anything else holds, because an unknown tier is never
allowed. **Not built:** posting the `deploy.degraded` record for what was let through during an outage (the plugin
keeps no outbox).

The stamp is a content hash, not a secret; admission (G-ARGO-2's policy) matches it against the namespace's
`ClearanceGrant`. The plugin never trusts a `grant` annotation a tenant's chart wrote: it is replaced or removed. The three gate annotations a chart wrote are also removed before hashing (and an annotations map left empty), exactly as the agent (G-ARGO-3) strips them from a last-applied configuration, so `rendered` is `render.ObjectDigest` of what the agent recomputes (`TestTheStampIsWhatTheAgentRecomputesFromLastApplied`).

### The lookup by tree (core)

Argo CD syncs the merge commit, not the PR head the `clearance-gate` check registered, so `POST /v1/clearances`
with `pr: 0` and a bound manifest-tree digest first looks for a **cleared, unexpired change of the same app,
environment, cluster and tree** and answers it, recording nothing; otherwise the registration proceeds as before (a
new change, superseding older pushed commits of the same app, environment and cluster). A registration with a PR is
never answered by tree. One consequence for the existing rule that a new pushed head supersedes the older ones: a
push whose tree is already cleared no longer supersedes anything (the same tree is the same change). Memory and
Postgres stores gain `ChangesCleared(app, env)`.

### The PreSync wait

`providers/argocd/wait` is `clearance-wait`, the injected Job's container (distroless, nonroot, no shell). It reads
the change (`GET /v1/clearances/{id}`), then long-polls the generic wait route (`GET /v1/clearances/{id}/wait?state=holding`,
30 s at a time, C-10) until the state moves:

| Exit | When |
| --- | --- |
| 0 | `cleared` |
| 1 | `denied`, `expired`, `superseded` or any other state that will not clear; or the core refused the call (403, 404: not retried) |
| 2 | still `holding` after `--timeout` (default 24 h; the Job's `activeDeadlineSeconds` is that plus 5 minutes) |
| 3 | a usage error |

An unreachable core (5xx, timeout) is retried until the deadline, never read as a decision. The last line is also the
container's termination message (`clearance awaiting approval: ...`, `clearance denied: ...`), which is what Argo CD
history and `kubectl describe` show for the hook. The Job runs as uid 65532 with a read-only root filesystem, mounts a
projected service-account token (audience `clearance`) and nothing else, and is deleted on success
(`BeforeHookCreation,HookSucceeded`).

**It is not a control.** `argocd app sync --strategy apply` skips hooks, and so skips the wait; the sync still meets
admission, which refuses every object the namespace's grant does not list. The wait makes the sync readable and
keeps Argo CD from applying while a person is deciding; admission is what refuses.

### Parameters and settings

The tenant-onboarding ApplicationSet sets the plugin's parameters (all strings; Argo CD gives them to the plugin as
`PARAM_<NAME>`): `app`, `env`, `cluster`, `chartRepo`, `chartRevision`, `chartPath`, `valueFiles` (comma-separated,
paths in the gitops repo), `valuesJson`, `kustomizeDir`, and optionally `clusterScopedKinds`. The sidecar's
environment: `CLEARANCE_URL`, `CLEARANCE_TOKEN_FILE` (default `/var/run/secrets/tokens/clearance`, read on every call),
`CLEARANCE_WAIT_IMAGE`, `CLEARANCE_WAIT_HOST_ALIAS` (`ip=host`, for the Job's pod when the core is on another cluster),
`CLEARANCE_WAIT_TIMEOUT`, `CLEARANCE_CMP_CACHE_DIR`, `CLEARANCE_CMP_CACHE_TTL`.
Paths and the chart tag are validated (relative, no `..`, no leading `-`). The sidecar's `git` and `helm` run with a
bare environment, so the clearance token is not in their reach.

Images: `providers/argocd/cmp/Dockerfile` (alpine with git, helm and kustomize pinned and checksum-verified, the static
binary, `plugin.yaml`; uid 999) and `providers/argocd/wait/Dockerfile` (distroless static). Both build from the
repository root; neither is in a release workflow yet.

### Parity with the Tekton check, and what is not yet the same

`providers/argocd/cmp/testdata/parity-gate-api` holds gate-api's `hangar-prod/prod` values, a recorded `helm template`
(airframe v0.3.168) and the digests Glidepath's own Python code (`tekton_digest.py`, verbatim from the task) computes
for it. `TestParityWithTheTektonGateRender` holds the plugin's tree and all six object hashes to them. Three
differences remain, none in this repository to close:

1. **The release name.** The Tekton task renders with `helm template "${APP_NAME}"` (`gate-api`); Argo CD, and the
   plugin, use the Application's name (`gate-api-prod`), and the chart stamps `app.kubernetes.io/instance` from it.
   The trees differ (`TestTheTektonTaskTodayRendersADifferentTree` pins this). Until the task renders with
   `<app>-<env>`, a PR's clearance is not found by tree at sync time. G-ARGO-8 (glidepath `clearance-gate` task).
2. **The platform values.** The ApplicationSet gives the chart `observability` (namespace, instrumentation, runtime);
   the task's injected values do not. A tenant with those set renders differently in the two. Same fix.
3. **Only the diff is registered.** A PR registration lists the changed objects; `ClearanceGrant.spec.objects` is to
   hold every object of the cleared tree. The plugin's own registration lists all of them (every object is `added`),
   so a tree first seen by the plugin is complete; a tree the Tekton task cleared is not, and the grant's other
   objects need the full list (G-ARGO-2/3/6: the grant feed or a `GET` for the tree's objects).

Not built: `release.id` on the registration (the request has no such field until C-10's release work lands; the plugin
could read it from the Rollout's `hangar.io/release-id`), an OCI chart (the chart is a git repository), a private
chart repository's credential, and `--include-crds` and cluster capabilities (`KUBE_VERSION`, `--api-versions`) on
the render, which Argo CD's own Helm passes and the Tekton task does not.

### Wiring for the manager (hangar-prod to hangar-dev; D29)

The code does none of this; each line is a change to a values file or a manifest.

**Core and clearance-api (hangar-dev, apron values):**

| What | Value |
| --- | --- |
| `CLEARANCE_FOREIGN_SERVICE_ACCOUNTS` (core) | `argocd-apps/argocd-apps-repo-server` (the plugin's identity: `hangar-prod/argocd-apps/argocd-apps-repo-server`); and the wait Job's account (below) |
| `CLEARANCE_VERIFIERS` | `hangar-prod/argocd-apps/argocd-apps-repo-server`: the plugin registers changes (`POST /v1/clearances`) |
| `CLEARANCE_PROVIDERS` | one entry for the wait Job, e.g. `argocd-wait`, principals `hangar-prod/app-*/default` and `hangar-prod/infra-*/default` (the Job runs in the destination namespace as its default account: the CMP sets no `serviceAccountName`, and the admission policy refuses one), **no kinds**: the wait route admits a registered provider or the verifier that registered the change, and a Job pod is neither the repo-server nor listed. Confirm a provider with no kinds is accepted, else a read-only variant is a core change |
| route allowlist (HTTPRoute `clearance-github-webhook`) | `Exact /v1/clearances` (POST, already reaching the core) and **`PathPrefix /v1/clearances/`** for `GET /v1/clearances/{id}` and `/wait` |

**hangar-prod (apron, `clearance.gate`, and the repo-server and tenant namespaces):**

| What | Value |
| --- | --- |
| cluster.yaml | `clearance.gate.enabled: true`, `clearance.gate.url: http://clearance.hangar-dev.local`, `clearance.gate.hostAlias: 192.168.1.72=clearance.hangar-dev.local`, `clearance.protectedEnvironments: [hangar-prod/prod]`, `versions.clearance.cmpImage` and `waitImage` by digest |
| repo-server pod | a hostAlias `192.168.1.72 clearance.hangar-dev.local` (the sidecar shares the pod's) and an egress NetworkPolicy to 192.168.1.72:80 |
| tenant namespaces (`app-*-prod`) | egress for the wait Job's pod to 192.168.1.72:80 (the hostAlias is set on the Job by `CLEARANCE_WAIT_HOST_ALIAS`) |
| admission (G-ARGO-2's policy) | exempt Jobs labelled `clearance.hangar.io/injected: wait` from "no stamp, refused": the injected Job is not in the tree and carries no grant entry; without the exemption the PreSync hook is refused |
| the images | `clearance-cmp` and `clearance-wait` published and pinned (a release workflow step, not in this change) |

### Checking it on hangar-prod (steps for the manager)

Prerequisites: the wiring above applied, the images published, hangar-dev's core on a release with this change, a
protected tenant (gate-api, `hangar-prod/prod`) whose Application has become `plugin: clearance` (the ApplicationSet
regenerates it). Nothing below mutates hangar-prod beyond what Argo CD itself does; run reads from the laptop.

1. **The sidecar is up and registered.** `kubectl -n argocd-apps get pod -l app.kubernetes.io/name=argocd-apps-repo-server`
   shows the extra container `clearance-cmp` ready; `kubectl -n argocd-apps logs <pod> -c clearance-cmp` shows the
   plugin server listening. The Application `app-gate-api-prod-cicd/gate-api-prod` (or its name in `argocd-apps`)
   has `spec.sources[0].plugin.name: clearance` and no other generating source.
2. **Tier 1 syncs with annotations.** Land a release PR for gate-api that only bumps the image on
   `hangar-prod/prod/release.yaml`; the `clearance-gate` check clears it by policy (tier 1). Merge it. On the next
   refresh `argocd app get gate-api-prod` shows the new revision, and a render from the plugin logged
   `rendered 6 objects, tree <12 hex>`. Expect **Synced**, then:
   `kubectl -n app-gate-api-prod get rollout,svc,sa,networkpolicy -o json | jq '.items[].metadata.annotations | with_entries(select(.key|startswith("clearance.hangar.io/")))'`
   shows `rendered`, `tree` and `grant` on every object, `grant` equal to the PR's change id
   (`GET /v1/clearances/<id>` on clearance-api: `state: cleared`, `tree_digest` equal to the annotation). This needs the
   release-name fix (parity item 1); until then the plugin registers the tree itself and the sync **holds** (step 3's
   shape): that outcome is the finding.
3. **Held for people (tier 2).** Merge a change that edits replicas. The Application syncs: PreSync Job
   `clearance-awaiting-approval` runs (`kubectl -n app-gate-api-prod get job,pod`), history reads
   "PreSync: clearance awaiting approval"; clear the change in Tower (or `POST /v1/clearances/<id>/clear` as a
   delegate); the Job exits 0, the sync proceeds, the next render adds `grant`.
4. **Tier 3 denial is a ComparisonError.** Open a change that puts a Secret reference or RBAC object into the
   tree with a `clearance.yaml` that loosens the baseline (`DG-POLICY`, denied by policy), merge it, and
   `argocd app get gate-api-prod` shows **ComparisonError** with `change ch-... is denied (tier 3): DG-POLICY ...;
   nothing syncs`, and no object of the Application changed (`kubectl get ... -o jsonpath='{.metadata.resourceVersion}'`
   before and after). A tier 3 change held for two people is not a denial: it waits like step 3. Revert the commit
   afterwards.
5. **Outage hold.** (Optional, hangar-dev's core only: `kubectl scale` on hangar-dev is fine, hangar-prod is not
   touched.) Scale `clearance-core` to 0 on hangar-dev; a refresh of an unchanged, cleared tree keeps its sync
   (served from the cache while its tier is allow-and-record) and a changed tree shows ComparisonError
   `clearance outage hold`. Scale it back.
6. **Skipping the wait.** On a held change, `argocd app sync gate-api-prod --strategy apply` skips the hook and
   applies the manifests: with G-ARGO-2's admission enforcing, the apply is refused for want of a grant (Warn mode:
   logged). This is the documented bypass the admission policy backstops.

## A person's resolution of an observation (O-5)

`POST /v1/observations/{seq}/resolution` on the core, for an observation record (`GET /v1/observations` lists them).
The caller is a person who is an admin (`CLEARANCE_ADMINS`), signed in, or a delegate (Tower's backend) naming one in
the on-behalf-of header: the same authentication and the same `person` resolution as `deny` and break-glass, so a
service, an agent or a person who is not an admin is refused (403). The body is `{state, cause?, note?}` and nothing
else (a field the route does not take is 400): `state` one of `reverted`, `ratified`, `declared-break-glass`,
`still-live`; `cause` only for `reverted`, and one of the seven (`agent-caused`, `policy-triggered`, `human-initiated`,
`automated-remediation`, `requirement-changed`, `external-dependency`, `unattributed`): the same check
(`observe.Check`) a collector's resolution gets, so no other value is stored. An unknown seq, or a seq that is not an
observation, is 404.

It writes a `resolution` record about the observation's seq, in the observation's scope, in one transaction, and answers
`{seq, about, scope, state, cause, note, by, via, ts}`. The record names the person: `principal` is the person,
`initiator` is `{sub, iss}` (`iss` is `delegate:<delegate>` when a delegate asked), `resolution.by` is the person; when the
person signed in themselves the core marks `initiator` verified, and when a delegate named them it does not. Append-only:
an edit is another record about the same seq, the newest wins when read, and the earlier ones stay in the chain
([evidence.md](evidence.md#observations-clearanceevidencev11-o-1)). Tested: `TestAPersonSetsAResolutionCauseAndTheRecordNamesThem`.
