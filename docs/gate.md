# The deployment gate (Clearances): design pass, 2026-10-31

Status (v0.30.0): **phase 1a built** (the gate's core, v0.19.0; in Go since R-1c), fed by Glidepath's
`clearance-gate-` check (advisory on Hangar) and `clearance register` (v0.23.0), and answered to GitHub Actions
deployments by the App's protection rule (v0.22.0; [provenance-app.md](provenance-app.md)). **Not built**: phase 2
admission (the pulled grant and the admission policy), `deploy.exception` and outcome records. **Phase 2's shapes are
chosen** ([Phase 2 design pass](#phase-2-design-pass-g-argo-1-2026-11-03), Draft, spiked on hangar-dev 2026-11-03):
the admission policy is a native ValidatingAdmissionPolicy, not the Kyverno policy the first draft below names. The
design below is as reviewed; the Built sections at the end say what exists.

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
| `deploy.clear` | policy or a person clears | principal (policy or the person), via, which requirement it satisfies; `approvals` (each person's IdP `sub` and `iss`, `via`, `role`, `at`), `cleared_by`, and `token` (the clearance token's nonce) when it cleared the change (C-1) |
| `deploy.revoke` | a new head supersedes a cleared change | the revoked token's nonce and the head that superseded it (C-1) |
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
the change: the state and the live clearance token, the read a gate provider waits on (the long-poll wait,
`.../{id}/wait`, is G-TF-2's on this route).
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

Status: **Draft.** The shapes below are chosen; none of them is built. Each was spiked on hangar-dev (Argo CD 3.5.0,
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
  so unchanged objects stay admitted. Older grants stay for the record, unlabelled.
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
reposts the last operation, which the core must answer idempotently.

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
| `deploy.outcome` | `release: {id}` beside `change: {id, tree}` | the agent, from the live Rollout's `hangar.io/release-id` and the object's `clearance.hangar.io/grant` |
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
  `image-bump`, `image:not-trusted-registry`, `metadata-only`, `non-runtime`, `lines>400`, `checks:ci,render`,
  `provenance:agent`), then the decision: tiers 0 and 1 clear by policy, 2 and 3 hold for a `Requirement`
  (owner-group people, outside-group people), an unknown proposer is denied (`DG-PROVENANCE`). `Change`: the record,
  with `role_for()` (owner first, then outside; `DG-PROPOSER`, `DG-TWICE`, `DG-FILLED`, `DG-FORBIDDEN`, `DG-STATE`).
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
  whose token is live, each with it. The grant-sync agent (G-ARGO-3) reads it as a feed reader
  (`CLEARANCE_API_FEED_READERS`), verifies each token against `GET /v1/keys`, and writes the ClearanceGrants.
- `registerChange` takes an optional `taskId` (the run that proposed the change), kept on the change as `task_id`,
  carried in the token and on every `deploy.*` record's `task_id`.

Not yet: admission on the grant (G-ARGO-2), the CMP that registers the whole rendered tree with unchanged objects
marked (G-ARGO-4; today `objects` lists the objects the change touches, each `changed: true`), the PreSync wait
(G-ARGO-5), and the Terraform plan subject (G-TF-1, which adds `subjects.plan_digest`).

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
`group:default/<name>` and a user owner ignored, cached 300 s. Configuration, the same variables as autopilot
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
