# The observation pipeline (O-2)

The pipeline turns the raw events a collector reads (Kubernetes audit events, CloudTrail records) into the things the
evidence record holds: an assessment per surviving event, one change transaction per change, one exception per thing
that needs a person. It is `internal/observe/pipeline`. It reads no cluster and calls no API: a collector (O-3 for
Kubernetes and Argo CD, O-4 for the cloud) supplies the events and backs the lookups, and POSTs what comes out through
`POST /v1/records` (the record kinds of [evidence.md](evidence.md), "Observations").

```
raw event -> Normalize -> Scope -> Noise -> Attribute -> Classify -> Correlate -> assessment, transaction, exception
                            |        |
                            |        +-- "filtered: N events under rule X"
                            +-- counted for the population, not assessed
```

Everything but Normalize and Correlate is a **rule set**: a versioned bundle of CEL rules, compiled once at load with a
cost limit. The bundle's name, version and sha256 are in every assessment (`rule_set`), so a record says which
allowlist and which attribution orders it was made under. The build ships `default.yaml` (documentation-style
scopes); a deployment supplies its own with the same schema (`clearance.observe-rules/v1`).

## The stages

**Normalize** flattens an event (`Event`: the actor as the source verified it and as the actor reported it, the
resource, the verb, whether it succeeded) and canonicalizes the stored object: no `status`, no server-managed
metadata, none of the gate's own annotations (named in the bundle's `annotations`, so a deployment sets its stamp names; the default bundle uses `clearance.example.com/grant`, `/rendered`, `/tree`, `/release`, and Argo's
tracking id), and none of the annotations and labels a controller keeps on an object it manages
(`annotations.controller_owned` and `controller_labels`; an entry ending in `/` is a prefix; the default bundle lists
`rollout.argoproj.io/`, `rollouts.argoproj.io/`, `deployment.kubernetes.io/`, `notified.notifications.argoproj.io` and the
`rollouts-pod-template-hash` and `pod-template-hash` labels). The gate never renders any of those, so dropping them leaves the
rendered hash unchanged; what remains is the fields a grant covers, which a controller does not write. The hash covers no
status. Its digest is `render.ObjectDigest`, the hash the gate computes for a rendered object, so a live object
and a grant's render compare directly. A **Secret** is never carried: its body, before or after, is not read into the
event, hashed or diffed (`TestSecretBodiesNeverLeaveNormalize`). Reads and non-final audit stages are counted, not
assessed.

**Scope** keeps writes in the governed clusters, namespaces, accounts and kinds (`scope.governed`) and counts the rest
per scope (`out_of_scope`), so the coverage statement's population is honest. A rule set that governs nothing does not
load.

**Not changes** (since the rule set 2026.11.2). Two writes change no object's desired state and are counted under
`out_of_scope`, not assessed: a controller's `update` or `patch` of the **`status` subresource**, and a service account's **`create`
on `serviceaccounts/token`** (a TokenRequest mints a credential and changes no object). They are decided in the pipeline, after the
named noise rules (a rule still claims what it names and its count carries its `why`) and before attribution, and only for a
succeeded write. Never dropped: a refused attempt; an actor who is a person, a `kubectl` client, an impersonation or a federated
agent (the status subresource of the built-in kinds can change labels and annotations, so only a controller is believed); an operation
on monitoring; a node's token (`system:node:*` stays an exact noise rule per named kubelet); and a `status` write to an object a valid
grant lists or whose owner chain reaches one, which keeps its attribution (`listed-grant`, `owner-grant`: the coverage statement
counts it as verified, which a drop would not). `scale`, `ephemeralcontainers` and every other subresource are unchanged.
This is why the signal `listed-grant` keeps its `event.subresource == "status"` guard: it only ever sees the status writes of
objects a grant relates to. It is not a Normalize decision, because Normalize decides *whether an event is a write* (it counts reads
under `not_writes`) and a status write is a write that is outside what a coverage statement is about; the stage that already owns
that count is Scope.

**Not refusals, and controller children** (since the rule set 2026.11.3, collector 0.41.1). Two more things are counted under
`out_of_scope`, in the same place as the not-changes above (after the named noise rules, before attribution):

- *A controller's failed write that is not a security refusal.* `attempted-refused` means the system said no to a caller it did not
  trust: a **401**, a **403**, or an **admission denial** (a validating webhook or a ValidatingAdmissionPolicy denied the request, a Pod Security
  violation, or a webhook that had to answer and failed closed; whatever code the denial carries, because a policy denies with 422 unless it says
  otherwise). The event carries `responseStatus.code`, `reason` and `message`, and the audit annotations
  (`validation.policy.admission.k8s.io/*` for a policy); Normalize reads them into `Event.Code`, `Reason` and `AdmissionDenied`. A **409
  Conflict** (a status update that lost an optimistic-concurrency race; a create that found the object there, AlreadyExists), a **404
  NotFound** (a delete or patch of what is gone) and a **422 Invalid** that admission did not deny are a controller's ordinary retries: nothing
  was refused for who the caller is. Only when the caller is a *controller* (a service account or system identity acting as itself: the same
  test as for status writes). Never counted out: a refusal by a person, a `kubectl` client, an impersonation or a federated agent; a
  refusal of a monitoring kind; a 401, a 403 or an admission denial; any other code (a 5xx stays visible: a webhook that fails closed
  answers 500). Observed on hangar-dev: the deployment controller's `update deployments/status` (409), a redis secret-init Job's
  `create secrets` (AlreadyExists), kube-controller-manager's `create serviceaccounts/token`, the platform Argo CD's `patch roles`.
- *A kube-system controller managing the objects it created* (`scope.controller_children`). A ReplicaSet controller creating the Pods of a
  ReplicaSet, a Deployment controller its ReplicaSets, a Job controller its Pods, a CronJob controller its Jobs, a StatefulSet or DaemonSet
  controller its Pods; the garbage collector and the TTL-after-finished controller deleting what is finished or orphaned (the garbage collector: delete only, of Pod, ReplicaSet and Job, and a `PartialObjectMetadata` patch
  of those kinds). That is the consequence of a change to desired state someone else made (the Deployment, the Job), not a
  change to desired state. Each entry is one exact service account in `kube-system` (the loader refuses a pattern, another namespace, a person, a
  monitoring kind, a duplicate) with the kinds of its children (`"*"` for any), optionally `verbs` (exact write verbs; empty: all) and `partial_metadata_verbs` (verbs allowed only when the event body is a `PartialObjectMetadata`; an event that does not carry it stays visible). The default garbage-collector entry is `kinds: [Pod, ReplicaSet, Job]`, `verbs: [delete]`, `partial_metadata_verbs: [patch]`: anything else it writes or deletes (a ConfigMap, a Role, a Deployment, a plain-body patch) stays visible. The write counts out of scope
  when the controller is acting as itself, **the object has a controller `ownerReference`** (as the body, the collector's before-state or an
  earlier event the pipeline remembers shows it) and nothing ties it to a grant. **A Metadata-level event that shows nothing of the object**
  (a create in a namespace the audit policy records at Metadata, a delete) cannot be checked: the controller's identity and the kind it may write
  stand for the owner reference there. An object that *is* shown without a controller owner is not a child and stays visible. A person, another
  service account or a `kubectl` client writing the same Pod stays visible, and a derived child of a granted object keeps its `owner-grant`
  attribution (the coverage statement counts it as verified, which a drop would not). The kind is read from the resource, not from a
  `PartialObjectMetadata` body.

**Noise** drops legitimate controller writes. A rule pairs **one exact identity** with **the exact shape it may
touch**: `identity.subject` (exact, never a pattern) with `shape.kinds` and `shape.verbs` (exact), optionally
namespaces, subresources and a CEL `when`. Each rule says `why`. The loader refuses everything wider
(`ErrBlanketNoise`): a pattern, a service-account group, "every service account of a namespace", no kinds or verbs, an
unconditional `when`, a kind that is a monitoring control. "Anything from a service account" is not a rule
(`TestNoiseRuleAnythingFromAServiceAccountIsRefused`). Two more guards are in the pipeline, not the bundle: a
**refused attempt is never noise**, and **an operation on monitoring is never noise**. The default rules:

| rule | identity | shape |
|---|---|---|
| `argo-application-bookkeeping` | Argo CD's application controller | update or patch of `Application` objects in `argocd` |
| `cert-manager-secret-rotation` | cert-manager | create, update or patch of a `Secret` owned by a `Certificate` |
| `hpa-scale` | the HorizontalPodAutoscaler | update or patch of the `scale` subresource of workloads |

A deployment adds its own (the observe-k8s chart's are in [observe-k8s.md](observe-k8s.md)). A person, a `kubectl`
client, an impersonation or a refused attempt is never matched by the derived-object signals above: a write to a rendered
field by anyone who is not the gate stays out-of-band.

The Argo rule is deliberately narrow. The objects Argo *applies* are what attribution must verify (a write with no
grant is out-of-band), so they are not filtered; only Argo's bookkeeping on its own `Application` objects is. The
packet prints the count per rule: **`filtered: N events under rule X (<rule set>@<version>)`**
(`pipeline.FilteredCount.Line`, `packet.FilteredRule.Line`).

**Attribute** ties each surviving event to an authorization. The rule list is **ordered, strongest signal first, per
provider**; the first rule whose `when` holds decides, and the last is a catch-all. `when` reads `event` and `facts`
(what the pipeline looked up through `Lookups`: grants and their rendered hashes, break-glass windows, attestations,
runs, sessions, plans, apply windows). The orders in `default.yaml`:

*Kubernetes*: a 403 (or any refusal) with a VAP denial in the audit annotations (attempted-refused); any other refusal that is
not counted out as above (a 401, a 403, an admission denial, a code outside 404/409/422, or any refusal by a person); the grant
annotation with the live object's hash among the grant's rendered hashes (cleared; the stamp annotation is only a
claim, the grant's own list is what matches); **`owner-grant`**, a controller (a service account or system identity: not a
`kubectl` client, not impersonation, not a federated agent) writing an object whose `ownerReferences` chain reaches an
object a valid grant lists (a ReplicaSet of a granted Rollout, a Pod of that ReplicaSet), attributed to that grant (cleared,
and the assessment names the owner's grant; the chain is walked through `ObjectGrants`, up to four hops, with the owners the
pipeline has seen of each object in a bounded in-process memory, so a delete with no body and the second hop work; a restart
forgets it and an unwalkable chain stays out-of-band); **`listed-grant`**, a controller writing the `status` subresource of
an object a valid grant lists (cleared); **`grant-annotation+unchanged`**, a controller's write to an object that names a
known grant and leaves it, as the grant hashes an object, as it was before (cleared; needs the before-state, so the kind
must be watched: a live Rollout carries fields its render leaves out, so its own hash may never equal the render's);
grant present and hash differing with a mutating webhook in the audit
annotations (cleared, low); grant present and hash differing (out-of-band, **high**); a grant the store does not know
(out-of-band, high); a live break-glass record (break-glass); the Argo service account naming a known grant when the
event has no hash to compare, as with a delete (observed-not-attributed; "hash differing" needs a hash); the Argo
service account with no grant (out-of-band, high, cross-referenced to Argo's own log); a federated identity with no `task_id` (observed-not-attributed); a
federated identity with one, impersonation, a `kubectl` client, an unknown service account, a human (out-of-band, with
the diff).

*AWS*: `userIdentity.type` Root (always out-of-band, critical); `errorCode` (attempted-refused); then the correlation
hierarchy, each a signal in this order: signed execution attestation, verified pipeline identity and run (the
`sourceIdentity`), apply role and session, the cleared plan's resource-change set against the resource and action (a
call outside a plan the run claims is out-of-band, high), commit and plan digest (the `clearance/grant=...;plan=...`
user agent, weak), the apply window last (weak). The user agent is self-reported, so the plan signals also require the
apply role (`sessionIssuer.arn`). Then the SSO admin role (out-of-band, high; the actor is the quoted `sourceIdentity`)
and the catch-all.

<a id="platform-gitops"></a>**`platform-gitops`** (G-ARGO-10a, in the attribution order right after `break-glass.live`). A write by an
Argo CD instance's application controller to an object whose Argo CD tracking annotation names an Application is attributed to
that Application and its sync revision, not out-of-band. A write by that controller to an object with no tracking annotation stays
out-of-band. The rule set names the platform instance's identity exactly (`identities.platform_gitops`: exact service-account
subjects; the loader refuses a pattern, a group, and a subject that is also in `identities.argo_controller`, because the gated
instance's writes are cleared by grants, not by GitOps). The pipeline reads the annotation from the object the event carries
(`annotations.tracking_id`, default `argocd.argoproj.io/tracking-id`; value `[<app namespace>_]<app>:<group>/<kind>:<namespace>/<name>`,
which must be about this very object) and asks the lookups, `ArgoApplications.Application`, for the Application (in the controller's
own namespace unless the id carries one) and its revision. A **delete** has no body, so the annotation is read from the object as it stood: the collector's before-state (its watch cache) is the
event's object for a delete, and its `argocd.argoproj.io/tracking-id` is read exactly as above, under the same rules (it must name this very
object, a known Application with a revision). This is how a prune of a Role, RoleBinding or ServiceAccount is attributed, which the
Application's `status.resources` cannot do, because the pruned object is no longer in it.

*Cluster-scoped objects (0.41.2).* Argo CD writes the Application's **destination namespace** into the tracking id of a cluster-scoped object
(v3.5.0, `util/argo/resource_tracking.go`, `UnstructuredToAppInstanceValue`: the namespace of the object, else the one it is given, the Application's
destination), so a ClusterRole has `clearance-observe-k8s:rbac.authorization.k8s.io/ClusterRole:clearance-system/clearance-observe-k8s`. For an event with
no namespace the id must still match the object's **group** (`objectRef.apiGroup`), **kind** and **name**, but its namespace part is ignored; a namespaced
object must match the namespace too. The Application must still be known with a revision.

*Sync hooks (0.41.2).* A hook (an object with `argocd.argoproj.io/hook`, or `helm.sh/hook`, which Argo CD honours; `Skip` is not a hook) carries no tracking
annotation. When the platform controller writes one, and the object carries no tracking id, the pipeline asks the optional `ArgoHooks.HookOf` lookup: exactly
one Application of the controller's namespace must list the object, with a `hookType`, in `status.operationState.syncResult.resources` (Argo CD v3.5.0
`ResourceResult.HookType`, empty for a non-hook; `operationState` is the Application's current or last operation). The attributed revision is that
operation's (`syncResult.revision`, or `revisions` joined), else `status.sync.revision`. A hook deleted by its hook-delete-policy is read from the
before-state like any delete. A hook-looking object no Application lists, or two do, stays out-of-band, and a tracking id that names another object is never
rescued by the hook list. A hook created before the Application's status records it is decided as it stands (out-of-band); the next sync records it. An event with no object and no before-state (a Secret at Metadata, a delete of an unwatched
kind) carries no annotation: `ArgoApplications.ManagedBy` answers from the Applications' own `status.resources`, only when exactly
one Application of the controller's namespace lists the object. No Application, no revision, no lookup support: no attribution. It
sits below every grant signal (an object that names a grant whose hash differs is out-of-band whatever tracking annotation it
carries) and below a refusal; in a live break-glass window the window decides, as for every controller. The assessment carries the
Application (`<namespace>/<name>`) and the revision and its detail names both. Its outcome is `observed-not-attributed` (coverage `observed-not-attributed`, tier 1), never `cleared`: see **Classify**.

**Classify** maps the outcome to a coverage state and a tier (`classify`): cleared is `authorized-and-verified`, tier 0;
observed-not-attributed 1; attempted-refused 1; out-of-band and break-glass 2. Monitoring protection is tier 3 and the
loader refuses a rule set that lowers it. `platform-gitops` is an `observed-not-attributed` outcome: **known source, not authorized**. The write is tied to an Application and a
revision, but nothing cleared it: the application is not protected, and an application that should be is protected with the Argo CD
gate, whose grant signals attribute its writes as today. It is not counted as cleared, and it is not an exception.

**Correlate** collapses bursts into a `Transaction`. An event joins an open transaction of its scope, within
`correlate.window` (30s) of its last event, when it shares the execution context (the grant a record quotes, the AWS
session), when it is related by ownership (a Deployment and the ReplicaSet it cascades into), or when it is the same
actor with the same tool (a `kubectl apply -f dir/`). It folds an **apply-and-revert** into one exception. The business rule: a change undone within the revert window,
by one later change or by several, resolves as `reverted`, even when the undo arrives in a later pass. (For AWS the diff each change carries is its own: the collector joins a Config item that lists no related event to the single nearest CloudTrail event, so an add and its later removal carry inverse diffs; see `docs/observe-aws.md`.) The window is
`correlate.revert_window` (default 1h, measured on event times; the collector's settle time is a separate 15m). An undo is:

- **one change put back as it was** (Kubernetes, whole-object hashes; used only for a pair where neither change carries a
  `Delta`, because a collector's diff covers only the changed properties and equal hashes of two such subsets do not mean the
  object is back as it was): the later change's after-hash is the first's
  before-hash, or it deletes what the first created; or
- **values removed that a run of changes added** (the only rule for a change that carries a `Delta`) (and values added back that the run removed), whatever the property names:
  the collector supplies the change as before and after property values (`RawEvent.Delta`, the AWS Config diff), and the
  most recent *k* unreverted changes on the resource, followed by one change, match when the values added by the run equal the
  values removed by the change and the values removed by the run equal the values added by the change, as multisets. The
  smallest *k* that matches wins. The names are ignored because a list position is not stable from one change to the next: two
  rules added in turn are both element 0 and one revoke of both names elements 0 and 1. A change with no value diff never
  matches.

Each pass (`Flush`) closes the open transactions, but the correlator keeps a **revert memory**: every landed, revertible change
that no change has undone yet, per resource and by event time, for the revert window from its event time. An apply and its undo
are emitted when each one's own settle time ends, so they are usually in different passes; a later pass finds the earlier
change in the memory and the folded exception lists the events of all of them, so the collector posts `reverted` for each
(the packet reads the newest resolution by seq, so it replaces `still-live`). The memory holds at most 64 changes per resource
and 10000 in all, oldest first out, and nothing past its window. A refused attempt and a monitoring operation are never folded away.
Exception kinds are the gate's
(`out-of-band`, `attempted-refused`, `monitoring-protection`, `drift` for observed-not-attributed) and `break-glass`,
the packet's class of that name.

**Settling an unknown grant.** A grant is cleared a moment before Argo CD stamps and applies its objects, and the
collector learns of it a sync later. `Pipeline.HoldUnknownGrants(true)` makes `Process` answer `Held` (nothing counted, nothing
correlated, no record) for a write that would be `grant-annotation.unknown`; the collector holds it for a settle window, re-reads
its lookups, and processes it again with `RawEvent.Final` set, which decides at once. A refusal and an operation on monitoring
are never held. See [observe-k8s.md](observe-k8s.md).

## Operations on monitoring

AWS `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `StopConfigurationRecorder`,
`DeleteConfigurationRecorder`, `DisableRule`, `DeleteRule`; Kubernetes `ValidatingWebhookConfiguration` and
`MutatingWebhookConfiguration` changes and the `kube-system/audit-policy` ConfigMap; the Azure diagnostic-setting and
Google log-sink operations (the lists are in the bundle; those two providers have no normalizer yet). The bundle's
lists add to the deployment's `CLEARANCE_MONITORING_PROTECTION_OPS` (`observe.Monitoring`, the same function
`POST /v1/records` uses): there is one vocabulary. Such an observation is tier 3 whether or not it succeeded and
whatever signal explains it, it is never noise, it **alerts immediately** (`Pipeline.OnAlert`, called from `Process`)
and it flips the scope's health: **blind** when it succeeded, **degraded** when it was refused, with the check
`monitoring-protection`, as [evidence.md](evidence.md) says. `Pipeline.Healthy(scope)` is the provider's next healthy
record, the only thing that clears the flip.

**Named exceptions.** Controllers that maintain their own webhook configurations write them constantly (Kyverno's
admission controller every ~20 s, cert-manager's cainjector injecting `caBundle`), and treating every such write as an
attack leaves the feed permanently blind. `monitoring.kubernetes_exempt` lists the carve-outs, each with a `name`, a `why`,
one exact `subject`, exact `verbs`, `kinds` (only the two webhook configuration kinds) and `names` (globs on the object
name). The defaults are `kyverno-admission-controller` (update, patch, `kyverno-*`), `cert-manager-cainjector` (patch, any
name), Kyverno's cleanup controller (its cleanup and TTL webhooks) and the Tekton operator, proxy, Pipelines, Triggers and
Pipelines-as-Code webhooks, each limited to its own webhook names. A **succeeded** write that matches an entry is routine noise: not monitoring-protection, no alert, no health flip, no
exception, counted in the filtered count as `monitoring-exempt:<name>`. Everything else stays monitoring-protection: another
verb (`delete`), another name, a person, a refused attempt, and any write to the `kube-system/audit-policy` ConfigMap, by
these identities too. The loader refuses an entry with no name or reason, an empty or pattern subject, no verbs, no names, or
kinds other than the webhook kinds. **Trade-off:** a compromised named controller can change its own webhooks (within
the verbs and names listed) without an alert; the exemption is as narrow as the rule makes it, and no narrower.

## The cost limit and failing closed

Every `when` is compiled once, must be a boolean, and its worst-case cost (cel-go's estimate, every variable-length
value sized at 64) must be at most `cost_limit` (default 10000); the same limit cuts off an evaluation at run time,
which for attribution is an error, never a pass. A rule that does not compile, is over the limit, or is refused by a
validator makes the **whole bundle fail to load**: there is no partial rule set. `RuleSet.Costs` lists each rule's
estimate.

## Replaying recorded events

```
clearance observe replay [--rules bundle.yaml] [--lookups lookups.json] [--summary] events.jsonl
```

`events.jsonl` is one `{"provider": "kubernetes"|"aws", "scope": "...", "raw": <the audit event or CloudTrail record>,
"before": <the prior object, optional>}` per line, in time order (`#` lines are comments); `-` reads standard input.
`--lookups` is the JSON of `pipeline.StaticLookups` (grants with their rendered objects, break-glass windows,
attestations, runs, sessions, plans, apply windows); without it nothing is known, so nothing is cleared. The output is
the report as JSON (assessments, transactions, exceptions, alerts, per-rule filtered counts, out-of-scope counts,
health), or with `--summary` a line per assessment. It touches no network, store or cluster. A bundle that does not
load exits 1 with the rule at fault.

The golden corpus is `internal/observe/pipeline/testdata`: synthetic Kubernetes audit events and CloudTrail records
(documentation-style account ids, no credentials, no Secret bodies), `lookups.json`, and the expected reports
(`*.golden.json`). `go test ./internal/observe/pipeline` replays them; after a deliberate change to the rules,
`go test ./internal/observe/pipeline -update` rewrites the goldens, and the diff is what to review.
`go test -bench Process ./internal/observe/pipeline` measures the whole per-event path (about 25 microseconds on a
laptop; `TestPerEventPathUnderOneMillisecond` holds it under the 1 ms bound).

## What the collectors do

The Kubernetes collector ([observe-k8s.md](observe-k8s.md), O-3) is the first caller: it reads the API server's audit
webhook (and a managed cluster's export) into a durable queue, supplies each event with the object *before* the change
from its watch cache (an audit event carries only the new state; for a Secret there is no object at all), backs `Lookups`
over the cluster's `ClearanceGrant`s and the core's break-glass windows, posts the observation and assessment of each
assessed event, gives an apply-and-revert its `reverted` resolution, calls `Healthy` on its next healthy health record, and
reports the pipeline's per-rule counters in the `noise-filtered` check of that health record (`observe.FilteredSchema`),
which the packet sums over its window into `packet.Params.Filtered` (the *"filtered: N events under rule X"* line). The
AWS collector ([observe-aws.md](observe-aws.md), O-4) does the same for CloudTrail.

`Lookups` has three optional extensions. `ArgoApplications` backs `platform-gitops` (the collector indexes the Argo CD
Applications it watches: their revision and their `status.resources`); without it nothing is attributed to GitOps.
`ArgoIndexState` (`ApplicationsSynced`) says the index has synced; with `Pipeline.HoldUnsyncedApplications(true)` a succeeded write by a
`platform_gitops` controller is answered `HeldIndex` while it has not, so the collector can wait for the index (a write decided against
an empty index is recorded out-of-band for the collector's start, not the write); a `Final` event is decided as it stands.
The other, `ObjectGrants`: an event with no object (a Secret at Metadata, a delete) carries no
grant annotation, so for Argo CD's controller only the pipeline asks which active grant lists that namespace, kind and name,
and the answer feeds the same facts the annotation would, so the event reaches `grant-annotation.no-hash`
(observed-not-attributed) and not `argo-controller.no-grant`. Anyone else is attributed as before.
