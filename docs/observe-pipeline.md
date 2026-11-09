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
tracking id). Its digest is `render.ObjectDigest`, the hash the gate computes for a rendered object, so a live object
and a grant's render compare directly. A **Secret** is never carried: its body, before or after, is not read into the
event, hashed or diffed (`TestSecretBodiesNeverLeaveNormalize`). Reads and non-final audit stages are counted, not
assessed.

**Scope** keeps writes in the governed clusters, namespaces, accounts and kinds (`scope.governed`) and counts the rest
per scope (`out_of_scope`), so the coverage statement's population is honest. A rule set that governs nothing does not
load.

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

The Argo rule is deliberately narrow. The objects Argo *applies* are what attribution must verify (a write with no
grant is out-of-band), so they are not filtered; only Argo's bookkeeping on its own `Application` objects is. The
packet prints the count per rule: **`filtered: N events under rule X (<rule set>@<version>)`**
(`pipeline.FilteredCount.Line`, `packet.FilteredRule.Line`).

**Attribute** ties each surviving event to an authorization. The rule list is **ordered, strongest signal first, per
provider**; the first rule whose `when` holds decides, and the last is a catch-all. `when` reads `event` and `facts`
(what the pipeline looked up through `Lookups`: grants and their rendered hashes, break-glass windows, attestations,
runs, sessions, plans, apply windows). The orders in `default.yaml`:

*Kubernetes*: a 403 with a VAP denial in the audit annotations (attempted-refused); any other refusal; the grant
annotation with the live object's hash among the grant's rendered hashes (cleared; the stamp annotation is only a
claim, the grant's own list is what matches); grant present and hash differing with a mutating webhook in the audit
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

**Classify** maps the outcome to a coverage state and a tier (`classify`): cleared is `authorized-and-verified`, tier 0;
observed-not-attributed 1; attempted-refused 1; out-of-band and break-glass 2. Monitoring protection is tier 3 and the
loader refuses a rule set that lowers it.

**Correlate** collapses bursts into a `Transaction`. An event joins an open transaction of its scope, within
`correlate.window` (30s) of its last event, when it shares the execution context (the grant a record quotes, the AWS
session), when it is related by ownership (a Deployment and the ReplicaSet it cascades into), or when it is the same
actor with the same tool (a `kubectl apply -f dir/`). It folds an **apply-and-revert** into one exception: an uncleared
change followed, within `correlate.revert_window` (15m), by a change that puts the object back as it was (its
after-hash is the first's before-hash, or it deletes what the first created) is one exception, resolution `reverted`,
naming both events. A refused attempt and a monitoring operation are never folded away. Exception kinds are the gate's
(`out-of-band`, `attempted-refused`, `monitoring-protection`, `drift` for observed-not-attributed) and `break-glass`,
the packet's class of that name.

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

## What the collectors still do

O-4's collector ([observe-aws.md](observe-aws.md)) wires the AWS side; O-3's wires Kubernetes. They read the sources, implement `Lookups` over the record store, post the
assessments and the exceptions, call `Healthy` on their next healthy record, persist the pipeline's counters (`Stats`)
and pass the per-rule filtered counts to the packet job (`packet.Params.Filtered`); until a collector stores them the
packet's "filtered" line is empty rather than zero. A Kubernetes collector supplies `before` from its watch cache (an
audit event carries only the new state), and for Secrets only metadata.
