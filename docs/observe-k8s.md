# The Kubernetes audit collector (O-3)

Status: **Built, not yet rolled out.** Code, image, chart and the audit-policy template are in this repository
(`providers/observe-k8s`, `charts/clearance-observe-k8s`); nothing runs on a cluster yet, and on Hangar neither cluster
has any audit flag set. [observe-k8s-runbook.md](observe-k8s-runbook.md) is what the operator does to the API server.

The collector watches what is written to a Kubernetes cluster, whoever wrote it, and tells the evidence chain. The
Argo CD agent ([gate.md](gate.md#the-argo-cd-agent)) sees what is *there*; the collector sees *who did it, and the diff*.
It is an observed provider ([provider-protocol.md](provider-protocol.md#the-observed-role)): it posts `observation`,
`assessment`, `resolution` and `observation.health` records, and everything it sees is `observed-not-attributed` until
[the pipeline](observe-pipeline.md) says otherwise.

## What it does

- **Takes the API server's audit webhook** in batches and acknowledges a batch only after it is on a volume
  (an fsynced append-only log). A collector crash, restart or core outage loses nothing the API server was told arrived.
- **Normalizes and attributes** each write through the O-2 pipeline: cleared (grant annotation and a matching rendered
  hash), out-of-band (hash differs; a person; impersonation; `kubectl`; an unknown service account; Argo CD with no
  grant), break-glass, attempted-refused (a 403 with an admission-policy denial), observed-not-attributed (a federated
  identity with no `task_id`). The orders are the pipeline's; this package supplies the events and the lookups.
- **Keeps the object as it stood before** each change in a watch cache (an audit event carries only the new state), so an
  exception has a diff.
- **Finds what the audit feed missed.** A change to desired state on the watch stream with no audit event within a grace
  period becomes an observation with an `audit-gap` assessment and degrades the feed.
- **Says what it can vouch for.** A health record every minute: the heartbeat, the live policy, Secrets at Metadata, the
  queue, the watches, the gaps, the lookups. A collector that stops is `blind`, not clean.
- **Reads managed clusters** (EKS, GKE, AKS) through the same normalizer. Fixture-tested only; see below.

## The guardrails

- **No Secret body ever leaves the API server's wire into a record, a queue file or a log.** Four layers, any one of
  which is enough:
  1. The shipped audit policy records Secrets at `Metadata` at most, first in the policy so no later rule can widen it
     (`providers/observe-k8s/auditpolicy`). A **build-failing test** (`TestShippedPolicyNeverRecordsASecretBody`) probes
     every verb, namespace, user and group the policy names, and `observe-k8s policy check` runs the same probe on any
     policy file. `Render` refuses to emit a policy that fails it.
  2. The receiver cuts `requestObject` and `responseObject` from any event about a Secret (or a service-account token, or
     whose body is a Secret) **before the queue write**, marks the event, and the health record says the live policy is
     wrong (`secrets-metadata-only`).
  3. The pipeline never reads a Secret into its event, hashes or diffs it (`TestSecretBodiesNeverLeaveNormalize`), and the
     observation says `source.level: Metadata` with no `state_change`, which the core enforces
     ([evidence.md](evidence.md)).
  4. The collector's service account has **no `get`, `list` or `watch` on Secrets** (a metadata-only read still needs
     `get`, which returns the values, so none is used). The chart's render test fails if any rule grants one; the single
     rule on Secrets is a `patch` of one named, empty canary.
- **"With the key named" is not possible, and the records do not pretend.** A `Metadata` event carries the Secret's
  namespace and name, not its data keys, and keys cannot be read without reading values. A Secret change appears with its
  **namespace and Secret name**, the actor, the verb and the time. No key names are invented.
- **Only the API server may post.** Mutual TLS: a client certificate that chains to the configured CA *and* names an
  allowed identity (`--allowed-client`; the receiver does not start without one). A handler reached without a verified
  certificate answers 401.
- **Never acknowledged and lost.** A batch the queue cannot hold (full disk, the size cap) is answered 503 and the API
  server retries; it is never dropped to make room.
- **The collector writes nothing but its own heartbeat.** One ConfigMap and one empty Secret, by name, `patch` only.
- **A blind collector is never a clean one.** Health is a record with an interval; the core, not the collector, marks a
  window blind when the next record is overdue.

## Design choices

**The durable queue is an embedded append-only log on a PersistentVolume, not a broker** (`queue`). Frames carry a
length, a CRC-32C and the append time; a torn tail from a crash is cut off on open (the API server never got its 200 for
it, so it sends it again); segments roll at 16 MiB and are deleted once handled. `Append` fsyncs before it returns, and
the receiver answers after `Append`. The processor reads with `Next` and moves the cursor with `Commit`, which also
stores the processor's counters in the same atomic write, so a batch is counted once however many times it is retried.
Delivery is at least once; the core de-duplicates observations on `source.event_id` (the audit id). A broker would be
another thing to run, secure and back up for one writer and one reader.

**What is and is not durable.** From the 200 on, it is durable. Before it, the API server's own buffer
(`--audit-webhook-batch-buffer-size`, default 10000 events) is the cushion for a collector that is down; a longer outage
drops events *at the API server*. That is not hidden: the heartbeat stops coming back, the feed goes `blind` and the core
writes an audit gap, so the window is reported blind and never clean. Raise the buffer, and keep the API server's local
audit log on as a second sink if a longer outage matters ([the runbook](observe-k8s-runbook.md)).

**The API server is authenticated by mutual TLS**, with its own client CA and a name allowlist; it needs a certificate
from a CA that is not the cluster's. The kubeconfig it needs is in the runbook.

**Attribution lookups.** `Lookups` reads the cluster's `ClearanceGrant`s (the Argo CD agent keeps them) and the core's
open break-glass windows, refreshed each health interval; a failed refresh keeps the last snapshot (a stale answer
attributes less, never more) and the `lookups-fresh` check says how stale it is. **A Secret write arrives at Metadata with
no object, so no grant annotation:** the lookup finds the *active* grants (valid, unexpired, carried trees too) whose
object list names that namespace, kind and name (`pipeline.ObjectGrants`, optional on `Lookups`). Argo CD's controller
writing a Secret a grant lists, or pruning (deleting) an object a grant lists, reaches `grant-annotation.no-hash`
(observed-not-attributed), not `argo-controller.no-grant`. Anyone else writing that Secret, and Argo writing a Secret no
grant lists, is out-of-band. A break-glass window is matched as open *now*; an event that trailed a window's close is not
matched to it.

**One exception, not two.** The Argo CD agent's `deploy.exception` (it names objects and the cluster) and the
collector's observation (it names who and the diff) of the same change are folded into one row of the packet's
exceptions section. The correlation key is `observe.KubeObjectKey(scope, kind, namespace, name)`: the cluster's name,
which is the collector's scope and the agent's cluster, and the object. The row is the observation's (actor and diff)
with the gate record's seq in `also_reported_seq` and its detail appended; the two are folded when they are within 15
minutes, for out-of-band rows only (a refusal, a monitoring operation and a break-glass window are never merged away),
and a gate exception naming several objects is folded only if every one was observed. The fold is made when the packet
reads the chain, so it does not depend on which arrived first (`TestReconcilerAndCollectorReportOneException`, both
orders). The reconciler stays the backstop: with the collector off, its exceptions stand alone.

**The filtered counts.** The pipeline's per-rule counters (events, assessed, filtered by noise rule, out of scope by scope,
not-writes) are held with the queue cursor, reported each health interval in the `noise-filtered` check of the health
record (`observe.FilteredSchema`: since, until, rule set, per-rule counts and their `why`) and cleared when the health record
is posted. They are in the chain, so the packet sums those whose time falls in its window and passes them as
`packet.Params.Filtered` (`packet.chainFiltered`; a caller's own counts win): *"filtered: N events under rule X
(observe-hangar@2026.11.2)"*.

**Blind window.** The collector posts a health record with `interval_seconds`; the core holds it for twice that, then the
feed is blind until the next. The coverage route and the packet read it the same way (`observe.Build`): a collector that is
stopped, or whose pod is gone, leaves a `blind` window with reason `stale`. `TestStoppedCollectorIsBlindNotClean` posts the
collector's real record and asks `observe.Build` ten minutes later.

## The health check, and what a pod cannot read

The API server's flags and policy file and its webhook kubeconfig are files on the control-plane node. A pod cannot read
them. The collector does the strongest check it can:

| Check | What it shows | How |
|---|---|---|
| `webhook-delivering` | the audit path works end to end | it **patches a heartbeat ConfigMap** every 30 s and the write must come back through the webhook, newer than any operation on monitoring |
| `audit-policy-live` | the live policy records writes | the heartbeat's own audit event: it exists and says which level it was recorded at |
| `secrets-metadata-only` | the live policy's Secret rule | no Secret event arrived above Metadata (the receiver cut and marked it), and a **canary Secret** the collector patches (and cannot read) comes back at Metadata with no body |
| `audit-policy-mirror` | the policy the operator keeps in `kube-system/audit-policy` is sound | read by name and held to the Secret rule. It is a **mirror**: it says nothing about the file on the node, and changing it is itself an operation on monitoring |
| `queue-draining`, `records-posting`, `lookups-fresh` | the collector's own work | queue age, core errors, grant and break-glass snapshot age |
| `watch-current`, `audit-gap` | the watch cache is current; the audit feed missed nothing | list/watch loops, and the gap tracker |

**The gap, named:** the live policy is not read. A policy that is wrong *only* for something the heartbeat and canary do
not exercise (say, ConfigMaps in one namespace dropped) cannot be seen this way; the `audit-gap` check catches the
watched kinds, and the mirror is only as good as the operator's discipline. Without a heartbeat object (`--heartbeat-configmap`
empty) the check falls back to "a batch arrived recently", names itself that, and a quiet cluster looks like a dead webhook.

A healthy record also clears the flip the pipeline makes after an operation on monitoring (`Pipeline.Healthy`); the
heartbeat must have come back *after* the operation, or the feed stays blind.

## Gaps and the watch cache

The collector lists and watches the configured kinds (never Secrets): namespaced kinds in the protected namespaces and the
Argo CD namespace, cluster-scoped ones (RBAC, admission configuration) once. **CustomResourceDefinitions are not
watched by default**: the cache keeps whole objects, and a cluster with hundreds of CRDs is tens of MB of JSON (the hangar-dev
rehearsal, about 470 CRDs, was OOMKilled at the 256Mi limit). `CustomResourceDefinition` stays in `rules.governedKinds`, so a CRD
write is still observed through its audit event; it just has no before-object (no diff) and no watch-based audit-gap
detection. A deployment that wants them back adds the resource to `watch.resources` and raises the memory limit. The cache keeps the last four versions
of each object: with the `resourceVersion` of the audit event's response object the object before is exact; without one
(a Metadata event) it is the second newest if the newest was seen at about the event's time. A watch change to *desired
state* (canonical hash differs; a status write does not count) waits for an audit event for the same object (by
`resourceVersion`, else within 30 s), in either order. Past `--gap-grace` (3 min) plus the age of the oldest event still in
the queue it is an **audit gap**: an observation (source level `watch`, actor `unknown (no audit event)`, before and after)
and a not-attributed `audit-gap` assessment, and the feed is degraded for 15 minutes (the core writes the
`observation.audit-gap` record when a health record goes from healthy to degraded). A change while the collector was
restarting is not seen on the stream; the reconciler is the backstop for that.

## Managed clusters (fixture-tested only)

`providers/observe-k8s/readers`: EKS (CloudWatch Logs, the `kube-apiserver-audit` stream, the message is the audit event),
GKE (Cloud Logging `k8s.io` entries, mapped to the audit event shape: principal, verb from the method, object from
`resourceName`, gRPC status to HTTP code, request and response bodies) and AKS (the `kube-audit` or `kube-audit-admin`
diagnostic category, `properties.log`). Each declares its latency (EKS and GKE 2 min, AKS 5 min; measure your own) and the
gap detector waits for it. They run through the **same** sanitizer, queue, pipeline and records (a managed cluster's own
policy is not ours to set, so the body cut is the only guard), with their own `source.name` and health.

**Not built, not verified:** no managed cluster is live, and the package has no cloud SDK. The parsers, the poll loop
(cursor moves only after the append) and a **file transport** are tested against recorded fixtures
(`readers/testdata`); `observe-k8s run --reader eks --reader-file export.jsonl` reads a JSON-lines export a log shipper
appends to. The CloudWatch `FilterLogEvents`, Logging `entries.list` and Event Hub or Log Analytics fetches are the
`Fetcher` each deployment supplies. `observe-k8s normalize --source gke export.jsonl | clearance observe replay -` shows
what a source's recorded entries become.

## The audit policy

`observe-k8s policy render --namespaces shop,payments` writes it (the template, `providers/observe-k8s/auditpolicy/audit-policy.yaml.tmpl`,
is the documentation). First match wins:

1. Secrets and `serviceaccounts/token` at `Metadata` (reads of Secrets dropped); token and access reviews dropped.
2. **Dropped:** every read; the control-plane loops (scheduler, `system:apiserver`, kube-proxy, the endpoint
   controllers, the `system:nodes` group); events, endpoints, endpoint slices, leases; health and discovery URLs.
3. Status writes at `Metadata`.
4. **With bodies (`RequestResponse`):** writes (create, update, patch, delete, deletecollection) in the protected
   namespaces, and to cluster-scoped governed kinds: RBAC (cluster roles and bindings), admission configuration, CRDs,
   Argo CD applications, namespaces.
5. Every other write at `Metadata`; everything else dropped.

## What the apron render has to give it

Under `56-clearance-gate/`, behind `clearance.observe.enabled`, from `charts/clearance-observe-k8s` (the values are
documented in the chart's `values.yaml`):

- `cluster` (hangar-prod; must equal the Argo CD agent's cluster name), `coreURL` (+ `hostAliases` on hangar-prod: the
  core is on hangar-dev), `protectedNamespaces`, `argocd.namespace`, `rules.argoControllerSubject`.
- **Provider registration in the core** (`CLEARANCE_PROVIDERS`): `observe-k8s` with `kinds` `observation`, `assessment`,
  `resolution`, `observation.health`; the collector's service account (`<ns>/clearance-observe-k8s`) in
  `CLEARANCE_FOREIGN_SERVICE_ACCOUNTS`. Its identity is the projected token, audience `clearance`; no secret.
- **A PersistentVolumeClaim** (5Gi default, ReadWriteOnce, `helm.sh/resource-policy: keep`); one replica, `Recreate`.
- **RBAC:** a ClusterRole (list on `clearancegrants`; list and watch on the cluster-scoped watched kinds), a Role and
  RoleBinding per protected namespace and the Argo CD namespace (list and watch on the namespaced watched kinds), a Role
  on the heartbeat ConfigMap and the canary Secret (`patch` by name), and, if `auditPolicyMirror` is set, `get` on that one
  ConfigMap. **No `get`, `list` or `watch` on Secrets anywhere.**
- **NetworkPolicy:** ingress on 8443 and 8080 from the control-plane CIDRs only; egress to DNS, the API server and the
  core.
- **A TLS Secret** (`webhook.tlsSecret`: `tls.crt`, `tls.key`, `ca.crt`) the owner creates; the chart creates no key. The
  server certificate needs the Service's IP as an IP SAN.
- **A Service** with a pinned `clusterIP` (the API server runs on the host network and cannot resolve cluster DNS) or a
  NodePort.
- **The API server's flags**: not rendered by apron, applied by the owner on the control-plane node:
  [the runbook](observe-k8s-runbook.md).

## Limits

- The collector sees what the API server audits, under the policy it is given: a write dropped by the policy is invisible
  to the webhook, and visible only as an audit gap if it changes watched desired state.
- Secrets are not watched, so a Secret write with no audit event has no backstop.
- Break-glass and grants are read as of the last refresh; an event delayed past a window's close, or past a grant's
  expiry, is attributed as of now.
- One flush interval (20 min) bounds how far apart an apply and its revert may be and still fold into one exception.
