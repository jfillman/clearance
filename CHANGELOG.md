# Changelog

What each Clearance release shipped. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions are [semantic](https://semver.org/spec/v2.0.0.html): a `vX.Y.Z` tag on `main` after green CI. A tag
publishes a GitHub Release whose notes are that version's section here (`.github/workflows/release.yaml`), so a
release PR adds its section before the tag is pushed.

Entries before v0.26.1 were reconstructed on 2026-11-02 from the commits between tags and their pull requests.

## [Unreleased]

### Fixed (0.41.1)

Five defects found by the live verification of 0.41.0 on hangar-dev (observe-k8s, `internal/observe/pipeline`).

- **Observe-k8s: `lookups-fresh` no longer fails on a cluster with no gate.** The check listed `ClearanceGrant`s, a CRD that exists only
  where the Argo CD agent is installed, so hangar-dev's collector was `degraded` ("not read: kubernetes API: 404") since 0.40.0. New chart
  value `grants.enabled` (default `true`; `--grants-enabled`): `false` lists no grant, drops the `clearancegrants` rule from the
  ClusterRole and reports "no gate on this cluster" (break-glass windows are still read). Explicit, not detected: with grants enabled a 404
  stays a failure (a deleted CRD or a lost role on a gated cluster must not look healthy), and its message says to set the value if there is
  no gate. **Apron: set `grants.enabled: false` for hangar-dev.**
- **Observe-k8s: platform GitOps writes wait for the Application index.** During the collector's own rollout the platform Argo CD was still
  patching the RBAC that lets the collector watch its Applications; the index was empty and tracked writes were recorded out-of-band. A
  succeeded write by a `platformGitops` controller is now held (durable, with the grant settle) until every Application watch has listed
  once, for at most `argoIndexTimeout` (default `5m`, `--argo-index-timeout`; `-1s` never waits), then decided as it stands. New check
  `argo-applications-synced` (only when a platform instance is named). New pipeline disposition `HeldIndex`, `Pipeline.HoldUnsyncedApplications`,
  `ArgoIndexState` (optional on `Lookups`).
- **Observe-k8s: a platform Argo CD prune is attributed.** A delete has no body and the Application's `status.resources` no longer lists the
  pruned object, so a delete of a tracked Role, RoleBinding or ServiceAccount was out-of-band. The tracking annotation is now read from the
  collector's before-state (the watch cache), under the same rules as any other write. The chart now watches `roles` and `rolebindings`
  (new `watch.extraNamespaces` adds namespaces such as `kube-system`).
- **Observe-pipeline: `attempted-refused` means a security refusal.** A controller's 409 Conflict (a lost status update, AlreadyExists), 404
  NotFound and 422 Invalid that admission did not deny are no longer refusals: counted under `out_of_scope`, not assessed. 401, 403 and an
  admission denial (a policy's audit annotation, or a webhook/policy/Pod Security denial in the response message, whatever the code), any
  other code, and every refusal by a person, `kubectl`, an impersonation or of a monitoring kind stay as before. The event now carries
  `Reason` and `AdmissionDenied`.
- **Observe-pipeline: controllers' own children are out of scope.** `scope.controller_children` (chart `rules.controllerChildren`): the
  kube-system ReplicaSet, Deployment, Job, CronJob, StatefulSet, DaemonSet, garbage-collector and TTL-after-finished controllers writing the
  objects they created (Pods of a ReplicaSet or Job, ReplicaSets of a Deployment, Jobs of a CronJob) are counted out of scope when the object
  has a controller ownerReference (a Metadata-level event that shows nothing of the object is judged by the identity and the kind). Exact
  service accounts and kinds, validated at load; a person or another service account creating a Pod stays visible; a granted object's
  derived children keep their `owner-grant` attribution. A `PartialObjectMetadata` body (the garbage collector's) no longer names the kind.
  Rule sets `observe-default` 2026.11.3 and the chart's `observe-hangar` 2026.11.7.

## [0.41.0] - 2026-11-12

### Added

- **Observe-k8s: `platform-gitops` attribution (G-ARGO-10a).** A write by an Argo CD instance's application controller to an object
  whose tracking annotation (`argocd.argoproj.io/tracking-id`) names an Application is attributed to that Application and its sync
  revision (`status.sync.revision`), not out-of-band; a write by that controller to an object with no tracking annotation stays
  out-of-band. The rule set names the instance exactly (`identities.platform_gitops`, exact service accounts, never one that is also
  `argo_controller`). Placed after `break-glass.live`, below every grant signal; outcome and coverage `observed-not-attributed`, tier 1: known
  source, not authorized (the application is not protected; protect it with the Argo CD gate). Never counted as cleared. The assessment carries `application` and `revision` and names both in its detail. A Secret or a
  delete carries no object, so for those the Application's own `status.resources` stands in (exactly one claimant in the
  controller's namespace). The collector indexes the Applications it watches (`pipeline.ArgoApplications`, optional on `Lookups`).
  Chart: `rules.platformGitops.subjects` and `.namespaces` (the namespace is watched and gets a watch Role), `rules.annotations.trackingID`.
- **Observe-k8s chart: `rules.extraNoise`**, a deployment's own noise rules (an exact identity and the exact shape it writes), held to the
  same validator as the chart's own; and the rule `external-secrets-owned-secrets` (External Secrets creating, updating or patching
  Secrets in the governed namespaces; by identity, because a Secret's owner reference is not visible at Metadata).
- **Argo CD plugin (G-ARGO-10b): a generic renderer, and a parity suite that proves it.** Set the plugin parameter `sources` (the
  Application's original `spec.sources`, unchanged, as JSON) and `clearance-cmp` renders what the Application already uses, as Argo CD
  would: Helm from an HTTP repository, an OCI registry or a git path (value files including multi-source `$ref/` ones, `valuesObject`
  and `values`, parameters, file parameters, release name and namespace, `--include-crds`, the cluster's `KUBE_VERSION` and
  `KUBE_API_VERSIONS`), Kustomize, and a plain directory (`recurse`, `include`, `exclude`). The code is `internal/argosrc`, written
  against Argo CD v3.5.0's own. Anything it cannot reproduce (another plugin, jsonnet, `kustomize.patches`, a version range, a remote
  value file, `.argocd-source.yaml`, submodules, a field it does not know) is refused with an error that names the gap; the Airframe-chart
  parameters work as before, and setting both is a configuration error. `clearance-cmp parity` renders each Application both ways and
  compares objects and hashes (identical, differs with the first differing pointer, unsupported, not comparable, error), with a scope
  audit against the cluster's discovery. Run against all 143 Applications on both clusters: 133 identical (2,130 objects), 6 differ, 3
  unsupported, 1 not comparable; the report and the parameter contract are in docs/gate.md ("Rendering any source"). `clusterScopedKinds`
  now also takes `!Kind` (a kind the built-in rules wrongly treat as cluster-scoped).

### Changed

- **Observe pipeline: a controller's status write and a service account's TokenRequest are not changes.** A succeeded `update` or
  `patch` of the `status` subresource by a controller (a service account or system identity, not `kubectl`, not impersonation, not a
  federated agent), and a service account's `create` on `serviceaccounts/token`, are counted under `out_of_scope` and not assessed
  (false exceptions on hangar-prod: the replicaset and deployment controllers' status writes, `calico-node` minting a token). Never for
  a refusal, a person, an operation on monitoring or a node's token; a status write to an object a grant lists or owns keeps its
  attribution (`listed-grant`, `owner-grant`); `scale` and every other subresource are as before. Named noise rules are still checked first.
- Rule set 2026.11.2 (default) and 2026.11.6 (the Kubernetes and AWS charts); the digests in the golden replay reports change with them.
- **Any signed-in person may read coverage and observations (O-5, owner decision 2026-11-12).** `GET /v1/coverage`,
  `GET /v1/observations` and `GET /v1/observations/health` on clearance-api were auditor-only; they now take a person
  (an OIDC user on `CLEARANCE_OIDC_ALLOWED_USERS`), a delegate acting for one (Tower's Backstage proxy) and an auditor,
  and a person reads the whole scope. A person's observation records have their `state_change` redacted by key name
  (`redacted` names the fields); an auditor reads them as stored. `GET /v1/exceptions` is the same: every person reads
  every exception, with `state_change` and `exception` redacted. The resolution write is unchanged (admin only).
- **`GET /v1/coverage` with no `scope`** answers every observed scope's statement (`{from, to, scopes, truncated}`)
  instead of 400.
- **`CLEARANCE_API_OBSERVATION_READERS`** (chart `api.observationReaders`): principal globs of machine pollers (the
  `observer` role) that read coverage, observations, observation health and exceptions, whole scope and redacted, and
  nothing else.
- **The plugin image's Helm and kustomize are Argo CD's: Helm v4.2.1 and kustomize v5.8.1** (were v3.21.3 and v5.7.1; checksum-verified,
  both architectures). A different Helm renders different objects (found by the parity suite); move them with Argo CD. Takes effect when
  the image is rebuilt.

## [0.40.3] - 2026-11-11

### Fixed

- **observe-aws: an add and a later removal of the same security group rule now fold as `reverted`.** A Config item that lists no
  `relatedEvents` was attached to every pending event its resource and 15-minute window matched, so the removal's item also joined the
  add (still pending), overwrote its diff, and both observations carried the same diff; nothing could cancel. Now such an item joins
  exactly one event, the nearest (latest event time no later than a minute after the item's capture; ties by event id), after waiting
  a short grace (`Reconciler.Grace`, default 2m, capped at `settle`) for a nearer event to arrive; the same rule decides `Late`.
  Items that list `relatedEvents` behave as before. When one event carries several items on the same property, `state_change` and the
  revert diff are the net (earliest previous, latest updated, by capture time) rather than whichever item was merged last.

## [0.40.2] - 2026-11-11

### Fixed

- **A change undone later, by one change or several, resolves as `reverted`, in any pass.** A console user added two rules to a
  security group and removed both with one `RevokeSecurityGroupIngress`; Clearance recorded three `out-of-band` exceptions, all
  `still-live`, though the group was back as it was. Three causes: (1) the pipeline folded reverts only among the transactions
  closed in one pass, and an apply and its undo are emitted in different passes; (2) the revert window was 15 minutes; (3) matching
  was one-to-one on hashes, and the diff pointers are positional (both adds were `IpPermissions.0`, the revoke named `.0` and `.1`).
- The pipeline now keeps a **revert memory** across `Flush`es (per resource, by event time, bounded to 64 changes per resource and
  10000 in all, expired by the window), and matches an undo by **values** as well as by hash: the most recent *k* unreverted
  changes, followed by one change that removes exactly what they added and adds back exactly what they removed (multisets, names
  ignored; smallest *k*). The folded exception lists every event, so the collector posts `reverted` for each (the AWS collector
  now passes its Config diff to the pipeline as `RawEvent.Delta`; the Kubernetes collector posts `reverted` for every folded change
  but the undo). An empty diff never matches; a monitoring operation and a refused attempt are never folded away.
- **`correlate.revert_window` defaults to 1h** (was 15m), in the rule set and both charts' `attribute.yaml`. The collector's
  `settle` stays 15m. The rule set digest changes with it, so the golden replay reports carry the new digest.
- The packet reads the newest resolution by seq (as before); a test now pins that a later `reverted` replaces `still-live`.

## [0.40.1] - 2026-11-11

### Fixed

- **A monitoring flip to blind is cleared only by a healthy record.** A successful `StopLogging` flips the account blind through
  the core, and the collector's routine `degraded` report a minute later (the trail was still stopped) ended the blind window.
  The statement, `/v1/coverage` and the packet now hold a core-written flip until a record from the collector with state
  `healthy`; a degraded or blind record in between counts as the worse of its own state and the flip's.
- **observe-aws: a console change carries a diff when AWS Config is slow.** With no Config diff joined, the event's own request
  is the `state_change` (`{before: {}, after: <request, secrets stripped, bounded>, source: "cloudtrail-request"}`) and the
  created id (`sg-...`) is the resource id with the name kept. The core accepts `state_change.source`. The default `settle` is
  15 minutes (chart `settle`), and late Config items and request diffs are counted in a new `config-join` health check. A Config
  item that arrives after its event was posted is still not attached (a new record kind would be needed); this is the
  documented limit.
- **observe-aws: AWS Config's first discovery is a baseline, not an unexplained change.** A `ResourceDiscovered` item with no
  related event whose `resourceCreationTime` is more than an hour before its capture is counted as baseline and not posted;
  a resource really created without a CloudTrail event stays a `config.item-without-event` exception.
- **observe-aws: every real digest failed `digest-signature-invalid`.** The signed string put `digestEndTime` in the compact
  `yyyymmddThhmmssZ` form; AWS signs the end time exactly as the digest writes it (`2026-11-10T21:33:00Z`). Checked against
  a digest AWS signed for the Hangar lab account: the old form does not verify, the new one does.

## [0.40.0] - 2026-11-10

### Added

- **The packet shows a resolution's note.** Exception and observed-change rows carry the newest resolution's `note` as
  `resolution_note` (in full in `packet.json`; cut to 200 characters in `exceptions.csv`, `observed-changes.csv` and the
  PDF), so a ratified exception reads with its reason, not only who ratified it.

- **observe-k8s: a controller's writes to what a grant created are not exceptions.** A rollout under a correctly cleared grant used to
  leave about 54 `out-of-band-detected` rows in two minutes and about 170 an hour at rest (hangar-prod, last 6 h: 1154 rows, 1016
  before the release). Three changes, all keeping a person's, a `kubectl` client's and a refused write out-of-band:
  - **Settle window for an unknown grant** (`--grant-settle`, chart `grantSettle`, default 3m). A write that names a grant the
    collector's lookups (the `ClearanceGrant` objects the Argo CD agent keeps) do not know yet is held, the grants are re-read when
    the window is over, and then it is decided. Held events are kept with the queue cursor.
  - **Derived objects are attributed to their parent's grant.** New attribution signals `owner-grant` (a controller writing an object
    whose ownerReferences chain reaches an object a valid grant lists: ReplicaSet of a Rollout, Pod of a ReplicaSet or Job),
    `listed-grant` (a controller writing the status of a listed object) and `grant-annotation+unchanged` (a controller's bookkeeping on a
    granted object that leaves it as it was before). The stamp hash now ignores controller-owned annotations and labels
    (`annotations.controller_owned`, `controller_labels`: `rollout.argoproj.io/*`, `notified.notifications.argoproj.io`, ...), as
    well as status. A delete's `DeleteOptions` body is no longer taken for the kind. The chart watches Rollouts for the before-state;
    a deployment that overrides `watch.resources` should add `argoproj.io/v1alpha1 rollouts`.
  - **Exact noise rules for routine writers**: Calico's CNI plugin (pod status), the Clearance Argo CD agent (its `ClearanceGrant`s,
    both kind spellings), Crossplane (its composite `RolloutWatch`es and the resources it composes for them, values-driven), the
    disruption controller (PDB status), External Secrets (ExternalSecret status) and the Job controller (the PreSync wait Job).
    Rules version 2026.11.5; new values `rules.grantAgentSubject`, `externalSecretsSubject`, `crossplaneSubject`,
    `crossplaneCompositeKinds`, `crossplaneComposedKinds`, `annotations.controllerOwned`, `annotations.controllerLabels`.

- A person (an admin, or a delegate naming one) can record a resolution on a gate exception, the way they can on an
  observation: `POST /v1/observations/{seq}/resolution` now also takes the seq of a `deploy.exception` of kind
  out-of-band, drift, untraced-apply or digest-mismatch (attempted-refused and monitoring-protection stay 404). The
  resolution is scoped to the exception's destination (cluster, else workspace `backend/key#name`), is append-only
  and names the person. The packet's Exceptions row shows the newest resolution instead of "none recorded", and a
  provider's `resolution` about such an exception is accepted in that scope. `contract/clearance-core.json` changes
  (route text only).

### Fixed

- **observe-aws: `digests-validating` failed on every real digest (`digest-malformed`), and `event-selectors` on the lab's data trail.**
  First live read, hangar-dev, 2026-11-10. (1) S3 serves CloudTrail objects with `Content-Encoding: gzip`; the collector's S3 client
  did not set `Accept-Encoding`, so Go's transport asked for gzip itself and handed back the decompressed body, which `digest.Gunzip`
  then rejected. `S3.Get` now sets `Accept-Encoding: gzip` (the stored bytes arrive as stored) and the trail reader uses the new
  `digest.Content`, which decompresses a gzip body and takes any other body as already-decompressed content (bounded by `MaxFile`),
  for digests and log files alike. Every hash AWS records is over the uncompressed content, so verification is unchanged and a
  tampered body still fails. (2) The data buckets' events may now be recorded by any logging trail with log file validation in the
  observed account (read with the observed-account role; new `Control.DataTrails`) or by the main trail, not only the main trail:
  hangar-infra's `observe-data` trail records the state bucket and the organization trail cannot be read from the lab account.
  Optional `trail.dataTrail` (config `dataTrail`) names the account trail expected; empty searches all. A bucket whose trail is not
  logging, or has validation off, fails `event-selectors` and names the trail ("data trail observe-data is not logging"); the detail
  lists each trail. The lab read role needs `cloudtrail:DescribeTrails`, `GetTrailStatus`, `GetEventSelectors`
  (hangar-infra `observe/lab/role.tf`).

- **The Argo CD agent no longer sends creates the API server refuses.** Writing a grant, the agent POSTed it, got 409
  AlreadyExists for a grant that was already there, then PATCHed it, so every pass left an `attempted-refused` row in the
  Kubernetes audit collector (215 in 6 hours on hangar-prod). It now creates only a grant it listed as absent, patches one
  that exists and differs (no create first), writes nothing for an equal grant, and writes its state ConfigMap by a patch
  (a create only after a 404). A create that loses a race reads the grant and writes only if it differs. The `Kube`
  interface's `ApplyGrant` is replaced by `CreateGrant` and `UpdateGrant`.
- **An applied change stays valid for its stamps until its successor applies.** A new pushed head superseded the older
  change for the same app, environment and cluster even when that change was already applied, and revoked its token, so
  its `ClearanceGrant` left the cluster and the Argo CD agent raised a false `deploy.exception` ("hash listed by no
  grant") for the live objects until the new head applied. Now a superseded change that has an applied `deploy.outcome`
  keeps its token in the signed grant feed, as no clearance (the old head still cannot render as cleared), and is revoked
  when a later change for the same app, environment and cluster applies. A change that was never applied is revoked on
  supersede as before. The feed's shape and signature are unchanged.

## [0.39.3] - 2026-11-10

### Added

- **observe-aws renders its own rule set.** The chart builds the collector's rule set from `ruleset.applyRoles`,
  `ruleset.ssoAdminRoles` and `ruleset.governedAccounts` (default: the observed account), with the pipeline's default
  attribution, classification and monitoring operations. Before, an empty `rules_bundle` left the collector on the
  documentation-style default, which governs no real account. `ruleset.applyRoles` is required unless `rules_bundle` is set.

## [0.39.2] - 2026-11-10

### Fixed

- **observe-k8s reports `still-live`.** The collector now posts its own first resolution, `still-live`, for each observation of
  a change that landed and was not put back, as `docs/evidence.md` says. Packet rows no longer read `none recorded` until a
  person acts. Refused events, including a refused event in a transaction with a landed one, and break-glass windows get none.

## [0.39.1] - 2026-11-10

### Fixed

- **observe-k8s false exceptions from controllers.** An API server restart made Tekton's webhooks and Kyverno's cleanup controller
  rewrite their own webhook configurations, which flipped health to blind: each is now a named exemption limited to its own
  names. The chart adds exact-identity noise rules for kubelet and controller-manager token minting, status writes by the
  Deployment, ReplicaSet and ApplicationSet controllers, the Prometheus operator's kubelet Service, and CRDs Crossplane's
  revisions own. New value `rules.kubeletNodes`; rules version 2026.11.4; the collector's memory limit is 384Mi.

## [0.39.0] - 2026-11-10

### Added

- **O-5: coverage in the packet, a person's resolution, and the trail's verification** (clearance side; the Tower tab, banner
  and alert follow). The packet prints each scope's three-part statement (cleared and verified, seen not cleared, could not
  see), its health summary and how many observations had their source verified, from the same `observe.Build` that `GET
  /v1/coverage` runs; exceptions rows carry the newest resolution and who set it; the freeze and incident views gain an
  `observed_changes` section. `clearance-verify` rebuilds each scope's statement from the carried records, so a packet that
  calls a stopped collector's scope healthy and clean fails ([docs/packet.md](docs/packet.md), [docs/verify.md](docs/verify.md)).
  `POST /v1/observations/{seq}/resolution` on the core: an admin (or a delegate naming one) sets a resolution state and, for
  `reverted`, one of the seven causes; it is a `resolution` record naming the person, append-only, newest wins
  ([docs/gate.md](docs/gate.md)). New `observation.verification` kind (evidence revision 6, additive): the AWS collector's
  S3 trail copy of an event the EventBridge copy recorded first is no longer dropped as a duplicate; it reaches the evidence
  as a verification record about the observation, counted once, never a second observation or exception. **Rollout:** add
  `observation.verification` to the observe-aws provider's registered `kinds`; until then the collector counts and logs
  the core's refusal and the observations stay `sourceVerified: false`. The evidence record schema is `x-clearance-revision` 6.

### Fixed

- **observe-k8s: the collector no longer caches CustomResourceDefinitions.** The chart's default `watch.resources` listed
  `customresourcedefinitions`, and the watch cache keeps whole objects: about 470 CRDs on hangar-dev was 68 MB of JSON and the
  collector was OOMKilled at its 256Mi limit. CRDs are out of the default watch list; `CustomResourceDefinition` stays in
  `rules.governedKinds`, so a CRD write is still observed through its audit event, with no before-object and no watch-based
  gap detection ([docs/observe-k8s.md](docs/observe-k8s.md)).
- **observe: controllers that maintain their own webhooks no longer keep the feed blind.** Every write to a validating or
  mutating webhook configuration was monitoring-protection (tier 3, health blind), and Kyverno's admission controller and
  cert-manager's cainjector write theirs continually. New rule key `monitoring.kubernetes_exempt`: named entries (exact subject,
  verbs, webhook kinds only, name globs, validated at load). A succeeded write matching one is routine noise, counted as
  `monitoring-exempt:<name>`: no alert, no flip, no exception. Defaults: `kyverno-admission-controller` update/patch on
  `kyverno-*`, `cert-manager-cainjector` patch on any name. Anything else stays monitoring-protection, including a refused
  attempt, other verbs or names, and the audit-policy ConfigMap. Trade-off: a compromised named controller can change its own
  webhook without an alert ([docs/observe-pipeline.md](docs/observe-pipeline.md)).

## [0.38.0] - 2026-11-09

### Added
- **The AWS collector, observe-aws** (O-4; `providers/observe-aws`, [docs/observe-aws.md](docs/observe-aws.md)). Three feeds
  through one normalizer and the O-2 pipeline: CloudTrail writes and AWS Config items from an EventBridge queue, and the S3
  trail read in batches with log-file integrity validation (each digest's RSA signature, its link to the previous digest
  and each log file's hash, verified before extraction; the result is `integrity.sourceVerified`). A Config item and the
  event that caused it are one exception (a correlation key, tested in both arrival orders). First-release scope is a
  filter with tests; what is not evaluated is named in the health record. Per-account health. G-TF-5's untraced-apply and
  drift detectors are now stages of it and the `terraform-detector` command is removed (same exceptions, same
  once-only rule). Chart `clearance-observe-aws`, image `clearance-observe-aws`. Unverified against a real trail, queue and
  Config recorder (see the doc).
- **O-3: the Kubernetes audit collector (`providers/observe-k8s`), its image (`clearance-observe-k8s`) and chart
  (`clearance-observe-k8s`).** The webhook receiver for the API server's audit backend (mutual TLS with a name allowlist,
  Secret bodies cut before anything is written, acknowledged only after an fsynced append to a durable queue on a
  volume); the processor (pipeline, observation and assessment records, reverted resolutions, lookups over the grants and
  break-glass windows, a watch cache for the object before each change); audit-gap records for a watch change no audit
  event reported; a health record per minute (a heartbeat and a canary Secret through the live policy, the queue, the
  watches, the gaps) that makes a stopped collector blind, not clean; readers for EKS, GKE and AKS exports (fixture-tested
  only). The audit policy ships as a template with a build-failing test that no rule records a Secret body
  (`observe-k8s policy render|check`). The packet folds the Argo CD agent's `deploy.exception` and the collector's
  observation of the same object into one exception row, and prints the pipeline's `filtered: N events under rule X`
  counts from the collectors' health records. `pipeline.ObjectGrants` resolves an object-less Argo write (a Secret, a
  prune) through the grants' object lists. Docs: `docs/observe-k8s.md`, `docs/observe-k8s-runbook.md`.

## [0.37.0] - 2026-11-09

### Fixed
- **The Argo agent no longer tries to read namespaces the gate does not protect.** A protected project can hold an
  environment that is not gated, such as a staging beside a gated prod. The agent has no read in such a namespace, so
  every list logged a 403. It now reports only Applications whose destination namespace is labelled protected.

### Added
- **O-2: the observation pipeline (`internal/observe/pipeline`) and `clearance observe replay`.** Six stages over raw
  Kubernetes audit events and CloudTrail records: normalize, scope, noise, attribute, classify, correlate. The rules are
  CEL in a versioned bundle (`clearance.observe-rules/v1`) compiled once at load under a cost limit and named in every
  assessment; a rule that does not compile, is over the limit, or is a blanket noise rule (anything from a service
  account) makes the bundle refuse to load. Attribution is an ordered signal list per provider; a burst is one change
  transaction; an apply-and-revert is one exception; an operation on monitoring is tier 3, alerts and flips the scope's
  health. The packet carries the per-rule `filtered: N events under rule X` counts when a collector supplies them
  (`packet.Params.Filtered`). Documented in `docs/observe-pipeline.md`. Wired to no collector yet (O-3, O-4).
## [0.36.1] - 2026-11-09

### Fixed
- **The Argo gate's exception scan no longer reports its own PreSync wait Job as out-of-band.** The Job carries no stamp
  and no grant lists it, so every release held for people added a false `deploy.exception`. The agent now recognises a
  Job that is exactly what the plugin injects, using the same field allowlist as the admission policy's exemption and
  the pinned image, core URL and host alias (`waitJob` in the `clearance-argocd-agent` chart). A Job that only copies
  the name or label is still reported. With `waitJob.image` empty, behaviour is unchanged.

## [0.36.0] - 2026-11-09

### Added
- **C-4: the offline verifier, `clearance verify` (also the standalone `clearance-verify`).** Checks an evidence packet
  with no network and no call to Clearance: every record re-hashed from its original (an altered line is named, and so
  is the record on either side of a broken `prev_hash` link), the checkpoint's log signature and the witnesses'
  countersignatures against keys the verifier's user supplies (the packet's own copies are used only when none is
  given, and the output says **SELF-VOUCHED**; a checkpoint signed by the log alone, which is what a truncated or
  re-signed log looks like, fails; retired keys listed after the one in use keep old entries verifiable), an inclusion
  proof for every record under the checkpoint, the packet's counted figures recounted, every attestation's Sigstore
  signature, Rekor entry and inclusion proof under a TrustedRoot (from the bundle's own material; nothing is fetched),
  and a local note of checkpoints seen that names a fork. A packet with no witnessed checkpoint reports NOT
  CHECKPOINTED, not a pass. Exit 0 verified, 1 failed, 2 not fully established. The signing side of attestations
  (`Attestor`, `BuildStatement`) moved from `internal/attest` to `internal/attestor` so the verifier's dependencies hold
  no store or database. See [docs/verify.md](docs/verify.md).
- **C-5: the evidence packet, `clearance packet`.** A date range and scope to one canonical JSON document, CSV projections
  and a PDF (standard library only), with the originals an offline verifier (C-4) needs: the stored records as hashed,
  an inclusion proof for each under the witnessed checkpoint, the checkpoint with its countersignatures, the public keys
  and the change attestation bundles; with the ledger off it says the records are not checkpointed. Sections: header,
  coverage statement (every coverage and assurance state, degraded windows, per-scope observation health from the same
  function `GET /v1/coverage` uses: "no exceptions detected" is printed only for a window whose feeds were all verified
  healthy; a scope with no collector prints blind), control assertions (resting on verified fields only), changes (Argo
  CD manifest trees and Terraform plans side by side, who reported each outcome), human-cleared changes
  (`token.ApproversStatement`), AI identities, exceptions in seven classes, policy changes, verification and acceptances (the signed receipts from assurance recipients, P-1: none recorded yet, so the section says so).
  `--view freeze` and `--view incident` are scoped views. Control mappings are data (`soc2/2017` CC8.1 and
  `soc2/2027-draft` CC7.1 first), published as an OSCAL component definition, signed as a DSSE envelope on request
  (`clearance packet oscal`). New in `internal/ledger`: `Tree` (inclusion proofs from the chain's record hashes alone,
  tested equal to `Log.Prove`) and `ParseCheckpointNote`. See [docs/packet.md](docs/packet.md).
- **I-1: the operational class.** Beside the tier (the customer's policy), every `deploy.*` record about a registered
  change carries `operational_class` (one or more of `availability`, `privilege`, `data-integrity`,
  `security-boundary`, `credential-exposure`, or `["none"]` when nothing operational changed, such as release stamps
  only) and `class_mapping` (`opclass/1`), computed from the rendered diff or the plan by a mapping shipped as data
  (`internal/gate/opclass.json`) and stored on the change. Additive: `x-clearance-revision` 5, same schema file.
  A Secret rotation is `credential-exposure`, an IAM policy change `privilege`, a Deployment image bump `availability`.
  Tiers, requirements and verdicts are unchanged. The packet prints both later (C-5).
- **The Terraform gate and the Argo CD gate pass the provider conformance suite** (G-TF-7, G-ARGO-9). Two further
  flows for a deployment provider (`info.flow`: `terraform-plan`, `pushed-tree`; `info.stamps`), and an adapter per gate
  in its own tests: `terraform-ci` (`clearance hold`, `release`, `report`) and `argocd-agent` (the plugin's `Generate` and
  the agent's outcome handling behind a fake Argo CD). The suite's assertions are unchanged (`clearance-conformance/v1`).
- **O-1: `clearance.evidence/v1.1`, observations.** Additive: the schema file is the same (`x-clearance-revision` 4),
  and a record says v1.1 only when it is an observation kind or its coverage is new; every other record is still v1.
  Two new coverage states (`break-glass`, `attempted-refused`); five new kinds: `observation` (the normalized event,
  with `integrity` splitting `sourceVerified` from `completenessClaimed`), `assessment`, `resolution` (with a cause on a
  revert), `observation.health` (healthy, degraded or blind, with the checks) and the core's `observation.audit-gap`.
  `deploy.exception` gains `attempted-refused` (does not move a change) and `monitoring-protection`.
  Secrets are observed at Metadata only and an observation cannot carry a Secret body. An operation on monitoring
  (`CLEARANCE_MONITORING_PROTECTION_OPS`, chart `vocabulary.monitoringProtectionOps`, default none) is tier 3 whether or
  not it succeeded and flips its scope's health. A provider writes the observation kinds only when its `kinds` name them.
- **`POST /v1/records` de-duplicates** a provider's own event by provider, kind, `source.name` and `source.event_id`: a
  repeat answers 200 with the first record's reference and `duplicate: true` and writes nothing (closes the R-9 line).
  New indexes `clearance_evidence_event` and `clearance_evidence_observed` (created on start).
- **clearance-api** (auditors): `GET /v1/observations`, `GET /v1/observations/health` and `GET /v1/coverage?scope=&from=&to=`,
  the three-part statement (cleared and verified; seen, not cleared; could not see) with the health summary. A stale or
  missing health record makes the window `blind`, and a blind window is never clean.
- The core contract and the Python client models are regenerated (`duplicate` on the record reference).
- **The evidence ledger (C-3), off unless configured.** A Tessera log of the evidence chain's record hashes, checkpointed
  and countersigned by a witness Clearance does not operate; a record's assurance state moves from
  `recorded-not-checkpointed` to `checkpointed` when its hash is under a witnessed checkpoint. A witness that rejects a
  checkpoint (a truncated, rewritten or forked log) stops its publication; an altered row is named; a lost volume is
  rebuilt from the chain and must reach the root a witness signed, or the core does not serve. The outage knob
  `CLEARANCE_LEDGER_TIER3_WAIT` (default on) makes a tier 3 change wait while evidence cannot be checkpointed
  (`evidence_wait` on the change; it clears when the ledger recovers). `GET /readyz` reports `ledger`. Set
  `CLEARANCE_LEDGER_DIR` (chart `ledger.enabled`) to turn it on; nothing changes without it. See
  [docs/core.md](docs/core.md#the-evidence-ledger-c-3).
- `clearance-witness`, the ledger's witness, in its own binary, image and chart (`charts/clearance-witness`), and
  `clearance ledger keygen`.
- The local anchored `Checkpoint` and `clearance chain verify --anchor` stay: they are the only protection against
  truncation while the ledger is off.
- **The HCP Terraform run task** (G-TF-6; `internal/hcprun`, `POST /v1/terraform/run-task`;
  [docs/terraform-gate.md](docs/terraform-gate.md#the-hcp-terraform-run-task-g-tf-6-built-not-live-verified)). Verifies
  HCP Terraform's `X-TFC-Task-Signature` (HMAC-SHA512, constant time, per-organization key from a file), reads the plan
  JSON with the run's access token, registers the terraform-plan subject, and reports `running`, then `passed` or
  `failed` to the run task callback. Off unless `CLEARANCE_HCP_RUN_TASK_CONFIG_FILE` is set. The plan and callback URLs
  are restricted to the configured HCP Terraform host. Contract tests use HashiCorp's published payload; not
  verified against a real organization. Targeted plans are not detectable from the payload. Atlantis and Spacelift
  adapters are deferred.
- **Tier 3 approvers are people (C-14, rule `GATE-APPROVER-001`).** The clear route refuses an approver that is
  automation (a service account, GitHub Actions, a bot account, an ID-JAG agent identity, or a delegate naming one) with
  `DG-APPROVER-AUTOMATION` 403, and a second approval that resolves to the same subject, alias or session with
  `DG-APPROVER-SAME` 409. Approvals record and carry `kind: person` (change, token, `deploy.clear`, attestation).
  Patterns are configuration: `CLEARANCE_AUTOMATION_SUBJECTS`, `CLEARANCE_AUTOMATION_ISSUERS`,
  `CLEARANCE_APPROVER_ALIASES`. A non-person principal calling clear without naming a person now gets
  `DG-APPROVER-AUTOMATION`, where it got `DG-PERSON`.

### Changed
- **The outcome of a terraform-plan change names the provider its caller is registered as.** `POST
  /v1/clearances/{id}/outcome` writes the `deploy.outcome` on the caller's behalf; when the caller's principal matches a
  `CLEARANCE_PROVIDERS` entry (say `terraform-ci`) the record's verified `provider` is that entry, not `clearance`. No
  entry, no change. The core's own findings (a `digest-mismatch` exception) keep the core's name.

## [0.35.0] - 2026-11-09

### Changed
- **What a release stamps on its objects is no longer a change.** `CLEARANCE_GATE_RELEASE_STAMPS` (chart
  `vocabulary.gateReleaseStamps`) lists the JSON pointers; the default is the `app.kubernetes.io/version` label, on the
  object and its pod template. An object whose only changes are stamps on its own metadata is tier 0 (`release-stamp`),
  whatever its kind, and an image change plus stamps is still `image-bump`. Before, a chart that moves its version label
  made every release tier 3, through the label on the ServiceAccount. A stamp in a pod template restarts pods, so alone it
  stays tier 2.

## [0.34.2] - 2026-11-08

### Fixed
- **The release install test runs on `ubuntu-24.04`.** `ubuntu-latest` moved to 26.04, where `kind load` fails on the
  pulled multi-arch image, so v0.34.1's images and chart published but its GitHub Release did not. 0.34.2 carries
  0.34.1's fixes and is the version to deploy.

## [0.34.1] - 2026-11-08

### Fixed
- **A catalog owner written `namespace/name` is that group.** `spec.owner: default/admins` became
  `group:default/default/admins`, a group nobody is in, so a tier 3 hold's owner slot could not be filled. It is now
  `group:default/admins`.
- **A holding change takes the owner of its latest registration**, in `owner` as well as the requirement, so the
  correction reaches a hold already open the next time it is registered.

## [0.34.0] - 2026-11-07

### Added
- **`clearance trust-root build`** (C-2a; [docs/core.md](docs/core.md#trusted-root-c-2a), Built): a Sigstore TrustedRoot JSON
  from public Fulcio chains and Rekor keys, each with a validity window. **`clearance attest verify --trust-root`
  accepts it** (Rekor's key comes from the document, picked by the entry's log id and its signed time), so one trust root
  verifies the legacy root's attestations and the new Hangar PKI's through a cutover. The PEM form is unchanged.
- **The Fulcio and Rekor URLs may be `http` for an in-cluster Service name** (`<svc>.<ns>.svc`, `.cluster.local`), beside
  https and loopback. The platform's Fulcio and Rekor serve plain HTTP inside the cluster; any other host stays https.
- **The release-record join (G-ARGO-6)** ([docs/gate.md](docs/gate.md#the-release-record-join-g-argo-6-built)). A
  `deploy.outcome` names its release in the record's own `release {id}` (`ProviderEvent.release`; `change.release.id`
  is still accepted and copied), and the attestation's `predicate.release.id` reads either. The change's `outcome`
  (record `seq` and `hash`, applied, matched, digest, release, provider) is set when the provider's outcome is recorded
  and shows in `GET /v1/clearances/{id}` on the core and clearance-api (with the attestation and Rekor index). The Argo
  CD agent sends `release {id}` and reads the CMP's new `clearance.hangar.io/release` stamp first; the CMP stamps it on
  every object from the chart's `hangar.io/release-id` or the values' `releaseTracking.releaseId`. Wire change:
  `plan_digest` is now omitted from a manifest change's outcome (it was never set there); the Python client is
  regenerated.
- G-ARGO-2: the `ClearanceGrant` CRD (`clearancegrants.clearance.hangar.io/v1`) and the admission policies
  `clearance-protected-writes` and `clearance-grant-writer` (`providers/argocd/crd/`), shipped in Warn mode, with an
  envtest suite (`test_admission.py`, CI job `admission-policy`). docs/gate.md "G-ARGO-2".
- **The lab Terraform workflow** (G-TF-4, docs only; the workflow lives in jfillman/hangar-infra,
  [docs/terraform-gate.md](docs/terraform-gate.md#the-lab-workflow-g-tf-4-draft)): `network/lab` plans on a pull
  request and applies on merge through `terraform/action.yml`, behind the `lab` environment's Clearance protection rule.
- **Terraform exception detection** (G-TF-5; `providers/terraform/detect`, `terraform-detector`;
  [docs/terraform-gate.md](docs/terraform-gate.md#exception-detection-g-tf-5-built-not-deployed)). A scheduled drift
  check (`terraform plan -detailed-exitcode`) and an untraced-apply check (S3 state versions against `deploy.outcome`,
  CloudTrail for the principal) file `deploy.exception` kind `drift` and `untraced-apply`. SigV4 over the standard
  library, no AWS SDK. The core's report check now accepts `destination.workspace` {backend, key, name} in place of
  cluster and environment, so a Terraform plan's exception is no longer refused (`internal/gate/exception.go`).

## [0.33.0] - 2026-11-07

### Fixed
- **A terraform-plan change registered by a workflow can be released and reported by another job of that repository**
  (G-TF-4; `gate.SameRepoWorkflow`; [docs/terraform-gate.md](docs/terraform-gate.md)). The plan job and the
  environment job have different OIDC subjects, so `release` and `report` got 403. Same repository, still a verifier;
  other change kinds stay exact-registrant.

### Added
- **`objects[].op: "unchanged"`** on a change request: an object in the rendered tree that the diff does not touch. It
  is accepted, never tiered, and is in the token with `changed: false`, so Glidepath's clearance-gate can register every
  rendered object (grants need the whole tree). Glidepath sends it, so it needs a Clearance release with this first.
- **The release workflow builds the Argo CD gate's images and the agent chart** (`.github/workflows/release.yaml`): on a
  tag, `clearance-argocd-agent`, `clearance-cmp` and `clearance-wait` are built (linux/amd64 and linux/arm64, SBOM and
  provenance), signed keyless and pushed to `ghcr.io/jfillman/<name>:vX.Y.Z`, and `charts/clearance-argocd-agent` is
  packaged and pushed to `oci://ghcr.io/jfillman/charts` and signed; the Release notes list each digest. The agent
  chart's default image tag is now `v<appVersion>`, matching the published tag.
- **The change attestation signer (C-2)** (`internal/attest`, `cmd/clearance/attest.go`;
  [docs/core.md](docs/core.md#change-attestations)). After a deploy reports an applied outcome for a cleared change,
  the core signs an in-toto Statement v1 (predicate `https://clearance.hangarplatform.dev/change-attestation/v1`,
  [schema](schemas/change-attestation.schema.json)) in a DSSE envelope, logs it in Rekor, appends `deploy.attestation`
  with the envelope digest and keeps the Sigstore bundle (new table `clearance_attestations`). No attestation for an
  approved change that never synced, a mismatched apply, or a change never cleared. Backends: keyless (Fulcio + Rekor;
  tested against fakes, not yet against a real Fulcio) and static key (`CLEARANCE_ATTEST_KEY_FILE`, labs). With neither
  configured attestations are off and `/readyz` says so (`attestation`).
- clearance-api: `GET /v1/clearances/{id}` adds `attestation`; `GET /v1/clearances/{id}/attestation` is the bundle.
- `clearance attest verify`: checks a bundle offline (signature, certificate chain and identity, Rekor's signed entry
  timestamp, subjects).
- Config `CLEARANCE_ATTEST_KEY_FILE`, `CLEARANCE_ATTEST_FULCIO_URL`, `CLEARANCE_ATTEST_REKOR_URL`,
  `CLEARANCE_ATTEST_OIDC_TOKEN_FILE`; chart `attestation.*`.

- **The Argo CD plugin and the PreSync wait** (G-ARGO-4, G-ARGO-5; `providers/argocd/cmp`, `providers/argocd/wait`;
  [docs/gate.md](docs/gate.md#the-argo-cd-plugin-and-the-presync-wait-g-argo-4-and-g-argo-5-built-not-deployed)).
  `clearance-cmp` is a Config Management Plugin sidecar for argocd-apps' repo-server: it renders the chart at its pinned
  tag (recording the peeled commit), hashes the tree with the manifest-tree digest, registers the change as a verifier
  and emits the manifests stamped `clearance.hangar.io/{rendered,tree,grant}` (cleared), with an injected PreSync Job
  (held for people), or fails the render (denied, outage hold). `clearance-wait` is the Job's image: it long-polls
  `GET /v1/clearances/{id}/wait` and exits 0 on clear, non-zero on deny or timeout. Both have a Dockerfile. Apron's `clearance.gate.enabled` wires them (off by default).
- `POST /v1/clearances` with `pr: 0` and a bound manifest-tree digest answers the **cleared, unexpired change of the
  same app, environment, cluster and tree** and records nothing (Argo CD syncs the merge commit, not the PR head);
  otherwise it registers as before. The stores gain `ChangesCleared(app, env)`.
- **The Argo CD agent** (`providers/argocd/agent`, G-ARGO-3; [docs/gate.md](docs/gate.md#the-argo-cd-agent-g-argo-3-built)):
  one controller on the protected cluster. Grant sync (every 30 s: verifies the signed grant feed and each token,
  writes `ClearanceGrant`s, one active per namespace, expires them through `status.valid`), outcomes (watches
  Applications, posts `deploy.outcome` per operation with the applied tree digest from the stamps), exceptions (posts
  `deploy.exception` for objects with no grant annotation, a hash no grant lists, or content that differs from its
  stamp, and for a sync the admission policy refused). Own image (`providers/argocd/agent/Dockerfile`) and chart
  (`charts/clearance-argocd-agent`). Fails closed; touches no workload.
- The grant feed carries an **`epoch`** (the hash of the chain's first record), and `token.FeedOptions.Epoch` applies
  `MinSeq` within one epoch: a rebuilt core starts again at seq 1 without an operator resetting readers; the same
  epoch's lower seq is still `ErrFeedReplay`. Additive: a reader that ignores `epoch` behaves as before.
- **The plain-CI Terraform adapter (G-TF-3)** (`cmd/clearance/terraform.go`, `internal/tfplan`, `terraform/action.yml`;
  [docs/terraform-gate.md](docs/terraform-gate.md)). `clearance hold` computes a terraform-plan subject locally (plan,
  redacted plan JSON and variable-set digests, resources, summary; no secret value and no plan upload), registers it
  and waits (exit 0 cleared, 3 holding, 1 denied, 2 usage); `clearance release` proves the plan file is the cleared
  digest before the apply; `clearance report` posts `terraform apply -json`'s outcome to
  `POST /v1/clearances/{id}/outcome`. The composite action `jfillman/clearance/terraform` runs the three steps and
  is linted in CI.

### Changed
- A pushed commit (`pr: 0`) whose tree an earlier change already cleared no longer supersedes that change: the same
  tree is the same change. A push of a new tree supersedes as before.

## [0.32.0] - 2026-11-04

### Added
- **agent-unattested: AI co-author trailers** (`internal/provenance`, `internal/vocab`, `internal/githubapp`;
  [docs/provenance-app.md](docs/provenance-app.md#ai-co-author-trailers-agent-unattested-built)). A PR Clearance has
  no record of, with no `<prefix>*` trailers and no agents' login, whose head commit carries an AI coding agent's
  `Co-Authored-By` (or `Assisted-by`, `Generated-by`) trailer is `unattested` on both verdicts: `ok: true`, no rule,
  `agent_pr: true`, and `coauthor: {commit, trailer}`. Warn-only (user decision 2026-11-04): the App's
  `Clearance / agent-identity` and `agent-scope` checks conclude **neutral**, never failure, and say the PR was
  co-authored by an AI agent outside Clearance; `provenance.verify` records `identity:unattested scope:unattested`.
  Forged trailers (AI001), the agents' login (AI002) and a record still win.
- `CLEARANCE_AI_COAUTHORS` (chart `vocabulary.aiCoauthors`): the matchers, `<email>` or `Name <email>`. Default:
  Claude Code (`noreply@anthropic.com`), OpenAI Codex (`noreply@openai.com`), GitHub Copilot CLI
  (`223556219+copilot@users.noreply.github.com`), Cursor (`cursoragent@cursor.com`), aider (`aider@aider.chat`);
  `none` (chart `[]`) turns it off.
- `POST /v1/provenance` takes an optional `coauthors: [{commit, trailer}]` (at most 200). Callers that send none, as
  Glidepath's `agent-gates-` does today, get the verdicts they got before.

### Changed
- The deployment gate accepts `provenance: unattested` wherever it accepts `not-agent`, so the verdict never changes
  a tier or a decision.

Additive on the wire, with one exception for strict clients: a verdict's check may carry `coauthor`, so a Go client of
an earlier release that decodes verdicts strictly refuses an unattested one; take this release's clients.

## [0.31.1] - 2026-11-03

### Fixed
- A terraform-plan change to an environment the deployment does not protect (cleared at tier 0 by
  `CLEARANCE_PROTECTED_ENVIRONMENTS`) held the gitops 7 days, so its token could be re-issued for a week; it now keeps
  the plan's 24 hours on that path too (`unprotected()` applies the plan TTL; PR Lens on #60, fixed in #62).

## [0.31.0] - 2026-11-03

C-1: the clearance token. Additive on the wire, with one exception for strict clients: a change's view gains
`task_id`, and its approvals gain `sub` and `iss`, so a Go or Python client of an earlier release that decodes gate
answers strictly refuses them; take this release's clients (or `AllowUnknownFields`). Nothing changes for a
deployment that sets no signing key, except that records and views carry the new fields.

C-6: protected environments, the outage policy, the clearance state machine, exceptions and break-glass. Two
behaviour changes on the gate: a deployment that sets no `CLEARANCE_PROTECTED_ENVIRONMENTS` protects every
environment (as before; set the list to let the rest clear at tier 0), and `protected: false` on a registration is
now refused (`DG-PROTECTED`; no caller sends it). A new head now moves a cleared older head to `superseded` (it
stayed `cleared` with a revoked token), and a pushed commit supersedes only its own app, environment and cluster.
Additive on the wire for strict clients of this release's models: a change gains `outage` and `ended`, the policy
view `outage`, `ProviderEvent` `exception` and `outage`; take this release's clients.

### Added
- **The clearance token** (`internal/token`, `internal/gate/token.go`; [docs/core.md](docs/core.md#the-clearance-token)).
  On `deploy.clear` the core signs a short-lived token bound to the subject: a DSSE envelope
  (`application/vnd.clearance.token.v1+json`) and its JWT projection (ES256), one set of claims (`clearance.token/v1`:
  subjects, per-object rendered hashes with `changed`, target, tier, policy ref and verdict, provenance level and
  `task_id`, approvals, `iat`, `exp`, `nonce`). Standard-library ECDSA P-256 only. Tokens are re-issued with the
  same nonce while the change stays cleared, up to its horizon (the gate TTL after the clear); a new head on the pull
  request revokes the older head's token (`deploy.revoke`); a signing failure rolls the clear back. Verification
  (`token.Verify`, `token.VerifyJWT`, `Claims.Covers`, `token.NonceCache`, `gate.Service.CheckNonce`) is offline
  against the published keys; the parsers are fuzzed.
- `CLEARANCE_SIGNING_KEY_FILE` (a PEM P-256 key), `CLEARANCE_TOKEN_TTL` (default 15m), `CLEARANCE_TOKEN_ISSUER`
  (default `clearance`), and `CLEARANCE_SIGNING_KMS`, reserved (the core refuses to start with it until a KMS signer
  exists). Chart: `signing.existingSecret` and `signing.key` (an existing Secret, never created by the chart,
  mounted for the core only), `signing.kms`, `token.ttl`, `token.issuer`.
- The core's `GET /v1/clearances/{change_id}`: the state and live token, for registered providers and the verifier
  that registered the change. `GET /v1/keys` (the core and clearance-api, public): the verification keys, a JWKS.
- clearance-api: `cluster` on `GET /v1/clearances`; `cluster=<c>&state=cleared` is the grant feed (the cluster's
  cleared changes with live tokens, each with its token); `GET /v1/clearances/{id}` adds `token`; a `feed` role
  (`CLEARANCE_API_FEED_READERS`, chart `api.feedReaders`) that reads only its clusters' feed.
- Tables `clearance_tokens` and `clearance_signing_keys` (created on start, no migration step).
- Approvals name the person at their identity provider: `sub` and `iss` (the ID token's, or the person and
  `delegate:<delegate>` through a delegate). `deploy.clear` records carry `approvals`, `cleared_by` and `token`; the
  GitHub App's `deploy.request` and `deploy.answer` records carry `approvals` and `cleared_by` once the change is
  cleared, so they name the people (or `policy`), not only `app:<installation>`.
- `taskId` on `POST /v1/clearances` (kept as `task_id`, on every `deploy.*` record and in the token).
- `provider.conformance`: a `CLEARANCE_PROVIDERS` entry's `conformance` (`clearance-conformance/v1@<date>`) is stamped
  on every record that provider writes.
- Go client `Clearance`, `Keys`; Python client `get_clearance`, `keys` (models regenerated).
- Flight recorder fields and cost accounting (A-4: AP-C1, AP-C2); evidence schema revision 3, additive. A model
  call's outcome (`POST /v1/decisions/{id}/outcome`) takes `model_version` (the model that answered) and `usage`
  (`input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`, `charged_tokens`: what
  the gateway's model proxy charged the session), refused on any other tool's outcome. A run's provider records
  (`session.open`, `run.launch`, `run.finish`, `run.delete`) take `model_version` and `preflight` {result
  pass|fail|not-run, definition, cases}, and `run.finish` takes `cost` (the run's summary: tokens, model and tool
  calls, wall seconds, compute class). All claimed. The Go client and the Python client (`clearance-core-client`)
  carry the new fields (`Usage`, `Preflight`, `Cost`).
- clearance-api `GET /v1/evidence/counts?by=cost&per=task|session|agent|principal`: the model-call outcomes'
  usage and the run.finish records' runs and wall seconds summed per task tree, run, agent or principal, with the
  list's filters and scoping; each item carries `cost`, the answer `per` and the summed `cost`.
- Subject kind `model-call` (evidence schema revision 3): a `model.call` record's derived subject is
  `{kind: model-call, name: <target, the model alias>, digests: {sha256: args_sha256}}`, from `tool`, `target` and
  `args_sha256`, for records written from now on (the decision and its outcome). A stored v0-draft row is still
  projected with its `tool-call` subject.
- Postgres: the partial index `clearance_evidence_cost` on the records that carry `usage` or `cost` (created by the
  core's migration, `CREATE INDEX IF NOT EXISTS`).
- C-9, the Traefik Hub adapter (**Unverified**: built against the published record format, no live Hub yet).
  `internal/federate/traefikhub` and `clearance federate traefik-hub` read Traefik Hub's Sovereign Trust Plane
  decision records (Hub log) and access records, and join them on `trace_id`. A `task_id` comes from a kept
  `X-Clearance-Task-Id` header, or from a trace table. Each decision is posted as a claimed `federated.decision`
  record, provider `traefik-hub`. Coverage is always `observed-not-attributed`, because Hub's PDP decided, not
  Clearance. A correlated record keeps its `task_id` as a claim and sets `source.correlated: true`. A `--state`
  file keeps re-runs from posting a line twice. The recorded-format tests run on Traefik's
  published examples. Includes the `FuzzIngest` fuzz target.
- `POST /v1/records` takes a new kind, `federated.decision` (core contract, Go client and Python client
  `RECORD_KINDS`). The core holds it to observation: no rule, tier, effect, outcome, change or tool, and
  coverage `observed-not-attributed` only (`authorized-and-verified` is refused).
- docs/federate-traefik-hub.md: the record mapping, how to run the adapter, its sources, and the finding that
  Hub cannot use `POST /access/v1/evaluation` as its PDP today. Clearance lacks the AuthZEN metadata endpoint,
  a request profile for a foreign PEP, and an auth path Hub can refresh (Unverified).
- C-8: every deployment decision records its policy. Each `deploy.*` record carries a `policy` group:
  `ref` (`clearance.yaml@<commit>`, `clearance.yaml@sha256:<digest>` or `baseline`), `version` (the gate baseline
  plus the `clearance.yaml` digest), and the offline admission result the verifier sent: `engine`
  (`kyverno/<version>`, or `none`), `verdict` (`pass`, `warn`, `fail`, `skipped`, `error`, or `not-evaluated`) and
  `bundle` (the rule set, `<repo>//<path>@<commit>`). `POST /v1/clearances` takes `policyCommit` and
  `admission {engine, verdict, bundle, deny, warn}` (`checks.admission` must agree with the verdict); the change
  keeps `policy_ref` and `admission` (optional in the contract: older rows have neither). The verdict is recorded,
  not enforced. The evidence schema's `policy` gains `verdict` and `bundle` (docs/gate.md "The policy in the record").
- The clearance token's `policy` claim is the record's policy group (C-8): `{ref, version, engine, verdict, bundle}`,
  so the token attests what its `deploy.clear` record says. It replaces C-1's `{ref, repo_policy_digest, engine:
  "clearance-gate", engine_version, verdict: "clear" | "hold"}`: the gate's decision stays in `clearance.cleared_by`
  and `tier`, and the `clearance.yaml` digest is in `version`. Not yet released, so no token in the field carries
  the old shape.
- `docs/gate.md`, "Phase 2 design pass" (G-ARGO-1, Draft): the Argo CD gate's chosen shapes, each spiked on hangar-dev
  in Warn mode. The CMP replaces the tenant Application's Helm source; grants match the stamped
  `clearance.hangar.io/rendered` annotation; admission is a native ValidatingAdmissionPolicy (not Kyverno), one
  active grant per protected namespace, objects as a map; the agent watches Application status for outcomes; the CMP
  and the agent reach the core as more hangar-prod foreign workloads. Also the release-record cross-reference the
  owner decided on 2026-11-03 (Clearance's signed record is the authority; Glidepath's release record points at it by
  `releaseId` and change id) and the card changes the spikes call for.
- `docs/spikes/g-argo-1/`: the spike plugin, manifests and scripts (hangar-dev only), a CEL cost measurement with
  the API server's own admission CEL evaluator (`celcost`, its own module), and `prod-plan.md`, the two hangar-prod
  measurements prepared for the user.
- `internal/authn`: a test that several service accounts of one foreign cluster authenticate as separate principals
  (`TestSeveralServiceAccountsOfOneForeignCluster`).
- **C-10: clearance-api for the gates.**
  - **The signed grant feed** (`token.Feed`, `internal/gate/feed.go`; [docs/gate.md](docs/gate.md#the-signed-grant-feed-c-10-built)):
    per cluster, a DSSE envelope (`application/vnd.clearance.grant-feed.v1+json`, the token key) over every live
    token with a per-cluster `seq`, `iat`/`exp` (5 minutes), the chain's `records_seq` and each token's payload
    digest, so a grant-sync agent can tell a whole, fresh feed from a trimmed or replayed one (`token.VerifyFeed`,
    `Feed.Match`, fuzzed). The core signs it in every transaction that writes the cluster's tokens and re-signs every
    2 minutes; clearance-api serves it at `GET /v1/grant-feeds/{cluster}` (feed readers of the cluster, auditors).
  - **The core's wait route** `GET /v1/clearances/{change_id}/wait?state=&timeout=` for every provider: long-polls
    up to 60 s and answers the state and token as soon as the state changes, woken by an in-process notifier on the
    gate's commit (no database polling); at most 512 waits; Go client `Wait`.
  - **`GET /v1/stream`** (clearance-api): server-sent events of new records and gate state changes, `id` = record
    seq, resumable with `Last-Event-ID`, scoped as the reads (a feed reader: its clusters' clearance events only);
    one head poller per replica, 64 streams per replica and 8 per caller, a 10 s write deadline per event, 15 s
    keep-alives, 10-minute streams.
  - **`GET /v1/github/installations`** and **`installation=<id>`** on `/v1/evidence`, `/v1/evidence/counts`,
    `/v1/provenance` and `/v1/receipts`, from the records the GitHub App writes (`app:<installation>`).
  - Chart: `networkPolicy.kubeAPIServer.ciliumEntity` (default false) renders a CiliumNetworkPolicy to the
    `kube-apiserver` entity for the core and the api (on Cilium an ipBlock never matches the API server).
  - Store: table `clearance_feeds` and index `clearance_evidence_app`, created on start.

- **Protected environments** (`CLEARANCE_PROTECTED_ENVIRONMENTS`, chart `gate.protectedEnvironments`):
  `<cluster glob>/<env glob>` entries. Empty protects every environment (fail closed); a change to an environment not
  listed is cleared at tier 0 with the reason `unprotected` and recorded. `ChangeRequest.protected` is no longer
  trusted: `false` is refused 400 `DG-PROTECTED`, `true` decides nothing.
- **The outage policy**: the platform baseline (tiers 0 and 1 `allow-and-record`, 2 and 3 `hold`) and a tighten-only
  `outage:` block in `clearance.yaml` (`DG-POLICY` when it loosens); `outage` in `GET /v1/clearance-policy` and on
  each change.
- **The state machine** (`gate.Transitions`): side states `degraded` and `exception` beside `holding`, `cleared`,
  `denied`, `expired`, `superseded`; every edge tested, any other refused; a token is live only while its change is
  cleared (every edge out of cleared revokes it, `deploy.revoke`).
- **`deploy.exception` as a first-class record**: `exception.kind` `out-of-band`, `drift`, `untraced-apply`,
  `digest-mismatch`, each with what it must carry; the core sets the coverage from the kind and moves a named holding
  or cleared change to `exception`.
- **`deploy.degraded`**, a provider's report on recovery of what it did while the core was unreachable
  (`coverage-unavailable`, `outage` {from, to}); the core records `outage_policy` {action, source, conforms} and
  moves a named holding change it let through to `degraded`.
- **Break-glass**: `POST /v1/breakglass` (admins, or a delegate naming one; reason, TTL at most
  `CLEARANCE_BREAKGLASS_MAX_TTL`, never over 4h; cluster and env), recorded as `breakglass.open` before it answers;
  `POST /v1/breakglass/{id}/close`; `GET /v1/breakglass` for providers and admins; reconciled at its TTL by the expiry
  loop into `breakglass.close` listing what the record store knows changed in the window and what it cannot know.
  Exceptions inside a window carry its id. Refusals `DG-BREAKGLASS`, `DG-BREAKGLASS-TTL`, `DG-BREAKGLASS-SCOPE`,
  `DG-BREAKGLASS-OPEN`. Table `clearance_breakglass`.
- clearance-api `GET /v1/exceptions`: the packet's exceptions (the four tools above and every `coverage-unavailable`
  record), on the partial index `clearance_evidence_exceptions`.
- Evidence schema revision 3: `exception`, `outage`, `outage_policy`, `breakglass`, `window`, `changes`, `reported`,
  `truncated`, `limitations`.
- A fuzz target for provider reports (`FuzzProviderReport`); `tools/fuzz-all.sh` caps input minimization at 5s
  (`FUZZ_MINIMIZE_TIME`) so a short run does not end "context deadline exceeded".

### Changed
- **`contract/clearance-api.json` is OpenAPI 3.1** (info.version 1.1.0), still generated from the route table: each
  operation carries `x-clearance-roles`, its query parameters and its answers' schemas; `/v1/stream` is
  `x-clearance-stream`. The pre-OpenAPI document (`api`, `version`, `notes`, `operations`) is gone, and
  `GET /v1/contract` names the core and gateway as `x-clearance-core` and `x-clearance-gateway`. Breaking for a
  reader of the old shape: the Backstage backend reads both.

### Added (G-TF-1)
- G-TF-1, the terraform-plan subject: `POST /v1/clearances` takes `subject: {kind: terraform-plan, planDigest,
  planJsonDigest, workspace: {backend, key, name}, versions: {terraform, providers}, summary: {create, update,
  replace, destroy, destroyedAddresses}, targeted, variableSetDigest, resources}` from a verifier or a GitHub Actions
  workflow (DG-REPO still applies). The Terraform baseline: destroy or replace in a protected workspace is tier 3; a
  change to an IAM, security-group, network-ACL, KMS or database type is tier 3; a tag-only or description-only
  update is tier 1; `-target` or `-replace` is one tier up with a floor of 2; everything else is tier 2. Reasons name
  the resource addresses, and the decision's result names the workspace and what set the tier. The summary must
  match the resources. A placeholder plan digest is refused (`DG-UNBOUND`). No variable value is sent or stored: the
  record carries the redacted plan JSON's digest and the variable set's hash (docs/gate.md).
- `clearance.yaml` `workspaces:` (tighten-only): `protected` (globs on the state key or workspace name),
  `tiers.3.types` and `tiers.2.types`. Anything looser is `DG-POLICY`.
- Every change on record carries `subject` (`manifest-tree`, `definition` or `terraform-plan`, with its digests), and
  every `deploy.*` record carries it as the evidence subject, so clearance-api lists `subject.kind`. A change stored
  earlier reads back as `manifest-tree`. `GET /v1/clearance-policy` adds `terraform`.
- `schemas/change-request.schema.json` (clearance.change-request/v1), the request's schema; a test holds it to the
  parser. The contracts and the Go and Python clients are regenerated (`client.PlanSubject`, `client.ChangeSubject`).
- `CLEARANCE_GATE_UNBOUND_TREE` (chart `gate.unboundTree`): `flag` (default) or `refuse` for a manifest change whose
  `treeDigest` is a placeholder (64 copies of one digit, or sha256 of nothing). Flagged, it is registered with
  reason `tree:unbound`, `subject.flags: ["unbound-tree"]` and a subject bound to the commit only; refused, it is
  `DG-UNBOUND`. Flag is the default for this release for backward compatibility; refuse is planned to become it.

### Changed (G-TF-1)
- The manifest-tree digest is defined (docs/gate.md): sha256 over the sorted lines
  `apiVersion/kind/namespace/name:<sha256 of the object's canonical JSON>`, joined with newlines. `clearance register`
  now computes this, which is what Glidepath's `clearance-gate-` check already computed for the same render (it
  hashed the canonical documents themselves before, so the two differed). Changes registered earlier keep their
  digest.
- `clearance register` refuses an `--after` that is not a directory or holds no manifests (exit 2) instead of
  registering an empty tree; the README's example now renders into directories.

### Added (G-TF-2)
- G-TF-2, hold, release and outcome for a plan
  ([docs/gate.md](docs/gate.md#hold-release-and-outcome-for-a-plan-g-tf-2-built)):
  `POST /v1/clearances/{change_id}/outcome` takes a cleared terraform-plan change's apply result, once, from the
  principal that registered it: `{applied, planDigest, changes, startedAt, finishedAt, error}` (`changes` from
  `terraform apply -json`; strictly decoded, 4 MiB cap). The core records `deploy.outcome` with `matched` (verified:
  the applied plan digest is the cleared one) and, on a mismatch, a `deploy.exception` of kind `digest-mismatch`
  (C-6's shape: `expected`, `observed`, `coverage: out-of-band-detected`), and keeps `outcome {seq, applied,
  matched, plan_digest, at, exception}` on the change. A mismatch moves the change from `cleared` to `exception`
  (C-6's state machine; `ended` names the exception) and revokes its token (`deploy.revoke`) in the same transaction. A second outcome, or one for a change that is not cleared, is
  `DG-STATE` (409); another caller is `DG-FORBIDDEN`; a manifest change is `DG-SUBJECT`. Go client `ChangeOutcome`,
  Python client `record_change_outcome`; contracts and models regenerated; a fuzz target for the route.
- A plan waits on C-10's `GET /v1/clearances/{id}/wait` like any change, and wakes cleared with a token bound to
  its plan digest (tested end to end on the core).
- `GET /v1/clearance-policy` adds `terraform.ttlHours`.

### Changed (G-TF-2)
- A terraform-plan change holds **24 hours** (`DefaultPlanTTLDays = 1`), not the gitops 7 days, then expires with
  `deploy.expire` ("not cleared within 24 hours"); a `clearance.yaml` `ttlDays` still only shortens it. Gitops
  changes keep 7 days.
- A terraform-plan change's id is derived from (repo, workspace backend, key and name, plan digest) instead of
  (repo, pr, head): registering the same plan again returns the same change, and two workspaces planned at one
  commit are two changes (they shared an id before). (G-TF-1 is unreleased, so no stored plan change carries the old id.) A
  strict Go or Python client of an earlier release refuses the new `outcome` field on a change; take this release's.

## [0.30.0] - 2026-11-03

R-3: the Python package is gone. Breaking for anyone who installs `clearance` from this repository with pip (or
`uv`), imports it, or runs its `clearance` console script: there is no Python `clearance` any more. Clearance is the
Go module and its one binary; the gateway half of the old package is Autopilot's. Nothing deployed changes: hangar-dev
has run the Go core and clearance-api, and the Autopilot gateway's own copies of the gateway modules, since the
cutover of 2026-11-03.

### Removed
- `src/clearance`, the Python package (last at v0.29.0), its tests (`tests/*.py`), `pyproject.toml` and `uv.lock`.
  Where each module went:
  - **To Autopilot** (`src/autopilot/engine/`, R-3a to R-3c): the MCP surface (`server.py`), sessions, the run tree,
    budgets and spend (`dispatch.py`, `session.py`, `limits.py`), the tool registry (`tiers.py`; the tier vocabulary
    stays shared), the model proxy (`modelproxy.py`), the backend protocols (`backends.py`), agent definitions and
    their schema (`profile.py`, `schemas/agent-definition.schema.json`, `definitions.py`'s loader), the runtime
    catalog (`runtimes.py`), the human inbox (`inbox.py`), person controls (`control.py`), run results
    (`results.py`), trigger history (`events.py`), artifacts and the gateway's tables (`pg.py`'s runtime half,
    `src/autopilot/engine/pg.py`), and the runtime's reads of `api.py` (`src/autopilot/read_api.py`, served by
    `autopilot-gateway api`).
  - **To the Go core** (this repository): policy, scope and the CEL rules (`policy.py`, `scope.py` to
    `internal/decide`, `internal/scope`), the evidence record and recorder (`audit.py`, `pg.py`'s evidence half to
    `internal/evidence`, `internal/store`), the deployment gate (`gate.py` to `internal/gate`), definition review
    and pins as a gate subject (`review.py`, `definitions.py` to `internal/review`, `internal/definitions`,
    `internal/profile`), provenance (`provenance.py` to `internal/provenance`), the GitHub App (`github_app.py` to
    `internal/githubapp`), who is calling (`auth.py` to `internal/authn`, `internal/directory`), Clearance's reads
    (`api.py` to `clearance api`, `internal/api`) and `clearance register` (`register.py` to
    `cmd/clearance/register.go`).
  - **To a policy bundle** (R-5): packs (`pack.py`, `packs/hangar`) are policy bundles a deployment loads; Hangar's
    ships with Autopilot (`policy/hangar/bundle.json`).
- The Python recorders that imported the package: `tools/golden/export_bundle.py`, `record.py`,
  `golden_recorder.py`, `test_fixture_calls.py`, `tools/api-golden/golden_py.py` and
  `internal/evidence/testdata/python_chain.py`. What they recorded stays as frozen fixtures (the golden corpus, the
  evidence chains, the API answers); they are at v0.29.0 for anyone who needs to re-record against the Python engine.
  `tools/golden/gen_vectors.py` and `internal/canon/testdata/gen_vectors.py` stay (standard library and PyYAML only).
- The `test` workflow (the pytest job) and the release's `clearance` wheel.

### Changed
- `register/action.yml` builds the Go `clearance` binary from the action's own checkout at its ref (`actions/setup-go`
  with the repo's `go.mod`) and runs `clearance register`, instead of pip-installing the Python package. Its inputs and
  outputs are unchanged. `args` reaches the Go command, which refuses `--paths-from-git` (only the Python command had
  it). A workflow pinned to an older tag (for example `@v0.24.1`) keeps installing that tag's Python package.
- The release version is the `VERSION` file (was `pyproject.toml`'s `[project].version`): `tools/pyclient` reads it for
  the Python client's `_version.py`, and the release workflow checks the tag against it.
- The release notes come from `go run ./tools/releasenotes` (was `tools/release_notes.py`), which also checks the tag
  (`-check-tag`); `internal/release`'s test is the changelog check `tests/test_release.py` was.
- The release ships the Python client's wheel and sdist (`clearance_core_client-X.Y.Z`) with `SHA256SUMS`, and checks
  the client was generated at the tag's version.
- The agent-definition schema check (`internal/profile`) compares the embedded copy with Autopilot's
  (`CLEARANCE_AGENT_SCHEMA`; CI checks out jfillman/autopilot), not with the Python package's.

### Added
- `internal/boundary`: the core holds no session store, MCP server or tool dispatch. `go list -deps` of the core names
  no MCP or model-provider SDK; no package is named for a gateway part; no identifier is a session store, dispatcher,
  MCP handler, tool registry, model proxy or inbox; no literal is the `/mcp` endpoint, an MCP method or a model API
  route. R-5's check that the core names no Hangar product (`tests/test_boundary.py`) is ported here, unchanged in
  what it checks.
- CI: a `register-action` job builds and dry-runs the register action.

## [0.29.0] - 2026-11-03

R-5: policy bundles and Hangar's vocabulary out of the core. Breaking for a deployment of the Go
core: `CLEARANCE_PACKS`, `CLEARANCE_FLIGHT_REGISTRIES` and `TOWER_*` are gone (set, the first two stop the start).

### Added
- Policy bundles (`clearance.policy/v1`, [docs/core.md](docs/core.md#policy-bundles)): a deployment's tools, CEL rules,
  CEL context (vars, argument checks, the recorded app) and document field scope (`internal/docscope`), loaded from
  `CLEARANCE_BUNDLES` by the core and clearance-api. A bundle's sources (for example a CI system's `GET /v1/contract`)
  are fetched at start from `CLEARANCE_BUNDLE_SOURCES` (HTTP(S) with a projected token, or a file), with a
  compatible-version check (a version the bundle does not list fails the start). No fallback copy: a source that
  does not answer within `CLEARANCE_BUNDLE_SOURCE_WAIT` (default 10s) leaves its bundle degraded. Its tools and the
  checks that need the source are denied R000 naming the bundle, with no denial charged. `/readyz` names it in
  `degraded`, still 200, and the gate and records keep working. A background loader retries with backoff (2s to
  60s) and loads it whole once the source answers; the load is logged and named in later decisions
  (`policy.bundles[].status`).
- Every decision names its policy: `context.policy.bundles` (each bundle's name, version, digest and the sources it
  read), and each decision record carries `policy: {ref, version, engine}` (the evidence schema's Decision group).
- The deployment's vocabulary as configuration (`internal/vocab`): `CLEARANCE_ON_BEHALF_OF_HEADER`,
  `CLEARANCE_TRAILER_PREFIX`, `CLEARANCE_RUN_IDENTITY_NAMESPACE`, `CLEARANCE_BASELINE_DENY_PATHS`,
  `CLEARANCE_BASELINE_DENY_FIELDS`, `CLEARANCE_GATE_OUTSIDE_GROUPS`, `CLEARANCE_GATE_OWNER_FALLBACK`,
  `CLEARANCE_V0_PROVIDER`, and the environment naming `CLEARANCE_ENV_*`; chart values `policy.*` and `vocabulary.*`.
- The Go client's `Options.OnBehalfOfHeader` and the Python client's `on_behalf_of_header`.
- `tests/test_boundary.py`: a data-level check that the Go core's source names no Hangar product.

### Changed
- The Hangar pack (`internal/decide/packs/hangar`, its vendored Glidepath scope) is gone from the Go core. Its policy
  is a bundle (Autopilot's `policy/hangar/bundle.json`); the corpus replays identically with it
  (`testdata/bundles/hangar` is the test fixture).
- Defaults are product-neutral: on-behalf-of header `X-Clearance-On-Behalf-Of` (was `X-Hangar-On-Behalf-Of`), trailer
  prefix `Clearance-` (was `Hangar-`), run namespace `agent-runs` (was `autopilot-runs`), baseline deny paths
  `CODEOWNERS`, `**/CODEOWNERS`, `.github/**` (the Tekton, AppProject and release-file globs and the deny fields are
  Hangar's to set), no outside group or owner fallback (was `group:default/admins`), no `AGENT_LOGINS` (was
  `hangar-autopilot-agents[bot]`), v0 rows projected as `unrecorded` (was `autopilot-gateway`), and the environment
  naming knows only `dev`, `development`, `sandbox`, `scratch` (the `pr-`/`agent-` prefixes, `-lower` projects and
  `gitops-` repos are Hangar's to set).
- `CLEARANCE_FLIGHT_REGISTRIES` is `CLEARANCE_TRUSTED_REGISTRIES` (chart `gate.trustedRegistries`, gate policy
  `trustedRegistries`, rule `image:not-trusted-registry`); `TOWER_*` are `CLEARANCE_FOREIGN_*` (chart
  `foreignCluster.*`).

## [0.28.0] - 2026-11-03

What the Autopilot gateway needs of the core before the hangar-dev cutover (R-3e).

### Added
- `POST /v1/records` takes the kinds the gateway held in its outbox: `run.finish`, `session.end`, `trigger.release`,
  and `tool.call` with `coverage: coverage-unavailable`, the outage policy's replay of a T0 read the gateway ran
  while the core was unreachable (`tool` names a T0 tool the core knows; no rule, subject, effect or outcome; all
  claimed). Required fields are what the Python gateway recorded for each at v0.26.1
  ([docs/provider-protocol.md](docs/provider-protocol.md#record-kinds)).
- `PUT /v1/definitions` (operation `publishDefinitions`): the provider registered with `"definitions": true` in
  `CLEARANCE_PROVIDERS` (at most one) publishes its cluster-pinned agent definitions, its Agent XR loader's pins and
  rejections. The core decides each pin again with its own schema (`definitions.FromPin`, `internal/profile`),
  replaces the stored set and records each change once through `definitions.Service.Apply` (`definition.load`,
  `definition.unload`, `definition.reject`, sealed by the core with `caller`; the pin's fields claimed). Provenance
  reads the published set at once and a restarted core reads it back. Go client `PublishDefinitions`, Python client
  `publish_definitions`.
- A person's run on `session.open`: `action.properties.run` and `via` (the delegate). The record is Gateway.run_agent's
  at v0.26.1: `args_sha256({"via": ...})` and `opened to run[ via <delegate>]`.
- An outcome may carry `refusal: {rule, message}`, a handler's refusal after the core allowed the call, recorded as
  `refusal` (claimed) beside the decision's own `decision` and `rule`. Evidence schema `x-clearance-revision` 2.
- `CLEARANCE_MAX_CLOCK_SKEW` (a Go duration, default `5m`, at most `24h`; chart value `core.maxClockSkew`) and
  `clearance core --max-clock-skew`. `0` turns the check off and is accepted only with `--memory`.
- `clearance core --memory --insecure-dev-auth` serves the in-memory chain at `GET /v1/dev/records` (dev only, not
  in the contract), so autopilot's tests run against the unmodified binary instead of a `go build -overlay` test
  core.

### Changed
- `definition.load`, `definition.unload` and `definition.reject` are the core's records only: `POST /v1/records`
  refuses them (it never accepted them).

## [0.27.1] - 2026-11-03

### Added
- Chart values `core.hostAliases` and `api.hostAliases` (a portal hostname with no DNS, as Hangar's lab reaches Tower).

### Fixed
- `GET /v1/clearances/counts` refuses an unknown `state` or a non-ISO `since` with 400, as `GET /v1/clearances` does (#45).

## [0.27.0] - 2026-11-03

### Added
- `CHANGELOG.md` (this file) and a release workflow: a `v*` tag on `main` builds the wheel and publishes a GitHub
  Release with this file's section for the version as its notes, and fails when the section is missing.
- Clearance's own image and Helm chart (R-2): `Dockerfile` (static `CGO_ENABLED=0 -trimpath` build onto
  `gcr.io/distroless/static-debian12:nonroot` pinned by digest, uid 65532) and `charts/clearance` (the core as one
  `Recreate` replica, clearance-api with 2 replicas and a PodDisruptionBudget, Services, default-deny NetworkPolicy,
  optional CloudNativePG cluster with a read-only role, ExternalSecrets and HTTPRoutes, `helm test` chain verify,
  a value for every core variable). The release workflow now pushes `ghcr.io/jfillman/clearance:vX.Y.Z` (amd64 and
  arm64, SPDX SBOM, keyless signature) and `oci://ghcr.io/jfillman/charts/clearance`, and reruns the install test on
  them. Chart CI (`.github/workflows/chart.yaml`): lint, render tests (`tools/charttest`), kubeconform, and an install
  test on kind (`tools/chart-install-test`, `tools/installtest`). See [docs/install.md](docs/install.md).
- `clearance api` (R-2b): Clearance's read API in Go (`internal/api`), on the read-only Postgres store: evidence
  (filters, `seq` cursor, chain verify, counts), receipts and provenance verdicts, the gate's changes and policy, the
  policy as data and the dry-run explainer (`decide.(*Engine).Trace`), and the new `GET /v1/definitions`. Same paths,
  parameters, answers and codes as api.py for every route kept, identical on the 612-record hangar-dev chain; the
  runtime's reads move to the gateway (R-3). Counts exclude the core's outcome records by default (`outcomes`).
  `contract/clearance-api.json` is now generated from the Go handlers, and `tools/gen_api_contract.py` is gone
  ([docs/clearance-api.md](docs/clearance-api.md)).
- `CLEARANCE_FLIGHT_REGISTRIES` (chart value `gate.flightRegistries`): the image prefixes a tier-1 image bump may come
  from; unset, the default, is any registry. Hangar sets `ghcr.io/riley-roooo/` from the R-4 cutover.
- `tools/release_notes.py`: print one version's section (the workflow's notes; exits 1 when there is none).
- The Go core (R-1): one `clearance` binary (`core [--memory]`, `chain verify`, `register`, `conformance`, `version`); the
  decision engine on cel-go with a golden corpus replayed from the Python engine; the Postgres store extending the
  same chain byte for byte; the deployment gate, provenance and GitHub App ported; `POST /access/v1/evaluation`,
  `POST /v1/decisions/{id}/outcome`, `POST /v1/records` for registered providers (`CLEARANCE_PROVIDERS`);
  `contract/clearance-core.json`; Go (`client/`) and Python (`clients/python`) clients; the provider protocol and
  `clearance conformance` ([docs/core.md](docs/core.md)). Built, not deployed.
- Evidence record v1 (R-6): `schemas/evidence.schema.json`, `clearance.evidence/v1`, with `provider` and `subject`;
  v0-draft rows are projected on read by clearance-api ([docs/evidence.md](docs/evidence.md)).

### Changed
- `clearance.__version__` comes from the installed package's metadata (pyproject's version), not a hard-coded
  `0.1.0.dev0`.
- The durable evidence log (`pg.PgAuditLog`) verifies the chain at start through a server-side cursor, 1000 rows a
  round trip, instead of loading every record into memory.
- A `Gateway` given an inbox refuses `human.request` or `human.request.get` handlers too (for example
  `core_handlers(human=...)`): the inbox used to replace them silently. Pass one or the other.

### Fixed
- Docs status: `docs/index.md`, `catalog-info.yaml`, and the status lines of `docs/gate.md` and
  `docs/provenance-app.md` say what is built at v0.26.1 (the gate's core, the GitHub App phases 1, 2a and 2b),
  not "designed" and "not built".

## [0.26.1] - 2026-11-02

### Changed
- `catalog.read`: the tool description says which query form filters (#41).

## [0.26.0] - 2026-11-01

### Added
- Model proxy: streaming Messages. Server-sent events are relayed as they arrive and their usage is charged when
  the stream ends, however it ends; Claude Code and the Agent SDK always stream (#40).

### Changed
- The client's `anthropic-beta` header is forwarded, less OAuth's betas (#40).

## [0.25.0] - 2026-11-01

### Added
- Run results: an in-cluster run hands back its answer with `run_finish`, kept 30 days (`results.py`); sessions keep
  their `input` and `outcome`, and clearance-api serves `GET /v1/sessions/{id}/result` (#39).

## [0.24.2] - 2026-11-01

### Fixed
- GitHub Actions OIDC: match the immutable-ID subject by repository name (#38).

## [0.24.1] - 2026-11-01

### Changed
- `clearance register` sends its own User-Agent and says when a refusal did not come from Clearance (#37).

## [0.24.0] - 2026-11-01

### Added
- Hangar pack: glidepath live, release-run, evidence, tests, events and previews tools (#36).

## [0.23.0] - 2026-11-01

### Added
- `clearance register`: a workflow registers its deployment with the gate, authenticated by its GitHub Actions OIDC
  token, for its own repository only (provenance App phase 2b, #34).
- Agent definitions carry a one-line `description`, and `runs_in` follows from the runtime (`cluster` or `client`);
  a person's Run (#35).

### Changed
- `run_agent`: the person's input is the runtime's prompt, with the definition's instructions (#35).

### Fixed
- CI: the wheel check names the vendored `glidepath-scope.json` (renamed in v0.20.3).

## [0.22.0] - 2026-11-01

### Added
- The deployment protection rule: the GitHub App answers GitHub Actions deployments from the deployment gate's
  change: approved, rejected, or waiting on people (provenance App phase 2a, #33).
- The Clearance logo, for the GitHub App (#32).

### Changed
- Hangar's App is named "Hangar Clearance": "Clearance" is taken on GitHub (#32).

## [0.21.0] - 2026-11-01

### Added
- The Clearance GitHub App, phase 1: signature-checked PR webhooks, a one-repo read-only installation token, and
  Clearance's own `Clearance / agent-identity` and `Clearance / agent-scope` check runs (#31).
- `docs/provenance-app.md`: decisions 1 and 2 (#30).

## [0.20.3] - 2026-10-31

### Changed
- Vendor only the scope section of Glidepath's contract, as `packs/hangar/vendor/glidepath-scope.json` (#28).
- `docs/provenance-app.md`: the provenance App design pass (#29).

## [0.20.2] - 2026-10-31

### Changed
- Re-vendor Glidepath's contract 0.9.0 after glidepath#213 (#27).

## [0.20.1] - 2026-10-31

### Changed
- Re-vendor Glidepath's contract after glidepath#208 (glidepath-api 0.8.0) (#26).

## [0.20.0] - 2026-10-31

### Added
- Definition review: validate a definition, tier its change and gate its release through the deployment gate
  (`review.py`) (#25).
- The runtime catalog: the deployment's agent images, allowed for `runtime.image` and listed at `GET /v1/runtimes`
  (#25).

## [0.19.0] - 2026-10-31

### Added
- The deployment gate's core: a change to a protected environment classified 0 to 3 from its rendered diff, cleared
  by policy or by people, recorded in the deployment boundary (`gate.py`) (#24).
- TechDocs: `mkdocs.yml` over `docs/`, a home page, and the catalog Component (#22).
- `docs/gate.md`: decisions 1 to 5 recorded (#22, #23).

### Changed
- Re-vendor Glidepath's contract after glidepath#207 (the clearance-gate guardrail).

## [0.18.0] - 2026-10-31

### Added
- Definitions pinned by `Agent` XRs: the live set, `from_pin`, evidence per change, and `source` and `rejected` in
  the API (`definitions.py`) (#20, #21).
- `docs/gate.md`: the deployment gate design pass (#18).

### Changed
- Re-vendor Glidepath's contract after glidepath#202 (cicd validations endpoint).

## [0.17.0] - 2026-10-31

### Added
- Person controls: freeze and end a session, hold and release an agent's triggers, through the delegate model
  (`control.py`) (#17).

## [0.16.0] - 2026-10-31

### Added
- `glidepath.cicd.validate` and `glidepath.cicd.propose`: a cicd.yaml change as a PR tool (#19).

## [0.15.0] - 2026-10-31

### Added
- Event history: what the trigger bridge received and did, served as `GET /v1/events` (`events.py`) (#16).

## [0.14.0] - 2026-10-31

### Added
- clearance-api: the policy as data, a dry-run explainer (`Policy.trace`) and evidence counts (#15).

## [0.13.0] - 2026-10-30

### Added
- clearance-api phase 1: the read API as a separate read-only process, `app` on every record that names one, and
  its contract `contract/clearance-api.json` (#13, #14).

## [0.12.0] - 2026-10-30

### Added
- Human inbox: a non-blocking `human.request`, `human.request.get` and the people API (#12).
- `ForeignWorkloadAuthenticator`: another cluster's service accounts verified by its public issuer (Tower as a
  delegate).

## [0.11.0] - 2026-10-30

### Added
- `PgArtifacts`: `artifact.put` and `artifact.get` on Postgres, per task, bounded and expiring (#11).

### Changed
- Re-vendor Glidepath's contract (the agent-gates release guardrail, glidepath#198).

## [0.10.0] - 2026-10-30

### Added
- OIDC sign-in only for the allowed people (#9).

### Changed
- Re-vendor Glidepath's contract (glidepath-api release records and events) (#10).

## [0.9.0] - 2026-10-30

### Added
- PR provenance: receipts on `repo.pr.open` and `POST /v1/provenance` for the agent gates (#8).

### Changed
- Re-vendor Glidepath's contract (glidepath 977ed7c, P6b).

## [0.8.0] - 2026-10-29

### Changed
- Token efficiency: cached tokens weighted in the model budget; `repo.file.get` lists the repository root (#7).

## [0.7.0] - 2026-10-29

### Changed
- `tools_list(session)`: only the tools the caller's own session may run (#6).

## [0.6.0] - 2026-10-29

### Added
- `repo.file.get`: a T0 read of a file or directory in an allowed repository (#5).

## [0.5.0] - 2026-10-29

### Added
- Runs act as their session; the model proxy forwarder (#4).
- Agent definitions: `runtime.instructions`, passed in a run's input; Glidepath event triggers.

### Changed
- Re-vendor Glidepath's contract 0.4.0 (#4).

## [0.4.0] - 2026-10-29

### Added
- `Gateway.expire`: delete expired sessions' runs, with a record each (Hangar D20) (#3).

## [0.3.0] - 2026-10-29

### Added
- The durable store and evidence sink on Postgres (`pg.py`, AP-A2) (#2).

## [0.2.0] - 2026-10-29

### Added
- HTTP transport and interim authentication (AP-A2) (#1).

## [0.1.0] - 2026-10-29

### Added
- Clearance as its own repository (Hangar decision D16), with its history from the `clearance` package in
  jfillman/autopilot: the Hangar-free core, packs and the boundary test (AP-A2); tiers and tripwires, path and field
  scope, narrow-only limits, CEL policy, sessions, the hash-chained audit log and the gateway; the Hangar pack's
  `glidepath.*` and `airframe.*` tools over glidepath-api and a GET-only Kubernetes adapter.

[Unreleased]: https://github.com/jfillman/clearance/compare/v0.41.0...HEAD
[0.41.0]: https://github.com/jfillman/clearance/compare/v0.40.3...v0.41.0
[0.40.3]: https://github.com/jfillman/clearance/compare/v0.40.2...v0.40.3
[0.40.2]: https://github.com/jfillman/clearance/compare/v0.40.1...v0.40.2
[0.40.1]: https://github.com/jfillman/clearance/compare/v0.40.0...v0.40.1
[0.40.0]: https://github.com/jfillman/clearance/compare/v0.39.3...v0.40.0
[0.39.3]: https://github.com/jfillman/clearance/compare/v0.39.2...v0.39.3
[0.39.2]: https://github.com/jfillman/clearance/compare/v0.39.1...v0.39.2
[0.39.1]: https://github.com/jfillman/clearance/compare/v0.39.0...v0.39.1
[0.39.0]: https://github.com/jfillman/clearance/compare/v0.38.0...v0.39.0
[0.38.0]: https://github.com/jfillman/clearance/compare/v0.37.0...v0.38.0
[0.37.0]: https://github.com/jfillman/clearance/compare/v0.36.1...v0.37.0
[0.36.1]: https://github.com/jfillman/clearance/compare/v0.36.0...v0.36.1
[0.36.0]: https://github.com/jfillman/clearance/compare/v0.35.0...v0.36.0
[0.35.0]: https://github.com/jfillman/clearance/compare/v0.34.2...v0.35.0
[0.34.2]: https://github.com/jfillman/clearance/compare/v0.34.1...v0.34.2
[0.34.1]: https://github.com/jfillman/clearance/compare/v0.34.0...v0.34.1
[0.34.0]: https://github.com/jfillman/clearance/compare/v0.33.0...v0.34.0
[0.33.0]: https://github.com/jfillman/clearance/compare/v0.32.0...v0.33.0
[0.32.0]: https://github.com/jfillman/clearance/compare/v0.31.1...v0.32.0
[0.31.1]: https://github.com/jfillman/clearance/compare/v0.31.0...v0.31.1
[0.31.0]: https://github.com/jfillman/clearance/compare/v0.30.0...v0.31.0
[0.30.0]: https://github.com/jfillman/clearance/compare/v0.29.0...v0.30.0
[0.29.0]: https://github.com/jfillman/clearance/compare/v0.28.0...v0.29.0
[0.28.0]: https://github.com/jfillman/clearance/compare/v0.27.1...v0.28.0
[0.27.1]: https://github.com/jfillman/clearance/compare/v0.27.0...v0.27.1
[0.27.0]: https://github.com/jfillman/clearance/compare/v0.26.1...v0.27.0
[0.26.1]: https://github.com/jfillman/clearance/compare/v0.26.0...v0.26.1
[0.26.0]: https://github.com/jfillman/clearance/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/jfillman/clearance/compare/v0.24.2...v0.25.0
[0.24.2]: https://github.com/jfillman/clearance/compare/v0.24.1...v0.24.2
[0.24.1]: https://github.com/jfillman/clearance/compare/v0.24.0...v0.24.1
[0.24.0]: https://github.com/jfillman/clearance/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/jfillman/clearance/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/jfillman/clearance/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/jfillman/clearance/compare/v0.20.3...v0.21.0
[0.20.3]: https://github.com/jfillman/clearance/compare/v0.20.2...v0.20.3
[0.20.2]: https://github.com/jfillman/clearance/compare/v0.20.1...v0.20.2
[0.20.1]: https://github.com/jfillman/clearance/compare/v0.20.0...v0.20.1
[0.20.0]: https://github.com/jfillman/clearance/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/jfillman/clearance/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/jfillman/clearance/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/jfillman/clearance/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/jfillman/clearance/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/jfillman/clearance/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/jfillman/clearance/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/jfillman/clearance/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/jfillman/clearance/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/jfillman/clearance/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/jfillman/clearance/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/jfillman/clearance/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/jfillman/clearance/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/jfillman/clearance/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jfillman/clearance/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jfillman/clearance/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jfillman/clearance/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jfillman/clearance/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jfillman/clearance/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jfillman/clearance/releases/tag/v0.1.0
