# The AWS collector (O-4)

Status: **Built**, tested with fixtures and fakes (the digest chain with a generated key, the queue, the reconciler in both
arrival orders, the whole path through a real in-memory core). **Unverified** against a real trail, queue, Config recorder
and an AWS-signed digest: the rollout's live checks do that. Code: `providers/observe-aws`. It reads AWS and never writes
it (SQS consumption is the one write, the collector's own messages).

```
CloudTrail --(management + data events)--> EventBridge rule --> SQS --\
AWS Config --(configuration item changes)--> EventBridge rule --> SQS ---> drain -> scope filter -> reconciler -> pipeline -> POST /v1/records
S3 trail (organization trail, logging account) --> digests verified --> log files hash-checked --/   (observation, assessment, resolution)
state bucket versions + scheduled plan --> detector stages --> deploy.exception (untraced-apply, drift)
```

## The three feeds, one normalizer

All three become CloudTrail records (or Config items) the O-2 pipeline normalizes; the collector supplies events and
lookups and re-implements no attribution ([observe-pipeline.md](observe-pipeline.md)).

| Feed | What | `sourceVerified` | `integrity.method` |
| --- | --- | --- | --- |
| EventBridge to SQS | CloudTrail writes (`readOnly: false`, identity not `AWSService`) and data events on the state, artifact and secrets buckets; Config configuration item changes | false: delivered, not signed | `eventbridge-delivery`, `config-item` |
| S3 trail | the organization trail's hourly digests and the log files they cover | true when the digest, its link and the file hash verified | `cloudtrail-digest-chain` |

`completenessClaimed` is true on every observation; the core decides `completeness_supported` from the account's latest
health record ([evidence.md](evidence.md)). Both event feeds report under one `source.name` (`observe-aws`), so the core's
de-duplication on (provider, source, event id) makes a change reported by both feeds one record. **An event first seen
through EventBridge keeps `sourceVerified: false`**; the trail's copy is the core's duplicate. Its verification still counts:
the `digests-validating` check covers every digest read, and an event only the trail has (EventBridge dropped it) is posted
`sourceVerified: true`. That is the trail's job as the completeness reference.

### Digest-chain validation (`digest`)

Per AWS's description of log file integrity validation: each digest carries an RSA signature (SHA256withRSA, in the S3 object
metadata) over `<digestEndTime as yyyymmddThhmmssZ> \n <bucket>/<key> \n <sha256 of the digest file> \n <previous digest's
signature>`; the key is found by the digest's fingerprint (`cloudtrail:ListPublicKeys`). The collector verifies, in this order:

1. the digest's signature (a tampered digest fails here and nothing of it is extracted);
2. the link to the previous digest (key, file hash, signature). A digest that verifies but does not link (one is missing or was
   replaced) is extracted with `sourceVerified: false` and fails `digests-validating`;
3. each log file's sha256 against the hash the digest lists, **before** any record is parsed (a tampered file is not extracted).

The first digest of a run is linked to the previous digest object, fetched for the purpose. The signing string follows AWS's
documentation and is tested against a key generated for the test; it has not yet been checked against a digest AWS signed. If
the first live read reports `digest-signature-invalid` on every digest, suspect the signing string before the trail.

### The reconciler: one change, one exception

A Config item is the effect of a CloudTrail event when the item lists the event (`relatedEvents`, AWS Config's own pointer), or,
when it lists none, when the same account's item resource is a resource the event names and the item was captured within
15 minutes after it. An item that lists related events never joins one it does not list. The join is made when an entry is due
over everything pending, so arrival order does not matter. An event waits `settle` (default 10 minutes) for its item and for
the apply outcome that clears it; an item waits `settle` for its event. The merged change is one observation whose
`state_change` is the Config diff, one assessment (the detail names the changed properties and the quoted actor) and one
resolution. An item no event explains is reported alone, observed-not-attributed, signal `config.item-without-event`: an effect
the trail did not report. An item that arrives after its event was posted cannot be attached and is counted (`Late`).

### Attribution inputs

`userIdentity.type` (Root is always an exception), `sessionIssuer.arn` (the apply role or the SSO admin role),
`sourceIdentity` as the actor the record quotes (`actor.subject`; the ARN stays in `actor.attributes.arn` and the chain), the
self-reported session name and user agent (`TF_APPEND_USER_AGENT="clearance/grant=clr_...;plan=sha256:..."`), and `errorCode` for
refused attempts. The lookups behind the correlation hierarchy are made from the chain's `deploy.outcome` records
(`EvidenceLookups`): a recorded apply names its change (the grant), its plan digest and its apply window, which back the two
weakest signals (plan digest, apply window; both require the apply role). The stronger ones (a signed execution attestation, a
verified run and its session) need records the chain does not carry yet and fall through. A user agent claim no recorded
apply backs does not clear anything (`TestUnbackedClaimIsNotCleared`).

## First-release scope (`scope`)

Evaluated: IAM, CloudTrail and Config configuration, security groups, S3 bucket policies and public access, KMS, EventBridge
rules (the collector's own feed), and the data events (`PutObject`, `DeleteObject`, ...) of the configured buckets.
Second release (named as not evaluated until `secondWave` is set): VPC routing, Secrets Manager, Lambda configuration, EKS
access, RDS. Never evaluated: SSM session contents, database content, S3 data events of other buckets, and every service
outside the list (partially covered). Counts per area are kept, and the health record's `scope-not-evaluated` check carries
the statement, so a coverage statement reads what was not looked at beside what was.

## Health, per account

One `observation.health` record per account every 5 minutes: `trail-enabled`, `regions-covered`, `event-selectors` (management
events, writes included, data events for the configured buckets, log file validation on, no delivery error),
`digests-arriving`, `digests-validating` (a failure holds for 24 hours: a tampered file does not heal), `recorder-running`,
`rules-enabled`, `collector-current`, and `scope-not-evaluated`. State: **blind** when the trail is not enabled or unreadable,
digests stopped arriving or the queue is not being drained; **degraded** for any other failing check; healthy otherwise. A
successful `StopLogging` (and the other operations on monitoring) flips the account to blind through the core, a refused
one to degraded ([evidence.md](evidence.md)); only the collector's next healthy record clears it, and the pipeline's own flip
is cleared with it.

## Detector stages (absorbed from G-TF-5)

The untraced-apply witness (state-bucket versions no `deploy.outcome` window explains, with the CloudTrail principal) and the
scheduled plan as the drift detector (`terraform plan -detailed-exitcode`) are `providers/observe-aws/detect`, unchanged and with
their tests. Exceptions `drift` and `untraced-apply` are raised once (a drift per distinct set of addresses within seven days;
an untraced version once). The drift stage needs the terraform binary and a checkout, so it runs as `observe-aws --stage drift`
in a scheduled workflow, or in the collector where a terraform binary is on the PATH.

## Deployment

Chart `charts/clearance-observe-aws`, image `ghcr.io/jfillman/clearance-observe-aws`, one replica per account, no Kubernetes
RBAC, no Secret. Two projected service-account tokens are its whole credential: audience `clearance` (to the core) and audience
`sts.amazonaws.com` (assumed per run into two roles: one in the observed account, one in the logging account). Register it:

```json
{"name": "observe-aws", "version": "0.1.0", "principals": ["<namespace>/clearance-observe-aws"],
 "kinds": ["observation", "assessment", "resolution", "observation.health", "deploy.exception"]}
```

and give it the auditor role on clearance-api (outcomes). Terraform for the AWS side is in
[hangar-infra](https://github.com/jfillman/hangar-infra) `observe/`.

### Customer precondition: the logging account

The trail and the Config aggregator must deliver into an account production administrators cannot write to (a separate
account in the organization, with no production principal able to modify the bucket policy, the trail or the aggregator). The
collector reads that account with a read-only role; Clearance monitors it too (the trail, its selectors, its digests). A trail
delivered into an account the administrators control proves nothing against them: the same people who change the system can
change its record. In the Hangar lab, the organization trail `organization` already delivers to the management account's
bucket; the lab's own setup reuses it.

### Onboarding

A cross-account role for the lab account (this build). StackSets for many accounts, and a Marketplace-managed deployment, are
the open question (section 14, #16): the Terraform here is one account's worth and would become the StackSet template.

## Not done in this build

- Reading Config through the aggregator API (`BatchGetAggregateResourceConfig`) as a sweep; the aggregator exists in Terraform
  and Config items arrive through EventBridge.
- The packet's "filtered: N events under rule X" counter: the pipeline's `Stats` are in memory; persisting them for the packet
  is the O-3 collector's work and is not duplicated here.
- A persisted trail cursor: a restart re-reads the last three hours and the core's de-duplication absorbs it.
- Lookups from signed attestations, verified runs and sessions; the plan resource-change set (digest-only plans for now).
- Multi-account collectors in one process: one deployment per account.
