# The Terraform gate in plain CI (G-TF-3)

Status: **Built** (`clearance hold`, `release` and `report`, `terraform/action.yml`), tested against `clearance core
--memory` with fixture plans. **Draft** on a real workflow: the lab workflow that uses it (G-TF-4) is
[`network-lab.yaml` in jfillman/hangar-infra](https://github.com/jfillman/hangar-infra/pull/3), **Unverified** until its
first real apply is cleared and matched.

Three subcommands of the `clearance` binary put a saved Terraform plan behind the gate
([The terraform-plan subject](gate.md#the-terraform-plan-subject-g-tf-1), [Hold, release and
outcome](gate.md#hold-release-and-outcome-for-a-plan-g-tf-2-built)). They work in any CI that can run the binary; the
composite action is the GitHub form.

```
terraform plan -out=tfplan
clearance hold    --plan tfplan --app network --env lab --backend s3 --state-key network/lab/terraform.tfstate
clearance release --plan tfplan --clearance <id>      # the apply step runs only after this exits 0
terraform apply -json tfplan > apply.jsonl
clearance report  --plan tfplan --apply-log apply.jsonl --clearance <id>
```

## Guardrails

- **The plan never leaves the runner.** `hold` sends the subject only: the sha256 of the saved plan file, of the
  *redacted* plan JSON and of the variable set; the workspace; versions; the counts; and per resource its address,
  type, Terraform's actions and the JSON pointers of the attributes an update changes. Never a value.
- **Secret values are in no output or request.** The redacted plan JSON keeps its shape and structural keys
  (addresses, types, actions, versions) and replaces every other scalar with `(redacted)`. The variable-set digest
  hashes each variable's name and the sha256 of its value, except a variable the configuration marks `sensitive`,
  which contributes its name only, so a secret cannot be brute-forced out of a digest. Unit tests assert a sensitive
  variable and a sensitive attribute value appear in neither the request nor the redacted JSON, and the apply log's
  diagnostic detail is never read.
- **The CLI never applies.** `release` only proves the saved plan is the cleared one; the workflow's apply step must
  run after it, so a non-zero `release` stops the apply.
- **A different plan is caught twice.** `release` re-hashes the plan file and compares it with the digest the change
  was cleared for (exit 1 on any difference, an unknown change, or a change that is not `cleared`). `report` posts
  the digest of the file that was applied, and the core compares it itself: a mismatch is recorded as
  `deploy.exception` (`digest-mismatch`), revokes the token and exits 1.
- **Identity** is the workflow's GitHub Actions OIDC token (the job needs `permissions: id-token: write`), as for
  `register`, or `--token-file` for a verifier's bearer token. The core accepts the token for its own repository only.
  **Another job of the same repository may release and report.** A workflow holds the plan in one job (OIDC subject
  `repo:o/r:ref:refs/heads/main`) and applies it in another, inside a GitHub environment (`repo:o/r:environment:lab`),
  so the subjects differ. For a terraform-plan change registered by a GitHub Actions workflow, `GET
  /v1/clearances/{id}`, its `/wait` and `POST /v1/clearances/{id}/outcome` accept any principal of the same repository
  (the same `repo:<owner>/<repo>` prefix, matching the change's repository and the caller's own verified `repository`
  claim) that is still a configured verifier (`CLEARANCE_VERIFIERS`, e.g. `github:repo:jfillman/hangar-infra:*`).
  Every other kind of change keeps the exact-registrant rule. Status: **Built**.

## `clearance hold`

`hold` reads `terraform show -json <plan>` (run `--binary terraform|tofu`, or give the output as `--json plan.json`),
computes the subject, validates it with the gate's own parser, registers the change (`POST /v1/clearances`) and
waits (`GET /v1/clearances/{id}/wait`, 60 s long-polls). It prints `<id> <state> tier <n>` first.

| Exit | Meaning |
| --- | --- |
| 0 | cleared (policy or people) |
| 3 | holding: with `--no-wait`, or `--wait-timeout` passed |
| 1 | denied, expired, superseded, refused by the core, or Clearance unreachable |
| 2 | usage: a missing flag, an unreadable plan, a plan the gate would refuse |

Flags: `--plan` (required), `--json`, `--workspace` (default `default`), `--binary` (default `terraform`), `--app`,
`--env`, `--backend` and `--state-key` (required: the plan JSON does not say where the state is, and the change's id
binds repository, workspace and plan), `--cluster`, `--owner`, `--targeted` (the plan was made with `-target`; the plan
JSON does not say), `--lock-file` (default `.terraform.lock.hcl`, where provider versions come from; missing means
none), `--check name=value` (repeatable, e.g. `ci=pass`), `--path` (repeatable, the files the change touches, for the
path rules), `--repo`, `--head`, `--pr`, `--proposer`, `--proposer-kind`, `--no-wait`, `--wait-timeout`, `--dry-run`
(print the request and stop), `--url` / `CLEARANCE_URL`, `--audience`, `--token-file`. A plan holds 24 hours; the same
saved plan registered again is the same change.

## `clearance release` and `clearance report`

`release --plan tfplan --clearance <id>` exits 0 and prints `released` only when the change is `cleared` and its
digest is the plan file's. `report --plan tfplan --apply-log apply.jsonl --clearance <id>` reads `terraform apply
-json` (the apply hooks and the error diagnostics' summaries; timestamps from the log) and posts
`POST /v1/clearances/{id}/outcome`. It needs `--plan` because the outcome carries the digest of the plan that was
applied, re-hashed at that moment. Exit 0 means the outcome was recorded and matched; 1 means a mismatch, a refusal
(a second outcome is `DG-STATE`) or Clearance unreachable. A failed apply is reported too (`applied: false`).

## The GitHub action

```yaml
- uses: jfillman/clearance/terraform@<ref>   # a release tag, once one carries this
  id: hold
  with: { step: hold, url: https://clearance.example.com, plan: tfplan, app: network, env: lab,
          backend: s3, state-key: network/lab/terraform.tfstate, args: "--check ci=pass" }
- uses: jfillman/clearance/terraform@<ref>
  with: { step: release, url: https://clearance.example.com, plan: tfplan, clearance: "${{ steps.hold.outputs.clearance }}" }
- run: terraform apply -json tfplan > apply.jsonl
- if: always()
  uses: jfillman/clearance/terraform@<ref>
  with: { step: report, url: https://clearance.example.com, plan: tfplan, apply-log: apply.jsonl,
          clearance: "${{ steps.hold.outputs.clearance }}" }
```

Like `register/action.yml`, it builds the Go binary at its own ref. Outputs: `clearance` (the id), `result`, `state`.
A holding exit (3) is not a failure of the `hold` step, and `release` then refuses it. CI lints the action
(`terraform-action` job: metadata, shellcheck on every embedded script) and runs a `hold --dry-run` of a fixture plan.

## The lab workflow (G-TF-4, Draft)

`jfillman/hangar-infra` runs `network/lab` through this gate: a pull request plans and comments; a merge saves the plan
and holds it (`--no-wait`) in a job with a read-only role, and an `apply` job in the GitHub environment `lab` (the
Clearance App is its deployment protection rule) runs `release`, `terraform apply -json tfplan > apply.jsonl` and `report` (`apply-log: apply.jsonl`, run `if: always()` once release passed, so a failed apply is reported too). Both
enforcement paths are exercised (GitHub will not start the job until Clearance clears; `release` stops a different plan
file), and the apply role's trust policy names `repo:jfillman/hangar-infra:environment:lab`, so only that job holds
credentials that can change the lab. Two things a workflow must do that the steps above do not show: the hold has to
run in a job *before* the environment job (the App looks up the registered change when the deployment is requested), and
`terraform show -json` is run by the workflow and passed as `json` so `hold` need not run inside an initialized
directory. The repository needs `autopilot.githubWorkflows: ["repo:jfillman/hangar-infra:*"]` in the cluster's config.

## Exception detection (G-TF-5, Built, not deployed)

The gate only sees applies that go through it. `terraform-detector` (`providers/terraform/detect`, Go) looks at what
goes around it, once per run, meant for a schedule. It posts `deploy.exception` through `POST /v1/records` as the
registered provider `terraform-detector/<version>`, located by `destination.workspace` {backend, key, name}: a plan
has no cluster, so the core accepts a workspace in its place (`where()` in `internal/gate/exception.go`; a gitops
report keeps `destination.cluster` and `environment`, and a destination with both is refused).

| Detector | How | Record |
| --- | --- | --- |
| Drift | `terraform plan -detailed-exitcode -lock=false` in each workspace's directory. Exit 0: nothing. Exit 2: a diff nobody cleared; `terraform show -json` names the addresses. Exit 1: the plan could not run, an error for the run, never an exception | `kind=drift`, `addresses`, `observed` (a fingerprint, so the same drift is filed once per window); the core sets coverage `observed-not-attributed` |
| Untraced apply | S3 `ListObjectVersions` for the state key; each version in the window (older than `--settle`) must fall inside the apply window of a `deploy.outcome` for the workspace's environment (give or take `--slack`). One that does not is untraced; CloudTrail `LookupEvents` (PutObject) names the principal | `kind=untraced-apply`, `actor` (the CloudTrail ARN; `unknown` when no event is found), `state` {backend, key, version}; coverage `out-of-band-detected` |

Why a version is judged by time and environment: the plan outcome's destination carries the environment, not the
workspace, so an outcome in `prod` explains any `prod` workspace's state write during its apply. Two workspaces of the
same environment applying at once can mask each other. Adding the workspace to the outcome record would close this
(not built). If Clearance cannot be read, nothing is reported: a blind outcome list would flag every apply. A drift
plan reads the live infrastructure, so run it on the branch that was last applied; a merged but unapplied change is
a diff too.

**CloudTrail limit.** `LookupEvents` serves management events. S3 object writes are data events, so the principal
is found only where the account makes them visible to `LookupEvents`; otherwise the exception is still filed with
`actor: unknown` and the version id, which is enough to find the write in a trail's S3 or CloudTrail Lake logs.
Enable data events for the state bucket's key on a trail, and consider a CloudTrail Lake lookup in a later change.

**Config** (`--config`, JSON): `{"workspaces": [{"name": "default", "key": "prod/network.tfstate", "bucket":
"acme-tf-state", "dir": "infra/network", "env": "prod"}]}`. Flags: `--core-url`, `--api-url`, `--token-file`,
`--region`, `--only drift|untraced|all`, `--window` (default 2h: longer than the schedule), `--settle` (10m),
`--slack` (5m), `--drift-dedup` (7 days: how long a filed drift suppresses the same drift; it is its own lookback because drift runs nightly, far apart from `--window`), `--terraform`. Exit 1 when any workspace's check failed.

**Credentials, never stored.** Clearance: a bearer token from `--token-file` (a projected service-account token or the
workflow's OIDC token), read per request. AWS: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` from
the environment, or `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` (the detector assumes the role for 15 minutes with
STS, mints them once per run and keeps them in memory only, replacing them 2 minutes before they expire). Requests are SigV4-signed with the standard library; the repository takes no AWS
SDK. The drift plan's own provider credentials are the plan role's, outside this tool.

**Read-only IAM policy** (for the owner to create; nothing here creates it). Attach it to the detector's role beside
whatever read access `terraform plan` needs for the workspace's providers:

```json
{"Version": "2012-10-17", "Statement": [
  {"Sid": "StateVersionsList", "Effect": "Allow", "Action": "s3:ListBucketVersions",
   "Resource": "arn:aws:s3:::acme-tf-state",
   "Condition": {"StringLike": {"s3:prefix": ["prod/network.tfstate"]}}},
  {"Sid": "StateVersionsRead", "Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
   "Resource": "arn:aws:s3:::acme-tf-state/prod/network.tfstate"},
  {"Sid": "WhoWrote", "Effect": "Allow", "Action": "cloudtrail:LookupEvents", "Resource": "*"}]}
```

`s3:GetObject*` is for `terraform plan` reading the state (the detector itself only lists versions). `LookupEvents`
supports no resource-level scoping. Add `s3:GetObjectVersion` only if you want the detector to read an old version's
serial later. The role gets no `s3:PutObject` and no `s3:DeleteObject`: a detector that could write state would be
the thing it watches for.

**Registration** (the manager adds it to `CLEARANCE_PROVIDERS`; the principal is the detector's workload identity):

```json
{"name": "terraform-detector", "version": "0.1.0", "principals": ["<detector principal>"],
 "kinds": ["deploy.exception"]}
```

The same principal needs read access to evidence (`GET /v1/evidence`, `GET /v1/exceptions`: the auditor role) for the
outcome list and for de-duplication.

**Schedule.** Run it more often than `--window`: every 30 to 60 minutes for untraced applies (with the default window,
a missed run or two is covered, and a version already filed is skipped), and every few hours or nightly for drift
(`--only drift`; a plan is slow and reads a lot). A scheduled GitHub Actions workflow in the hangar-infra repo
(G-TF-4's repo) is the intended home: `on: schedule`, OIDC to AWS and to Clearance, `terraform-detector --config
detectors.json`; it is not written yet. Status: **Built**, tested against a fake plan exit code and fake S3 and
CloudTrail answers (`go test ./providers/terraform/...`, including the SigV4 published test vector);
**Unverified** against a real bucket and trail.

## The HCP Terraform run task (G-TF-6, Built, not live-verified)

Status: **Built** (`internal/hcprun`, `POST /v1/terraform/run-task`), tested against HashiCorp's published run task
payload (a fake HCP Terraform serves the plan JSON and records the callbacks). **Unverified** against a real HCP
Terraform organization: that waits for a design partner. Off unless `CLEARANCE_HCP_RUN_TASK_CONFIG_FILE` is set; until
then the route answers 404.

HCP Terraform (or Terraform Enterprise) POSTs a run task request to the route at the **post-plan** (or pre-apply) stage
of a run. Clearance verifies the request, reads the plan JSON, computes and registers the terraform-plan subject
([the subject](gate.md#the-terraform-plan-subject-g-tf-1)), and reports the result to HCP Terraform's
`task_result_callback_url`: `running` at once, then `passed` when the change is cleared (policy or people) or `failed`
when it is denied, expired or superseded. A mandatory run task then blocks the apply on `failed`. The route answers 200
`{"result":"accepted"}` straight away and works in the background.

```
HCP Terraform --POST /v1/terraform/run-task (X-TFC-Task-Signature)--> Clearance
Clearance     --GET plan_json_api_url (Bearer access_token)--------> HCP Terraform
Clearance     --PATCH task_result_callback_url: running ------------> HCP Terraform
              ... registers the plan; holds for people if tier 2 or 3 ...
Clearance     --PATCH task_result_callback_url: passed | failed ----> HCP Terraform
```

**Config** (`CLEARANCE_HCP_RUN_TASK_CONFIG_FILE`, JSON), one installation per HCP Terraform organization:

```json
{"installations": [{"organization": "acme", "host": "app.terraform.io", "hmacKeyFile": "/etc/clearance/hcp/acme-key",
                    "environment": "prod"}]}
```

`hmacKeyFile` holds the HMAC key set on the run task in HCP Terraform; it is read on every request and never kept (rotate
it by replacing the file). `environment` is the environment name the organization's plans register under (the gate's
own list of protected environments decides whether it is protected). `host` defaults to `app.terraform.io`; a Terraform
Enterprise host is allowed. `redirectHosts` (default `archivist.terraform.io` for the HCP host) are the hosts the plan
download may be redirected to. The adapter registers as the principal `hcp-run-task:<organization>`, so
`CLEARANCE_VERIFIERS` must include it (for example `hcp-run-task:*`), exactly as for any registrant.

In the chart: `hcpRunTask.enabled`, `existingSecret` (one key per organization) and `installations` (`organization`, `environment`, `secretKey`, optional `host`, `redirectHosts`); the chart writes the config file and mounts the keys at mode 0400. It does not open egress to the HCP Terraform host (`networkPolicy.extraEgress`) or expose the route (`httproute` matches): both are yours to set.

**What is registered.** The workspace is `{backend: remote, key: <workspace id>, name: <workspace name>}`; `app` is the
workspace name made a DNS label; `repo` is the VCS repository (else `<organization>/<workspace name>`); `head` is the
commit (else a digest of the run id, for a CLI-driven run); `pr` is the pull request when there is one. The plan digest
is the sha256 of the plan JSON as HCP Terraform serves it (HCP Terraform does not hand out the binary plan), and the
redacted-JSON and variable-set digests are computed as in `clearance hold`. The plan JSON is never stored and its values
never leave the process; the registration carries digests, addresses, types, actions and changed attribute pointers.
The same plan registered again (an HCP Terraform retry) is the same change; a new run is a new plan.

**Stages.** `post_plan` and `pre_apply` are judged. `pre_plan` has no plan: the task is answered `failed` with a message
to attach it at post-plan. `post_apply` is answered `passed` (nothing left to gate; recording the apply's outcome for
HCP Terraform is not built). A request with stage `test` (an unconfirmed guess at HCP Terraform's URL check when a run
task is created) is answered 200 without calling anything.

**Waiting for people.** A tier 2 or 3 plan is held. The run task reports `running` (with who must clear it) and sends
a progress update every 4 minutes, because HCP Terraform fails a task with no progress for 10 minutes. HCP Terraform
also limits a task to 60 minutes, so after 55 minutes still holding the task is answered `failed` ("start a new run once
it is decided"); the change itself keeps its own 24 hour life.

### Guardrails

- **Signature.** `X-TFC-Task-Signature` is HMAC-SHA512 of the body, hex; it is compared in constant time
  (`hmac.Equal`). A missing or wrong signature, an unknown organization and a malformed body all answer 401, before the
  payload is used or anything is called. The key is per organization; an unreadable key is 503 (fail closed).
- **Body size.** The body is capped at 64 KiB before it is read (413).
- **No SSRF.** `plan_json_api_url` and `task_result_callback_url` must be `https` on the installation's configured host
  (exact match, no credentials, no port other than 443, no dot segments, under `/api/v2/`) or the request is refused
  (400) before anything is called. Redirects are followed at most 3 times, only to the configured host or its
  `redirectHosts`, and the access token is sent to the configured host only.
- **The access token** lives in memory for one run, goes in one `Authorization` header to the HCP Terraform host, and
  is never logged, stored or put in an error message (tests assert it appears in no log line and no registration).
  Logs carry the organization, run id, workspace, stage and outcome only.
- **Load.** At most 64 runs are worked at once (503, which HCP Terraform retries); a retried request for a task result
  already being worked is not run twice.

### Not built (HCP Terraform)

- **Targeted plans are not detected.** The run task payload and the plan JSON do not say a plan was made with
  `-target`, so `targeted` is always false (the plain-CI `--targeted` flag has no HCP Terraform equivalent). Do not
  rely on this adapter alone for a workspace that allows targeted runs.
- No `checks` are sent, so a plan that policy would clear at tier 1 only on green checks is held at tier 2 for people.
- No structured `outcomes` in the callback and no link back to Clearance (only `status` and `message`).
- No outcome or exception recording for HCP Terraform applies (G-TF-5's detector reads S3 state, not HCP Terraform).
- Per-workspace environment mapping: one `environment` per organization.
- Not built, deferred until a design partner asks: **Atlantis** (its `pre_workflow_hooks` / custom workflow could call
  `clearance hold`, which already works in any CI) and **Spacelift** (a push or approval policy that calls the gate).

## Not built

The plan's `targeted` and the state's backend are flags, not read from the plan; the CLI does not verify the clearance
token's signature on `release` (it trusts the core's answer over the authenticated channel, and the core re-checks the
digest on `report`); a plan with more than 2000 resource changes is refused by the core.
