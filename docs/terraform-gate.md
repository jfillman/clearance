# The Terraform gate in plain CI (G-TF-3)

Status: **Built** (`clearance hold`, `release` and `report`, `terraform/action.yml`), tested against `clearance core
--memory` with fixture plans. **Unverified** on a real workflow: the lab workflow that uses it is G-TF-4, and nothing
in `jfillman/hangar-infra` calls it yet.

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

## Not built

The plan's `targeted` and the state's backend are flags, not read from the plan; the CLI does not verify the clearance
token's signature on `release` (it trusts the core's answer over the authenticated channel, and the core re-checks the
digest on `report`); a plan with more than 2000 resource changes is refused by the core.
