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
Clearance App is its deployment protection rule) runs `release`, `terraform apply tfplan` and `report`. Both
enforcement paths are exercised (GitHub will not start the job until Clearance clears; `release` stops a different plan
file), and the apply role's trust policy names `repo:jfillman/hangar-infra:environment:lab`, so only that job holds
credentials that can change the lab. Two things a workflow must do that the steps above do not show: the hold has to
run in a job *before* the environment job (the App looks up the registered change when the deployment is requested), and
`terraform show -json` is run by the workflow and passed as `json` so `hold` need not run inside an initialized
directory. The repository needs `autopilot.githubWorkflows: ["repo:jfillman/hangar-infra:*"]` in the cluster's config.

## Not built

The plan's `targeted` and the state's backend are flags, not read from the plan; the CLI does not verify the clearance
token's signature on `release` (it trusts the core's answer over the authenticated channel, and the core re-checks the
digest on `report`); a plan with more than 2000 resource changes is refused by the core.
