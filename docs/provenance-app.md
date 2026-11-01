# The Clearance provenance App: design pass, 2026-11-01

Clearance decides whether a pull request is the one its agent opened and whether it stays inside that agent's scope
(`provenance.py`). Today those verdicts reach GitHub through a CI check someone else runs: on Hangar, Glidepath's
`agent-gates-` Pipelines-as-Code check reads the PR with Glidepath's GitHub App and asks `POST /v1/provenance`. That is
an integration, not a product surface. A team that buys Clearance and does not run Glidepath has no way to get the
verdicts onto its PRs, and no way to let the deployment gate hold a GitHub deployment.

The **Clearance provenance App** is Clearance's own GitHub App: the customer installs it on their repos, Clearance
receives the webhooks itself, and it posts its own check runs and answers GitHub's deployment protection rules. This
document proposes how; it builds nothing, and every decision is the owner's.

## What exists, and what the App adds

| Today | What the App adds |
|---|---|
| `provenance.verify` decides identity (`confirmed`, `not-agent`, AI001-AI004) and scope (`in-scope`, `not-agent`, AS001-AS004) from Clearance's own receipts; each verdict is a `provenance.verify` evidence record | nothing changes in the decision; the App is a new way to ask and to report |
| `POST /v1/provenance` answers a verifier (a principal in `CLEARANCE_VERIFIERS`); the caller gathers the PR's head, paths, author and trailers | Clearance gathers them itself, from the webhook and the GitHub API, with an installation token for that repo only |
| Glidepath's `agent-gates-` check reports the verdict as a PaC check run and a PR comment (Hangar only) | `Clearance / agent-identity` and `Clearance / agent-scope` check runs, posted by Clearance, on any GitHub repo the App is installed on |
| The deployment gate (`gate.md`) is enforced at merge by Glidepath's `clearance-gate-` check and, in phase 2, at admission by a pulled grant | a **GitHub custom deployment protection rule**: a GitHub Actions deployment to a protected environment waits until Clearance clears the change |
| Decision D4: the agents' App authors agent PRs | unchanged, and kept separate: the App that writes a change must never be the App that attests to it, and each needs its own rate-limit bucket |

## Two Apps, never one

| | The agents' App | The Clearance provenance App |
|---|---|---|
| Job | open PRs as agents (`repo.pr.open`) | attest to PRs and gate deployments |
| Permissions | contents and pull requests **write** on one repo per token | pull requests, contents, metadata **read**; checks **write**; deployments **read** and deployment protection rules; never contents write, administration or workflows |
| Who holds its key | Glidepath's broker on Hangar; Clearance's runtime for a customer | Clearance only |
| Events | none | `pull_request` (opened, synchronize, reopened, edited), `check_run` (rerequested), `check_suite` (rerequested), `deployment_protection_rule`, `installation`, `installation_repositories` |

An App that can write code can also make a commit look like its own work. Keeping attestation in an App with no
write permission on contents is what makes "Clearance confirmed this" mean something.

## How a PR is checked

1. GitHub sends `pull_request` to Clearance's webhook endpoint. Clearance verifies the `X-Hub-Signature-256` HMAC
   against the App's webhook secret before reading anything else, and answers within GitHub's 10-second limit by
   queueing the work.
2. A worker mints an **installation token scoped to that one repository**, read-only on contents and pull requests,
   write on checks. It reads the head commit, the changed paths including each rename's previous name (the files
   API, 100 per page, at most 3,000 as GitHub allows), the author, and the head commit's `Hangar-*` trailers. This is
   exactly what `agent-gates-` sends today, now gathered by Clearance.
3. It calls the same `provenance.verify` with the receipts from its own evidence chain, and records the verdict
   (`provenance.verify`, principal `app:<installation id>`, target `repo#pr`).
4. It creates or updates two check runs on the head commit:
   - `Clearance / agent-identity`: success for `confirmed` or `not-agent`, failure with the AI rule, its message and
     its fix hint in the check's output;
   - `Clearance / agent-scope`: the same for AS rules, each violation as a check annotation on the path.
   A person's PR passes both in seconds as not-agent, so both can be made required in branch protection without
   blocking anyone.
5. `check_run` rerequested (the "Re-run" button) runs it again; a new push is a new head and runs it again.

No PR comment by default: check runs already carry the summary and annotations, and a comment per PR is noise. A
customer may turn comments on for agent PRs only, the way `agent-gates-` does.

## How a deployment is gated

GitHub's custom deployment protection rules let an App approve or reject a GitHub Actions deployment to an
environment. This is the deployment gate's enforcement for customers who deploy with Actions instead of Argo CD.

1. The customer adds the App as a protection rule on the environments they mark protected.
2. A workflow job targeting such an environment makes GitHub send `deployment_protection_rule` with the environment,
   the commit SHA and a callback URL.
3. Clearance looks for a **grant** for that repository, commit and environment (`gate.md`'s change, registered and
   classified). It answers the callback: **approved** when the change is cleared, **rejected** when it is denied,
   and it waits while the change holds for people, approving later when they clear it (GitHub keeps the deployment
   waiting, up to 30 days).
4. Where does the change come from? Two options (open question 3): the customer's own CI registers it with a
   `clearance register` step that renders and diffs what it will deploy (`POST /v1/clearances`, as Glidepath's check
   does); or the App classifies the PR's diff by paths and objects it can read from the repo, which is weaker because
   it sees source, not the rendered result.

Every answer is a `deploy.clear`, `deploy.deny` or `deploy.expire` record naming the App installation, so the chain
holds the same evidence as Hangar's.

## Hosted and self-hosted

| | Hosted (Clearance as a service) | Self-hosted |
|---|---|---|
| The App | one public App, `clearance-provenance` (free on GitHub as of 2026-10-31; `Clearance` is taken), registered by us | registered by the customer from a manifest we ship (GitHub's App manifest flow: one click, their own key and secret) |
| Tenancy | each installation is a tenant: its repos, its agents' receipts, its evidence chain, keyed by installation id and its account | one tenant, the customer's |
| Secrets | the App's private key in a KMS, never on disk; webhook secret per App | the customer's, in their secret store |
| Webhooks | a public endpoint we run, signature-checked, rate-limited per installation | their Clearance's endpoint, which must be reachable from GitHub (or a relay they run) |
| Receipts | an agent that opens PRs through Clearance leaves receipts in that tenant's chain; PRs opened elsewhere are `not-agent` or fail AI002 when authored by the tenant's agents' login | the same |
| Data | evidence per tenant, exportable; the verify command checks a tenant's chain without us | theirs |

A customer who uses Clearance's runtime gateway gets agent receipts for free. A customer who only wants
attestation for agents that open PRs some other way gets `not-agent` for everything until their agents go through
Clearance: the App proves what Clearance did, not what it did not see.

## Hangar

Hangar can keep `agent-gates-`, or replace it with the App so Hangar runs exactly what customers run. Replacing it
removes Glidepath's need for a Clearance token and a NetworkPolicy exception, and gives Hangar the deployment
protection rule for any app that ever deploys through Actions. The recommendation is to replace it once the App runs,
behind a period where both report, so the verdicts can be compared.

## The record

| Tool | When | Carries |
|---|---|---|
| `provenance.verify` | every check, as today | principal `app:<installation>`, target `repo#pr`, both verdicts |
| `app.installation` | the App is installed, suspended or removed, or repositories are added or removed | the account, the repositories |
| `deploy.request`, `deploy.clear`, `deploy.deny`, `deploy.expire` | a deployment protection rule asks, and Clearance answers | the environment, the commit, the run, the grant |

## API

No new public API for PRs: the App is driven by webhooks. Internally, `POST /v1/github/webhook` (signature-checked,
no bearer token). clearance-api gains the installation as a filter on the existing evidence and receipts reads, and
`GET /v1/github/installations` for an operator page.

## Phases

1. **Check runs.** The App, webhooks, installation tokens, the two check runs, the records. Self-hosted first, on
   Hangar beside `agent-gates-`, so both verdicts can be compared on real PRs.
2. **Deployment protection rules.** Grants looked up and answered; `clearance register` for customers' CI.
3. **Hosted.** Multi-tenant tenancy, KMS for the key, per-installation rate limits, the public App listing.
4. **Hangar switches** from `agent-gates-` to the App.

## Decided 2026-11-01

| # | Question | Decision |
|---|---|---|
| 1 | Replace `agent-gates-` on Hangar | **Yes, after running both for a while.** The App's check runs report beside `agent-gates-` until their verdicts agree on real PRs, then `agent-gates-` retires (its onboarding template removed, the guardrail renamed to the App's check). |
| 2 | Self-hosted or hosted first | **Self-hosted first, on Hangar**: a Hangar-registered App, Clearance's webhook endpoint on hangar-dev, one tenant. Hosted (tenancy, KMS, the public listing) is phase 3. |

| 3 | Where a gated deployment's change comes from | **Both.** A `clearance register` step in the customer's deploy workflow (it renders and diffs what it applies, the same strength as Hangar's check) is preferred; without one, the App classifies the PR's source diff and the change is marked **source-only** so people know its tier is coarse. |
| 4 | PR comments | **Off by default**, a per-installation setting with **"failures on agent PRs"** as the option (Hangar uses it while both checks run, so the comparison is visible). Turning it on adds `issues: write` to the App's token. |
| 5 | Names | **As proposed**: the App is **Clearance** (slug `clearance`); the checks are `Clearance / agent-identity` and `Clearance / agent-scope`; the deployment rule is **Clearance deployment gate**; records name `app:<installation id>`. |

## Built, phase 1 (v0.21.0): the check runs

- **`github_app.py`**: `verify_signature` (HMAC-SHA256 of the raw body, constant-time), `GitHubApp.accept` (401 bad
  signature, 202 queued, 200 ignored; never works inline), a worker thread, `handle` for `pull_request` (opened,
  synchronize, reopened, edited, ready_for_review), `check_run` / `check_suite` rerequested (only the App's own
  checks) and `installation` / `installation_repositories`. The App's JWT (RS256, 9 minutes), an installation token
  for the one repository (`checks: write`, `contents`/`pull_requests`/`metadata: read`; `issues: write` only with
  comments on), `gather` (head, author, every changed path and a rename's old name, the head commit's `Hangar-*`
  trailers: what `agent-gates-` sends), two check runs with the rule, the hint, the evidence record and one annotation
  per out-of-scope path, and the optional comment (upserted by a marker).
- **Gateway**: `provenance_from_app(installation, request)` (the same `provenance.verify`, recorded with principal
  `app:<id>`), `record_app_installation` (`app.installation` records). The `/v1/provenance` path is unchanged.
- **Route**: `POST /v1/github/webhook` on the gateway (`create_http_app(github_app=)`), signature-authenticated, 404
  when no App is configured.
- **Registration**: `contract/github-app-manifest.json`, the App manifest for GitHub's manifest flow (replace
  `CLEARANCE_HOST`): private, the permissions and events above. A GitHub App's name is unique across all of GitHub
  and `Clearance` is taken (reserved for the account `clearance`), so the manifest names Hangar's `Hangar Clearance`;
  a customer registering their own names it after themselves (`<Org> Clearance`). The check runs keep their names
  (`Clearance / agent-identity`, `Clearance / agent-scope`) whatever the App is called: Clearance sets them, not GitHub.
- **Live on Hangar, 2026-11-01**: `Hangar Clearance` (app 5561694), installed on 25 Hangar repos, webhooks through
  `clearance-webhook.hangarplatform.dev` (a Cloudflare tunnel that forwards only `POST /v1/github/webhook`) to the
  hangar-dev gateway (gateway-v0.3.18, apron `autopilot.githubApp`). First verdicts: both checks `not-agent` on a
  person's PR (gitops-hangar-dev#93), evidence `provenance.verify` and `app.installation` as `app:177375213`. It runs
  beside `agent-gates-` until their verdicts agree on agent PRs (decision 1).
- Not yet: phase 2's deployment protection rule and `clearance register`.


## Open questions for the owner (all decided 2026-11-01; kept for the record)

1. ~~Replace `agent-gates-` on Hangar~~ Decided: yes, after running both.
2. ~~Hosted first or self-hosted first?~~ Decided: self-hosted on Hangar first.
3. ~~Where a gated deployment's change comes from~~ Decided: both. Was: a `clearance register` CI step that renders what it deploys
   (recommended: the same strength as Hangar's), or the App classifying the PR's source diff (weaker, zero setup).
4. ~~PR comments~~ Decided: off by default, "failures on agent PRs" as an option. Was: off by default, check runs only (recommended), or on for agent PRs like `agent-gates-`?
5. ~~Name~~ Decided: as proposed. Was: `clearance-provenance` for the App and `Clearance / agent-identity`, `Clearance / agent-scope` for the
   checks, or another name the product site uses.
