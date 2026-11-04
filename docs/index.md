# Clearance

Clearance is change assurance in the path of every change. It decides and records; it is not a gateway and enforces
nothing itself. An AI agent gateway (Autopilot's) asks it for a decision before every tool call, model call, session
open and spawn, and writes each outcome through it; a deployment gate's providers ask it whether a change may land in
a protected environment. A denial carries a stable rule id and a fix hint, so an agent corrects itself against a
deterministic gate instead of guessing, and every decision and outcome is one record in a hash-chained evidence chain.

It is a [Hangar](https://hangarplatform.dev) product. Autopilot, Hangar's agent gateway and runtime, is its native
consumer, but Clearance installs alone: the core knows nothing about Airframe, Glidepath, Autopilot or any other
platform. Source: [github.com/jfillman/clearance](https://github.com/jfillman/clearance).

## Two boundaries

| Boundary | Question | State |
|---|---|---|
| **Runtime** | May this agent make this call, now, with this budget, and what happened? | Built and deployed: the decision service (tiers and tripwires, path and field scope, narrow-only limits, CEL policy rules, policy bundles), the hash-chained evidence record, PR provenance for the agent gates. The gateway that asks and enforces (the MCP surface, sessions and the run tree, budgets, tool dispatch, the model proxy, the human inbox, person controls) is Autopilot's. |
| **Deployment** | May this change land in a protected environment, and can we prove it did so under policy? | Core built ([the deployment gate](gate.md)): changes tiered 0 to 3 from the rendered diff, cleared by policy or by named people, a 7-day TTL, a new head supersedes, `deploy.*` records. Fed by Glidepath's `clearance-gate-` check (advisory on Hangar) and by `clearance register`; answered to GitHub Actions deployments by the App's protection rule. Not built: admission (the pulled grant and the Kyverno policy), outcome records from the Argo CD and Terraform providers. |

## What is where

Clearance is one Go module and one binary, `clearance` ([core.md](core.md)); hangar-dev runs it since 2026-11-03.

- **The decision service** (`internal/decide`, `internal/scope`, `internal/docscope`): the rules, core plus each
  deployment's [policy bundles](core.md#policy-bundles). Anything that fails to evaluate denies.
- **Definitions as a subject** (`internal/profile`, `internal/definitions`, `internal/review`): validating an agent
  definition, deciding each cluster pin, and tiering a definition change. The definitions themselves, their schema
  and the loader are Autopilot's.
- **Evidence** (`internal/evidence`, `internal/store`): one hash-chained record per decision in the
  clearance.evidence/v1 shape ([evidence.md](evidence.md)); Postgres with one writer.
- **The deployment gate** (`internal/gate`, `clearance register`): changes to protected environments, tiered and
  cleared; definition releases reviewed through the same gate.
- **The GitHub App** (`internal/githubapp`, `internal/provenance`): check runs on PRs and the deployment protection rule.
- **The read API** (`clearance api`, `internal/api`, `contract/clearance-api.json`): clearance-api, a separate
  read-only process: evidence, counts, PR receipts and verdicts, clearances, the policy and its explainer,
  definitions, and for the gates the signed grant feed, the record stream (SSE) and the GitHub App installations
  ([clearance-api.md](clearance-api.md); an OpenAPI 3.1 contract). The runtime's reads (sessions, runs, agents, the inbox, trigger
  history, results) are the Autopilot gateway's own API.
- **The clients**: `client` (Go) and `clients/python` (`clearance-core-client`, generated from the contract).

Until v0.29.0 the repository also held the Python package (`src/clearance`), which ran the whole gateway in one
process. It left in v0.30.0; the [changelog](https://github.com/jfillman/clearance/blob/main/CHANGELOG.md) says
where each module went.

## On GitHub

The [provenance App](provenance-app.md) is built and live on Hangar as **Hangar Clearance**: Clearance's own GitHub
App posting its own check runs (`Clearance / agent-identity`, `Clearance / agent-scope`, phase 1, v0.21.0), answering
GitHub Actions deployments from the deployment gate as a custom deployment protection rule (phase 2a, v0.22.0), with
`clearance register` as the CI step that registers what a workflow deploys (phase 2b, v0.23.0). On Hangar it runs
beside Glidepath's `agent-gates-` check until their verdicts agree.

## Where it shows up

In Hangar's portal: the **Clearance** pages (evidence, policy) and the **Autopilot** pages (runs, agents, new agent),
and in Tower's Agent and Clearance tabs per app. Design: the Hangar repo's `docs/autopilot/`.

## Releases

Tagged `vX.Y.Z` on `main` (the `VERSION` file names it); each tag publishes the image, the Helm chart, the Python
client's wheel and a GitHub Release whose notes are its section of
[CHANGELOG.md](https://github.com/jfillman/clearance/blob/main/CHANGELOG.md). Autopilot pins the tag (the Python
client) and ships the gateway image.
