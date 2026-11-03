# Clearance

Clearance is the policy, audit and session gateway for AI agent workloads. Every tool call an agent makes passes
through it: Clearance checks the call against the agent's definition and its session's limits, records the decision as
evidence, spends the budget and only then calls the backend. A denial carries a stable rule id and a fix hint, so an
agent corrects itself against a deterministic gate instead of guessing.

It is a [Hangar](https://hangarplatform.dev) product. Autopilot, Hangar's agent runtime, is its native consumer, but
Clearance installs alone: the core knows nothing about Airframe, Glidepath or any other platform. Source and the full
module table: [github.com/jfillman/clearance](https://github.com/jfillman/clearance).

## Two boundaries

| Boundary | Question | State |
|---|---|---|
| **Runtime** | May this agent make this call, now, with this budget, and what happened? | Built: tiers and tripwires, path and field scope, narrow-only limits, CEL policy rules (R000 to R024), sessions and the run tree, the hash-chained evidence record, the gateway, the model proxy, the human inbox, PR provenance for the agent gates, person controls, definitions pinned from the cluster. |
| **Deployment** | May this change land in a protected environment, and can we prove it did so under policy? | Core built (v0.19.0, [the deployment gate](gate.md)): changes tiered 0 to 3 from the rendered diff, cleared by policy or by named people, a 7-day TTL, a new head supersedes, `deploy.*` records. Fed by Glidepath's `clearance-gate-` check (advisory on Hangar) and by `clearance register` (v0.23.0); answered to GitHub Actions deployments by the App's protection rule (v0.22.0). Not built: admission (the pulled grant and the Kyverno policy), `deploy.exception`, outcome records. |

## What is where

- **Definitions** (`profile.py`, `schemas/agent-definition.schema.json`, `definitions.py`): what an agent is. Bundled in
  the gateway's image, or pinned by an `Agent` XR to one commit of a file in the app's own repository
  ([clearance-api.md: definitions from the cluster](clearance-api.md#definitions-from-the-cluster-v0180)).
- **Policy** (`tiers.py`, `scope.py`, `limits.py`, `policy.py`, `pack.py`, `packs/hangar`): the rules, core plus a
  pack per platform. Anything that fails to evaluate denies.
- **Sessions and evidence** (`session.py`, `audit.py`, `pg.py`): budgets, the breaker, the run tree; one hash-chained
  record per decision in the clearance.evidence/v1 shape ([evidence.md](evidence.md)); Postgres as the one writer.
- **The gateway** (`dispatch.py`, `server.py`, `backends.py`, `modelproxy.py`): authenticate, decide, record, spend,
  call, record. The MCP surface for agents, the model proxy for their model calls, the human inbox, and the person
  controls (freeze, end, hold, release) through the delegate model, and run results (`results.py`).
- **The deployment gate** (`gate.py`, `review.py`, `register.py`): changes to protected environments, tiered and
  cleared; definition releases reviewed through the same gate.
- **The GitHub App** (`github_app.py`): check runs on PRs and the deployment protection rule.
- **The Go core** (`cmd/clearance`, `internal/`, `contract/clearance-core.json`): the decision service, the recorder
  and the gate in Go, one `clearance` binary. Built, not deployed: the live gateway runs the Python modules above
  until W1 ([core.md](core.md)).
- **The read API** (`api.py`, `contract/clearance-api.json`): clearance-api, a separate read-only process over the
  same tables: agents, sessions, evidence, counts, PR receipts, the inbox feed, the policy as data, the event history
  ([clearance-api.md](clearance-api.md)). Its Go port, `clearance api` (`internal/api`), is Built, not deployed:
  Clearance's own reads (evidence, receipts and verdicts, the gate, the policy and explainer, definitions); the
  runtime's reads move to the Autopilot gateway with R-3.

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

Tagged `vX.Y.Z` on `main`; each tag publishes a GitHub Release whose notes are its section of
[CHANGELOG.md](https://github.com/jfillman/clearance/blob/main/CHANGELOG.md). Autopilot pins the tag and ships the
gateway image. Recent: v0.23.0 `clearance register` and agent descriptions, v0.24.0 the Glidepath live and release
tools, v0.25.0 run results, v0.26.0 streaming through the model proxy, v0.26.1 the current release.
