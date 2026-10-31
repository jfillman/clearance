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
| **Deployment** | May this change land in a protected environment, and can we prove it did so under policy? | Designed: [the deployment gate](gate.md). Grants bound to the reviewed tree, tiers 0 to 3 from the rendered diff, cleared by policy or by named people, soft at merge then hard at admission. |

## What is where

- **Definitions** (`profile.py`, `schemas/agent-definition.schema.json`, `definitions.py`): what an agent is. Bundled in
  the gateway's image, or pinned by an `Agent` XR to one commit of a file in the app's own repository
  ([clearance-api.md: definitions from the cluster](clearance-api.md#definitions-from-the-cluster-v0180)).
- **Policy** (`tiers.py`, `scope.py`, `limits.py`, `policy.py`, `pack.py`, `packs/hangar`): the rules, core plus a
  pack per platform. Anything that fails to evaluate denies.
- **Sessions and evidence** (`session.py`, `audit.py`, `pg.py`): budgets, the breaker, the run tree; one hash-chained
  record per decision; Postgres as the one writer.
- **The gateway** (`dispatch.py`, `server.py`, `backends.py`, `modelproxy.py`): authenticate, decide, record, spend,
  call, record. The MCP surface for agents, the model proxy for their model calls, the human inbox, and the person
  controls (freeze, end, hold, release) through the delegate model.
- **The read API** (`api.py`, `contract/clearance-api.json`): clearance-api, a separate read-only process over the
  same tables: agents, sessions, evidence, counts, PR receipts, the inbox feed, the policy as data, the event history
  ([clearance-api.md](clearance-api.md)).

## Where it shows up

In Hangar's portal: the **Clearance** pages (evidence, policy) and the **Autopilot** pages (runs, agents, new agent),
and in Tower's Agent and Clearance tabs per app. Design: the Hangar repo's `docs/autopilot/`.

## Releases

Tagged `vX.Y.Z`; Autopilot pins the tag and ships the gateway image. Recent: v0.15.0 event history, v0.16.0 the
glidepath.cicd tools, v0.17.0 person controls, v0.18.0 definitions pinned by `Agent` XRs.
