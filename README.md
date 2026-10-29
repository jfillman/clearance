# Clearance

Clearance is a policy, audit and session gateway for AI agent workloads. Every tool call an agent makes passes
through it: Clearance checks the call against the agent's definition and its session's limits, records the decision,
spends the budget and only then calls the backend. A denial carries a stable rule id and a fix hint, so an agent can
correct itself against a deterministic gate instead of guessing.

It is a Hangar product (https://hangarplatform.dev). Autopilot, Hangar's agent runtime, is its native consumer, but
Clearance installs alone: the core knows nothing about Airframe, Glidepath or any other platform.

## What it decides

| Piece | Where | What it does |
|---|---|---|
| Tool tiers and tripwires | `tiers.py` | T0 read, T1 reversible write, T2 propose only (a human merges); T3 names are tripwires that are denied, audited and trip the session's breaker |
| Path and repo scope | `scope.py` | traversal-safe path globs and repo allowlists; JSON-pointer field scope |
| Narrow-only limits | `limits.py` | requested limits, and a child run's limits, can only narrow what they inherit |
| Agent definitions | `profile.py`, `schemas/agent-definition.schema.json` | durable, schema-validated; baseline deny paths cannot be removed |
| Sessions and the run tree | `session.py` | budgets, expiry, the breaker, parent-reserved child budgets |
| Policy | `policy.py`, `pack.py` | CEL deny rules with ids, an explicit order and fix hints, core plus each pack's; anything that fails to evaluate denies (R000) |
| Audit | `audit.py` | one record per decision, hash-chained; detects an edited, deleted or reordered record, and truncation against an anchored checkpoint |
| Gateway | `dispatch.py`, `backends.py` | authenticate, decide, audit, spend, call, audit. Handlers are registered per tool; the run tree goes through an injected run backend |
| Model access | `modelproxy.py` | model allowlist, network mode and token budget (the decision only) |
| MCP surface | `server.py` | `tools_list`, `session_open` and `call` on the mcp SDK v2 |

## Packs

A pack is the policy for tools only some deployments have: tool specs, CEL rules placed among the core rules by an
explicit order, a function that adds what those rules read, and an optional hook for a rule that reports structured
problems. A pack holds policy only; what a tool does is a handler the deployment registers.

`clearance.packs.hangar` is the pack for Hangar: the `glidepath.*` and `airframe.*` tools, R021 (cicd.yaml field
scope, from Glidepath's contract vendored byte for byte in `packs/hangar/vendor/`), R022 and R023 (per-agent app
scope). Nothing in the core imports it; `tests/test_boundary.py` fails if anything does.

```python
from clearance.dispatch import Gateway
from clearance.backends import core_handlers
from clearance.packs.hangar import HANGAR

gw = Gateway(definitions, store, audit, auth, clock,
             packs=(HANGAR,), handlers={**core_handlers(git=..., read=...), **my_handlers}, runs=my_run_backend)
```

A Gateway with no packs is a complete Clearance for the core tools.

## Tests

```shell
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

No cluster is needed. The Glidepath contract drift test reads a glidepath checkout under `HANGAR_TECH` and skips
without one (CI clones it).

## History

This code was the `clearance` package inside https://github.com/jfillman/autopilot until 2026-10-29 (Hangar decision
D16); its history came with it. Design: Hangar's `docs/autopilot/design.md`, section 0.1.
