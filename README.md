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
| Path and repo scope | `scope.py` | traversal-safe path globs and repo allowlists (for every tool that writes files or reads a repo: `repo.pr.open*`, `repo.file.get`); JSON-pointer field scope |
| Narrow-only limits | `limits.py` | requested limits, and a child run's limits, can only narrow what they inherit |
| Agent definitions | `profile.py`, `schemas/agent-definition.schema.json` | durable, schema-validated; baseline deny paths cannot be removed |
| Sessions and the run tree | `session.py`, `dispatch.py` (`expire`) | budgets, expiry, the breaker, parent-reserved child budgets; `Gateway.expire()` closes sessions past their deadline and deletes their runs (and their children's), each deletion a record in the same commit, a failed one recorded and retried next sweep (Hangar D20) |
| Policy | `policy.py`, `pack.py` | CEL deny rules with ids, an explicit order and fix hints, core plus each pack's; anything that fails to evaluate denies (R000) |
| Audit | `audit.py` | one record per decision, hash-chained, in the draft evidence-record shape (schema version, boundary, coverage, each field tagged verified or claimed); detects an edited, deleted or reordered record, and truncation against an anchored checkpoint |
| Durable store | `pg.py` (extra `pg`) | Postgres for sessions and evidence on one connection: an operation's records and the sessions it changed commit together; one writer (advisory lock); the chain is verified from genesis on start, so an edited row stops Clearance; each record's assurance state is kept beside it (`recorded-not-checkpointed` until the ledger exists) |
| Gateway | `dispatch.py`, `backends.py` | authenticate, decide, audit, spend, call, audit. Handlers are registered per tool; the run tree goes through an injected run backend. A run backend that names the identity its runs authenticate as (`principal(session)`) lets a run act as its own session, and only that session; records still name the run |
| Model access | `modelproxy.py`, `server.py` (`create_model_app`) | model allowlist, network mode and token budget, decided by `Gateway.model_authorize` on the same store and chain as tool calls; `create_model_app` is the HTTP forwarder: Anthropic's Messages API (non-streaming) for runs, which send their model-proxy token as `x-api-key` and their session in `x-hangar-session`; the provider key is read from a file per call, only the body is forwarded (with `model` rewritten to the route's), and actual usage is charged back (an overrun trips the breaker) |
| MCP surface | `server.py` | `tools_list`, `session_open` and `call` on the mcp SDK v2, over stdio or streamable HTTP (`create_http_app`: bearer auth before any tool runs, the caller's own token per call, `GET /healthz`) |
| Who is calling | `auth.py` | interim, until ID-JAG: service-account tokens by TokenReview for the `clearance` audience (principal `<namespace>/<name>`), people's OIDC ID tokens against the issuer's JWKS (RS256/ES256 only; principal `user:<email>`), routed by issuer and cached briefly (never past `exp`, never a failure) |

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

No cluster is needed. `tests/test_pg.py` needs a scratch Postgres in `CLEARANCE_TEST_DSN` (CI runs one) and skips without it. The Glidepath contract drift test reads a glidepath checkout under `HANGAR_TECH` and skips
without one (CI clones it).

## History

This code was the `clearance` package inside https://github.com/jfillman/autopilot until 2026-10-29 (Hangar decision
D16); its history came with it. Design: Hangar's `docs/autopilot/design.md`, section 0.1.
