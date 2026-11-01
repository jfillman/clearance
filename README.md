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
| Agent definitions | `profile.py`, `schemas/agent-definition.schema.json` | durable, schema-validated; baseline deny paths cannot be removed. From v0.23.0 each has a one-line `description`, and `runs_in` follows from the runtime: `cluster` with a runtime image, `client` without one (a person's MCP client is the agent; Clearance enforces the envelope, but not the model budget or instructions). Placeholder digests are refused |
| Sessions and the run tree | `session.py`, `dispatch.py` (`expire`) | budgets, expiry, the breaker, parent-reserved child budgets; `Gateway.expire()` closes sessions past their deadline and deletes their runs (and their children's), each deletion a record in the same commit, a failed one recorded and retried next sweep (Hangar D20) |
| Policy | `policy.py`, `pack.py` | CEL deny rules with ids, an explicit order and fix hints, core plus each pack's; anything that fails to evaluate denies (R000) |
| Audit | `audit.py` | one record per decision, hash-chained, in the draft evidence-record shape (schema version, boundary, coverage, each field tagged verified or claimed); detects an edited, deleted or reordered record, and truncation against an anchored checkpoint |
| Durable store | `pg.py` (extra `pg`) | Postgres for sessions and evidence on one connection: an operation's records and the sessions it changed commit together; one writer (advisory lock); the chain is verified from genesis on start, so an edited row stops Clearance; each record's assurance state is kept beside it (`recorded-not-checkpointed` until the ledger exists) |
| Artifacts | `pg.py` `PgArtifacts` | `artifact.put`/`artifact.get` on the same connection: text per task (a run tree shares it, nothing else sees it), 256 KiB each, 32 and 2 MiB per task, gone 7 days after the last write; a write commits with its call's evidence |
| Human inbox | `inbox.py`, `pg.py` `PgInbox`, `server.py` `/v1/human/*` | `human.request` asks a person and returns at once (non-blocking: whether to wait is the agent's choice); `human.request.get` (granted with it) reads the answer. The session's owner or a member of the definition's `owner` group (a Backstage group ref, resolved by the deployment's `Directory`) answers, signed in themselves or through a delegate (Gateway `delegates`, e.g. Tower's backend) naming them with `X-Hangar-On-Behalf-Of`: `GET /v1/human/requests`, `POST /v1/human/requests/{id}/answer`. One answer per request, recorded as `human.answer` (who, and through what); a request expires with its session; at most 5 pending per session |
| Read API | `api.py` (`create_api_app`, `contract/clearance-api.json`) | clearance-api ([docs/clearance-api.md](docs/clearance-api.md)): a separate read-only process over the gateway's tables, through its own read-only DSN (connections forced read-only, 5 s statement timeout, a small pool). Agents, sessions, run trees, evidence (filters, `seq` cursor, chain verify, counts by rule/tool/agent/app), PR receipts and gate verdicts, the inbox and its feed, the policy as data and a dry-run explainer (`Policy.trace`). Roles: person (own sessions, their teams' agents, records on apps they own), delegate, notifier, auditor. Every record now carries `app` when its call names one (`Pack.app_of`) |
| Gateway | `dispatch.py`, `backends.py` | authenticate, decide, audit, spend, call, audit. Handlers are registered per tool; the run tree goes through an injected run backend. A run backend that names the identity its runs authenticate as (`principal(session)`) lets a run act as its own session, and only that session; records still name the run |
| Model access | `modelproxy.py`, `server.py` (`create_model_app`) | model allowlist, network mode and token budget, decided by `Gateway.model_authorize` on the same store and chain as tool calls; `create_model_app` is the HTTP forwarder: Anthropic's Messages API, plain or streaming (v0.26.0: server-sent events relayed as they arrive, their usage charged when the stream ends; Claude Code and the Agent SDK always stream) for runs, which send their model-proxy token as `x-api-key` and their session in `x-hangar-session`; the provider key is read from a file per call, only the body is forwarded (with `model` rewritten to the route's) and, of the client's headers, `anthropic-beta` less OAuth's, and actual usage is charged back, weighted by what each kind of token costs (`USAGE_WEIGHTS`: a prompt-cache read is 0.1, a cache write 1.25, input and output 1), so a run that caches its resent conversation is charged for what it costs; an overrun trips the breaker |
| MCP surface | `server.py` | `tools_list` (with `session`: only the tools that session may call and this deployment runs), `agents_list`, `session_open`, `call` and `run_finish` (v0.25.0: an in-cluster run hands back its result as it exits; kept 30 days, `results.py`) on the mcp SDK v2, over stdio or streamable HTTP (`create_http_app`: bearer auth before any tool runs, the caller's own token per call, `GET /healthz`) |
| PR provenance | `provenance.py`, `server.py` (`POST /v1/provenance`) | each PR Clearance opens leaves a receipt in its hashed record (`effect`: repo, PR, the commit it made, the paths it carried); a CI gate posts a PR's head, changed paths, author and `Hangar-*` trailers and gets two verdicts: **identity** (confirmed; or AI001 trailers with no record, AI002 an agents' login with no record, AI003 commits added after the agent's, AI004 edited trailers) and **scope** (AS001 a path the agent's commit did not carry, AS002 a path the definition denies now, AS003 the repo left `repos.allow`, AS004 the definition is gone); a PR with none of that is `not-agent` and passes. Only principals matching the deployment's `verifiers` globs may ask; every verdict is a record |
| Deployment gate | `gate.py`, `dispatch.py` (`register_change`, `clear_change`, `deny_change`), `pg.py` `PgChanges`, `api.py` | the second boundary ([docs/gate.md](docs/gate.md)): a change to a protected environment, classified 0 to 3 from its rendered diff against a baseline a repo's `clearance.yaml` may only tighten; tiers 0 and 1 cleared by policy, 2 and 3 held for the owner group and an outside group (never the proposer, never twice); `deploy.*` records in the deployment boundary; 7-day TTL; a new head supersedes |
| GitHub App | `github_app.py`, `server.py` (`POST /v1/github/webhook`), `contract/github-app-manifest.json` | Clearance's own GitHub App ([docs/provenance-app.md](docs/provenance-app.md)): GitHub's PR webhooks, signature-checked; a one-repo read-only installation token; the same `provenance.verify`; check runs `Clearance / agent-identity` and `Clearance / agent-scope`; PR comments off by default. Phase 2a (v0.22.0): a custom deployment protection rule, answering a GitHub Actions deployment from the deployment gate's change (approved, rejected, or waiting on people) |
| `clearance register` | `register.py` (the `clearance` console script), `register/action.yml`, `auth.GitHubActionsAuthenticator` | Phase 2b: a customer's CI registers what it deploys with the deployment gate (the diff of two rendered manifest directories), authenticated by the workflow's GitHub Actions OIDC token, for its own repository only (`DG-REPO`) |
| Who is calling | `auth.py` | interim, until ID-JAG: service-account tokens by TokenReview for the `clearance` audience (principal `<namespace>/<name>`), people's OIDC ID tokens against the issuer's JWKS (RS256/ES256 only; principal `user:<email>`), and only the people its `allowed` globs name (a valid token from an issuer that federates GitHub is anyone with a GitHub account; empty allows nobody), routed by issuer and cached briefly (never past `exp`, never a failure). Another cluster's service accounts (`ForeignWorkloadAuthenticator`, e.g. Tower's backend on hangar-prod) are verified against that cluster's public issuer and named `<cluster>/<namespace>/<sa>`, only for the service accounts it allows |

## Packs

A pack is the policy for tools only some deployments have: tool specs, CEL rules placed among the core rules by an
explicit order, a function that adds what those rules read, and an optional hook for a rule that reports structured
problems. A pack holds policy only; what a tool does is a handler the deployment registers.

`clearance.packs.hangar` is the pack for Hangar: the `glidepath.*` and `airframe.*` tools, R021 (cicd.yaml field
scope, from Glidepath's contract vendored byte for byte in `packs/hangar/vendor/`), R022 and R023 (per-agent app
scope). `glidepath.cicd.propose` is a PR tool like `repo.pr.open` (budgeted, receipted for the agent gates); the
handler asks glidepath-api for the verdict on the change first. Nothing in the core imports the pack; `tests/test_boundary.py`
fails if anything does.

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

## Docs

The TechDocs site is `mkdocs.yml` over `docs/` (home, clearance-api, the deployment gate), published in Hangar's
portal from `catalog-info.yaml` (`backstage.io/techdocs-ref: dir:.`). Preview locally with `pip install
mkdocs-techdocs-core && mkdocs serve`.

## Specs

- [clearance-api](docs/clearance-api.md): the read API (sessions, evidence, agents, the inbox feed) as a separate read-only process. Phase 1 in v0.13.0; person controls (the write path) in v0.17.0; definitions pinned by `Agent` XRs in v0.18.0 (`definitions.py`); the deployment gate's core in v0.19.0 (`gate.py`, [docs/gate.md](docs/gate.md)); definition review and definition releases through the gate in v0.20.0 (`review.py`).
