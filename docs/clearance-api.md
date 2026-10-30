# clearance-api: Clearance's read API (spec, draft 2026-10-30)

Status: **proposed**, open questions decided 2026-10-30. AP-B2 follow-on (Hangar roadmap M3). Owner decision 2026-10-30: build after Tower's Agent
requests; spec first.

## Why

Clearance today serves agents (MCP at `/mcp`) and two narrow routes (`POST /v1/provenance` for the agent gates,
`/v1/human/*` for the human inbox). Tower needs far more: sessions and runs, budgets, the evidence chain, receipts,
agent definitions, the inbox as a feed. Serving those reads from the gateway is wrong for two reasons:

1. **The gateway is single-writer.** Every gateway operation holds one lock (`SerializedGateway.lock`), and only
   one process may hold Postgres's writer lock (`pg.LOCK_KEY`). Reads from a busy Tower page would queue behind
   agents' tool calls, and the gateway cannot scale out.
2. **The people API has no feed.** Tower's notification poller asks once per catalog user per minute because there
   is no "what's new for anyone I can notify" call.

## Shape

- **Same package, separate process.** `clearance api` (a new entry point; on Hangar, `autopilot-gateway api`)
  serves HTTP only: no MCP, no tool handlers, no run backend, no model proxy.
- **Its own Deployment**, `clearance-api`, two or more replicas, behind its own Service and route
  (`clearance-api.<domain>`).
- **Read-only Postgres.** A CloudNativePG managed role `clearance_reader` with `SELECT` on the `clearance_*`
  tables and nothing else, via its own Secret. The API never takes the writer lock, never migrates, never
  writes. A gateway down (or restarting) does not take the API down.
- **Committed state only.** It reads what the gateway has committed (each gateway operation commits its evidence
  and sessions together), so it can lag the gateway by one in-flight operation, never show a half-written one.
- **Writes stay on the gateway.** Answering a human request (`POST /v1/human/requests/{id}/answer`) and any future
  operator write (close a session, trip or reset a breaker) go to the single writer, so the evidence chain has one
  author. The API documents the gateway URL for them.
- **Agent definitions** come from the same definitions directory the gateway loads (`CLEARANCE_AGENTS_DIR`, the
  same image), not from the database.

## Endpoints (v1, GET only)

All list endpoints are cursor-paginated (`limit`, max 200; `after`), newest first unless noted.

| Endpoint | Returns |
|---|---|
| `GET /v1/agents`, `/v1/agents/{name}` | definitions: kind, identity, owner, tier ceiling, tools, repos/apps scope, limits, triggers (never instructions' full text by default; `?full=1` for auditors) |
| `GET /v1/sessions` | sessions: `agent`, `principal`, `task`, `state` (`live`, `recent`, `closed`, `expired`), `since` filters; each with limits, budget used, breaker, run, parent, expiry |
| `GET /v1/sessions/{id}` | one session, with its children |
| `GET /v1/tasks/{task_id}` | the run tree: every session in the task, parent links, totals |
| `GET /v1/evidence` | records filtered by `task`, `session`, `agent`, `tool`, `principal`, `decision`, `rule`, `app`, `since`, `until`; cursor is `seq` |
| `GET /v1/evidence/{seq}` | one record, with its hash and assurance state |
| `GET /v1/evidence/verify` | the chain checked from genesis (or `from`/`to`): `ok`, `count`, `head`, first bad `seq` |
| `GET /v1/receipts` | PR receipts (`repo`, `pr`): what Clearance's agents opened, the commit, the paths |
| `GET /v1/provenance` | the agent-gate verdicts recorded for a PR (`provenance.verify` records) |
| `GET /v1/human/requests` | the inbox: for a person, what they may answer (as today); for a `notifier`, every pending request with who may answer it (owner and group), `since` for "new since" |
| `GET /v1/contract` | the API contract (below) |
| `GET /healthz` | liveness; `GET /readyz` checks the database |

Later (phase 3): `GET /v1/events`, server-sent events of new evidence records and inbox changes (the same shape as
glidepath-api's `/v1/events`), so Tower stops polling.

Never returned: tool arguments (only their digest is stored), artifact contents, tokens, model prompts.

## Who sees what

Callers authenticate exactly as at the gateway: service-account tokens (TokenReview), people's OIDC ID tokens, and
foreign workloads by public issuer (Tower). Roles are principal globs in config:

| Role | Config | May |
|---|---|---|
| person | any authenticated `user:*` | their own sessions and evidence; sessions and evidence of agents whose `owner` group they are in (the deployment's Directory, as the inbox uses); evidence records that target an app they own (below); the inbox as today |
| `delegate` | `CLEARANCE_DELEGATES` (Tower) | everything a person may, for the person named in `X-Hangar-On-Behalf-Of` |
| `notifier` | `CLEARANCE_API_NOTIFIERS` (Tower) | the inbox feed across everyone (for notifications), nothing else |
| `auditor` | `CLEARANCE_API_AUDITORS` | every read, including definitions' full instructions and the chain check |

A record's visibility is decided by its session's owner and agent, so a person never sees another team's agents'
sessions through a filter.

**App owners see what agents did to their app** (decided 2026-10-30). A person who owns an app in the catalog (the
Component's `spec.owner`, directly or through a group) sees every evidence record whose target is that app: its
repos (`<app>`, `gitops-<app>`), its Argo CD Applications, its Glidepath app. Records only, not the rest of the
session that made them, so another team's agent's work elsewhere stays theirs. The gateway records `effect.app` on
every record whose target maps to an app (`repo.*` by repo name, `argo.*` by the Application's app, `glidepath.*`
by its `app` argument), indexed; older records are backfilled from `target`. Tower's per-app tabs use it for an
"Agent activity" view (`GET /v1/evidence?app=<app>`). Reads are not themselves recorded as evidence (they change nothing); they are logged
and counted.

## The contract

`contract/clearance-api.json`, generated from the route table (`tools/gen_api_contract.py`, with a `--check` CI
step, as glidepath does): every operation's method, path, parameters, roles and response schema. Tower's backend
vendors it with a drift test, as Clearance vendors `glidepath-contract.json`. `/v1` changes are additive only; a
breaking change is `/v2`.

## Hangar deployment (apron `55-autopilot/clearance`)

- `api.yaml`: the `clearance-api` Deployment (same image, `api` command, read-only root fs, no projected tokens
  except the catalog one for the Directory), Service, PodDisruptionBudget.
- `postgres.yaml`: the `clearance_reader` managed role and its Secret.
- NetworkPolicy: ingress to `clearance-api` from the Gateway namespace; egress to Postgres and the catalog.
- HTTPRoute `clearance-api.<domain>`. `clearance.<domain>/v1/human/` stays on the gateway for the answer POST.

## Phases

1. **Read API v1:** agents, sessions, tasks, evidence (with verify), the inbox feed, the contract; deployed;
   Tower's Agent requests poller switches to the feed (one call per minute, not one per user).
2. **Tower's Clearance plugin:** sessions and run trees, an evidence explorer, agent definitions, gate verdicts on
   a PR, on the API.
3. **Events:** `/v1/events` (SSE); Tower subscribes instead of polling.

## Decided (2026-10-30)

- **App-scoped visibility:** yes, at the record level: an app owner sees records that target their app, not
  whole sessions of agents scoped to it (Who sees what, above).
- **Read replica:** not in v1. The API reads the primary through its own DSN (`CLEARANCE_API_DSN`, the
  `clearance_reader` role) with guardrails: `statement_timeout` 5 s, a pool of 5 connections per replica, page size
  at most 200, and indexes for the hot filters (`session`, `task_id`, `tool`, `ts`, `effect.app`). Moving to a
  replica is configuration: CloudNativePG publishes `<cluster>-ro`; add one instance and point the DSN at it.
  Trigger: API p95 over 300 ms, or the gateway's write latency rising while Tower is busy (both on Prometheus).
