# clearance-api: Clearance's read API (spec, draft 2026-10-30)

Status: **phase 1 built** (v0.13.0, `api.py`; policy, explain and counts in v0.14.0); open questions decided 2026-10-30. AP-B2 follow-on (Hangar roadmap M3). Owner decision 2026-10-30: build after Tower's Agent
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
| `GET /v1/evidence/counts` | records you may see counted by `by` (rule, tool, agent, app, decision), same filters as the list: the 7-day hits on the Policy page |
| `GET /v1/policy` | the policy in force: deny rules in evaluation order (id, name, CEL, message, hint, pack), the tool registry with tiers, the packs |
| `GET /v1/policy/explain` | "would this be allowed?": `agent`, `tool`, `args` (JSON); the real policy on a fresh session of that definition, the decision and every rule's verdict in order (the path). Records nothing, spends nothing |
| `GET /v1/receipts` | PR receipts (`repo`, `pr`): what Clearance's agents opened, the commit, the paths |
| `GET /v1/provenance` | the agent-gate verdicts recorded for a PR (`provenance.verify` records) |
| `GET /v1/human/requests` | the inbox: for a person, what they may answer (as today); for a `notifier`, every pending request with who may answer it (owner and group), `since` for "new since" |
| `GET /v1/events` | the trigger bridge's history (v0.15.0): every event it received, newest first, with what it did per agent (`launched`, `deduped`, `braked`, `refused`, `launch-failed`, with the session and run); filters `app`, `agent`, `source`, `key` (routing key), `subject` (the event's subject id, e.g. a PipelineRun name), `since`, `until`; cursor is `received_at`. Kept 30 days. The trigger dry run, an agent's trigger statistics and Tower's run marks read it |
| `GET /v1/contract` | the API contract (below) |
| `GET /healthz` | liveness; `GET /readyz` checks the database |

Later (phase 3): `GET /v1/stream`, server-sent events of new evidence records and inbox changes (the same shape as
glidepath-api's `/v1/events`), so Tower stops polling. (`/v1/events` is the trigger bridge's history, above.)

Never returned: tool arguments (only their digest is stored), artifact contents, tokens, model prompts.

## Person controls: the write path (v0.17.0)

Decided 2026-10-31: people write through the **delegate model**, the same one the human inbox uses. A person
calls the gateway with their own sign-in, or Tower's backend calls as itself and names them in
`X-Hangar-On-Behalf-Of`. Clearance decides who may act: the agent's owner group (the definition's `owner`, resolved
by the catalog directory), a platform admin (`CLEARANCE_ADMINS`, principal globs), and for a session, the person whose
session it is. Every control is an evidence record naming the person and the delegate. These are gateway routes
(`clearance.hangar-dev.local`), not clearance-api's: the read API never writes.

| Route | Does | Record |
|---|---|---|
| `POST /v1/sessions/{id}/freeze` `{reason}` | trips the session's breaker (and its children's): every further call is refused, the run stays for a person to read | `session.freeze` |
| `POST /v1/sessions/{id}/end` `{reason}` | closes the session and its children; the budget is settled; the run's pod ends with its AgentRun's TTL | `session.end` |
| `POST /v1/agents/{name}/hold` `{reason, hours}` | holds the agent's triggers: `open_triggered` refuses with **R024** until `until` (24 h by default, 336 at most; renewing replaces the hold) | `trigger.hold` |
| `DELETE /v1/agents/{name}/hold` | lifts a hold early | `trigger.release` |

A hold is an emergency brake, not a policy: anything meant to last ("turn this agent off", "weekdays only") is a
definition PR. `GET /v1/agents` and `/v1/agents/{name}` carry the active hold as `hold` (`by`, `via`, `reason`,
`since`, `until`), or `null`. Refusals carry a `rule` (`CT-FORBIDDEN` 403, `CT-UNKNOWN` 404, `CT-CLOSED` /
`CT-TRIPPED` 409, `CT-REASON` / `CT-HOURS` 400, `CT-NOHOLD` 404, `CT-OFF` 404 when the deployment keeps no holds).

Not yet: replay a past event, launch a run by hand, open the definition PRs (A3).

## Definitions from the cluster (v0.17.0)

Autopilot M4: an agent definition no longer has to ship in the gateway's image. An **`Agent` XR** (airframe
`xrds/agent.yaml`, in the app's `tenants/<app>/xr-requests/`) pins one commit of a definition file in the app's own
repository (`agents/<name>.yaml`). The gateway's loader (autopilot `agent_xrs.py`) lists the XRs, fetches each pinned
file through the agents' GitHub App (the broker allows an onboarded app's own repositories only), and hands the
documents to `definitions.py`, which decides whether a pin becomes a definition:

- the file passes the schema, its `name` is the XR's name, its `owner` is the XR's `spec.owner`, and a workload identity
  is `autopilot-runs/<name>`;
- the name is not a bundled platform definition's (the image's `agents/` keep their names; a pin can never replace one);
- one name, one pin (two XRs naming the same agent load neither).

The live set is `definitions.Definitions`, the Mapping the gateway and this API hold: bundled first, cluster second.
Every change is evidence, once per change and never per poll: `definition.load` (a new or re-pinned definition, result
`loaded <repo>@<commit> <path>` or `re-pinned …`), `definition.unload` (a pin removed), `definition.reject` (decision
`deny`, rule `DF-PIN`, the reason as result). The principal is `pin:<namespace>/<name>`. The gateway persists the set
(`clearance_definitions`) and this API refreshes from it, so it never fetches anything.

A running session resolves its definition by name on every call, so a re-pin to a **tighter** definition applies to
runs in flight (lowering authority is immediate); raising it is the reviewed pin.

`GET /v1/agents` carries, per agent, `source`: `{kind: bundled}` or `{kind: cluster, repo, path, commit, namespace, xr,
loaded_at, pin}`; and a top-level `rejected`: the pins Clearance could not load, each with `name`, `source` and
`reason`, so the team sees why. `GET /v1/agents/{name}` carries `source` too. Whether a pin loaded is **this** record,
never the XR's status: Clearance writes no XR status (its one Kubernetes write stays AgentRun).

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
session that made them, so another team's agent's work elsewhere stays theirs. The gateway records `app` on every
record whose call names an application (the pack's `app_of`: on Hangar `glidepath.*`, `airframe.*` and
`xr.request` by their `app` argument, `repo.*` by the repo, `<app>` or `gitops-<app>`; `argo.*` names an Argo CD
Application, not an app, so none yet). Records are hashed into the chain, so older ones cannot be backfilled: app
visibility starts with the release that records `app` (v0.13.0); the owner and team rules cover the rest. Tower's per-app tabs use it for an
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
3. **Event history** (v0.15.0, done): `/v1/events`, what the trigger bridge received and did, kept 30 days; Gateway.record_event writes it from the bridge (autopilot event_bridge.py). Not evidence: not in the chain.
4. **Stream:** `/v1/stream` (SSE); Tower subscribes instead of polling.

## Decided (2026-10-30)

- **App-scoped visibility:** yes, at the record level: an app owner sees records that target their app, not
  whole sessions of agents scoped to it (Who sees what, above).
- **Read replica:** not in v1. The API reads the primary through its own DSN (`CLEARANCE_API_DSN`, the
  `clearance_reader` role) with guardrails: `statement_timeout` 5 s, a pool of 5 connections per replica, page size
  at most 200, and indexes for the hot filters (`session`, `task_id`, `tool`, `ts`, `app`). Moving to a
  replica is configuration: CloudNativePG publishes `<cluster>-ro`; add one instance and point the DSN at it.
  Trigger: API p95 over 300 ms, or the gateway's write latency rising while Tower is busy (both on Prometheus).
