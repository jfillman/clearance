"""clearance-api: Clearance's read API (docs/clearance-api.md), a separate, read-only process.

It reads what the gateway committed to Postgres (sessions, evidence, the human inbox), with its own read-only role
and DSN, never the gateway's writer lock, so reads never queue behind agents' tool calls and the API can run as
many replicas as it needs. It writes nothing: answering a human request stays on the gateway (the single writer of
the evidence chain).

Who sees what (`Viewer`):
  auditor    every read (CLEARANCE_API_AUDITORS)
  person     their own sessions; sessions of agents whose definition `owner` group they are in (Directory); and,
             for evidence, records that act on an app they own (`app`, Ownership); the human inbox as at the gateway
  delegate   everything the person named in X-Hangar-On-Behalf-Of may (CLEARANCE_DELEGATES, e.g. Tower)
  notifier   the human-inbox feed across everyone, nothing else (CLEARANCE_API_NOTIFIERS, e.g. Tower's poller)

ROUTES is the route table and the contract (`contract()`, contract/clearance-api.json, checked by a test): one
entry per operation, with its parameters and the roles that may call it.
"""
from __future__ import annotations

import json
import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence

from . import provenance
from .audit import GENESIS, canonical, sha256_hex
from .dispatch import AuthError, Authenticator
from .policy import RULES
from .session import Session
from .tiers import Tier

API_VERSION = "v1"
MAX_LIMIT = 200
DEFAULT_LIMIT = 50
STATEMENT_TIMEOUT_MS = 5000

PERSON_ROLES = ("person", "delegate", "auditor")
ROUTES: tuple[dict[str, Any], ...] = (
    {"operationId": "listAgents", "method": "GET", "path": "/v1/agents", "roles": PERSON_ROLES, "params": ["full"],
     "summary": "Agent definitions: kind, identity, owner, tier ceiling, tools, scope, limits, triggers"},
    {"operationId": "getAgent", "method": "GET", "path": "/v1/agents/{name}", "roles": PERSON_ROLES, "params": ["full"],
     "summary": "One agent definition"},
    {"operationId": "listSessions", "method": "GET", "path": "/v1/sessions", "roles": PERSON_ROLES,
     "params": ["agent", "principal", "task", "state", "limit", "after"],
     "summary": "Sessions you may see, newest first: limits, budget used, breaker, run, parent, expiry; state is live, closed or expired"},
    {"operationId": "getSession", "method": "GET", "path": "/v1/sessions/{id}", "roles": PERSON_ROLES, "params": [],
     "summary": "One session"},
    {"operationId": "getTask", "method": "GET", "path": "/v1/tasks/{task_id}", "roles": PERSON_ROLES, "params": [],
     "summary": "A run tree: every session of the task, with parent links and totals"},
    {"operationId": "listEvidence", "method": "GET", "path": "/v1/evidence", "roles": PERSON_ROLES,
     "params": ["task", "session", "agent", "tool", "principal", "decision", "rule", "app", "since", "until", "limit", "after"],
     "summary": "Evidence records you may see, newest first; the cursor is seq"},
    {"operationId": "getEvidence", "method": "GET", "path": "/v1/evidence/{seq}", "roles": PERSON_ROLES, "params": [],
     "summary": "One evidence record with its hash"},
    {"operationId": "verifyEvidence", "method": "GET", "path": "/v1/evidence/verify", "roles": ("auditor",), "params": [],
     "summary": "The whole chain checked from genesis: ok, count, head, the first bad seq"},
    {"operationId": "countEvidence", "method": "GET", "path": "/v1/evidence/counts", "roles": PERSON_ROLES,
     "params": ["by", "decision", "agent", "tool", "app", "since", "until"],
     "summary": "Records you may see, counted by rule, tool, agent, app or decision (`by`), with the same filters as the list"},
    {"operationId": "getPolicy", "method": "GET", "path": "/v1/policy", "roles": PERSON_ROLES, "params": [],
     "summary": "The policy in force: the deny rules in evaluation order (id, name, CEL expression, message, hint, pack), the tool registry with tiers, the packs"},
    {"operationId": "explainPolicy", "method": "GET", "path": "/v1/policy/explain", "roles": PERSON_ROLES,
     "params": ["agent", "tool", "args"],
     "summary": "Would this be allowed? A dry run of the real policy for an agent, a tool and its args (JSON) on a fresh session: the decision and each rule's verdict in order. Records nothing"},
    {"operationId": "listReceipts", "method": "GET", "path": "/v1/receipts", "roles": PERSON_ROLES, "params": ["repo", "pr"],
     "summary": "PR receipts: what Clearance's agents opened on a repo (and PR), the commit, the paths"},
    {"operationId": "listProvenance", "method": "GET", "path": "/v1/provenance", "roles": PERSON_ROLES, "params": ["repo", "pr"],
     "summary": "The agent-gate verdicts recorded for a PR (provenance.verify)"},
    {"operationId": "listHumanRequests", "method": "GET", "path": "/v1/human/requests", "roles": ("person", "delegate", "notifier", "auditor"),
     "params": ["since"],
     "summary": "Pending human requests: a person's, those they may answer; a notifier's, every pending one (with owner and group), created since `since`"},
    {"operationId": "listEvents", "method": "GET", "path": "/v1/events", "roles": PERSON_ROLES,
     "params": ["app", "agent", "source", "key", "subject", "since", "until", "limit", "after"],
     "summary": "The events the trigger bridge received, newest first, each with what it did per agent (launched, deduped, braked, refused): the history a trigger dry run, an agent's trigger statistics and an app's run marks read. Kept 30 days; the cursor is received_at"},
    {"operationId": "getContract", "method": "GET", "path": "/v1/contract", "roles": ("any",), "params": [],
     "summary": "This contract"},
)


def contract() -> dict[str, Any]:
    return {"api": "clearance-api", "version": API_VERSION,
            "notes": "GET only. Writes (POST /v1/human/requests/{id}/answer) go to the gateway.",
            "operations": [dict(r, roles=list(r["roles"])) for r in ROUTES]}


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message
        super().__init__(message)


class Directory(Protocol):
    def groups(self, principal: str) -> set[str]: ...


class Ownership(Protocol):
    """The apps a person owns (directly or through a group), for app-scoped evidence."""
    def apps(self, principal: str) -> set[str]: ...


@dataclass(frozen=True)
class Viewer:
    role: str                         # auditor | person | notifier
    person: str | None = None         # user:<login> for a person or a delegate's person
    via: str | None = None            # the delegate, when a delegate asked
    agents: frozenset[str] = field(default_factory=frozenset)   # agents of the person's teams
    apps: frozenset[str] = field(default_factory=frozenset)     # apps the person owns

    @property
    def all(self) -> bool:
        return self.role == "auditor"


def _any(principal: str, globs: Sequence[str]) -> bool:
    return any(fnmatchcase(principal, g) for g in globs)


@dataclass
class Access:
    auth: Authenticator
    definitions: Mapping[str, Any]
    delegates: Sequence[str] = ()
    notifiers: Sequence[str] = ()
    auditors: Sequence[str] = ()
    directory: Directory | None = None
    ownership: Ownership | None = None

    def viewer(self, token: str | None, on_behalf_of: str | None) -> Viewer:
        if not token:
            raise ApiError(401, "a bearer token is required")
        try:
            principal = self.auth.authenticate(token)
        except AuthError:
            raise ApiError(401, "token not accepted") from None
        if on_behalf_of:
            if not _any(principal.id, self.delegates):
                raise ApiError(403, f"{principal.id} may not act for a person")
            if not on_behalf_of.startswith("user:") or len(on_behalf_of) > 200:
                raise ApiError(400, "X-Hangar-On-Behalf-Of must name a person (user:<name>)")
            return self._person(on_behalf_of, via=principal.id)
        if _any(principal.id, self.auditors):
            return Viewer("auditor", person=principal.id)
        if _any(principal.id, self.notifiers):
            return Viewer("notifier")
        if principal.kind == "user":
            return self._person(principal.id)
        raise ApiError(403, f"{principal.id} is not a person, delegate, notifier or auditor")

    def _person(self, person: str, via: str | None = None) -> Viewer:
        groups = self.directory.groups(person) if self.directory else set()
        agents = frozenset(n for n, d in self.definitions.items() if getattr(d, "owner", None) in groups)
        apps = frozenset(a.lower() for a in (self.ownership.apps(person) if self.ownership else set()))
        return Viewer("person", person=person, via=via, agents=agents, apps=apps)


# -- the store -------------------------------------------------------------------------------------------------------

class ReadStore(Protocol):
    def sessions(self, f: dict[str, Any], v: Viewer, limit: int, after: str | None) -> list[dict[str, Any]]: ...
    def session(self, sid: str) -> dict[str, Any] | None: ...
    def task(self, task_id: str) -> list[dict[str, Any]]: ...
    def evidence(self, f: dict[str, Any], v: Viewer, limit: int, after: int | None) -> list[dict[str, Any]]: ...
    def evidence_one(self, seq: int, v: Viewer) -> dict[str, Any] | None: ...
    def by_pr(self, tools: Sequence[str], repo: str, pr: str | None, v: Viewer) -> list[dict[str, Any]]: ...
    def counts(self, f: dict[str, Any], v: Viewer, by: str) -> list[dict[str, Any]]: ...
    def chain(self, batch: int) -> Iterable[list[dict[str, Any]]]: ...
    def human_pending(self, now: datetime, since: datetime | None) -> list[dict[str, Any]]: ...
    def events(self, f: dict[str, Any], v: Viewer, limit: int, after: str | None) -> list[dict[str, Any]]: ...
    def holds(self, now: datetime) -> dict[str, dict[str, Any]]: ...
    def definitions(self) -> list[dict[str, Any]]: ...
    def ping(self) -> None: ...


class Pool:
    """A few read-only connections, opened lazily and replaced when one fails. Every connection is read only and
    bounded by a statement timeout, server-side, whatever the role allows."""

    def __init__(self, dsn: str, size: int = 5, connect: Callable[..., Any] | None = None):
        import psycopg
        self.dsn, self.size, self._connect = dsn, size, connect or psycopg.connect
        self._free: "queue.Queue[Any]" = queue.Queue()
        self._made, self._lock = 0, threading.Lock()

    def _new(self):
        return self._connect(self.dsn, autocommit=True,
                             options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS} -c default_transaction_read_only=on")

    def run(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]:
        try:
            conn = self._free.get_nowait()
        except queue.Empty:
            with self._lock:
                grow = self._made < self.size
                if grow:
                    self._made += 1
            conn = self._new() if grow else self._free.get(timeout=10)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall() if cur.description else []
            self._free.put(conn)
            return rows
        except Exception:
            try:
                conn.close()
            finally:
                with self._lock:
                    self._made -= 1
            raise


def _session_view(r: dict[str, Any], now: datetime) -> dict[str, Any]:
    state = "closed" if r.get("closed") else ("expired" if datetime.fromisoformat(r["expires_at"]) <= now else "live")
    return {**r, "state": state}


class PgReadStore:
    """ReadStore on the gateway's tables (pg.py SCHEMA). Every query is scoped by the viewer in SQL."""

    def __init__(self, pool: Pool, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.pool, self.now = pool, clock

    @staticmethod
    def _session_scope(v: Viewer, alias: str = "s") -> tuple[str, list[Any]]:
        if v.all:
            return "TRUE", []
        return (f"({alias}.record->>'principal' = %s OR {alias}.record->>'agent' = ANY(%s))", [v.person, list(v.agents)])

    def sessions(self, f, v, limit, after):
        where, params = [], []
        scope, sp = self._session_scope(v)
        where.append(scope); params += sp
        for key, col in (("agent", "agent"), ("principal", "principal"), ("task", "task_id")):
            if f.get(key):
                where.append(f"s.record->>'{col}' = %s"); params.append(f[key])
        state, now = f.get("state"), self.now()
        if state == "live":
            where.append("NOT s.closed AND s.expires_at > %s"); params.append(now)
        elif state == "closed":
            where.append("s.closed")
        elif state == "expired":
            where.append("NOT s.closed AND s.expires_at <= %s"); params.append(now)
        if after:
            where.append("s.record->>'created_at' < %s"); params.append(after)
        rows = self.pool.run("SELECT s.record FROM clearance_sessions s WHERE " + " AND ".join(where)
                             + " ORDER BY s.record->>'created_at' DESC LIMIT %s", params + [limit])
        return [_session_view(r[0], now) for r in rows]

    def session(self, sid):
        rows = self.pool.run("SELECT record FROM clearance_sessions WHERE id = %s", [sid])
        return _session_view(rows[0][0], self.now()) if rows else None

    def task(self, task_id):
        now = self.now()
        rows = self.pool.run("SELECT record FROM clearance_sessions WHERE record->>'task_id' = %s "
                             "ORDER BY record->>'created_at'", [task_id])
        return [_session_view(r[0], now) for r in rows]

    def _evidence_scope(self, v: Viewer) -> tuple[str, list[Any]]:
        if v.all:
            return "TRUE", []
        return ("(s.record->>'principal' = %s OR e.record->>'agent' = ANY(%s) OR e.record->>'app' = ANY(%s) "
                "OR (e.record->>'session' IS NULL AND e.record->>'principal' = %s))",
                [v.person, list(v.agents), list(v.apps), v.person])

    def evidence(self, f, v, limit, after):
        where, params = [], []
        scope, sp = self._evidence_scope(v)
        where.append(scope); params += sp
        for key, col in (("task", "task_id"), ("session", "session"), ("agent", "agent"), ("tool", "tool"),
                         ("principal", "principal"), ("decision", "decision"), ("rule", "rule"), ("app", "app")):
            if f.get(key):
                where.append(f"e.record->>'{col}' = %s"); params.append(f[key])
        if f.get("since"):
            where.append("e.record->>'ts' >= %s"); params.append(f["since"])
        if f.get("until"):
            where.append("e.record->>'ts' < %s"); params.append(f["until"])
        if after is not None:
            where.append("e.seq < %s"); params.append(after)
        rows = self.pool.run("SELECT e.record, e.assurance FROM clearance_evidence e LEFT JOIN clearance_sessions s "
                             "ON s.id = e.record->>'session' WHERE " + " AND ".join(where)
                             + " ORDER BY e.seq DESC LIMIT %s", params + [limit])
        return [{**r[0], "assurance": r[1]} for r in rows]

    def evidence_one(self, seq, v):
        scope, sp = self._evidence_scope(v)
        rows = self.pool.run("SELECT e.record, e.assurance FROM clearance_evidence e LEFT JOIN clearance_sessions s "
                             "ON s.id = e.record->>'session' WHERE e.seq = %s AND " + scope, [seq] + sp)
        return {**rows[0][0], "assurance": rows[0][1]} if rows else None

    def counts(self, f, v, by):
        where, params = [], []
        scope, sp = self._evidence_scope(v)
        where.append(scope); params += sp
        for key in ("decision", "agent", "tool", "app"):
            if f.get(key):
                where.append(f"e.record->>'{key}' = %s"); params.append(f[key])
        if f.get("since"):
            where.append("e.record->>'ts' >= %s"); params.append(f["since"])
        if f.get("until"):
            where.append("e.record->>'ts' < %s"); params.append(f["until"])
        rows = self.pool.run(f"SELECT e.record->>'{by}', count(*) FROM clearance_evidence e LEFT JOIN clearance_sessions s "
                             "ON s.id = e.record->>'session' WHERE " + " AND ".join(where)
                             + f" GROUP BY e.record->>'{by}' ORDER BY count(*) DESC, 1 LIMIT %s", params + [MAX_LIMIT])
        return [{"key": r[0], "count": r[1]} for r in rows]

    def by_pr(self, tools, repo, pr, v):
        """Receipts (effect.repo/pr, the clearance_evidence_receipt index) and verdicts (target repo#pr) for a PR."""
        scope, sp = self._evidence_scope(v)
        match = "(e.record->'effect'->>'repo' = %s" + (" AND e.record->'effect'->>'pr' = %s" if pr else "") + ")"
        mp: list[Any] = [repo] + ([pr] if pr else [])
        match += " OR " + ("e.record->>'target' = %s" if pr else "e.record->>'target' LIKE %s")
        mp.append(f"{repo}#{pr}" if pr else f"{repo}#%")
        rows = self.pool.run("SELECT e.record, e.assurance FROM clearance_evidence e LEFT JOIN clearance_sessions s "
                             "ON s.id = e.record->>'session' WHERE e.record->>'tool' = ANY(%s) AND (" + match + ") AND "
                             + scope + " ORDER BY e.seq DESC LIMIT %s", [list(tools)] + mp + sp + [MAX_LIMIT])
        return [{**r[0], "assurance": r[1]} for r in rows]

    def chain(self, batch=1000):
        after = -1
        while True:
            rows = self.pool.run("SELECT record FROM clearance_evidence WHERE seq > %s ORDER BY seq LIMIT %s", [after, batch])
            if not rows:
                return
            recs = [r[0] for r in rows]
            yield recs
            after = recs[-1]["seq"]

    def human_pending(self, now, since):
        sql, params = ("SELECT record FROM clearance_human_requests WHERE status = 'pending' AND expires_at > %s", [now])
        if since:
            sql += " AND record->>'created_at' > %s"; params.append(since.isoformat())
        return [r[0] for r in self.pool.run(sql + " ORDER BY record->>'created_at'", params)]

    def events(self, f, v, limit, after):
        """clearance_events (pg.py PgEvents): an app's events to its owners, an agent's to its team, all to an auditor."""
        where, params = [], []
        if not v.all:
            where.append("(e.app = ANY(%s) OR EXISTS (SELECT 1 FROM jsonb_array_elements(e.record->'outcomes') o "
                         "WHERE o->>'agent' = ANY(%s)))")
            params += [list(v.apps), list(v.agents)]
        for key, col in (("app", "e.app"), ("source", "e.source"), ("key", "e.routing_key"),
                         ("subject", "e.record->'subject'->>'id'")):
            if f.get(key):
                where.append(f"{col} = %s"); params.append(f[key])
        if f.get("agent"):
            where.append("EXISTS (SELECT 1 FROM jsonb_array_elements(e.record->'outcomes') o WHERE o->>'agent' = %s)")
            params.append(f["agent"])
        if f.get("since"):
            where.append("e.received_at >= %s"); params.append(f["since"])
        if f.get("until"):
            where.append("e.received_at < %s"); params.append(f["until"])
        if after:
            where.append("e.received_at < %s"); params.append(after)
        sql = "SELECT e.record FROM clearance_events e" + (" WHERE " + " AND ".join(where) if where else "")
        rows = self.pool.run(sql + " ORDER BY e.received_at DESC LIMIT %s", params + [limit])
        return [r[0] for r in rows]

    def holds(self, now):
        """The active holds on agents' triggers (pg.py PgHolds), by agent."""
        rows = self.pool.run("SELECT record FROM clearance_holds WHERE until > %s", [now])
        return {r[0]["agent"]: r[0] for r in rows}

    def definitions(self):
        """The cluster-pinned definitions the gateway loaded (pg.py PgDefinitions): rows for definitions.Definitions.apply_records."""
        rows = self.pool.run("SELECT record FROM clearance_definitions ORDER BY state, name")
        return [r[0] for r in rows]

    def ping(self):
        self.pool.run("SELECT 1")


def verify_chain(batches: Iterable[list[dict[str, Any]]]) -> dict[str, Any]:
    """audit.verify, streamed: the whole chain from genesis, a batch at a time."""
    prev, count = GENESIS, 0
    for recs in batches:
        for r in recs:
            body = {k: val for k, val in r.items() if k != "hash"}
            if r.get("seq") != count or r.get("prev_hash") != prev or sha256_hex(canonical(body)) != r.get("hash"):
                return {"ok": False, "count": count, "head": prev, "bad_seq": r.get("seq")}
            prev, count = r["hash"], count + 1
    return {"ok": True, "count": count, "head": prev, "bad_seq": None}


# -- the HTTP app -------------------------------------------------------------------------------------------------

def _definition_view(d: Any, full: bool, hold: dict[str, Any] | None = None,
                     source: Any = None) -> dict[str, Any]:
    lim = d.limits.as_dict()
    out = {"name": d.name, "kind": d.kind, "owner": getattr(d, "owner", None),
           "identity": {"type": d.identity_type, "serviceAccount": d.service_account},
           "tierCeiling": lim["tier_ceiling"], "tools": lim["tools"], "models": lim["models"],
           "limits": {k: lim[k] for k in ("ttl_minutes", "tool_calls", "github_calls", "open_prs", "model_tokens", "children")},
           "network": lim["network"], "compute": lim["compute"], "repos": {"allow": list(d.repos_allow)},
           "triggers": list(d.triggers), "runtime": {"framework": d.framework, "sandbox": d.sandbox, "image": d.image},
           "scopes": {k: v for k, v in (d.raw_profile or {}).items() if k in ("glidepath", "airframe")},
           # The active hold on its triggers (control.py), or None: by, via, reason, since, until.
           "hold": hold,
           # Where the definition came from (definitions.py): {kind: bundled} or {kind: cluster, repo, path, commit,
           # namespace, xr, loaded_at, pin}. None when the deployment's definitions are a plain directory.
           "source": source.view() if source is not None else None}
    if full:
        out["instructions"] = d.instructions
    return out


def _limit(q: Mapping[str, str]) -> int:
    try:
        n = int(q.get("limit") or DEFAULT_LIMIT)
    except ValueError:
        raise ApiError(400, "limit must be a number") from None
    return max(1, min(n, MAX_LIMIT))


COUNT_BY = ("rule", "tool", "agent", "app", "decision")
MAX_EXPLAIN_ARGS = 16 << 10


def policy_view(policy: Any) -> dict[str, Any]:
    """The policy as data: rules in evaluation order with their pack, the tool registry with tiers, the packs."""
    core_ids = {r.id for r in RULES}
    pack_of = {}
    for p in policy.packs:
        for r in p.rules:
            pack_of[r.id] = p.name
    return {
        "rules": [{"id": r.id, "name": r.name, "expression": r.expr, "message": r.message, "hint": r.hint,
                   "order": r.order, "pack": "core" if r.id in core_ids else pack_of.get(r.id, "unknown")}
                  for r in policy.rules],
        "tools": [{"name": s.name, "tier": s.tier.name, "summary": s.description, "required_args": list(s.required_args),
                   "target": s.target, "propose_only": s.propose_only, "writes_files": s.writes_files,
                   "github_cost": s.github_cost} for s in sorted(policy.tools.values(), key=lambda s: (int(s.tier), s.name))],
        "packs": ["core", *(p.name for p in policy.packs)],
    }


def explain(policy: Any, definition: Any, person: str, tool: str, args: dict[str, Any], now: datetime) -> dict[str, Any]:
    """A dry run: the real policy on a fresh session of `definition` for `person`, nothing recorded, nothing spent."""
    from datetime import timedelta
    session = Session(id="s-dry-run", principal=person, agent=definition.name, limits=definition.limits,
                      created_at=now, expires_at=now + timedelta(minutes=definition.limits.ttl_minutes), task_id="t-dry-run")
    ctx = policy.build_context(session, person, Tier.T1, tool, args, list(definition.deny_paths), list(definition.repos_allow),
                               now, api_allow=list(definition.api_allow), agent_kind=definition.kind,
                               field_deny=list(definition.field_deny), field_allow=list(definition.field_allow),
                               definition=definition)
    decision = policy.evaluate(ctx)
    path = policy.trace(ctx)
    first = next((i for i, r in enumerate(path) if r["matched"] or r["error"]), None)
    return {"agent": definition.name, "tool": tool, "known_tool": tool in policy.tools, "decision": decision.as_dict(),
            "path": path if first is None else path[: first + 1], "all_rules": path, "dry_run": True}


def create_api_app(store: ReadStore, access: Access, *, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                   gateway_url: str | None = None, policy: Any = None):
    """The Starlette app for `clearance api`. `policy` (a clearance.policy.Policy with the deployment's packs) serves
    /v1/policy and the dry-run explainer; without it those answer 404."""
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    import anyio

    allowed = {r["operationId"]: set(r["roles"]) for r in ROUTES}

    def viewer_for(request: Request, op: str) -> Viewer:
        auth = request.headers.get("authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
        v = access.viewer(token, request.headers.get("x-hangar-on-behalf-of") or None)
        role = "delegate" if v.via else v.role
        if role not in allowed[op] and not (role == "auditor" and "person" in allowed[op]):
            raise ApiError(403, f"a {role} may not call {op}")
        return v

    def endpoint(op: str, fn: Callable[[Request, Viewer], Any]):
        async def handle(request: Request) -> JSONResponse:
            try:
                v = viewer_for(request, op)
                out = await anyio.to_thread.run_sync(fn, request, v)
                return JSONResponse(out)
            except ApiError as e:
                return JSONResponse({"error": e.message}, status_code=e.status)
            except Exception as e:  # noqa: BLE001 - a database failure is the API's, never a leak of internals
                return JSONResponse({"error": f"read failed: {type(e).__name__}"}, status_code=503)
        return handle

    def page(items: list[dict[str, Any]], limit: int, cursor_key: str) -> dict[str, Any]:
        nxt = items[-1][cursor_key] if len(items) == limit and items else None
        return {"items": items, "next": nxt}

    def source_of(name):
        src = getattr(access.definitions, "source", None)
        return src(name) if src else None

    def list_agents(req, v):
        full = v.all and req.query_params.get("full") == "1"
        holds = store.holds(clock())
        # `rejected`: pins (Agent XRs) Clearance could not load, with the reason, for the teams that own them (and
        # everyone: a rejected pin names no instructions, only where it points and why it failed).
        rejected = [r.view() for r in getattr(access.definitions, "rejected", ())]
        return {"items": [_definition_view(d, full, holds.get(n), source_of(n)) for n, d in sorted(access.definitions.items())],
                "rejected": rejected}

    def get_agent(req, v):
        name = req.path_params["name"]
        d = access.definitions.get(name)
        if d is None:
            raise ApiError(404, "no such agent")
        return _definition_view(d, v.all and req.query_params.get("full") == "1", store.holds(clock()).get(name), source_of(name))

    def visible(s: dict[str, Any], v: Viewer) -> bool:
        return v.all or s.get("principal") == v.person or s.get("agent") in v.agents

    def list_sessions(req, v):
        q, limit = req.query_params, _limit(req.query_params)
        f = {k: q.get(k) for k in ("agent", "principal", "task", "state") if q.get(k)}
        if f.get("state") and f["state"] not in ("live", "closed", "expired"):
            raise ApiError(400, "state is live, closed or expired")
        return page(store.sessions(f, v, limit, q.get("after")), limit, "created_at")

    def list_events(req, v):
        q, limit = req.query_params, _limit(req.query_params)
        f = {k: q.get(k) for k in ("app", "agent", "source", "key", "subject", "since", "until") if q.get(k)}
        for k in ("since", "until"):
            if f.get(k):
                try:
                    datetime.fromisoformat(f[k].replace("Z", "+00:00"))
                except ValueError:
                    raise ApiError(400, f"{k} is an ISO time") from None
        if f.get("app"):
            f["app"] = f["app"].lower()
        return page(store.events(f, v, limit, q.get("after")), limit, "received_at")

    def get_session(req, v):
        s = store.session(req.path_params["id"])
        if s is None or not visible(s, v):
            raise ApiError(404, "no such session")
        return s

    def get_task(req, v):
        sessions = [s for s in store.task(req.path_params["task_id"]) if visible(s, v)]
        if not sessions:
            raise ApiError(404, "no such task")
        used: dict[str, int] = {}
        for s in sessions:
            for k, n in (s.get("used") or {}).items():
                used[k] = used.get(k, 0) + int(n)
        return {"task_id": req.path_params["task_id"], "sessions": sessions, "used": used}

    def list_evidence(req, v):
        q, limit = req.query_params, _limit(req.query_params)
        f = {k: q.get(k) for k in ("task", "session", "agent", "tool", "principal", "decision", "rule", "app", "since", "until") if q.get(k)}
        after = q.get("after")
        try:
            after_n = int(after) if after else None
        except ValueError:
            raise ApiError(400, "after is a seq") from None
        return page(store.evidence(f, v, limit, after_n), limit, "seq")

    def get_evidence(req, v):
        try:
            seq = int(req.path_params["seq"])
        except ValueError:
            raise ApiError(400, "seq is a number") from None
        r = store.evidence_one(seq, v)
        if r is None:
            raise ApiError(404, "no such record")
        return r

    def verify(req, v):
        return verify_chain(store.chain(1000))

    def count_evidence(req, v):
        q = req.query_params
        by = q.get("by") or "rule"
        if by not in COUNT_BY:
            raise ApiError(400, f"by is one of {', '.join(COUNT_BY)}")
        f = {k: q.get(k) for k in ("decision", "agent", "tool", "app", "since", "until") if q.get(k)}
        items = store.counts(f, v, by)
        return {"by": by, "items": items, "total": sum(i["count"] for i in items)}

    def get_policy(req, v):
        if policy is None:
            raise ApiError(404, "this deployment serves no policy")
        return policy_view(policy)

    def explain_policy(req, v):
        if policy is None:
            raise ApiError(404, "this deployment serves no policy")
        q = req.query_params
        d = access.definitions.get(q.get("agent") or "")
        if d is None:
            raise ApiError(404, "no such agent")
        tool = q.get("tool") or ""
        if not tool:
            raise ApiError(400, "tool is required")
        raw = q.get("args") or "{}"
        if len(raw) > MAX_EXPLAIN_ARGS:
            raise ApiError(400, "args too large")
        try:
            args = json.loads(raw)
        except ValueError:
            raise ApiError(400, "args is a JSON object") from None
        if not isinstance(args, dict):
            raise ApiError(400, "args is a JSON object")
        return explain(policy, d, v.person or "user:dry-run", tool, args, clock())

    def receipts_or_verdicts(tools: tuple[str, ...]):
        def run(req, v):
            q = req.query_params
            repo, pr = (q.get("repo") or "").lower(), q.get("pr")
            if not repo or "/" not in repo:
                raise ApiError(400, "repo is required (owner/name)")
            if pr is not None and not pr.isdigit():
                raise ApiError(400, "pr is a number")
            return {"items": store.by_pr(tools, repo, pr, v)}
        return run

    def human(req, v):
        since_s = req.query_params.get("since")
        try:
            since = datetime.fromisoformat(since_s) if since_s else None
        except ValueError:
            raise ApiError(400, "since is an ISO time") from None
        pending = store.human_pending(clock(), since)
        if v.role == "notifier" or v.all:
            return {"items": pending}
        groups = access.directory.groups(v.person) if access.directory else set()
        return {"items": [r for r in pending if r.get("owner") == v.person or (r.get("group") and r["group"] in groups)]}

    async def get_contract(_: Request) -> JSONResponse:
        return JSONResponse({**contract(), **({"gateway": gateway_url} if gateway_url else {})})

    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    async def readyz(_: Request) -> JSONResponse:
        try:
            await anyio.to_thread.run_sync(store.ping)
            return JSONResponse({"ok": True})
        except Exception as e:  # noqa: BLE001
            return JSONResponse({"ok": False, "error": type(e).__name__}, status_code=503)

    fns = {"listAgents": list_agents, "getAgent": get_agent, "listSessions": list_sessions, "getSession": get_session,
           "getTask": get_task, "listEvidence": list_evidence, "getEvidence": get_evidence, "verifyEvidence": verify,
           "listReceipts": receipts_or_verdicts(provenance.PR_TOOLS),
           "listProvenance": receipts_or_verdicts(("provenance.verify",)), "listHumanRequests": human,
           "countEvidence": count_evidence, "getPolicy": get_policy, "explainPolicy": explain_policy,
           "listEvents": list_events}
    # /v1/evidence/verify must be matched before /v1/evidence/{seq}.
    order = sorted((r for r in ROUTES if r["operationId"] in fns), key=lambda r: "{" in r["path"])
    routes = [Route(r["path"], endpoint(r["operationId"], fns[r["operationId"]]), methods=["GET"]) for r in order]
    routes += [Route("/v1/contract", get_contract, methods=["GET"]), Route("/healthz", healthz, methods=["GET"]),
               Route("/readyz", readyz, methods=["GET"])]
    return Starlette(routes=routes)

