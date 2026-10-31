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

import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence

from .audit import GENESIS, canonical, sha256_hex
from .dispatch import AuthError, Authenticator

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
    {"operationId": "listReceipts", "method": "GET", "path": "/v1/receipts", "roles": PERSON_ROLES, "params": ["repo", "pr"],
     "summary": "PR receipts: what Clearance's agents opened on a repo (and PR), the commit, the paths"},
    {"operationId": "listProvenance", "method": "GET", "path": "/v1/provenance", "roles": PERSON_ROLES, "params": ["repo", "pr"],
     "summary": "The agent-gate verdicts recorded for a PR (provenance.verify)"},
    {"operationId": "listHumanRequests", "method": "GET", "path": "/v1/human/requests", "roles": ("person", "delegate", "notifier", "auditor"),
     "params": ["since"],
     "summary": "Pending human requests: a person's, those they may answer; a notifier's, every pending one (with owner and group), created since `since`"},
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
    def chain(self, batch: int) -> Iterable[list[dict[str, Any]]]: ...
    def human_pending(self, now: datetime, since: datetime | None) -> list[dict[str, Any]]: ...
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

def _definition_view(d: Any, full: bool) -> dict[str, Any]:
    lim = d.limits.as_dict()
    out = {"name": d.name, "kind": d.kind, "owner": getattr(d, "owner", None),
           "identity": {"type": d.identity_type, "serviceAccount": d.service_account},
           "tierCeiling": lim["tier_ceiling"], "tools": lim["tools"], "models": lim["models"],
           "limits": {k: lim[k] for k in ("ttl_minutes", "tool_calls", "github_calls", "open_prs", "model_tokens", "children")},
           "network": lim["network"], "compute": lim["compute"], "repos": {"allow": list(d.repos_allow)},
           "triggers": list(d.triggers), "runtime": {"framework": d.framework, "sandbox": d.sandbox, "image": d.image},
           "scopes": {k: v for k, v in (d.raw_profile or {}).items() if k in ("glidepath", "airframe")}}
    if full:
        out["instructions"] = d.instructions
    return out


def _limit(q: Mapping[str, str]) -> int:
    try:
        n = int(q.get("limit") or DEFAULT_LIMIT)
    except ValueError:
        raise ApiError(400, "limit must be a number") from None
    return max(1, min(n, MAX_LIMIT))


def create_api_app(store: ReadStore, access: Access, *, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                   gateway_url: str | None = None):
    """The Starlette app for `clearance api`."""
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

    def list_agents(req, v):
        full = v.all and req.query_params.get("full") == "1"
        return {"items": [_definition_view(d, full) for _, d in sorted(access.definitions.items())]}

    def get_agent(req, v):
        d = access.definitions.get(req.path_params["name"])
        if d is None:
            raise ApiError(404, "no such agent")
        return _definition_view(d, v.all and req.query_params.get("full") == "1")

    def visible(s: dict[str, Any], v: Viewer) -> bool:
        return v.all or s.get("principal") == v.person or s.get("agent") in v.agents

    def list_sessions(req, v):
        q, limit = req.query_params, _limit(req.query_params)
        f = {k: q.get(k) for k in ("agent", "principal", "task", "state") if q.get(k)}
        if f.get("state") and f["state"] not in ("live", "closed", "expired"):
            raise ApiError(400, "state is live, closed or expired")
        return page(store.sessions(f, v, limit, q.get("after")), limit, "created_at")

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
           "listReceipts": receipts_or_verdicts(("repo.pr.open", "repo.pr.open_upper")),
           "listProvenance": receipts_or_verdicts(("provenance.verify",)), "listHumanRequests": human}
    # /v1/evidence/verify must be matched before /v1/evidence/{seq}.
    order = sorted((r for r in ROUTES if r["operationId"] in fns), key=lambda r: "{" in r["path"])
    routes = [Route(r["path"], endpoint(r["operationId"], fns[r["operationId"]]), methods=["GET"]) for r in order]
    routes += [Route("/v1/contract", get_contract, methods=["GET"]), Route("/healthz", healthz, methods=["GET"]),
               Route("/readyz", readyz, methods=["GET"])]
    return Starlette(routes=routes)

