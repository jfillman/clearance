"""Postgres: the durable session store and the evidence sink, sharing one connection and one transaction.

A gateway operation writes its audit records (INSERTs) and then, in store.flush(), the sessions it changed
(UPSERTs), and commits once: a call's evidence and the budget it spent land together or not at all. Every
decision is recorded unsampled; this is the evidence sink, not telemetry.

One writer only. Opening a PgState takes a session-level advisory lock and fails if another Clearance holds it,
because two writers would fork the hash chain. On start the chain is verified from genesis and the head read back,
so a row edited, deleted or reordered in the database stops Clearance from starting rather than being extended.

Tables (created if missing; `migrate` is idempotent):
  clearance_evidence  seq, hash, prev_hash, the record (jsonb, exactly what was hashed), and its assurance state
                      beside it: recorded-not-checkpointed until a witnessed checkpoint covers it (the ledger).
  clearance_sessions  id, the session record (jsonb), expires_at and closed for the load query.
  clearance_artifacts artifact.put's text, per task and name, bounded and expiring (PgArtifacts).
  clearance_human_requests  human.request's questions and their answers (PgInbox, inbox.py).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import psycopg
from psycopg.types.json import Jsonb

from .audit import ENVELOPE, GENESIS, Checkpoint, canonical, evidence, sha256_hex, verify

LOCK_KEY = 0x636C7230  # "clr0": one Clearance writer per database
RECENT = timedelta(days=1)  # closed or expired sessions kept in memory this long, for the run tree's lookups

SCHEMA = """
CREATE TABLE IF NOT EXISTS clearance_evidence (
  seq        bigint PRIMARY KEY,
  hash       text   NOT NULL UNIQUE,
  prev_hash  text   NOT NULL,
  record     jsonb  NOT NULL,
  assurance  text   NOT NULL DEFAULT 'recorded-not-checkpointed'
             CHECK (assurance IN ('checkpointed', 'recorded-not-checkpointed', 'not-recorded')),
  written_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS clearance_sessions (
  id         text PRIMARY KEY,
  record     jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  closed     boolean NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_sessions_live ON clearance_sessions (closed, expires_at);
CREATE INDEX IF NOT EXISTS clearance_evidence_receipt ON clearance_evidence
  ((record->'effect'->>'repo'), (record->'effect'->>'pr')) WHERE record ? 'effect';
CREATE TABLE IF NOT EXISTS clearance_artifacts (
  task_id    text        NOT NULL,
  name       text        NOT NULL,
  content    text        NOT NULL,
  bytes      integer     NOT NULL,
  expires_at timestamptz NOT NULL,
  written_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (task_id, name)
);
CREATE INDEX IF NOT EXISTS clearance_artifacts_expiry ON clearance_artifacts (expires_at);
CREATE TABLE IF NOT EXISTS clearance_human_requests (
  id         text        PRIMARY KEY,
  session    text        NOT NULL,
  status     text        NOT NULL,
  expires_at timestamptz NOT NULL,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_human_requests_pending ON clearance_human_requests (status, expires_at);
CREATE TABLE IF NOT EXISTS clearance_events (
  id          text        PRIMARY KEY,
  received_at timestamptz NOT NULL,
  source      text        NOT NULL,
  app         text,
  routing_key text,
  record      jsonb       NOT NULL,
  written_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_events_received ON clearance_events (received_at DESC);
CREATE INDEX IF NOT EXISTS clearance_events_app ON clearance_events (app, received_at DESC);
CREATE TABLE IF NOT EXISTS clearance_holds (
  agent      text        PRIMARY KEY,
  until      timestamptz NOT NULL,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS clearance_changes (
  id         text        PRIMARY KEY,
  app        text        NOT NULL,
  env        text        NOT NULL,
  state      text        NOT NULL,
  repo       text        NOT NULL,
  pr         integer     NOT NULL,
  head       text        NOT NULL,
  expires_at timestamptz NOT NULL,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_changes_pr ON clearance_changes (repo, pr);
CREATE INDEX IF NOT EXISTS clearance_changes_state ON clearance_changes (state, expires_at);
CREATE INDEX IF NOT EXISTS clearance_changes_app ON clearance_changes (app, env, updated_at DESC);
CREATE TABLE IF NOT EXISTS clearance_definitions (
  name       text        NOT NULL,
  state      text        NOT NULL,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (name, state)
);
"""


class WriterLocked(RuntimeError):
    pass


class PgState:
    def __init__(self, dsn: str, connect=psycopg.connect):
        self.conn = connect(dsn, autocommit=False)
        with self.conn.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,))
            if not cur.fetchone()[0]:
                self.conn.close()
                raise WriterLocked("another Clearance is writing to this database")
        self.migrate()

    def migrate(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute(SCHEMA)
        self.conn.commit()

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class PgAuditLog:
    """AuditLog's interface on clearance_evidence. append() does not commit: the operation's flush does."""

    def __init__(self, state: PgState):
        self.state = state
        records = self.records
        ok, bad = verify(records)
        if not ok:
            raise ValueError(f"evidence chain in the database is broken at seq {bad}")
        self._count, self._head = len(records), (records[-1]["hash"] if records else GENESIS)

    @property
    def head(self) -> str:
        return self._head

    @property
    def records(self) -> list[dict[str, Any]]:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_evidence ORDER BY seq")
            return [r[0] for r in cur.fetchall()]

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        if ENVELOPE & set(event) - {"coverage", "boundary"}:
            raise ValueError(f"event must not set {sorted(ENVELOPE & set(event) - {'coverage', 'boundary'})}")
        rec = {"seq": self._count, **event, **evidence(event), "prev_hash": self._head}
        rec["hash"] = sha256_hex(canonical(rec))
        with self.state.conn.cursor() as cur:
            cur.execute("INSERT INTO clearance_evidence (seq, hash, prev_hash, record) VALUES (%s, %s, %s, %s)",
                        (rec["seq"], rec["hash"], rec["prev_hash"], Jsonb(rec)))
        self._count, self._head = self._count + 1, rec["hash"]
        return rec

    def rollback(self) -> None:
        """After a failed commit: forget what this transaction appended, and re-read the head."""
        self.state.conn.rollback()
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT seq, hash FROM clearance_evidence ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
        self._count, self._head = (row[0] + 1, row[1]) if row else (0, GENESIS)

    def checkpoint(self) -> Checkpoint:
        return Checkpoint(self._count, self._head)

    def receipts(self, repo: str, pr: int, tools: tuple[str, ...]) -> list[dict[str, Any]]:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_evidence WHERE record->>'tool' = ANY(%s) "
                        "AND record->'effect'->>'repo' = %s AND record->'effect'->>'pr' = %s ORDER BY seq",
                        (list(tools), repo, str(pr)))
            return [r[0] for r in cur.fetchall()]

    def assurance(self, seq: int) -> str | None:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT assurance FROM clearance_evidence WHERE seq = %s", (seq,))
            row = cur.fetchone()
        return row[0] if row else None


class PgSessions:
    """SessionStore persistence on clearance_sessions. save() upserts and commits the operation's transaction
    (its evidence included); a failed commit rolls the audit log back too, and the error reaches the caller."""

    def __init__(self, state: PgState, audit: PgAuditLog | None = None, now=lambda: datetime.now(timezone.utc)):
        self.state, self.audit, self.now = state, audit, now

    def load(self) -> Iterable[dict[str, Any]]:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_sessions WHERE NOT closed OR expires_at > %s",
                        (self.now() - RECENT,))
            rows = [r[0] for r in cur.fetchall()]
        self.state.commit()
        return rows

    def save(self, records: list[dict[str, Any]]) -> None:
        try:
            with self.state.conn.cursor() as cur:
                for r in records:
                    cur.execute(
                        "INSERT INTO clearance_sessions (id, record, expires_at, closed) VALUES (%s, %s, %s, %s) "
                        "ON CONFLICT (id) DO UPDATE SET record = EXCLUDED.record, expires_at = EXCLUDED.expires_at, "
                        "closed = EXCLUDED.closed, updated_at = now()",
                        (r["id"], Jsonb(r), datetime.fromisoformat(r["expires_at"]), r["closed"]))
            self.state.commit()
        except Exception:
            if self.audit is not None:
                self.audit.rollback()
            else:
                self.state.conn.rollback()
            raise


ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


class PgArtifacts:
    """ArtifactBackend on clearance_artifacts: text a task's sessions keep for each other (a child's report, a plan),
    keyed by task, so a whole run tree shares them and nothing else sees them. Bounded and expiring: each artifact at
    most `max_bytes`, a task at most `max_count` and `max_total` bytes, gone `ttl` after its last write. A put with
    an existing name replaces it. Writes join the call's transaction, so they commit with its evidence."""

    def __init__(self, state: PgState, now=lambda: datetime.now(timezone.utc), ttl: timedelta = timedelta(days=7),
                 max_bytes: int = 256 << 10, max_count: int = 32, max_total: int = 2 << 20):
        self.state, self.now, self.ttl = state, now, ttl
        self.max_bytes, self.max_count, self.max_total = max_bytes, max_count, max_total

    def put(self, task_id: str, name: str, content: str) -> dict[str, Any]:
        from .dispatch import Denied
        if not isinstance(name, str) or not ARTIFACT_NAME.match(name):
            raise Denied("ART-NAME", f"{name!r} is not an artifact name", "Use letters, digits, '.', '_' or '-'.")
        if not isinstance(content, str):
            raise Denied("ART-CONTENT", "an artifact's content is text", "Pass a string (JSON-encode structured data).")
        size = len(content.encode())
        if size > self.max_bytes:
            raise Denied("ART-SIZE", f"{size} bytes is over the {self.max_bytes}-byte limit for one artifact",
                         "Store a summary, or split it.")
        now = self.now()
        with self.state.conn.cursor() as cur:
            cur.execute("DELETE FROM clearance_artifacts WHERE expires_at <= %s", (now,))
            cur.execute("SELECT count(*), coalesce(sum(bytes), 0) FROM clearance_artifacts WHERE task_id = %s AND name <> %s",
                        (task_id, name))
            count, total = cur.fetchone()
            if count + 1 > self.max_count or total + size > self.max_total:
                raise Denied("ART-QUOTA", f"this task may keep {self.max_count} artifacts and {self.max_total} bytes",
                             "Replace an existing artifact by its name instead of adding one.")
            expires = now + self.ttl
            cur.execute("INSERT INTO clearance_artifacts (task_id, name, content, bytes, expires_at) "
                        "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (task_id, name) DO UPDATE SET "
                        "content = EXCLUDED.content, bytes = EXCLUDED.bytes, expires_at = EXCLUDED.expires_at, "
                        "written_at = now()", (task_id, name, content, size, expires))
        return {"stored": name, "bytes": size, "expires_at": expires.isoformat()}

    def get(self, task_id: str, name: str) -> str | None:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT content FROM clearance_artifacts WHERE task_id = %s AND name = %s AND expires_at > %s",
                        (task_id, name, self.now()))
            row = cur.fetchone()
        return row[0] if row else None


class PgInbox:
    """InboxStore on clearance_human_requests. Writes join the operation's transaction (the request with the call
    that asked it, the answer with its human.answer record)."""

    def __init__(self, state: PgState):
        self.state = state

    @staticmethod
    def _load(rec: dict[str, Any]):
        from .inbox import HumanRequest
        d = dict(rec)
        for k in ("created_at", "expires_at", "answered_at"):
            d[k] = datetime.fromisoformat(d[k]) if d.get(k) else None
        return HumanRequest(**d)

    def _put(self, r) -> None:
        from dataclasses import asdict
        rec = asdict(r)
        for k in ("created_at", "expires_at", "answered_at"):
            rec[k] = rec[k].isoformat() if rec[k] else None
        with self.state.conn.cursor() as cur:
            cur.execute("INSERT INTO clearance_human_requests (id, session, status, expires_at, record) "
                        "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, "
                        "record = EXCLUDED.record, updated_at = now()",
                        (r.id, r.session, r.status, r.expires_at, Jsonb(rec)))

    add = save = _put

    def get(self, request_id: str):
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_human_requests WHERE id = %s", (request_id,))
            row = cur.fetchone()
        return self._load(row[0]) if row else None

    def pending(self, now: datetime) -> list:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_human_requests WHERE status = 'pending' AND expires_at > %s "
                        "ORDER BY record->>'created_at'", (now,))
            return [self._load(r[0]) for r in cur.fetchall()]

    def count_pending(self, session: str, now: datetime) -> int:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM clearance_human_requests WHERE session = %s AND status = 'pending' "
                        "AND expires_at > %s", (session, now))
            return cur.fetchone()[0]


class PgEvents:
    """EventsStore on clearance_events (events.py): one row per event the trigger bridge handled, kept
    events.RETENTION. A write joins the gateway operation's transaction (Gateway.record_event is durable). Every
    PRUNE_EVERY writes, rows past retention are deleted."""

    PRUNE_EVERY = 500

    def __init__(self, state: PgState):
        self.state = state
        self._writes = 0

    def record(self, ev) -> None:
        from .events import RETENTION
        with self.state.conn.cursor() as cur:
            cur.execute("INSERT INTO clearance_events (id, received_at, source, app, routing_key, record) "
                        "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO UPDATE SET record = EXCLUDED.record, "
                        "written_at = now()",
                        (ev.id, ev.received_at, ev.source, ev.app, ev.routing_key, Jsonb(ev.view())))
            self._writes += 1
            if self._writes % self.PRUNE_EVERY == 0:
                cur.execute("DELETE FROM clearance_events WHERE received_at < %s",
                            (datetime.now(timezone.utc) - RETENTION,))


class PgHolds:
    """HoldStore on clearance_holds (control.py): one row per held agent, written in the control's transaction."""

    def __init__(self, state: PgState):
        self.state = state

    def get(self, agent: str):
        from .control import Hold
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_holds WHERE agent = %s", (agent,))
            row = cur.fetchone()
        return Hold.from_record(row[0]) if row else None

    def put(self, hold) -> None:
        with self.state.conn.cursor() as cur:
            cur.execute("INSERT INTO clearance_holds (agent, until, record) VALUES (%s, %s, %s) "
                        "ON CONFLICT (agent) DO UPDATE SET until = EXCLUDED.until, record = EXCLUDED.record, "
                        "updated_at = now()", (hold.agent, hold.until, Jsonb(hold.view())))

    def delete(self, agent: str) -> None:
        with self.state.conn.cursor() as cur:
            cur.execute("DELETE FROM clearance_holds WHERE agent = %s", (agent,))

    def all(self) -> list:
        from .control import Hold
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_holds ORDER BY agent")
            return [Hold.from_record(r[0]) for r in cur.fetchall()]


class PgChanges:
    """gate.ChangeStore on clearance_changes: one row per change, written in the gate operation's transaction (the
    change with its deploy.* record). clearance-api reads the same rows (api.PgReadStore.changes)."""

    def __init__(self, state: PgState):
        self.state = state

    @staticmethod
    def _load(rec):
        from .gate import Change
        return Change.from_record(rec)

    def put(self, c) -> None:
        with self.state.conn.cursor() as cur:
            cur.execute("INSERT INTO clearance_changes (id, app, env, state, repo, pr, head, expires_at, record) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, "
                        "expires_at = EXCLUDED.expires_at, record = EXCLUDED.record, updated_at = now()",
                        (c.id, c.app, c.env, c.state, c.repo, c.pr, c.head, c.expires_at, Jsonb(c.view())))

    def get(self, change_id: str):
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_changes WHERE id = %s", (change_id,))
            row = cur.fetchone()
        return self._load(row[0]) if row else None

    def for_pr(self, repo: str, pr: int) -> list:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_changes WHERE repo = %s AND pr = %s ORDER BY record->>'created_at'", (repo, pr))
            return [self._load(r[0]) for r in cur.fetchall()]

    def holding(self, now: datetime) -> list:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_changes WHERE state = 'holding' ORDER BY record->>'created_at'")
            return [self._load(r[0]) for r in cur.fetchall()]

    def for_head(self, repo: str, head: str) -> list:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_changes WHERE repo = %s AND head = %s ORDER BY record->>'created_at'", (repo, head))
            return [self._load(r[0]) for r in cur.fetchall()]

    def undelivered(self) -> list:
        # Deployments answered but not yet taken by GitHub (github_app.py retries them); a JSONB containment test.
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_changes WHERE record->'deployments' @> '[{\"delivered\": false}]'::jsonb")
            return [c for c in (self._load(r[0]) for r in cur.fetchall())
                    if any(d.get("answer") and not d.get("delivered") for d in c.deployments)]


class PgDefinitions:
    """DefinitionsStore on clearance_definitions (definitions.py): the cluster-pinned set, replaced whole in the
    loader's transaction (a few rows). The read API reads it (api.PgReadStore.definitions) instead of fetching."""

    def __init__(self, state: PgState):
        self.state = state

    def replace(self, records: list) -> None:
        with self.state.conn.cursor() as cur:
            cur.execute("DELETE FROM clearance_definitions")
            for r in records:
                cur.execute("INSERT INTO clearance_definitions (name, state, record) VALUES (%s, %s, %s)",
                            (r["name"], r["state"], Jsonb(r)))

    def all(self) -> list:
        with self.state.conn.cursor() as cur:
            cur.execute("SELECT record FROM clearance_definitions ORDER BY state, name")
            return [row[0] for row in cur.fetchall()]


def open_durable(dsn: str, id_gen=None):
    """A PgState, its evidence log, and a SessionStore loaded from it: what a deployment passes to Gateway."""
    from .session import SessionStore
    state = PgState(dsn)
    audit = PgAuditLog(state)
    store = SessionStore(id_gen=id_gen, persist=PgSessions(state, audit))
    return state, audit, store
