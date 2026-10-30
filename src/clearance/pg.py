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
"""
from __future__ import annotations

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
        if ENVELOPE & set(event) - {"coverage"}:
            raise ValueError(f"event must not set {sorted(ENVELOPE & set(event) - {'coverage'})}")
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


def open_durable(dsn: str, id_gen=None):
    """A PgState, its evidence log, and a SessionStore loaded from it: what a deployment passes to Gateway."""
    from .session import SessionStore
    state = PgState(dsn)
    audit = PgAuditLog(state)
    store = SessionStore(id_gen=id_gen, persist=PgSessions(state, audit))
    return state, audit, store
