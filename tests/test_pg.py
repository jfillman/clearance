"""clearance.pg against a real Postgres (CLEARANCE_TEST_DSN; CI runs a service container, otherwise skipped):
a restart keeps every grant and budget, a call's evidence and spend commit together, one writer only, and a row
changed in the database stops Clearance from starting."""
import os
from datetime import datetime, timedelta, timezone

import pytest

from clearance.dispatch import Gateway
from clearance.packs.hangar import HANGAR
from clearance.dispatch import Denied
from clearance.pg import PgArtifacts, PgAuditLog, PgInbox, PgState, WriterLocked, open_durable

DSN = os.environ.get("CLEARANCE_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="set CLEARANCE_TEST_DSN to a scratch Postgres")
PR = {"repo": "jfillman/flight-api", "branch": "agent/t-1", "title": "fix probe",
      "files": [{"path": "charts/values.yaml", "content": "x"}]}


@pytest.fixture
def db():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("DROP TABLE IF EXISTS clearance_evidence, clearance_sessions, clearance_artifacts, clearance_human_requests")
    yield DSN


def gateway(db, defs, gw_parts, clock):
    state, audit, store = open_durable(db)
    auth, handlers, runs = gw_parts
    return state, Gateway(defs, store, audit, auth, clock, packs=(HANGAR,), handlers=handlers, runs=runs)


@pytest.fixture
def gw_parts(gw):
    return gw.auth, {k: v for k, v in gw._handlers.items() if k not in ("run.spawn", "run.close")}, gw.runs


def test_a_restart_keeps_the_session_its_budget_and_the_chain(db, defs, gw_parts, clock):
    state, g = gateway(db, defs, gw_parts, clock)
    sid = g.open_session("alice", "coding-agent").data["session"]
    assert g.call("alice", sid, "repo.pr.open", PR).ok
    denied = g.call("alice", sid, "repo.pr.open", {**PR, "files": [{"path": ".tekton/x.yaml", "content": "x"}]})
    assert not denied.ok
    head, n = g.audit.head, len(g.audit.records)
    state.close()

    state2, g2 = gateway(db, defs, gw_parts, clock)
    s = g2.store.get(sid)
    assert s is not None and s.principal == "user:alice"
    assert s.used["tool_calls"] == 1 and s.used["open_prs"] == 1 and s.denials == 1
    assert g2.audit.head == head and len(g2.audit.records) == n
    assert g2.call("alice", sid, "repo.pr.open", PR).ok, "the reloaded session still works"
    assert g2.audit.records[-1]["prev_hash"] == head, "the chain continues where it stopped"
    state2.close()


def test_records_are_evidence_shaped_with_assurance_beside_them(db, defs, gw_parts, clock):
    state, g = gateway(db, defs, gw_parts, clock)
    sid = g.open_session("alice", "coding-agent").data["session"]
    rec = g.audit.records[-1]
    assert rec["schema"] == "clearance.evidence/v0-draft" and rec["boundary"] == "runtime"
    assert rec["coverage"] == "authorized-and-verified" and "principal" in rec["verified"] and rec["claimed"] == []
    assert rec["session"] == sid and "assurance" not in rec
    assert g.audit.assurance(rec["seq"]) == "recorded-not-checkpointed"
    state.close()


def test_only_one_writer(db):
    first = PgState(db)
    with pytest.raises(WriterLocked):
        PgState(db)
    first.close()
    PgState(db).close()


def test_an_edited_row_stops_clearance_from_starting(db, defs, gw_parts, clock):
    state, g = gateway(db, defs, gw_parts, clock)
    g.open_session("alice", "coding-agent")
    g.open_session("bob", "coding-agent")
    with state.conn.cursor() as cur:
        cur.execute("UPDATE clearance_evidence SET record = jsonb_set(record, '{principal}', '\"user:mallory\"') "
                    "WHERE seq = 0")
    state.commit()
    state.close()
    with pytest.raises(ValueError, match="broken at seq 0"):
        PgAuditLog(PgState(db))


def test_a_failed_commit_rolls_back_the_operations_evidence(db, defs, gw_parts, clock, monkeypatch):
    state, g = gateway(db, defs, gw_parts, clock)
    g.open_session("alice", "coding-agent")
    head = g.audit.head
    real = state.commit

    def boom():
        raise RuntimeError("database went away")
    monkeypatch.setattr(state, "commit", boom)
    with pytest.raises(RuntimeError):
        g.open_session("bob", "coding-agent")
    monkeypatch.setattr(state, "commit", real)
    assert g.audit.head == head and len(g.audit.records) == 1, "the uncommitted record is gone, not half-kept"
    g.open_session("alice", "coding-agent")
    assert g.audit.records[-1]["prev_hash"] == head
    state.close()


def test_receipts_are_found_in_postgres_after_a_restart(db, defs, gw_parts, clock):
    state, g = gateway(db, defs, gw_parts, clock)
    sid = g.open_session("alice", "coding-agent").data["session"]
    commit = g.call("alice", sid, "repo.pr.open", PR).data["commit"]
    state.close()
    state2, g2 = gateway(db, defs, gw_parts, clock)
    found = g2.audit.receipts("jfillman/flight-api", 1, ("repo.pr.open",))
    assert [r["effect"]["commit"] for r in found] == [commit] and found[0]["session"] == sid
    assert g2.audit.receipts("jfillman/flight-api", 2, ("repo.pr.open",)) == []
    state2.close()


def test_artifacts_are_per_task_bounded_and_expire(db):
    t = [datetime(2026, 10, 30, tzinfo=timezone.utc)]
    state = PgState(db)
    art = PgArtifacts(state, now=lambda: t[0], ttl=timedelta(hours=1), max_bytes=10, max_count=2, max_total=15)
    assert art.put("t-1", "plan.md", "first")["bytes"] == 5
    art.put("t-1", "plan.md", "second")                  # a put by name replaces
    assert art.get("t-1", "plan.md") == "second" and art.get("t-2", "plan.md") is None
    for name, content, rule in (("../x", "a", "ART-NAME"), ("big", "x" * 11, "ART-SIZE")):
        with pytest.raises(Denied) as e:
            art.put("t-1", name, content)
        assert e.value.rule == rule
    art.put("t-1", "b", "123456789")                     # 6 + 9 = 15 bytes, 2 artifacts: at both limits
    with pytest.raises(Denied) as e:
        art.put("t-1", "c", "x")
    assert e.value.rule == "ART-QUOTA"
    state.commit()
    t[0] += timedelta(hours=1)
    assert art.get("t-1", "plan.md") is None, "expired"
    art.put("t-1", "c", "x")                             # expired ones no longer count
    state.commit()
    state.close()



def test_an_artifact_survives_a_restart(db):
    state = PgState(db)
    PgArtifacts(state).put("t-9", "report.md", "all green")
    state.commit()
    state.close()
    state2 = PgState(db)
    assert PgArtifacts(state2).get("t-9", "report.md") == "all green"
    state2.close()


def test_a_human_request_and_its_answer_survive_a_restart(db):
    from clearance.inbox import HumanRequest
    t = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)
    state = PgState(db)
    box = PgInbox(state)
    r = HumanRequest("h-0123456789ab", "t-1", "s-1", "orchestrator", "user:alice", "group:default/platform",
                     "Roll back?", ["yes", "no"], t, t + timedelta(hours=1))
    box.add(r)
    box.add(HumanRequest("h-00000000000e", "t-1", "s-1", "orchestrator", "user:alice", None, "Old?", [],
                         t - timedelta(hours=2), t - timedelta(hours=1)))
    state.commit()
    assert [x.id for x in box.pending(t)] == ["h-0123456789ab"] and box.count_pending("s-1", t) == 1
    r.status, r.answer, r.answered_by, r.answered_at = "answered", "no", "user:bob", t
    box.save(r)
    state.commit()
    state.close()
    state2 = PgState(db)
    back = PgInbox(state2).get("h-0123456789ab")
    assert (back.answer, back.answered_by, back.options, back.expires_at) == ("no", "user:bob", ["yes", "no"], t + timedelta(hours=1))
    assert PgInbox(state2).pending(t) == []
    state2.close()


def test_changes_find_a_head_and_the_answers_github_has_not_taken(db):
    """The deployment protection rule's two lookups on clearance_changes: by repo and head, and the changes with an
    answered deployment not yet delivered (a JSONB containment query), round-tripping the deployments list."""
    import psycopg
    from clearance import gate
    from clearance.pg import PgChanges
    with psycopg.connect(db, autocommit=True) as c:
        c.execute("DROP TABLE IF EXISTS clearance_changes")
    state, _, _ = open_durable(db)
    store = PgChanges(state)
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    body = {"app": "gate-api", "env": "prod", "cluster": "hangar-prod", "repo": "jfillman/gitops-gate-api", "pr": 0,
            "head": "a" * 40, "proposer": "user:dana", "treeDigest": "c" * 64}
    req = gate.ChangeRequest.from_dict(body)
    ch = gate.Change.open(req, gate.classify(req, gate.GatePolicy()), now, "ci")
    ch.deployments.append({"run_id": 5, "environment": "prod", "installation": "9", "callback_url": "u",
                           "requested_at": now.isoformat(), "answer": None, "delivered": False})
    store.put(ch)
    state.conn.commit()
    assert [c.id for c in store.for_head("jfillman/gitops-gate-api", "a" * 40)] == [ch.id]
    assert store.undelivered() == [], "a waiting deployment has nothing to deliver"
    ch.state = "cleared"
    assert gate.answer_deployments(ch, now) == 1
    store.put(ch)
    state.conn.commit()
    got = store.undelivered()
    assert [c.id for c in got] == [ch.id] and got[0].deployments[0]["answer"] == "approved"
    got[0].deployments[0]["delivered"] = True
    store.put(got[0])
    state.conn.commit()
    assert store.undelivered() == []
    state.close()
