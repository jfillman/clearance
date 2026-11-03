"""clearance.evidence/v1 (R-6, docs/evidence.md): the envelope every writer emits, the schema it satisfies, intent
redaction, the read-side projection of v0-draft rows, and a chain that crosses the v0-draft to v1 boundary.

Every record any test seals is also schema-checked by conftest.every_record_is_v1."""
import hashlib
import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from clearance import api
from clearance.audit import (EVIDENCE_SCHEMA, GENESIS, PROVIDER_VERIFIED, SCHEMA_V0, AuditLog, Provider, Writer,
                             args_digest, canonical, derive_subject, evidence, project, sha256_hex, stored, verify)
from conftest import EVIDENCE_SCHEMA as SCHEMA_DOC, EVIDENCE_VALIDATOR, ROOT
from test_api import MemStore, access  # noqa: F401  (the HTTP layer's fake store; the api's Access fixture)

V0_CHAIN = ROOT / "internal" / "evidence" / "testdata" / "python-chain.jsonl"
W = Writer(Provider("fixture-provider", "1.2.3"))


def lines(p: Path) -> list[dict]:
    # split on "\n" only: str.splitlines() also splits on U+2028.
    return [json.loads(l) for l in p.read_text(encoding="utf-8").split("\n") if l.strip()]


def strict(rec: dict) -> None:
    errors = list(EVIDENCE_VALIDATOR.iter_errors(rec))
    assert not errors, errors[0].message


def test_schema_is_published_and_versioned():
    assert SCHEMA_DOC["title"] == EVIDENCE_SCHEMA == "clearance.evidence/v1"
    assert SCHEMA_DOC["$id"].endswith("/schemas/evidence/v1.json") and SCHEMA_DOC["x-clearance-revision"] >= 1
    groups = {p["x-clearance-group"] for p in SCHEMA_DOC["properties"].values()}
    assert groups == set(SCHEMA_DOC["x-clearance-groups"]) == {
        "identities", "source", "target", "provenance", "decision", "outcome", "coverage", "assurance", "intent", "integrity"}
    for reserved in ("model_version", "preflight", "policy", "approvals", "token", "outcome", "subject", "provider"):
        assert reserved in SCHEMA_DOC["properties"]


def test_a_gateway_call_is_a_v1_tool_call_record(gw):
    sid = gw.open_session("alice", "coding-agent").data["session"]
    gw.call("alice", sid, "repo.file.get", {"repo": "jfillman/flight-api", "path": "README.md"})
    for rec in gw.audit.records:
        strict(rec)
        assert rec["schema"] == EVIDENCE_SCHEMA and rec["provider"]["name"] == "autopilot-gateway"
        assert rec["subject"] == {"kind": "tool-call", "name": rec["tool"], "digests": {"sha256": rec["args_sha256"]}}
        assert {"provider", "subject"} <= set(rec["verified"]) and rec["claimed"] == []
        assert set(rec["verified"]) | set(rec["claimed"]) == set(rec) - {"seq", "schema", "boundary", "coverage",
                                                                         "verified", "claimed", "prev_hash", "hash"}
    assert verify(gw.audit.records) == (True, None)


def test_subject_kinds_derived_from_the_event():
    tree, head = "c" * 64, "a" * 40
    s, src = derive_subject({"tool": "deploy.clear", "boundary": "deployment",
                             "change": {"app": "gate-api", "env": "prod", "tree": tree, "head": head}})
    assert s == {"kind": "manifest-tree", "name": "gate-api/prod", "digests": {"sha256": tree, "gitCommit": head}}
    assert src == ("change",)
    assert derive_subject({"tool": "deploy.request", "boundary": "deployment", "args_sha256": "d" * 64})[0] is None
    assert derive_subject({"tool": "deploy.answer", "boundary": "deployment", "change": {"tree": GENESIS}})[0] is None
    d = derive_subject({"tool": "definition.load", "target": "jfillman/gate-api@3a69746 agents/gate-reader.yaml",
                        "args_sha256": "e" * 64})[0]
    assert d == {"kind": "definition", "name": "jfillman/gate-api@3a69746 agents/gate-reader.yaml", "digests": {"sha256": "e" * 64}}
    # A gate record's subject rests on the change the verifier described: claimed, like change itself.
    rec = AuditLog(writer=W).append({"ts": "2026-11-02T10:00:00Z", "tool": "deploy.clear", "boundary": "deployment",
                                     "change": {"app": "a", "env": "prod", "tree": tree, "head": head}})
    assert "subject" in rec["claimed"] and "change" in rec["claimed"] and "provider" in rec["verified"]


def test_an_events_own_subject_is_checked_and_claimed():
    log = AuditLog(writer=W)
    plan = {"kind": "terraform-plan", "name": "ws/prod", "digests": {"sha256": "f" * 64}}
    rec = log.append({"ts": "2026-11-02T10:00:00Z", "tool": "deploy.request", "boundary": "deployment", "subject": plan})
    assert rec["subject"] == plan and "subject" in rec["claimed"]
    strict(rec)
    for bad in ({"kind": "image", "digests": {"sha256": "x"}}, {"kind": "tool-call", "digests": {}},
                {"kind": "tool-call", "digests": {"sha-256": "x"}}, {"kind": "tool-call", "digests": {"sha256": "x"}, "extra": 1},
                "tool-call"):
        with pytest.raises(ValueError):
            log.append({"tool": "x", "subject": bad})
    assert len(log.records) == 1


def test_a_registered_providers_records_are_claimed_but_for_who_sent_them():
    rec = AuditLog(writer=Writer(Provider("argo-gate", "0.1.0"), verified=PROVIDER_VERIFIED)).append(
        {"ts": "2026-11-02T10:00:00Z", "tool": "deploy.outcome", "boundary": "deployment", "decision": "allow"})
    assert rec["verified"] == ["provider", "subject"] and rec["subject"] is None, "no subject: nothing claimed"
    assert rec["claimed"] == ["decision", "tool", "ts"]
    rec = AuditLog(writer=Writer(Provider("argo-gate", "0.1.0"), verified=PROVIDER_VERIFIED)).append(
        {"ts": "2026-11-02T10:00:00Z", "tool": "deploy.outcome", "boundary": "deployment",
         "subject": {"kind": "manifest-tree", "digests": {"sha256": "c" * 64}}})
    assert rec["verified"] == ["provider"] and "subject" in rec["claimed"]


def test_the_envelope_refuses_what_it_does_not_define():
    log = AuditLog(writer=W)
    for ev in ({"provider": {"name": "me", "version": "1"}}, {"schema": "x"}, {"hash": "x"}, {"verified": []},
               {"boundary": "build"}, {"boundary": None}, {"coverage": "observed"}):
        with pytest.raises(ValueError):
            log.append({"tool": "x", **ev})
    for w in (lambda: Writer(Provider("Has Space", "1")), lambda: Writer(Provider("ok", "")),
              lambda: Writer(Provider("ok", "1"), intent_capture="summary")):
        with pytest.raises(ValueError):
            w()


def test_intent_is_redacted_by_default():
    text = "rotate the flight-api DB password to hunter2"
    rec = AuditLog(writer=W).append({"ts": "2026-11-02T10:00:00Z", "tool": "session.open", "intent": text})
    assert rec["intent"] == {"capture": "redacted", "sha256": hashlib.sha256(text.encode()).hexdigest()}
    assert "hunter2" not in json.dumps(rec) and "intent" in rec["claimed"]
    full = AuditLog(writer=Writer(W.provider, intent_capture="full")).append({"ts": "2026-11-02T10:00:00Z", "tool": "x", "intent": text})
    assert full["intent"]["text"] == text and full["intent"]["capture"] == "full"
    strict(rec), strict(full)
    with pytest.raises(ValueError):
        AuditLog(writer=W).append({"tool": "x", "intent": {"text": text}})


def test_a_v0_row_is_projected_on_read_and_still_verifies():
    v0 = lines(V0_CHAIN)
    assert all(r["schema"] == SCHEMA_V0 for r in v0) and verify(v0) == (True, None)
    for r in v0:
        p = project(r)
        assert p["projected"] == ["provider", "subject"] and p["provider"] == {"name": "autopilot-gateway", "version": "unrecorded"}
        assert p["schema"] == SCHEMA_V0, "the stored schema is not rewritten"
        assert stored(p) == r and sha256_hex(canonical({k: v for k, v in stored(p).items() if k != "hash"})) == r["hash"]
    assert project(v0[0])["subject"] == {"kind": "tool-call", "name": "session.open", "digests": {"sha256": v0[0]["args_sha256"]}}
    assert project(v0[3])["subject"] is None, "a deployment record without a change has no subject"
    # A row the v0-draft gateway wrote for a deployment (the shape of hangar-dev seq 336), projected, is a valid record.
    row = {"seq": 0, "ts": "2026-11-01T02:39:59Z", "tool": "deploy.clear", "boundary": "deployment", "coverage": "authorized-and-verified",
           "schema": SCHEMA_V0, "principal": "policy", "agent": None, "app": "a", "args_sha256": "f" * 64, "decision": "allow",
           "rule": None, "tier": None, "parent": None, "session": None, "task_id": None, "target": "jfillman/x#25@25216f9",
           "result": "tier 0: cleared by policy", "prev_hash": GENESIS,
           "change": {"app": "a", "env": "agents", "cluster": "hangar-dev", "head": "2" * 40, "tree": "8" * 64, "tier": 0}}
    tags = sorted(set(row) - {"seq", "schema", "boundary", "coverage", "prev_hash"})
    row.update(verified=[k for k in tags if k != "change"], claimed=["change"])
    row["hash"] = sha256_hex(canonical(row))
    p = project(row)
    strict(p)
    assert p["subject"] == {"kind": "manifest-tree", "name": "a/agents", "digests": {"sha256": "8" * 64, "gitCommit": "2" * 40}}
    v1 = AuditLog(writer=W).append({"ts": "2026-11-02T10:00:00Z", "tool": "x"})
    assert project(v1) == {**v1, "projected": []}


def test_the_api_serves_v0_rows_in_the_v1_shape(access):
    log = AuditLog(writer=W)
    v0 = lines(V0_CHAIN)
    rows = v0[:2] + [log.append({"ts": "2026-11-02T12:00:00Z", "tool": "repo.pr.open", "principal": "user:alice",
                                 "effect": {"repo": "jfillman/x", "pr": 7}})]
    rows[2] = dict(rows[2], seq=2)  # the HTTP layer pages by seq; the hash is not this test's
    app = api.create_api_app(MemStore([], rows, []), access)
    with TestClient(app) as c:
        items = c.get("/v1/evidence", headers={"Authorization": "Bearer audit"}).json()["items"]
        assert [i["seq"] for i in items] == [2, 1, 0]
        assert [i["projected"] for i in items] == [[], ["provider", "subject"], ["provider", "subject"]]
        assert all(i["provider"]["name"] for i in items) and items[2]["subject"]["kind"] == "tool-call"
        one = c.get("/v1/evidence/0", headers={"Authorization": "Bearer audit"}).json()
        assert one["projected"] == ["provider", "subject"] and stored(one) == v0[0]
        rcp = c.get("/v1/receipts?repo=jfillman/x", headers={"Authorization": "Bearer audit"}).json()["items"]
        assert rcp and rcp[0]["projected"] == []


def test_verify_crosses_the_v0_to_v1_boundary(tmp_path):
    """A copy of a v0-draft chain, extended by today's writer: one chain, one rule, both checkers agree."""
    p = tmp_path / "chain.jsonl"
    p.write_text(V0_CHAIN.read_text(encoding="utf-8"), encoding="utf-8")
    log = AuditLog(p, writer=W)
    assert len(log.records) == 4
    log.append({"ts": "2026-11-02T12:00:00Z", "tool": "session.open", "args_sha256": args_digest({})})
    log.append({"ts": "2026-11-02T12:00:01Z", "tool": "deploy.request", "boundary": "deployment"})
    recs = AuditLog(p).records
    assert [r["schema"] for r in recs] == [SCHEMA_V0] * 4 + [EVIDENCE_SCHEMA] * 2
    assert verify(recs) == (True, None) and recs[4]["prev_hash"] == recs[3]["hash"]
    assert api.verify_chain([recs[:3], recs[3:]]) == {"ok": True, "count": 6, "head": recs[-1]["hash"], "bad_seq": None}
    recs[2]["schema"] = EVIDENCE_SCHEMA  # "upgrading" a v0 row in place breaks the chain: they stay as written
    assert verify(recs) == (False, 2)


def test_evidence_is_the_envelope_seal_adds():
    env = evidence({"tool": "x", "app": "a", "zeta": 1, "coverage": "observed-not-attributed"}, W)
    assert env == {"schema": EVIDENCE_SCHEMA, "boundary": "runtime", "coverage": "observed-not-attributed",
                   "provider": {"name": "fixture-provider", "version": "1.2.3"}, "subject": None,
                   "verified": ["app", "provider", "subject", "tool"], "claimed": ["zeta"]}


def test_the_schema_and_the_writer_enumerate_the_same_values():
    from clearance import audit
    p = SCHEMA_DOC["properties"]
    assert tuple(p["boundary"]["enum"]) == audit.BOUNDARIES and tuple(p["assurance"]["enum"]) == audit.ASSURANCE
    assert tuple(SCHEMA_DOC["else"]["properties"]["coverage"]["enum"]) == audit.COVERAGE
    assert tuple(p["subject"]["oneOf"][1]["properties"]["kind"]["enum"]) == audit.SUBJECT_KINDS
    assert tuple(p["intent"]["properties"]["capture"]["enum"]) == audit.INTENT_CAPTURE
    assert p["schema"]["enum"] == [audit.EVIDENCE_SCHEMA, audit.SCHEMA_V0]


def test_the_go_fixtures_are_what_this_writer_writes():
    """internal/evidence/testdata/python-v1.jsonl is python_chain.py write-v1's output, which Go must reproduce byte
    for byte (TestPythonV1Identical): regenerate it here and compare, so a change on either side fails a test."""
    import subprocess, sys
    here = ROOT / "internal" / "evidence" / "testdata"
    for mode, f in (("write-v1", "python-v1.jsonl"), ("project", "python-projected.jsonl")):
        out = subprocess.run([sys.executable, str(here / "python_chain.py"), mode], capture_output=True, check=True).stdout
        assert out == (here / f).read_bytes(), f"{f} is stale: python_chain.py {mode} > {f}"
    for f in ("python-v1.jsonl", "go-extended.jsonl"):
        r = subprocess.run([sys.executable, str(here / "python_chain.py"), "verify", str(here / f), "--schema"],
                           capture_output=True, text=True)
        assert r.returncode == 0 and r.stdout.startswith("ok schema-valid-v1"), r.stdout + r.stderr
