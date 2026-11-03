"""Fixtures for Clearance's own tests: the core gateway with the Hangar pack's policy, core handlers over
in-memory fakes, and a run backend that starts nothing. Agent definitions are tests/fixtures/agents/."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

from clearance import audit as audit_mod, pg as pg_mod, profile
from clearance.audit import AuditLog
from clearance.backends import FakeArgo, FakeArtifacts, FakeGit, FakeHuman, FakeRead, FakeRunBackend, core_handlers
from clearance.dispatch import Gateway, Principal
from clearance.packs.hangar import HANGAR
from clearance.session import SessionStore
from clearance.tiers import Tier

ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / "tests" / "fixtures" / "agents"
T0 = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)
EVIDENCE_SCHEMA = json.loads((ROOT / "schemas" / "evidence.schema.json").read_text())
EVIDENCE_VALIDATOR = jsonschema.Draft202012Validator(EVIDENCE_SCHEMA)
# Every tool (record kind) a writer sealed during the session, schema-checked (tests/test_evidence.py reads it).
SEALED: dict[str, int] = {}


@pytest.fixture(autouse=True)
def every_record_is_v1(monkeypatch):
    """Every record any writer seals in any test is a clearance.evidence/v1 record that satisfies
    schemas/evidence.schema.json (R-6: writers emit v1). Synthetic events without a real ts (the chain tests'
    {"tool": "t0"}) are checked against the schema minus ts and tool."""
    real = audit_mod.seal

    def checked(seq, prev_hash, event, writer):
        rec = real(seq, prev_hash, event, writer)
        assert rec["schema"] == audit_mod.EVIDENCE_SCHEMA
        synthetic = not isinstance(rec.get("ts"), str) or len(rec["ts"]) != 20
        errors = [e for e in EVIDENCE_VALIDATOR.iter_errors(rec)
                  if not (synthetic and ((e.validator == "required" and ("'ts'" in e.message or "'tool'" in e.message))
                                         or (e.path and e.path[0] in ("ts", "tool"))))]
        assert not errors, f"record {rec.get('tool')!r} breaks the v1 schema: {errors[0].message}"
        SEALED[rec.get("tool") or "-"] = SEALED.get(rec.get("tool") or "-", 0) + 1
        return rec

    monkeypatch.setattr(audit_mod, "seal", checked)
    monkeypatch.setattr(pg_mod, "seal", checked)


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


class StaticAuth:
    def __init__(self, table):
        self.table = table

    def authenticate(self, token):
        return self.table[token]


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def defs():
    return profile.load_dir(AGENTS)


@pytest.fixture
def backends():
    return SimpleNamespace(git=FakeGit(), argo=FakeArgo(), read=FakeRead(), human=FakeHuman(),
                           artifacts=FakeArtifacts(), runs=FakeRunBackend())


@pytest.fixture
def gw(defs, backends, clock):
    counter = iter(range(1, 1000))
    store = SessionStore(id_gen=lambda: f"s-{next(counter):06x}")
    auth = StaticAuth({
        "alice": Principal("user:alice", "user", Tier.T1),
        "bob": Principal("user:bob", "user", Tier.T1),
        "readonly": Principal("user:ro", "user", Tier.T0),
        "holmes": Principal("holmesgpt/holmes", "workload", Tier.T1),
    })
    handlers = core_handlers(git=backends.git, argo=backends.argo, read=backends.read, human=backends.human,
                             artifacts=backends.artifacts)
    return Gateway(defs, store, AuditLog(), auth, clock, packs=(HANGAR,), handlers=handlers, runs=backends.runs)
