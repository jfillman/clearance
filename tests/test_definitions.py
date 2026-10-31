"""Cluster-pinned definitions (definitions.py, Gateway.apply_cluster_definitions, the API's `source` and `rejected`):
what a pin must satisfy, that bundled names can't be shadowed, that a swap is atomic and a change is recorded once."""
import copy

import pytest
import yaml
from starlette.testclient import TestClient

from clearance import api, definitions as defn
from clearance.audit import AuditLog
from clearance.dispatch import AuthError, Gateway, Principal
from clearance.packs.hangar import HANGAR
from clearance.session import SessionStore
from clearance.tiers import Tier

from conftest import AGENTS

PIN = defn.Source("cluster", repo="jfillman/gate-api", path="agents/gate-triage.yaml",
                  commit="1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", namespace="app-gate-api-cicd", xr="gate-triage",
                  loaded_at="2026-10-31T12:00:00Z")
OWNER = "group:default/team-gate"


def doc(name="gate-triage", owner=OWNER, sa=None, **over):
    d = yaml.safe_load((AGENTS / "triage-agent.yaml").read_text())
    d["name"], d["owner"] = name, owner
    d["identity"] = {"type": "workload", "serviceAccount": sa or f"autopilot-runs/{name}"}
    d.update(over)
    return d


def test_a_good_pin_loads_with_its_source():
    out = defn.from_pin(doc(), PIN, owner=OWNER)
    assert isinstance(out, defn.Loaded)
    assert out.name == "gate-triage" and out.source.pin == "jfillman/gate-api@1a2b3c4 agents/gate-triage.yaml"
    assert out.definition.owner == OWNER and out.doc["name"] == "gate-triage"


@pytest.mark.parametrize("bad, reason", [
    ("not a mapping", "not a YAML mapping"),
    (doc(name="other-name"), "a pin named 'gate-triage' must pin a definition named 'gate-triage'"),
    (doc(owner="group:default/someone-else"), "they must agree"),
    (doc(sa="autopilot-runs/triage-agent"), "workload identity is autopilot-runs/gate-triage"),
    ({**doc(), "profile": {**doc()["profile"], "tierCeiling": "T9"}}, "schema:"),
])
def test_a_bad_pin_is_rejected_with_the_reason(bad, reason):
    out = defn.from_pin(bad, PIN, owner=OWNER)
    assert isinstance(out, defn.Rejected) and reason in out.reason and out.name == "gate-triage"


def test_a_pin_cannot_take_a_bundled_name(defs):
    src = defn.Source("cluster", repo="jfillman/gate-api", path="agents/triage-agent.yaml", commit="f" * 40,
                      namespace="app-gate-api-cicd", xr="triage-agent")
    out = defn.from_pin(doc(name="triage-agent"), src, owner=OWNER, reserved=defs)
    assert isinstance(out, defn.Rejected) and "bundled platform definition" in out.reason
    # and the registry refuses it too, whoever built the Loaded
    reg = defn.Definitions(defs)
    ch = reg.replace_cluster([defn.Loaded(defs["triage-agent"], src, {})])
    assert "triage-agent" not in ch.added and [r.name for r in ch.rejected] == ["triage-agent"]
    assert reg["triage-agent"] is defs["triage-agent"] and reg.source("triage-agent").kind == "bundled"


def test_the_registry_is_a_mapping_over_bundled_and_cluster(defs):
    reg = defn.Definitions(defs)
    assert len(reg) == len(defs) and set(reg) == set(defs) and reg.get("nope") is None and reg.source("nope") is None
    loaded = defn.from_pin(doc(), PIN, owner=OWNER)
    ch = reg.replace_cluster([loaded])
    assert ch.added == ["gate-triage"] and not ch.changed and not ch.removed and reg.version == 1
    assert len(reg) == len(defs) + 1 and reg["gate-triage"].owner == OWNER and reg.source("gate-triage") == PIN
    assert [r["name"] for r in reg.records()] == ["gate-triage"] and reg.records()[0]["state"] == "loaded"
    # the same set again: no change, no version bump
    assert not reg.replace_cluster([loaded]) and reg.version == 1
    # a re-pin is a change
    repin = defn.from_pin(doc(), defn.Source(**{**PIN.__dict__, "commit": "b" * 40}), owner=OWNER)
    ch = reg.replace_cluster([repin])
    assert ch.changed == ["gate-triage"] and reg.source("gate-triage").commit == "b" * 40
    # the pin gone: removed, and the registry forgets it
    ch = reg.replace_cluster([])
    assert ch.removed == ["gate-triage"] and ch.sources["gate-triage"].commit == "b" * 40 and "gate-triage" not in reg


def test_two_pins_with_one_name_load_neither():
    reg = defn.Definitions({})
    a = defn.from_pin(doc(), PIN, owner=OWNER)
    b = defn.from_pin(doc(), defn.Source(**{**PIN.__dict__, "namespace": "app-other-cicd"}), owner=OWNER)
    ch = reg.replace_cluster([a, b])
    assert "gate-triage" not in reg and sorted(r.source.namespace for r in ch.rejected) == ["app-gate-api-cicd", "app-other-cicd"]


def test_rejections_are_reported_once_and_cleared_when_fixed():
    reg = defn.Definitions({})
    rej = defn.from_pin(doc(owner="group:default/x"), PIN, owner=OWNER)
    ch = reg.replace_cluster([], [rej])
    assert [r.name for r in ch.rejected] == ["gate-triage"] and reg.rejected == (rej,)
    assert not reg.replace_cluster([], [rej])                      # same rejection: nothing new
    ch = reg.replace_cluster([defn.from_pin(doc(), PIN, owner=OWNER)], [])
    assert ch.added == ["gate-triage"] and ch.cleared == [rej] and reg.rejected == ()


def test_apply_records_rebuilds_from_the_store():
    src = defn.Definitions({})
    src.replace_cluster([defn.from_pin(doc(), PIN, owner=OWNER)],
                        [defn.Rejected("bad-one", defn.Source(**{**PIN.__dict__, "xr": "bad-one"}), "schema: x")])
    rows = copy.deepcopy(src.records())
    reader = defn.Definitions({})
    ch = reader.apply_records(rows)
    assert ch.added == ["gate-triage"] and [r.name for r in ch.rejected] == ["bad-one"]
    assert reader["gate-triage"].owner == OWNER and reader.source("gate-triage") == PIN
    rows[0]["doc"]["profile"]["tierCeiling"] = "T9"                 # a row that no longer parses is shown, not dropped
    ch = defn.Definitions({}).apply_records(rows)
    assert [r.name for r in ch.rejected] == ["bad-one", "gate-triage"]


class Auth:
    def authenticate(self, token):
        if token == "run":
            return Principal("autopilot-runs/gate-triage", "workload", Tier.T1)
        raise AuthError("no")


@pytest.fixture
def g(defs, clock):
    counter = iter(range(1, 1000))
    reg = defn.Definitions(defs)
    return Gateway(reg, SessionStore(id_gen=lambda: f"s-{next(counter):06x}"), AuditLog(), Auth(), clock,
                   packs=(HANGAR,), definitions_store=defn.MemoryDefinitions())


def test_the_gateway_records_each_change_once_and_persists_the_set(g):
    loaded = defn.from_pin(doc(), PIN, owner=OWNER)
    ch = g.apply_cluster_definitions([loaded])
    assert ch.added == ["gate-triage"]
    recs = g.audit.records
    assert [(r["tool"], r["agent"], r["principal"], r["decision"], r["target"]) for r in recs] == [
        ("definition.load", "gate-triage", "pin:app-gate-api-cicd/gate-triage", "allow", PIN.pin)]
    assert recs[0]["result"] == f"loaded {PIN.pin}" and recs[0]["session"] is None
    assert [r["name"] for r in g.definitions_store.all()] == ["gate-triage"]
    # the same poll again: no record
    assert not g.apply_cluster_definitions([loaded]) and len(g.audit.records) == 1
    # a rejection is a deny record with the reason; a re-pin a second load; a removal an unload
    bad = defn.from_pin(doc(name="gate-two", owner="group:default/x"), defn.Source(**{**PIN.__dict__, "xr": "gate-two"}), owner=OWNER)
    repin = defn.from_pin(doc(), defn.Source(**{**PIN.__dict__, "commit": "c" * 40}), owner=OWNER)
    g.apply_cluster_definitions([repin], [bad])
    tools = [(r["tool"], r["decision"], r.get("rule")) for r in g.audit.records[1:]]
    assert tools == [("definition.load", "allow", None), ("definition.reject", "deny", "DF-PIN")]
    assert g.audit.records[1]["result"].startswith("re-pinned ") and "they must agree" in g.audit.records[2]["result"]
    assert sorted(r["state"] for r in g.definitions_store.all()) == ["loaded", "rejected"]
    g.apply_cluster_definitions([])
    assert g.audit.records[-1]["tool"] == "definition.unload" and g.definitions_store.all() == []


def test_a_loaded_pin_is_a_real_agent_for_sessions(g):
    g.apply_cluster_definitions([defn.from_pin(doc(), PIN, owner=OWNER)])
    r = g.open_session("run", "gate-triage")
    assert r.ok, r.data
    # a re-pin to a tighter definition applies to the live session: it is resolved by name on every call
    tighter = doc(); tighter["profile"]["tools"] = ["glidepath.runs.list"]
    g.apply_cluster_definitions([defn.from_pin(tighter, defn.Source(**{**PIN.__dict__, "commit": "d" * 40}), owner=OWNER)])
    assert g.defs["gate-triage"].limits.tools == frozenset({"glidepath.runs.list"})


def test_a_plain_dict_gateway_refuses_cluster_definitions(defs, clock):
    g = Gateway(defs, SessionStore(), AuditLog(), Auth(), clock, packs=(HANGAR,))
    with pytest.raises(TypeError):
        g.apply_cluster_definitions([])


class ApiAuth:
    def authenticate(self, token):
        if token == "aud":
            return Principal("aud/x", "workload", Tier.T1)
        raise AuthError("no")


class Store:
    def holds(self, now):
        return {}

    def definitions(self):
        return []


def test_the_api_shows_source_and_rejected(defs):
    reg = defn.Definitions(defs)
    reg.replace_cluster([defn.from_pin(doc(), PIN, owner=OWNER)],
                        [defn.Rejected("gate-two", defn.Source(**{**PIN.__dict__, "xr": "gate-two"}), "schema: boom")])
    app = api.create_api_app(Store(), api.Access(ApiAuth(), reg, auditors=("aud/*",)))
    c = TestClient(app)
    out = c.get("/v1/agents", headers={"Authorization": "Bearer aud"}).json()
    by = {a["name"]: a for a in out["items"]}
    assert by["gate-triage"]["source"] == PIN.view() and by["triage-agent"]["source"] == {"kind": "bundled", "pin": "bundled"}
    assert out["rejected"] == [{"name": "gate-two", "source": {**PIN.view(), "xr": "gate-two"}, "reason": "schema: boom"}]
    one = c.get("/v1/agents/gate-triage", headers={"Authorization": "Bearer aud"}).json()
    assert one["source"]["commit"] == PIN.commit and one["owner"] == OWNER


def test_the_api_over_a_plain_dict_has_no_source(defs):
    app = api.create_api_app(Store(), api.Access(ApiAuth(), defs, auditors=("aud/*",)))
    out = TestClient(app).get("/v1/agents", headers={"Authorization": "Bearer aud"}).json()
    assert out["rejected"] == [] and out["items"][0]["source"] is None
