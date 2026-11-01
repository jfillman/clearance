"""The deployment gate (gate.py, Gateway.register_change / clear_change / deny_change, the API's clearances routes):
tiers from a rendered diff, tighten-only clearance.yaml, who may clear, one record per step, expiry and supersession."""
import json
from datetime import timedelta

import pytest
from starlette.testclient import TestClient

from clearance import api, gate
from clearance import inbox as hr
from clearance.audit import AuditLog
from clearance.dispatch import AuthError, Gateway, Principal
from clearance.packs.hangar import HANGAR
from clearance.server import create_http_app
from clearance.session import SessionStore
from clearance.tiers import Tier

TOWER = "hangar-prod/app-backstage-prod/backstage"
HEAD = "a" * 40
BASE = "b" * 40
TREE = "c" * 64
OWNER = "group:default/team-gate"


def obj(kind, name, op="changed", fields=(), images=(), ns="app-gate-api-prod", api_version="apps/v1"):
    return {"apiVersion": api_version, "kind": kind, "namespace": ns, "name": name, "op": op, "fields": list(fields),
            "images": list(images), "digest": "d" * 64}


def change(objects=None, paths=None, checks=None, **over):
    body = {"app": "gate-api", "env": "prod", "cluster": "hangar-prod", "repo": "jfillman/gitops-gate-api", "pr": 7,
            "head": HEAD, "base": BASE, "proposer": "user:dana", "proposerKind": "person", "owner": OWNER, "protected": True,
            "treeDigest": TREE, "paths": paths if paths is not None else ["hangar-prod/prod/release.yaml"],
            "linesChanged": 4, "objects": objects if objects is not None else [], "checks": checks if checks is not None
            else {"ci": "pass", "provenance": "not-agent", "render": "ok", "admission": "pass"}}
    body.update(over)
    return body


IMAGE_BUMP = [obj("Rollout", "gate-api", fields=["/spec/template/spec/containers/0/image"],
                  images=["ghcr.io/jfillman/flight/gate-api@sha256:" + "e" * 64], api_version="argoproj.io/v1alpha1")]


# -- classification ------------------------------------------------------------------------------------------------
def classify(body, policy=gate.GatePolicy()):
    return gate.classify(gate.ChangeRequest.from_dict(body), policy)


def test_docs_only_is_tier_0_cleared_by_policy():
    c = classify(change(paths=["docs/runbook.md", "README.md"], objects=[]))
    assert (c.tier, c.decision) == (0, "clear") and c.requirement is None


def test_an_image_bump_with_green_checks_is_tier_1():
    c = classify(change(objects=IMAGE_BUMP))
    assert (c.tier, c.decision) == (1, "clear") and [r.rule for r in c.reasons if r.tier == 1] == ["image-bump"]


def test_an_image_bump_waits_for_ci_and_becomes_tier_2():
    c = classify(change(objects=IMAGE_BUMP, checks={"ci": "pending", "provenance": "not-agent", "render": "ok"}))
    assert (c.tier, c.decision) == (2, "hold") and "checks:ci" in [r.rule for r in c.reasons]
    assert c.requirement.owner == 1 and c.requirement.outside == 0 and c.requirement.owner_group == OWNER


def test_an_image_from_outside_the_flight_registry_is_tier_2():
    pol = gate.GatePolicy(flight_registries=("ghcr.io/jfillman/flight/",))
    assert classify(change(objects=IMAGE_BUMP), pol).tier == 1
    other = [dict(IMAGE_BUMP[0], images=["docker.io/library/nginx:latest"])]
    c = classify(change(objects=other), pol)
    assert c.tier == 2 and "image:not-flight-registry" in [r.rule for r in c.reasons]


def test_a_big_diff_is_not_a_tier_1_bump():
    assert classify(change(objects=IMAGE_BUMP, linesChanged=401)).tier == 2


def test_runtime_shape_is_tier_2():
    c = classify(change(objects=[obj("Rollout", "gate-api", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")]))
    assert (c.tier, c.decision) == (2, "hold")
    assert classify(change(objects=[obj("ConfigMap", "gate-api-config", fields=["/data/LOG_LEVEL"], api_version="v1")])).tier == 2
    assert classify(change(objects=[obj("Weird", "x", op="added", api_version="x.io/v1")])).tier == 2


def test_secrets_identity_and_policy_are_tier_3_however_small():
    assert classify(change(objects=[obj("Secret", "s", fields=["/metadata/labels/x"], api_version="v1")])).tier == 3
    assert classify(change(objects=[obj("ServiceAccount", "sa", op="added", api_version="v1")])).tier == 3
    c = classify(change(objects=[obj("Rollout", "gate-api", fields=["/spec/template/spec/containers/0/env/3/valueFrom/secretKeyRef/key"], api_version="argoproj.io/v1alpha1")]))
    assert c.tier == 3 and "field:secretKeyRef" in [r.rule for r in c.reasons]
    c = classify(change(paths=["hangar-prod/prod/values.yaml", "clearance.yaml"], objects=IMAGE_BUMP))
    assert c.tier == 3 and "path:clearance.yaml" in [r.rule for r in c.reasons]
    assert c.requirement.owner == 1 and c.requirement.outside == 1 and c.requirement.outside_groups == ("group:default/admins",)


def test_metadata_only_changes_are_tier_0():
    c = classify(change(objects=[obj("Rollout", "gate-api", fields=["/metadata/annotations/note"], api_version="argoproj.io/v1alpha1")]))
    assert c.tier == 0


def test_an_agents_pr_is_at_least_tier_1_and_an_unknown_one_is_denied():
    c = classify(change(paths=["docs/x.md"], objects=[], proposerKind="agent", proposer="autopilot-runs/release-proposer", agent="release-proposer"))
    assert (c.tier, c.decision) == (1, "clear") and "provenance:agent" in [r.rule for r in c.reasons]
    c = classify(change(objects=IMAGE_BUMP, proposerKind="unknown"))
    assert (c.decision, c.rule) == ("deny", "DG-PROVENANCE")


def test_clearance_yaml_tightens_and_never_loosens():
    tighter = {"tiers": {"3": {"kinds": ["ConfigMap"]}, "2": {"paths": ["**/values.yaml"]}}, "approvers": {"2": {"owner": 2}}, "ttlDays": 2}
    c = classify(change(objects=[obj("ConfigMap", "cm", fields=["/data/x"], api_version="v1")], policy=tighter))
    assert c.tier == 3 and c.policy.ttl_days == 2 and c.policy.repo_policy_digest
    c = classify(change(objects=[obj("Rollout", "r", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")], policy=tighter))
    assert c.requirement.owner == 2
    c = classify(change(paths=["hangar-prod/prod/values.yaml"], objects=[], policy=tighter))
    assert c.tier == 2 and "path:tier2" in [r.rule for r in c.reasons]
    for loosening, msg in [({"approvers": {"3": {"outside": 0}}}, "raised"), ({"ttlDays": 30}, "shortened"),
                           ({"tiers": {"1": {"kinds": ["Secret"]}}}, "tiers names 2 and 3"), ({"surprise": 1}, "unknown key")]:
        with pytest.raises(gate.GateError) as e:
            classify(change(objects=IMAGE_BUMP, policy=loosening))
        assert e.value.rule == "DG-POLICY" and msg in e.value.message


@pytest.mark.parametrize("bad, msg", [
    ({**change(), "head": "short"}, "head"), ({**change(), "pr": -1}, "pr"), ({**change(), "owner": "team"}, "owner"),
    ({**change(), "treeDigest": "x"}, "treeDigest"), ({**change(), "proposerKind": "robot"}, "proposerKind"),
    ({**change(), "objects": [{"kind": "Secret"}]}, "objects[]"), ({**change(), "checks": {"ci": 1}}, "checks"),
    ({**change(), "policy": "no"}, "policy"), ("nope", "JSON object"),
])
def test_a_malformed_change_is_refused(bad, msg):
    with pytest.raises(gate.BadChange) as e:
        gate.ChangeRequest.from_dict(bad)
    assert msg in str(e.value)


def test_the_change_id_is_the_pr_head():
    a, b = gate.ChangeRequest.from_dict(change()), gate.ChangeRequest.from_dict(change(head="f" * 40))
    assert a.id.startswith("ch-") and a.id != b.id and a.id == gate.ChangeRequest.from_dict(change()).id


# -- the gateway ---------------------------------------------------------------------------------------------------
class Auth:
    table = {"ci": Principal("app-gate-api-cicd/pipeline-runner", "workload", Tier.T1),
             "other": Principal("ns/other", "workload", Tier.T1), "tower": Principal(TOWER, "workload", Tier.T1),
             "dana": Principal("user:dana", "user", Tier.T1), "erin": Principal("user:erin", "user", Tier.T1),
             "fay": Principal("user:fay", "user", Tier.T1), "root": Principal("user:root", "user", Tier.T1),
             "sam": Principal("user:sam", "user", Tier.T1)}

    def authenticate(self, token):
        if token not in self.table:
            raise AuthError("no")
        return self.table[token]


class Groups:
    def groups(self, principal):
        return {"user:dana": {OWNER}, "user:erin": {OWNER}, "user:fay": {OWNER, "group:default/admins"},
                "user:root": {"group:default/admins"}}.get(principal, set())


class Owners:
    def owner_of(self, app):
        return {"gate-api": OWNER}.get(app)


@pytest.fixture
def g(defs, clock):
    counter = iter(range(1, 1000))
    return Gateway(defs, SessionStore(id_gen=lambda: f"s-{next(counter):06x}"), AuditLog(), Auth(), clock,
                   packs=(HANGAR,), inbox=hr.MemoryInbox(), directory=Groups(), delegates=(TOWER,),
                   verifiers=("app-*-cicd/pipeline-runner",), admins=("user:root",), changes=gate.MemoryChanges(),
                   gate_policy=gate.GatePolicy(), owners=Owners())


def records(g, tool=None):
    return [r for r in g.audit.records if tool is None or r["tool"] == tool]


def test_only_a_verifier_may_register_and_the_gate_can_be_off(g, defs, clock):
    with pytest.raises(AuthError):
        g.register_change("nobody", change())
    from clearance import provenance
    with pytest.raises(provenance.NotVerifier):
        g.register_change("other", change())
    with pytest.raises(gate.BadChange):
        g.register_change("ci", {"app": "x"})
    off = Gateway(defs, SessionStore(), AuditLog(), Auth(), clock, packs=(HANGAR,), verifiers=("app-*-cicd/pipeline-runner",))
    with pytest.raises(gate.GateError) as e:
        off.register_change("ci", change())
    assert e.value.rule == "DG-OFF"


def test_a_tier_1_change_is_cleared_by_policy_with_two_records(g):
    out = g.register_change("ci", change(objects=IMAGE_BUMP))
    assert out["state"] == "cleared" and out["cleared_by"] == "policy" and out["tier"] == 1
    recs = records(g)
    assert [(r["tool"], r["principal"], r["decision"]) for r in recs] == [
        ("deploy.request", "app-gate-api-cicd/pipeline-runner", "allow"), ("deploy.clear", "policy", "allow")]
    assert recs[0]["boundary"] == "deployment" and recs[0]["app"] == "gate-api" and recs[0]["target"] == "jfillman/gitops-gate-api#7@aaaaaaa"
    assert recs[0]["change"]["tier"] == 1 and "change" in recs[0]["claimed"] and "target" in recs[0]["verified"]
    # again: nothing changes, nothing is recorded
    assert g.register_change("ci", change(objects=IMAGE_BUMP))["state"] == "cleared" and len(records(g)) == 2


def test_a_holding_change_clears_when_ci_passes_on_re_registration(g):
    out = g.register_change("ci", change(objects=IMAGE_BUMP, checks={"ci": "pending", "provenance": "not-agent", "render": "ok"}))
    assert out["state"] == "holding" and out["tier"] == 2 and out["requirement"]["owner"] == 1
    assert records(g)[-1]["result"].startswith("tier 2: holding for 1 from group:default/team-gate")
    out = g.register_change("ci", change(objects=IMAGE_BUMP))
    assert out["state"] == "cleared" and out["tier"] == 1 and out["cleared_by"] == "policy"
    assert [r["tool"] for r in records(g)] == ["deploy.request", "deploy.clear"]


def test_who_may_clear_a_tier_2_change(g):
    cid = g.register_change("ci", change(objects=[obj("Rollout", "gate-api", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")]))["id"]
    # the proposer may not; a stranger may not; a person in neither group may not
    with pytest.raises(gate.GateError) as e:
        g.clear_change("dana", cid)
    assert e.value.rule == "DG-PROPOSER" and e.value.status == 403
    with pytest.raises(gate.GateError) as e:
        g.clear_change("sam", cid)
    assert e.value.rule == "DG-FORBIDDEN"
    with pytest.raises(AuthError):
        g.clear_change("nobody", cid)
    # an owner-group member through Tower clears it
    out = g.clear_change("tower", cid, on_behalf_of="user:erin")
    assert out["state"] == "cleared" and out["cleared_by"] == "people"
    assert out["approvals"] == [{"person": "user:erin", "via": TOWER, "role": "owner", "at": "2026-09-26T12:00:00Z"}]
    rec = records(g, "deploy.clear")[-1]
    assert (rec["principal"], rec["decision"]) == ("user:erin", "allow") and rec["result"].endswith(f"via {TOWER}")
    with pytest.raises(gate.GateError) as e:
        g.clear_change("erin", cid)
    assert e.value.rule == "DG-STATE"


def test_a_tier_3_change_needs_two_people_one_from_outside(g):
    cid = g.register_change("ci", change(objects=[obj("Secret", "db", fields=["/data/password"], api_version="v1")]))["id"]
    out = g.clear_change("erin", cid)                     # owner group: one of two
    assert out["state"] == "holding" and out["approvals"][0]["role"] == "owner"
    with pytest.raises(gate.GateError) as e:
        g.clear_change("erin", cid)                        # not twice
    assert e.value.rule == "DG-TWICE"
    with pytest.raises(gate.GateError) as e:
        g.clear_change("dana", cid)                        # the proposer, even from the owner group
    assert e.value.rule == "DG-PROPOSER"
    # a second owner-group member does not count as outside
    with pytest.raises(gate.GateError) as e:
        g.clear_change("sam", cid)
    assert e.value.rule == "DG-FORBIDDEN"
    out = g.clear_change("root", cid)                      # admins: the outside group
    assert out["state"] == "cleared" and [a["role"] for a in out["approvals"]] == ["owner", "outside"]
    assert records(g, "deploy.clear")[-1]["result"] == "cleared as outside (requirement met)"


def test_a_person_in_both_groups_counts_once(g):
    cid = g.register_change("ci", change(objects=[obj("Secret", "db", fields=["/data/password"], api_version="v1")]))["id"]
    out = g.clear_change("fay", cid)                       # owner first
    assert out["approvals"][0]["role"] == "owner" and out["state"] == "holding"
    with pytest.raises(gate.GateError) as e:
        g.clear_change("fay", cid)
    assert e.value.rule == "DG-TWICE"
    assert g.clear_change("root", cid)["state"] == "cleared"


def test_deny_with_a_reason(g):
    cid = g.register_change("ci", change(objects=[obj("Rollout", "gate-api", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")]))["id"]
    with pytest.raises(gate.GateError) as e:
        g.deny_change("erin", cid, "")
    assert e.value.rule == "DG-REASON"
    with pytest.raises(gate.GateError) as e:
        g.deny_change("sam", cid, "no")
    assert e.value.rule == "DG-FORBIDDEN"
    out = g.deny_change("tower", cid, "the replica count is wrong for prod", on_behalf_of="user:erin")
    assert out["state"] == "denied" and out["denied_by"] == "user:erin" and out["deny_reason"] == "the replica count is wrong for prod"
    rec = records(g, "deploy.deny")[-1]
    assert (rec["decision"], rec["rule"], rec["principal"]) == ("deny", "DG-DENIED", "user:erin")
    with pytest.raises(gate.GateError) as e:
        g.clear_change("erin", cid)
    assert e.value.rule == "DG-STATE"


def test_an_unknown_proposer_and_a_loosening_policy_are_denied_by_policy(g):
    out = g.register_change("ci", change(objects=IMAGE_BUMP, proposerKind="unknown"))
    assert out["state"] == "denied" and out["denied_by"] == "policy"
    assert [(r["tool"], r["rule"]) for r in records(g)] == [("deploy.request", None), ("deploy.deny", "DG-PROVENANCE")]
    out = g.register_change("ci", change(objects=IMAGE_BUMP, head="1" * 40, policy={"ttlDays": 99}))
    assert out["state"] == "denied" and records(g, "deploy.deny")[-1]["rule"] == "DG-POLICY"


def test_a_new_head_supersedes_the_holding_one_and_the_ttl_expires(g, clock):
    first = g.register_change("ci", change(objects=[obj("Rollout", "gate-api", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")]))
    second = g.register_change("ci", change(objects=[obj("Rollout", "gate-api", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")], head="2" * 40))
    old = g.changes.get(first["id"])
    assert old.state == "superseded" and old.superseded_by == "2" * 40
    assert records(g, "deploy.expire")[-1]["result"] == "superseded by 2222222"
    clock.advance(days=7, seconds=1)
    assert g.expire_changes() == [second["id"]]
    assert g.changes.get(second["id"]).state == "expired" and records(g, "deploy.expire")[-1]["result"] == "not cleared within 7 days"
    with pytest.raises(gate.GateError) as e:
        g.clear_change("erin", second["id"])
    assert e.value.rule == "DG-STATE"
    # the sweep that closes sessions also expires changes
    third = g.register_change("ci", change(objects=[obj("Rollout", "gate-api", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")], head="3" * 40))
    clock.advance(days=8)
    g.expire()
    assert g.changes.get(third["id"]).state == "expired"


def test_the_owner_group_comes_from_the_catalog_when_the_check_does_not_say(g):
    body = change(objects=[obj("Rollout", "gate-api", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")])
    del body["owner"]
    out = g.register_change("ci", body)
    assert out["owner"] == OWNER and out["requirement"]["ownerGroup"] == OWNER


def test_the_owner_group_can_be_omitted_only_when_something_answers(g):
    g.owners = None
    body = change(objects=IMAGE_BUMP, app="orphan-app")
    del body["owner"]
    out = g.register_change("ci", body)
    assert out["owner"] == "group:default/admins"      # the outside group stands in: admins clear it


# -- HTTP ------------------------------------------------------------------------------------------------------------
def test_http_routes(g):
    c = TestClient(create_http_app(g, resource_url="https://clearance.example/mcp", issuer_url="https://dex.example/dex"))
    assert c.post("/v1/clearances", json=change()).status_code == 401
    assert c.post("/v1/clearances", json=change(), headers={"Authorization": "Bearer other"}).status_code == 403
    r = c.post("/v1/clearances", json={"app": "x"}, headers={"Authorization": "Bearer ci"})
    assert r.status_code == 400
    r = c.post("/v1/clearances", json=change(objects=[obj("Rollout", "r", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")]), headers={"Authorization": "Bearer ci"})
    assert r.status_code == 200 and r.json()["state"] == "holding"
    cid = r.json()["id"]
    r = c.post(f"/v1/clearances/{cid}/clear", headers={"Authorization": "Bearer dana"})
    assert r.status_code == 403 and r.json()["rule"] == "DG-PROPOSER"
    r = c.post(f"/v1/clearances/{cid}/deny", json={"reason": ""}, headers={"Authorization": "Bearer erin"})
    assert r.status_code == 400 and r.json()["rule"] == "DG-REASON"
    r = c.post(f"/v1/clearances/{cid}/clear", headers={"Authorization": "Bearer tower", "X-Hangar-On-Behalf-Of": "user:erin"})
    assert r.status_code == 200 and r.json()["state"] == "cleared"
    assert c.post("/v1/clearances/nope/clear", headers={"Authorization": "Bearer erin"}).status_code == 404


# -- the read API --------------------------------------------------------------------------------------------------
class ApiAuth:
    def authenticate(self, token):
        t = {"aud": Principal("aud/x", "workload", Tier.T1), "erin": Principal("user:erin", "user", Tier.T1),
             "sam": Principal("user:sam", "user", Tier.T1)}
        if token not in t:
            raise AuthError("no")
        return t[token]


class Store:
    def __init__(self, changes):
        self.c = changes

    def holds(self, now):
        return {}

    def definitions(self):
        return []

    def _vis(self, c, v):
        req = c.get("requirement") or {}
        return v.all or c["app"] in v.apps or c.get("owner") in v.groups or any(gr in v.groups for gr in req.get("outsideGroups") or [])

    def changes(self, f, v, limit, after):
        out = [c for c in self.c if self._vis(c, v) and all(str(c.get(k)) == str(x) for k, x in f.items() if k not in ("since",))]
        return sorted(out, key=lambda c: c["updated_at"], reverse=True)[:limit]

    def change(self, cid):
        return next((c for c in self.c if c["id"] == cid), None)

    def change_counts(self, f, v, by):
        from collections import Counter
        return [{"key": k, "count": n} for k, n in Counter(str(c.get(by)) for c in self.c if self._vis(c, v)).items()]


def test_the_api_lists_changes_the_person_may_clear_or_owns(g, clock):
    g.register_change("ci", change(objects=[obj("Rollout", "r", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")]))
    g.register_change("ci", change(objects=IMAGE_BUMP, head="2" * 40, pr=8, app="other-app", repo="jfillman/gitops-other-app", owner="group:default/team-other"))
    rows = [c.view() for c in g.changes.all()]
    app = api.create_api_app(Store(rows), api.Access(ApiAuth(), g.defs, auditors=("aud/*",), directory=Groups()), gate_policy=gate.GatePolicy())
    c = TestClient(app)
    everything = c.get("/v1/clearances", headers={"Authorization": "Bearer aud"}).json()
    assert len(everything["items"]) == 2
    mine = c.get("/v1/clearances", headers={"Authorization": "Bearer erin"}).json()["items"]
    assert [x["app"] for x in mine] == ["gate-api"]
    assert c.get("/v1/clearances", headers={"Authorization": "Bearer sam"}).json()["items"] == []
    one = c.get(f"/v1/clearances/{rows[0]['id']}", headers={"Authorization": "Bearer erin"}).json()
    assert one["tier"] == 2 and one["reasons"][0]["rule"] == "kind:Rollout"
    assert c.get(f"/v1/clearances/{rows[1]['id']}", headers={"Authorization": "Bearer erin"}).status_code == 404
    counts = c.get("/v1/clearances/counts?by=state", headers={"Authorization": "Bearer aud"}).json()
    assert counts["total"] == 2 and {i["key"] for i in counts["items"]} == {"holding", "cleared"}
    assert c.get("/v1/clearances/counts?by=nope", headers={"Authorization": "Bearer aud"}).status_code == 400
    assert c.get("/v1/clearances?state=odd", headers={"Authorization": "Bearer aud"}).status_code == 400
    pol = c.get("/v1/clearance-policy", headers={"Authorization": "Bearer erin"}).json()
    assert pol["approvers"]["3"] == {"owner": 1, "outside": 1} and "Secret" in pol["tiers"]["3"]["kinds"] and pol["ttlDays"] == 7


def test_the_api_without_a_gate_policy_answers_404(g):
    app = api.create_api_app(Store([]), api.Access(ApiAuth(), g.defs, auditors=("aud/*",)))
    assert TestClient(app).get("/v1/clearance-policy", headers={"Authorization": "Bearer aud"}).status_code == 404
