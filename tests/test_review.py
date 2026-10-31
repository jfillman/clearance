"""review.py: validating a definition before it is live, and tiering its change (Autopilot M4's release flow); the
gateway's POST /v1/definitions/review; and the deployment gate tiering a definition release."""
import copy

import pytest
import yaml
from starlette.testclient import TestClient

from clearance import gate, review
from clearance.audit import AuditLog
from clearance.dispatch import AuthError, Gateway, Principal
from clearance.packs.hangar import HANGAR
from clearance.policy import Policy
from clearance.server import create_http_app
from clearance.session import SessionStore
from clearance.tiers import Tier


TOOLS = Policy((HANGAR,)).tools
IMG = "ghcr.io/jfillman/autopilot-agent-runtime@sha256:" + "a" * 64


BASE = yaml.safe_load(f"""
name: gate-triage
owner: group:default/team-gate
kind: event
identity: {{type: workload, serviceAccount: autopilot-runs/gate-triage}}
profile:
  tierCeiling: T1
  tools: [glidepath.runs.list, glidepath.run.get, glidepath.logs.get, glidepath.explain, repo.file.get, repo.pr.open]
  glidepath: {{apps: [gate-api]}}
  repos: {{allow: [jfillman/gate-api]}}
  models: [claude-sonnet-5-5]
  network: clearance+model
  compute: small
  limits: {{ttlMinutes: 20, toolCalls: 60, githubCalls: 40, openPrs: 1, modelTokens: 400000, children: 0}}
runtime:
  image: {IMG}
  framework: generic
  instructions: Find out why.
triggers:
  - {{type: event, source: glidepath, bindingKey: gate-api.pipelinerun.finished, match: {{subject.content.outcome: failure}}, maxPerHour: 4}}
""")


def doc(**over):
    d = copy.deepcopy(BASE)
    d.update(over)
    return d


def prof(d, **kw):
    d = copy.deepcopy(d)
    d["profile"].update(kw)
    return d


def rules(problems):
    return [p.rule for p in problems]


def test_a_good_definition_has_no_problems():
    assert review.validate(doc(), TOOLS, name="gate-triage", owner="group:default/team-gate", path="agents/gate-triage.yaml") == []


def test_validation_finds_what_a_pin_or_a_call_would_refuse():
    assert rules(review.validate("nope", TOOLS)) == ["DF-SCHEMA"]
    assert rules(review.validate(prof(doc(), tierCeiling="T9"), TOOLS)) == ["DF-SCHEMA"]
    assert rules(review.validate(doc(), TOOLS, path="agents/other.yaml")) == ["DF-NAME"]
    assert rules(review.validate(doc(), TOOLS, name="x")) == ["DF-NAME"]
    assert rules(review.validate(doc(), TOOLS, owner="group:default/x")) == ["DF-OWNER"]
    assert rules(review.validate(doc(identity={"type": "workload", "serviceAccount": "autopilot-runs/x"}), TOOLS)) == ["DF-IDENTITY"]
    d = prof(doc(), tools=["glidepath.runs.list", "no.such.tool"])
    assert rules(review.validate(d, TOOLS)) == ["DF-TOOL"]
    d = prof(doc(), tierCeiling="T0")                       # repo.pr.open is T1
    assert "DF-CEILING" in rules(review.validate(d, TOOLS))
    d = prof(doc(), repos={"allow": []})
    assert rules(review.validate(d, TOOLS)) == ["DF-REPOS"]
    assert rules(review.validate(doc(), TOOLS, models=["claude-haiku-5-5"])) == ["DF-MODEL"]
    d = doc(); d["runtime"]["image"] = "ghcr.io/x/y:latest"
    assert rules(review.validate(d, TOOLS)) in (["DF-IMAGE"], ["DF-SCHEMA"])   # the schema may already refuse a tag
    assert rules(review.validate(doc(), TOOLS, image_allow=("ghcr.io/jfillman/autopilot-agent-runtime@*",))) == []
    assert rules(review.validate(doc(), TOOLS, image_allow=("ghcr.io/jfillman/runtime-*@*",))) == ["DF-IMAGE"]


def test_classify_tiers_a_change_by_what_the_agent_may_do_after_it():
    base = doc()
    t, ch = review.classify(base, copy.deepcopy(base), TOOLS)
    assert (t, [c.change for c in ch]) == (0, ["no change in authority"])
    d = copy.deepcopy(base); d["runtime"]["instructions"] = "Be brief."
    assert review.classify(base, d, TOOLS)[0] == 0
    # narrowing only: tier 1
    assert review.classify(base, prof(base, tools=["glidepath.runs.list", "glidepath.run.get", "repo.pr.open"]), TOOLS)[0] == 1
    d = prof(base, limits={**base["profile"]["limits"], "toolCalls": 10})
    assert review.classify(base, d, TOOLS) == (1, [review.Change("profile.limits.toolCalls", "60 -> 10", 1)])
    assert review.classify(base, None, TOOLS)[0] == 1
    # spending more or running more often: tier 2
    d = prof(base, limits={**base["profile"]["limits"], "modelTokens": 900000})
    assert review.classify(base, d, TOOLS)[0] == 2
    d = copy.deepcopy(base); d["triggers"][0]["maxPerHour"] = 12
    t, ch = review.classify(base, d, TOOLS)
    assert t == 2 and "maxPerHour 4 -> 12" in ch[0].change
    d = copy.deepcopy(base); d["runtime"]["image"] = IMG.replace("a" * 64, "b" * 64)
    assert review.classify(base, d, TOOLS)[0] == 2
    d = prof(base, tools=base["profile"]["tools"] + ["catalog.read"])
    assert review.classify(base, d, TOOLS) == (2, [review.Change("profile.tools", "added catalog.read (T0)", 2)])
    # touching more: tier 3
    d = prof(base, tierCeiling="T2")
    assert review.classify(base, d, TOOLS)[0] == 3
    d = prof(base, repos={"allow": ["jfillman/gate-api", "jfillman/baggage-api"]})
    t, ch = review.classify(base, d, TOOLS)
    assert t == 3 and ch[0].field == "profile.repos.allow" and ch[0].change == "added jfillman/baggage-api"
    d = prof(base, glidepath={"apps": ["gate-api", "flight-api"]})
    assert review.classify(base, d, TOOLS)[0] == 3
    d = doc(owner="group:default/other")
    assert review.classify(base, d, TOOLS)[0] == 3
    d = prof(base, network="allowlist")
    assert review.classify(base, d, TOOLS)[0] == 3
    # a new agent: 3 with a writing tool, 2 with reads only
    assert review.classify(None, base, TOOLS)[0] == 3
    assert review.classify(None, prof(base, tools=["glidepath.runs.list"], repos={}), TOOLS)[0] == 2
    # the tier is the maximum: narrowing one thing does not offset widening another
    d = prof(base, tierCeiling="T2", limits={**base["profile"]["limits"], "toolCalls": 10})
    assert review.classify(base, d, TOOLS)[0] == 3


class Auth:
    t = {"ci": Principal("app-gate-api-cicd/pipeline-runner", "workload", Tier.T1), "dana": Principal("user:dana", "user", Tier.T1), "erin": Principal("user:erin", "user", Tier.T1),
         "tower": Principal("hangar-prod/app-backstage-prod/backstage", "workload", Tier.T1), "svc": Principal("ns/svc", "workload", Tier.T1)}

    def authenticate(self, token):
        if token not in self.t:
            raise AuthError("no")
        return self.t[token]


class Groups:
    def groups(self, p):
        return {"group:default/team-gate"} if p == "user:erin" else set()


@pytest.fixture
def g(defs, clock):
    return Gateway(defs, SessionStore(), AuditLog(), Auth(), clock, packs=(HANGAR,), directory=Groups(),
                   verifiers=("app-*-cicd/pipeline-runner",), delegates=("hangar-prod/app-backstage-prod/backstage",),
                   changes=gate.MemoryChanges(), runtime_images=("ghcr.io/jfillman/autopilot-agent-runtime@*",))


def test_the_review_route(g):
    c = TestClient(create_http_app(g, resource_url="https://c.example/mcp", issuer_url="https://dex.example"))
    assert c.post("/v1/definitions/review", json={"doc": doc()}).status_code == 401
    assert c.post("/v1/definitions/review", json={"doc": doc()}, headers={"Authorization": "Bearer svc"}).status_code == 403
    r = c.post("/v1/definitions/review", json={"doc": doc(), "path": "agents/gate-triage.yaml"}, headers={"Authorization": "Bearer ci"}).json()
    assert r == {"ok": True, "problems": [], "tier": 3, "changes": [{"field": "agent", "change": "new agent with writing tools repo.file.get, repo.pr.open", "tier": 3}]} or r["tier"] == 3
    bad = doc(); bad["runtime"]["image"] = "docker.io/x/y@sha256:" + "c" * 64
    r = c.post("/v1/definitions/review", json={"doc": bad}, headers={"Authorization": "Bearer dana"}).json()
    assert r["ok"] is False and [p["rule"] for p in r["problems"]] == ["DF-IMAGE"] and "tier" not in r
    r = c.post("/v1/definitions/review", json={"doc": doc(), "old": doc()}, headers={"Authorization": "Bearer tower", "X-Hangar-On-Behalf-Of": "user:dana"}).json()
    assert r["tier"] == 0
    assert c.post("/v1/definitions/review", json={}, headers={"Authorization": "Bearer ci"}).status_code == 400


def release(old, new, **over):
    body = {"app": "gate-api", "env": "agents", "cluster": "hangar-dev", "repo": "jfillman/gitops-hangar-dev-tenants", "pr": 40,
            "head": "e" * 40, "proposer": "user:dana", "owner": "group:default/team-gate", "treeDigest": "f" * 64,
            "paths": ["tenants/gate-api/xr-requests/gate-triage.yaml"], "checks": {"ci": "pass"},
            "definition": {"name": "gate-triage", "path": "agents/gate-triage.yaml", "old": old, "new": new}}
    body.update(over)
    return body


def test_the_gate_tiers_a_definition_release(g):
    narrower = prof(doc(), limits={**doc()["profile"]["limits"], "toolCalls": 10})
    out = g.register_change("ci", release(doc(), narrower))
    assert (out["tier"], out["state"], out["cleared_by"]) == (1, "cleared", "policy")
    assert out["reasons"] == [{"subject": "agent gate-triage: profile.limits.toolCalls", "rule": "60 -> 10", "tier": 1}]
    wider = prof(doc(), repos={"allow": ["jfillman/gate-api", "jfillman/baggage-api"]})
    out = g.register_change("ci", release(doc(), wider, head="1" * 40, pr=41))
    assert (out["tier"], out["state"]) == (3, "holding") and out["requirement"]["outside"] == 1
    assert g.clear_change("erin", out["id"])["state"] == "holding"
    broken = doc(); broken["runtime"]["image"] = "docker.io/x@sha256:" + "c" * 64
    out = g.register_change("ci", release(doc(), broken, head="2" * 40, pr=42))
    assert out["state"] == "denied" and "DF-IMAGE" in out["reasons"][0]["rule"]
    assert [r["rule"] for r in g.audit.records if r["tool"] == "deploy.deny"][-1] == "DG-DEFINITION"
    out = g.register_change("ci", release(None, doc(), head="3" * 40, pr=43))
    assert (out["tier"], out["state"]) == (3, "holding")


def test_a_malformed_definition_release_is_refused():
    with pytest.raises(gate.BadChange):
        gate.ChangeRequest.from_dict(release(None, None))
    with pytest.raises(gate.BadChange):
        gate.ChangeRequest.from_dict({**release(doc(), doc()), "definition": {"name": "Bad Name"}})
