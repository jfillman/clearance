"""PR provenance: a PR Clearance opened is confirmed and in scope; a forged trailer, an agents'-App PR with no
record, commits added after the agent's, and a path the definition denies all fail with their rule; a person's PR
passes as not-agent. Every verdict is recorded, and only a verifier may ask."""
import json

import pytest
from starlette.testclient import TestClient

from clearance import provenance
from clearance.audit import verify
from clearance.dispatch import AuthError, Principal
from clearance.server import create_http_app
from clearance.tiers import Tier

PR = {"repo": "jfillman/flight-api", "branch": "agent/t-1", "title": "fix probe",
      "files": [{"path": "charts/values.yaml", "content": "x"}, {"path": "./src/app.js", "content": "y"}]}
GATE = "app-flight-api-cicd/pipeline-runner"
BOT = "hangar-autopilot-agents[bot]"


@pytest.fixture
def pgw(gw):
    gw.auth.table["gate"] = Principal(GATE, "workload", Tier.T0)
    gw.verifiers, gw.agent_logins = ("app-*-cicd/pipeline-runner",), (BOT,)
    return gw


def opened(gw):
    sid = gw.open_session("alice", "coding-agent").data["session"]
    r = gw.call("alice", sid, "repo.pr.open", PR)
    assert r.ok
    s = gw.store.get(sid)
    return r.data, {"task": s.task_id, "session": sid, "agent": "coding-agent"}


def ask(gw, **kw):
    body = {"repo": "jfillman/flight-api", "pr": 1, "head": "0" * 39 + "1",
            "paths": ["charts/values.yaml", "src/app.js"], "author": BOT, **kw}
    return gw.provenance("gate", body)


def test_the_receipt_is_in_the_hashed_record_and_names_no_content(pgw):
    data, _ = opened(pgw)
    rec = pgw.audit.records[-1]
    assert rec["effect"] == {"pr": 1, "commit": data["commit"], "branch": "agent/t-1", "repo": "jfillman/flight-api",
                             "paths": ["charts/values.yaml", "src/app.js"]}
    assert "effect" in rec["verified"] and verify(pgw.audit.records)[0]
    assert '"x"' not in json.dumps(rec)


def test_a_pr_clearance_opened_is_confirmed_and_in_scope(pgw):
    _, trailers = opened(pgw)
    v = ask(pgw, trailers={"Task": trailers["task"], "Session": trailers["session"], "Agent": "coding-agent"})
    assert v["agent_pr"] and v["identity"]["status"] == "confirmed" and v["identity"]["ok"]
    assert v["scope"]["status"] == "in-scope" and v["scope"]["ok"]
    assert v["record"]["session"] == trailers["session"] and v["record"]["tool"] == "repo.pr.open"
    last = pgw.audit.records[-1]
    assert last["tool"] == "provenance.verify" and last["principal"] == GATE
    assert last["result"] == "identity:confirmed scope:in-scope" and last["target"] == "jfillman/flight-api#1"


def test_a_persons_pr_is_not_an_agent_pr(pgw):
    v = ask(pgw, author="jfillman", pr=7)
    assert not v["agent_pr"] and v["identity"]["status"] == "not-agent" and v["identity"]["ok"] and v["scope"]["ok"]


def test_a_forged_trailer_fails_identity(pgw):
    opened(pgw)
    v = ask(pgw, pr=2, author="jfillman", trailers={"task": "t-0123456789ab"})
    assert v["identity"]["rule"] == "AI001" and not v["identity"]["ok"] and not v["scope"]["ok"]


def test_an_agents_app_pr_without_a_record_fails_identity(pgw):
    v = ask(pgw, pr=9)
    assert v["identity"]["rule"] == "AI002" and not v["identity"]["ok"]


def test_commits_after_the_agents_fail_identity_and_extra_paths_fail_scope(pgw):
    opened(pgw)
    v = ask(pgw, head="f" * 40, paths=["charts/values.yaml", "src/app.js", "README.md"])
    assert v["identity"]["rule"] == "AI003"
    assert [x["rule"] for x in v["scope"]["violations"]] == ["AS001"] and v["scope"]["violations"][0]["path"] == "README.md"


def test_edited_trailers_fail_identity(pgw):
    _, trailers = opened(pgw)
    v = ask(pgw, trailers={"task": "t-ffffffffffff", "session": trailers["session"]})
    assert v["identity"]["rule"] == "AI004"


def test_a_denied_path_fails_scope_even_in_the_agents_own_commit(pgw):
    data, _ = opened(pgw)
    # A deny added to the definition since (or a receipt that names a path the policy refuses) still fails.
    pgw.audit.records[-1]["effect"]["paths"].append(".tekton/pr.yaml")
    v = ask(pgw, paths=["charts/values.yaml", ".tekton/pr.yaml"])
    assert v["identity"]["ok"] and [x["rule"] for x in v["scope"]["violations"]] == ["AS002"]


def test_only_a_verifier_may_ask(pgw):
    with pytest.raises(provenance.NotVerifier):
        pgw.provenance("alice", {"repo": "a/b", "pr": 1, "head": "0" * 40, "paths": []})


@pytest.mark.parametrize("body", [{}, {"repo": "nope", "pr": 1, "head": "0" * 40, "paths": []},
                                  {"repo": "a/b", "pr": 0, "head": "0" * 40, "paths": []},
                                  {"repo": "a/b", "pr": 1, "head": "abc", "paths": []},
                                  {"repo": "a/b", "pr": 1, "head": "0" * 40, "paths": "x"}])
def test_bad_requests_are_refused(pgw, body):
    with pytest.raises(provenance.BadRequest):
        pgw.provenance("gate", body)


class Tokens:
    def __init__(self, table):
        self.table = table

    def authenticate(self, token):
        if token not in self.table:
            raise AuthError("no")
        return self.table[token]


def test_http_route(pgw):
    opened(pgw)
    pgw.auth = Tokens(pgw.auth.table)
    app = create_http_app(pgw, resource_url="https://clearance.example/mcp", issuer_url="https://dex.example/dex")
    body = {"repo": "jfillman/flight-api", "pr": 1, "head": "0" * 39 + "1", "paths": ["charts/values.yaml", "src/app.js"]}
    with TestClient(app) as c:
        assert c.post("/v1/provenance", json=body).status_code == 401
        assert c.post("/v1/provenance", json=body, headers={"Authorization": "Bearer forged"}).status_code == 401
        assert c.post("/v1/provenance", json=body, headers={"Authorization": "Bearer alice"}).status_code == 403
        assert c.post("/v1/provenance", json={"repo": 1}, headers={"Authorization": "Bearer gate"}).status_code == 400
        r = c.post("/v1/provenance", json=body, headers={"Authorization": "Bearer gate"})
        assert r.status_code == 200 and r.json()["identity"]["status"] == "confirmed"
