"""Phase 2 of the Clearance GitHub App: a custom deployment protection rule (github_app.py protect / deliver_answers,
Gateway.deployment_requested / undelivered_deployments / deployment_delivered). A GitHub Actions deployment waits on
the deployment gate's change for that commit and environment: approved when cleared, rejected when denied, expired,
superseded or never registered, and a held change answers the waiting deployment when people decide."""
import json

import pytest

from clearance import github_app as ga
from test_gate import IMAGE_BUMP, change, g, obj, records  # noqa: F401 - g is the gate's gateway fixture
from test_github_app import keys, make  # noqa: F401 - keys is the App's key fixture

HEAD = "a" * 40
REPO = "jfillman/gitops-gate-api"
CALLBACK = f"https://api.github.com/repos/{REPO}/actions/runs/555/deployment_protection_rule"
REPLICAS = [obj("Rollout", "gate-api", fields=["/spec/replicas"], api_version="argoproj.io/v1alpha1")]


class FakeGitHub:
    def __init__(self, fail=False):
        self.reviews, self.tokens, self.fail = [], [], fail

    def __call__(self, req, timeout):
        body = json.loads(req.data) if req.data else None
        path = req.full_url.replace("https://api.github.com", "")
        if path.endswith("/access_tokens"):
            self.tokens.append(body)
            return 201, json.dumps({"token": "inst-token"}).encode()
        if path.endswith("/deployment_protection_rule"):
            if self.fail:
                return 502, b"{}"
            self.reviews.append((path, body))
            return 204, b""
        return 404, b"{}"


def event(environment="prod", sha=HEAD, callback=CALLBACK, repo=REPO):
    return {"action": "requested", "environment": environment, "event": "push", "deployment": {"sha": sha},
            "deployment_callback_url": callback, "repository": {"full_name": repo}, "installation": {"id": 9}}


def app_for(g, keys, fake):
    return make(g, keys, fake)


def test_the_event_is_wanted_and_the_token_asks_for_deployments_only(g, keys):
    fake = FakeGitHub()
    app = app_for(g, keys, fake)
    assert app.wanted("deployment_protection_rule", {"action": "requested"})
    g.register_change("ci", change(objects=IMAGE_BUMP))
    app.handle("deployment_protection_rule", event())
    assert fake.tokens[0] == {"repositories": ["gitops-gate-api"],
                              "permissions": {"deployments": "write", "actions": "read", "metadata": "read"}}


def test_a_cleared_change_approves_the_deployment_and_records_it(g, keys):
    fake = FakeGitHub()
    g.register_change("ci", change(objects=IMAGE_BUMP))                      # tier 1: cleared by policy
    out = app_for(g, keys, fake).handle("deployment_protection_rule", event(environment="Prod"))
    assert out == [{"run": 555, "environment": "Prod", "answer": "approved"}]
    path, body = fake.reviews[0]
    assert path == f"/repos/{REPO}/actions/runs/555/deployment_protection_rule"
    assert body["state"] == "approved" and body["environment_name"] == "Prod" and "Cleared by policy" in body["comment"]
    assert [(r["tool"], r["principal"]) for r in records(g)][-2:] == [("deploy.request", "app:9"), ("deploy.answer", "app:9")]
    assert g.undelivered_deployments() == []


def test_an_unregistered_commit_is_rejected(g, keys):
    fake = FakeGitHub()
    app_for(g, keys, fake).handle("deployment_protection_rule", event(sha="f" * 40))
    body = fake.reviews[0][1]
    assert body["state"] == "rejected" and "clearance register" in body["comment"]
    rec = records(g, "deploy.request")[-1]
    assert (rec["decision"], rec["rule"], rec["principal"]) == ("deny", "DG-UNREGISTERED", "app:9")


def test_another_environment_does_not_match(g, keys):
    fake = FakeGitHub()
    g.register_change("ci", change(objects=IMAGE_BUMP))                      # env prod
    app_for(g, keys, fake).handle("deployment_protection_rule", event(environment="staging"))
    assert fake.reviews[0][1]["state"] == "rejected"


def test_a_held_change_keeps_the_deployment_waiting_until_people_clear_it(g, keys):
    fake = FakeGitHub()
    app = app_for(g, keys, fake)
    cid = g.register_change("ci", change(objects=REPLICAS))["id"]           # tier 2: holds for the owner group
    assert app.handle("deployment_protection_rule", event()) == [{"run": 555, "environment": "prod", "answer": None}]
    body = fake.reviews[0][1]
    assert "state" not in body and "Held for people" in body["comment"]  # a status report, the run keeps waiting
    poked = []
    g.deployment_listeners.append(lambda: poked.append(1))
    g.clear_change("erin", cid)
    assert poked and g.undelivered_deployments()[0]["answer"] == "approved"
    assert app.deliver_answers() == [{"run": 555, "environment": "prod", "answer": "approved"}]
    assert fake.reviews[-1][1]["state"] == "approved"
    assert g.undelivered_deployments() == []


def test_a_denied_change_rejects_the_waiting_deployment(g, keys):
    fake = FakeGitHub()
    app = app_for(g, keys, fake)
    cid = g.register_change("ci", change(objects=REPLICAS))["id"]
    app.handle("deployment_protection_rule", event())
    g.deny_change("erin", cid, "not this week")
    app.deliver_answers()
    assert fake.reviews[-1][1]["state"] == "rejected" and "not this week" in fake.reviews[-1][1]["comment"]


def test_expiry_rejects_and_a_failed_delivery_is_retried(g, keys, clock):
    fake = FakeGitHub(fail=True)
    app = app_for(g, keys, fake)
    g.register_change("ci", change(objects=REPLICAS))
    app.handle("deployment_protection_rule", event())
    clock.advance(days=8)
    g.expire_changes()
    assert app.deliver_answers() == [] and g.undelivered_deployments()[0]["answer"] == "rejected"
    fake.fail = False
    assert app.deliver_answers() == [{"run": 555, "environment": "prod", "answer": "rejected"}]


def test_a_repeated_request_is_one_entry_and_a_foreign_callback_is_ignored(g, keys):
    fake = FakeGitHub()
    app = app_for(g, keys, fake)
    cid = g.register_change("ci", change(objects=REPLICAS))["id"]
    app.handle("deployment_protection_rule", event())
    app.handle("deployment_protection_rule", event())
    assert len(g.changes.get(cid).deployments) == 1
    before = len(fake.reviews)
    assert app.handle("deployment_protection_rule", event(callback="https://evil.example/repos/x/y/actions/runs/1/deployment_protection_rule")) == []
    assert app.handle("deployment_protection_rule", event(callback=CALLBACK.replace(REPO, "other/repo"))) == []
    assert len(fake.reviews) == before


def test_a_push_deploy_registers_without_a_pr():
    from clearance import gate
    req = gate.ChangeRequest.from_dict(change(pr=0))
    assert req.pr == 0
