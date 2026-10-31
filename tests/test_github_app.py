"""The Clearance GitHub App, phase 1 (github_app.py): the webhook's signature, what is queued and what is ignored, the
installation token's scope, what is gathered from GitHub, the two check runs, the record naming the installation, and
PR comments only on failing agent PRs when turned on. A fake GitHub, no network."""
import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

import jwt
from clearance import github_app as ga
from clearance.server import create_http_app

SECRET = b"s3cret"
BOT = "hangar-autopilot-agents[bot]"
HEAD = "0" * 39 + "1"


@pytest.fixture
def keys(tmp_path):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    (tmp_path / "key.pem").write_bytes(pem)
    (tmp_path / "secret").write_bytes(SECRET + b"\n")
    return tmp_path, k.public_key()


class FakeGitHub:
    def __init__(self, author="alice", trailers=None, files=("src/app.js",), head=HEAD):
        self.calls, self.author, self.files, self.head = [], author, list(files), head
        self.message = "fix\n\n" + "\n".join(f"Hangar-{k}: {v}" for k, v in (trailers or {}).items())
        self.token_body = None

    def __call__(self, req, timeout):
        body = json.loads(req.data) if req.data else None
        path = req.full_url.replace("https://api.github.com", "")
        self.calls.append((req.get_method(), path, req.headers.get("Authorization", "")[:6]))
        if path.startswith("/app/installations/") and path.endswith("/access_tokens"):
            self.token_body = body
            return 201, json.dumps({"token": "inst-token"}).encode()
        if path.endswith("/pulls/1"):
            return 200, json.dumps({"head": {"sha": self.head}, "user": {"login": self.author}}).encode()
        if "/pulls/1/files" in path:
            return 200, json.dumps([{"filename": f} for f in self.files]).encode()
        if f"/commits/{self.head}" in path:
            return 200, json.dumps({"commit": {"message": self.message}}).encode()
        if path.endswith("/check-runs"):
            return 201, json.dumps({"id": len(self.calls)}).encode()
        if "/issues/1/comments" in path:
            return (200, b"[]") if req.get_method() == "GET" else (201, b"{}")
        return 404, b"{}"


def make(gw, keys, fake, comments="off"):
    d, _ = keys
    cfg = ga.AppConfig(app_id="123", key_file=d / "key.pem", webhook_secret_file=d / "secret", comments=comments)
    return ga.GitHubApp(cfg, gw, opener=fake)


def sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()


def pr_event(action="opened"):
    return {"action": action, "installation": {"id": 9}, "repository": {"full_name": "jfillman/flight-api"},
            "pull_request": {"number": 1}}


def test_signature_and_what_is_queued(gw, keys):
    app = make(gw, keys, FakeGitHub())
    body = json.dumps(pr_event()).encode()
    assert ga.verify_signature(SECRET, body, sign(body)) and not ga.verify_signature(SECRET, body, "sha256=00")
    assert app.accept("pull_request", body, None) == (401, "bad signature")
    assert app.accept("pull_request", body, sign(body)) == (202, "queued")
    closed = json.dumps(pr_event("closed")).encode()
    assert app.accept("pull_request", closed, sign(closed)) == (200, "ignored")
    assert app.accept("push", body, sign(body)) == (200, "ignored")


def test_the_app_jwt_and_a_one_repo_read_only_token(gw, keys):
    d, pub = keys
    fake = FakeGitHub()
    app = make(gw, keys, fake)
    claims = jwt.decode(app.app_jwt(), pub, algorithms=["RS256"])
    assert claims["iss"] == "123" and claims["exp"] - claims["iat"] <= 600
    app.installation_token(9, "jfillman/flight-api")
    assert fake.token_body == {"repositories": ["flight-api"],
                               "permissions": {"checks": "write", "contents": "read", "pull_requests": "read", "metadata": "read"}}


def test_a_persons_pr_gets_two_passing_checks_and_a_record(gw, keys):
    fake = FakeGitHub()
    app = make(gw, keys, fake)
    runs = app.handle("pull_request", pr_event())
    assert [(r["name"], r["conclusion"]) for r in runs] == [(ga.IDENTITY_CHECK, "success"), (ga.SCOPE_CHECK, "success")]
    rec = gw.audit.records[-1]
    assert (rec["tool"], rec["principal"], rec["target"]) == ("provenance.verify", "app:9", "jfillman/flight-api#1")
    assert rec["result"] == "identity:not-agent scope:not-agent"
    assert not [c for c in fake.calls if "/comments" in c[1]]


def test_an_agents_login_without_a_receipt_fails_identity_and_comments_only_when_on(gw, keys):
    gw.agent_logins = (BOT,)
    off = FakeGitHub(author=BOT)
    runs = make(gw, keys, off).handle("pull_request", pr_event())
    assert runs[0]["conclusion"] == "failure" and not [c for c in off.calls if "/comments" in c[1]]
    on = FakeGitHub(author=BOT)
    app = make(gw, keys, on, comments="agent-failures")
    app.handle("pull_request", pr_event())
    assert ("POST", "/repos/jfillman/flight-api/issues/1/comments", "token ") in on.calls
    assert on.token_body["permissions"]["issues"] == "write"


def test_a_pr_clearance_opened_is_confirmed(gw, keys):
    sid = gw.open_session("alice", "coding-agent").data["session"]
    r = gw.call("alice", sid, "repo.pr.open", {"repo": "jfillman/flight-api", "branch": "agent/t-1", "title": "fix",
                                                "files": [{"path": "src/app.js", "content": "y"}]})
    assert r.ok
    s = gw.store.get(sid)
    gw.agent_logins = (BOT,)
    fake = FakeGitHub(author=BOT, trailers={"Task": s.task_id, "Session": sid, "Agent": "coding-agent"}, head=r.data["commit"])
    runs = make(gw, keys, fake).handle("pull_request", pr_event())
    assert [r["conclusion"] for r in runs] == ["success", "success"]
    assert gw.audit.records[-1]["result"] == "identity:confirmed scope:in-scope"


def test_rerequest_and_installation_events(gw, keys):
    fake = FakeGitHub()
    app = make(gw, keys, fake)
    ev = {"action": "rerequested", "installation": {"id": 9}, "repository": {"full_name": "jfillman/flight-api"},
          "check_run": {"name": ga.SCOPE_CHECK, "pull_requests": [{"number": 1}]}}
    assert len(app.handle("check_run", ev)) == 2
    other = {**ev, "check_run": {"name": "someone else", "pull_requests": [{"number": 1}]}}
    assert app.handle("check_run", other) == []
    inst = {"action": "created", "installation": {"id": 9, "account": {"login": "jfillman"}},
            "repositories": [{"full_name": "jfillman/flight-api"}, {"full_name": "jfillman/gate-api"}]}
    app.handle("installation", inst)
    rec = gw.audit.records[-1]
    assert (rec["tool"], rec["principal"], rec["target"], rec["result"]) == ("app.installation", "app:9", "jfillman", "created: 2 repositories")


def test_the_webhook_route(gw, keys):
    app = make(gw, keys, FakeGitHub())
    c = TestClient(create_http_app(gw, resource_url="https://c.example/mcp", issuer_url="https://dex.example", github_app=app))
    body = json.dumps(pr_event()).encode()
    assert c.post("/v1/github/webhook", content=body, headers={"x-github-event": "pull_request"}).status_code == 401
    r = c.post("/v1/github/webhook", content=body, headers={"x-github-event": "pull_request", "x-hub-signature-256": sign(body)})
    assert r.status_code == 202
    bare = TestClient(create_http_app(gw, resource_url="https://c.example/mcp", issuer_url="https://dex.example"))
    assert bare.post("/v1/github/webhook", content=body).status_code == 404


def test_config():
    assert ga.read_config(None, "k", "s") is None
    c = ga.read_config("1", "/k", "/s", "agent-failures")
    assert c.comments == "agent-failures"
    with pytest.raises(ValueError):
        ga.read_config("1", "/k", "/s", "always")
