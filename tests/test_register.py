"""Phase 2b of the provenance App: a GitHub Actions OIDC token as a verifier identity (auth.GitHubActionsAuthenticator),
bound to its own repository at the gate (DG-REPO), and `clearance register` (register.py): the change's objects from
two directories of rendered manifests, the body from the Actions environment, the exit codes. No network."""
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from clearance import gate, register
from clearance.auth import GITHUB_ACTIONS_ISSUER, JWKS, GitHubActionsAuthenticator
from clearance.dispatch import AuthError, Gateway, Principal
from clearance.audit import AuditLog
from clearance.packs.hangar import HANGAR
from clearance.session import SessionStore
from clearance.tiers import Tier

HEAD = "a" * 40
REPO = "jfillman/clearance-deploy-scratch"


# -- the authenticator ---------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwks_of(key):
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]}


def token(key, **over):
    now = int(time.time())
    claims = {"iss": GITHUB_ACTIONS_ISSUER, "aud": "clearance", "iat": now, "exp": now + 300,
              "sub": f"repo:{REPO}:environment:prod", "repository": "jfillman/Clearance-Deploy-Scratch",
              "environment": "prod", "ref": "refs/heads/main", "sha": HEAD}
    claims.update(over)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, key, algorithm="RS256", headers={"kid": "k1"})


def auth(key, **kw):
    fetched = []
    keys = JWKS("https://token.actions.githubusercontent.com/.well-known/jwks",
                fetch=lambda url: fetched.append(url) or jwks_of(key))
    return GitHubActionsAuthenticator("clearance", keys, **kw), fetched


def test_a_workflow_token_is_a_github_principal_with_its_repository(key):
    a, fetched = auth(key)
    p = a.authenticate(token(key))
    assert (p.id, p.kind) == (f"github:repo:{REPO}:environment:prod", "workload")
    assert p.attrs["repository"] == REPO and p.attrs["environment"] == "prod"
    a.authenticate(token(key))
    assert len(fetched) == 1, "the JWKS is cached"


@pytest.mark.parametrize("over", [
    {"aud": "someone-else"}, {"exp": int(time.time()) - 600}, {"iss": "https://evil.example"},
    {"sub": "system:serviceaccount:a:b"}, {"repository": None},
])
def test_wrong_audience_expired_foreign_or_not_a_repo_token_is_refused(key, over):
    a, _ = auth(key)
    with pytest.raises(AuthError):
        a.authenticate(token(key, **over))


def test_another_key_and_an_hmac_token_are_refused(key):
    a, _ = auth(key)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthError):
        a.authenticate(token(other))
    forged = jwt.encode({"iss": GITHUB_ACTIONS_ISSUER, "aud": "clearance", "sub": f"repo:{REPO}:ref:x",
                         "repository": REPO, "iat": int(time.time()), "exp": int(time.time()) + 60}, "s" * 32,
                        algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(AuthError):
        a.authenticate(forged)


def test_allowed_narrows_which_workflows_get_in(key):
    a, _ = auth(key, allowed=("repo:jfillman/other:*",))
    with pytest.raises(AuthError):
        a.authenticate(token(key))


# -- the gate binds the token to its repository ----------------------------------------------------------------------
class Auth:
    table = {"wf": Principal(f"github:repo:{REPO}:environment:prod", "workload", Tier.T1, {"repository": REPO})}

    def authenticate(self, t):
        if t not in self.table:
            raise AuthError("no")
        return self.table[t]


@pytest.fixture
def g(defs, clock):
    return Gateway(defs, SessionStore(), AuditLog(), Auth(), clock, packs=(HANGAR,), verifiers=("github:repo:jfillman/*",),
                   changes=gate.MemoryChanges(), gate_policy=gate.GatePolicy())


def body(**over):
    b = {"app": "deploy-scratch", "env": "prod", "cluster": "hangar-dev", "repo": REPO, "pr": 0, "head": HEAD,
         "proposer": "user:jfillman", "treeDigest": "c" * 64, "paths": ["README.md"], "owner": "group:default/admins"}
    b.update(over)
    return b


def test_a_workflow_registers_for_its_own_repository_only(g):
    out = g.register_change("wf", body())
    assert out["state"] == "cleared" and out["repo"] == REPO
    with pytest.raises(gate.GateError) as e:
        g.register_change("wf", body(repo="jfillman/gate-api"))
    assert (e.value.rule, e.value.status) == ("DG-REPO", 403)


# -- clearance register ----------------------------------------------------------------------------------------------
DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop-prod}
spec:
  replicas: {replicas}
  template:
    spec:
      containers:
        - name: web
          image: ghcr.io/acme/web@sha256:{digest}
"""


def write(d, replicas=2, digest="1" * 64, extra=""):
    d.mkdir(parents=True, exist_ok=True)
    (d / "web.yaml").write_text(DEPLOY.replace("{replicas}", str(replicas)).replace("{digest}", digest) + extra)
    return d


def test_objects_are_the_difference_of_two_rendered_directories(tmp_path):
    cm = "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: cfg, namespace: shop-prod}\ndata: {a: '1'}\n"
    before = register.load_dir(write(tmp_path / "b"))
    after = register.load_dir(write(tmp_path / "a", replicas=3, digest="2" * 64, extra=cm))
    objs = {(o["kind"], o["op"]): o for o in register.objects(before, after)}
    web = objs[("Deployment", "changed")]
    assert web["fields"] == ["/spec/replicas", "/spec/template/spec/containers/0/image"]
    assert web["images"] == ["ghcr.io/acme/web@sha256:" + "2" * 64] and len(web["digest"]) == 64
    assert ("ConfigMap", "added") in objs
    assert register.objects(after, after) == []
    assert register.changed_files(str(tmp_path / "b"), str(tmp_path / "a")) == ["web.yaml"]


def env_for(tmp_path, event=None):
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps(event or {"ref": "refs/heads/main"}))
    return {"GITHUB_REPOSITORY": "jfillman/Clearance-Deploy-Scratch", "GITHUB_SHA": HEAD, "GITHUB_ACTOR": "jfillman",
            "GITHUB_EVENT_PATH": str(ev), "ACTIONS_ID_TOKEN_REQUEST_URL": "https://x/token?v=1",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req"}


def args_for(tmp_path, *extra):
    return ["--url", "https://clearance.example", "--app", "deploy-scratch", "--env", "Prod", "--cluster", "hangar-dev",
            "--before", str(write(tmp_path / "b")), "--after", str(write(tmp_path / "a", replicas=3)), *extra]


def test_the_body_comes_from_the_actions_environment_and_is_a_valid_change(tmp_path):
    sent = {}

    def poster(url, tok, b):
        sent.update(url=url, token=tok, body=b)
        return 200, {"id": "ch-1", "state": "cleared", "tier": 1, "cleared_by": "policy"}
    code = register.main(args_for(tmp_path, "--check", "ci=pass"), env_for(tmp_path), poster=poster,
                         token_fetcher=lambda env, aud: f"oidc-for-{aud}")
    b = sent["body"]
    assert code == register.EXIT_CLEARED and sent["token"] == "oidc-for-clearance"
    assert (b["repo"], b["head"], b["pr"], b["env"], b["proposer"]) == (REPO, HEAD, 0, "prod", "user:jfillman")
    assert b["checks"] == {"render": "ok", "ci": "pass"} and b["objects"][0]["fields"] == ["/spec/replicas"]
    gate.ChangeRequest.from_dict(b)


def test_a_pull_request_event_names_its_pr_and_head(tmp_path):
    sent = {}
    event = {"pull_request": {"number": 12, "head": {"sha": "b" * 40}, "base": {"sha": "c" * 40}}}
    register.main(args_for(tmp_path), env_for(tmp_path, event), poster=lambda u, t, b: (sent.update(b) or (200, {"state": "cleared"})),
                  token_fetcher=lambda env, aud: "t")
    assert (sent["pr"], sent["head"], sent["base"]) == (12, "b" * 40, "c" * 40)


@pytest.mark.parametrize("reply, code", [
    ((200, {"id": "ch-1", "state": "holding", "tier": 2, "requirement": {"owner": 1, "ownerGroup": "group:default/admins"}}), register.EXIT_HOLDING),
    ((200, {"id": "ch-1", "state": "denied", "tier": 3, "deny_reason": "loosens"}), register.EXIT_DENIED),
    ((403, {"error": "may register changes for x only", "rule": "DG-REPO"}), register.EXIT_DENIED),
])
def test_exit_codes(tmp_path, reply, code):
    assert register.main(args_for(tmp_path), env_for(tmp_path), poster=lambda *a: reply,
                         token_fetcher=lambda env, aud: "t") == code


def test_no_oidc_permission_is_a_usage_error_and_dry_run_sends_nothing(tmp_path, capsys):
    env = {k: v for k, v in env_for(tmp_path).items() if not k.startswith("ACTIONS_")}
    assert register.main(args_for(tmp_path), env, poster=lambda *a: pytest.fail("sent")) == register.EXIT_USAGE
    assert "id-token: write" in capsys.readouterr().err
    assert register.main(args_for(tmp_path, "--dry-run"), env, poster=lambda *a: pytest.fail("sent")) == 0
    assert json.loads(capsys.readouterr().out)["app"] == "deploy-scratch"


def test_a_token_file_replaces_the_oidc_token(tmp_path):
    f = tmp_path / "tok"
    f.write_text("file-token\n")
    seen = []
    register.main(args_for(tmp_path, "--token-file", str(f)), env_for(tmp_path),
                  poster=lambda u, t, b: (seen.append(t) or (200, {"state": "cleared"})),
                  token_fetcher=lambda *a: pytest.fail("fetched"))
    assert seen == ["file-token"]


def test_post_names_itself_and_reports_a_refusal_from_in_front_of_clearance(monkeypatch):
    """Cloudflare's browser integrity check refuses Python's default User-Agent (403, error 1010) before Clearance
    sees the request; the CLI sends its own, and a non-JSON refusal is reported as not from Clearance."""
    import io
    import urllib.error
    import urllib.request
    from clearance import register as reg
    seen = {}

    def refuse(req, timeout):
        seen["ua"] = req.get_header("User-agent")
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b"error code: 1010"))

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    status, out = reg.post("https://clearance.example", "t", {})
    assert seen["ua"].startswith("clearance-register") and status == 403
    assert out["error"] == "not from Clearance: error code: 1010"
