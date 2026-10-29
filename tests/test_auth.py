"""clearance.auth: TokenReview for workloads, OIDC for people, routing by issuer, and the short cache."""
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from clearance.auth import JWKS, CachingAuthenticator, OIDCAuthenticator, RoutingAuthenticator, WorkloadAuthenticator
from clearance.dispatch import AuthError, Principal
from clearance.tiers import Tier

ISS, AUD = "https://dex.example/dex", "clearance"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(key, kid):
    d = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {**d, "kid": kid, "use": "sig", "alg": "RS256"}


def id_token(key=KEY, kid="k1", **over):
    now = int(time.time())
    claims = {"iss": ISS, "aud": AUD, "sub": "CiQx", "email": "alice@example.com", "email_verified": True,
              "iat": now, "exp": now + 300, **over}
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def fetches():
    return []


@pytest.fixture
def oidc(fetches):
    def fetch(url):
        fetches.append(url)
        return {"keys": [jwk(KEY, "k1")]}
    return OIDCAuthenticator(ISS, AUD, JWKS(f"{ISS}/keys", fetch=fetch))


def test_a_valid_id_token_is_a_user(oidc):
    assert oidc.authenticate(id_token()) == Principal("user:alice@example.com", "user", Tier.T1)


@pytest.mark.parametrize("bad", [
    {"aud": "someone-else"}, {"iss": "https://evil.example"}, {"exp": int(time.time()) - 3600},
    {"email": None}, {"email_verified": False}, {"sub": None},
])
def test_a_wrong_claim_is_refused(oidc, bad):
    with pytest.raises(AuthError):
        oidc.authenticate(id_token(**bad))


def test_a_token_signed_by_another_key_is_refused(oidc):
    with pytest.raises(AuthError):
        oidc.authenticate(id_token(key=OTHER))


def test_hmac_and_none_are_never_accepted(oidc):
    now = int(time.time())
    claims = {"iss": ISS, "aud": AUD, "sub": "x", "email": "a@b", "iat": now, "exp": now + 60}
    for tok in (jwt.encode(claims, "s" * 32, algorithm="HS256", headers={"kid": "k1"}),
                jwt.encode(claims, None, algorithm="none", headers={"kid": "k1"})):
        with pytest.raises(AuthError):
            oidc.authenticate(tok)


def test_an_unknown_kid_refetches_at_most_once_a_minute(oidc, fetches):
    oidc.authenticate(id_token())
    for _ in range(3):
        with pytest.raises(AuthError):
            oidc.authenticate(id_token(kid="nope"))
    assert len(fetches) == 1, "the first fetch happened under a minute ago"


class Opener:
    def __init__(self, status=None, raise_=None):
        self.status, self.raise_, self.bodies = status, raise_, []

    def __call__(self, req, timeout):
        self.bodies.append((req.full_url, json.loads(req.data), req.headers["Authorization"]))
        if self.raise_:
            raise self.raise_
        return {"status": self.status}


def workload(opener, tmp_path):
    tok = tmp_path / "token"
    tok.write_text("clearance-own-token\n")
    return WorkloadAuthenticator(token_file=tok, opener=opener)


def test_a_reviewed_service_account_token_is_a_workload(tmp_path):
    op = Opener({"authenticated": True, "audiences": ["clearance"],
                 "user": {"username": "system:serviceaccount:holmesgpt:holmes"}})
    p = workload(op, tmp_path).authenticate("caller-token")
    assert p == Principal("holmesgpt/holmes", "workload", Tier.T1)
    url, body, authz = op.bodies[0]
    assert url.endswith("/apis/authentication.k8s.io/v1/tokenreviews")
    assert body["spec"] == {"token": "caller-token", "audiences": ["clearance"]}
    assert authz == "Bearer clearance-own-token", "Clearance reviews with its own identity, re-read from the file"


@pytest.mark.parametrize("status", [
    {"authenticated": False},
    {"authenticated": True, "audiences": ["https://kubernetes.default.svc"], "user": {"username": "system:serviceaccount:a:b"}},
    {"authenticated": True, "audiences": ["clearance"], "user": {"username": "alice"}},
    {"authenticated": True, "audiences": ["clearance"], "user": {"username": "system:serviceaccount:a:b:c"}},
])
def test_an_unreviewed_or_foreign_token_is_refused(tmp_path, status):
    with pytest.raises(AuthError):
        workload(Opener(status), tmp_path).authenticate("t")


def test_the_api_server_unreachable_is_a_refusal(tmp_path):
    with pytest.raises(AuthError):
        workload(Opener(raise_=OSError("down")), tmp_path).authenticate("t")


class Count:
    def __init__(self, principal):
        self.principal, self.n = principal, 0

    def authenticate(self, token):
        self.n += 1
        if self.principal is None:
            raise AuthError("no")
        return self.principal


def test_routing_by_issuer_and_the_verifier_still_checks_everything(oidc):
    wl = Count(Principal("ns/sa", "workload"))
    r = RoutingAuthenticator({ISS: oidc}, wl)
    assert r.authenticate(id_token()).kind == "user" and wl.n == 0
    sa = jwt.encode({"iss": "https://kubernetes.default.svc", "exp": int(time.time()) + 60}, "x" * 32, algorithm="HS256")
    assert r.authenticate(sa).id == "ns/sa" and wl.n == 1
    with pytest.raises(AuthError):
        r.authenticate(id_token(key=OTHER))  # claims Dex's issuer, fails Dex's verification; never falls through
    assert wl.n == 1
    with pytest.raises(AuthError):
        r.authenticate("not-a-jwt")


def test_cache_holds_a_success_until_ttl_or_exp_and_never_a_failure():
    t = [1000.0]
    inner = Count(Principal("u", "user"))
    c = CachingAuthenticator(inner, ttl=60, clock=lambda: t[0])
    tok = jwt.encode({"exp": 1030}, "x" * 32, algorithm="HS256")
    c.authenticate(tok)
    c.authenticate(tok)
    assert inner.n == 1
    t[0] = 1031  # past exp, though inside the ttl
    c.authenticate(tok)
    assert inner.n == 2
    bad = CachingAuthenticator(Count(None), clock=lambda: t[0])
    for _ in range(2):
        with pytest.raises(AuthError):
            bad.authenticate(tok)
    assert bad.inner.n == 2
