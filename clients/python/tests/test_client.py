from __future__ import annotations

import asyncio
import datetime
import http.server
import json
import threading
import time
from pathlib import Path

import pytest

import clearance_client as cc
from conftest import CI, GW, REPO, free_port

HEAD = "a" * 40
CORPUS = REPO / "testdata" / "golden" / "corpus.jsonl"
PR_OPEN_ALLOWED, PR_OPEN_DENIED = 210, 218  # the corpus lines internal/server's tests use


def corpus_request(n: int) -> dict:
    with CORPUS.open() as fh:
        for i, line in enumerate(fh):
            if i == n:
                req = json.loads(line)["request"]
                break
    # The core refuses a context.now far from its clock; move the session with it.
    now = datetime.datetime.now(datetime.timezone.utc)
    req["context"]["now"] = now.isoformat()
    req["context"]["session"]["expires_at"] = (now + datetime.timedelta(minutes=30)).isoformat()
    return req


# -- the generated models ------------------------------------------------------------------------------------------


def test_every_corpus_request_decodes_strictly_into_the_generated_types():
    n = 0
    with CORPUS.open() as fh:
        for line in fh:
            req = json.loads(line).get("request")
            if req is None:
                continue
            typed = cc.EvaluationRequest.from_dict(req)
            assert typed.action.name in ("tool.call", "session.spawn", "session.open", "model.call")
            again = cc.EvaluationRequest.from_dict(typed.to_dict())
            assert again == typed
            n += 1
    assert n > 100


def test_strict_decoding_refuses_what_the_contract_does_not_say():
    good = {"seq": 1, "hash": "h"}
    assert cc.RecordRef.from_dict(good) == cc.RecordRef(seq=1, hash="h")
    for bad in ({"seq": 1}, {"seq": "1", "hash": "h"}, {"seq": True, "hash": "h"}, {"seq": 1, "hash": "h", "x": 1}, []):
        with pytest.raises(cc.DecodeError):
            cc.RecordRef.from_dict(bad)
    assert cc.RecordRef.from_dict({"seq": 1, "hash": "h", "x": 1}, strict=False).seq == 1
    with pytest.raises(cc.DecodeError, match="zone"):
        cc.Hold.from_dict({"by": "x", "until": "2026-01-01T00:00:00", "reason": "r"})


def test_the_version_is_the_clearance_release():
    assert cc.__version__ == (REPO / "VERSION").read_text().strip()


# -- against a real core -------------------------------------------------------------------------------------------


def test_evaluate_allow_and_deny(core):
    c = cc.CoreClient(core.url, token=GW)
    allow = c.evaluate(cc.EvaluationRequest.from_dict(corpus_request(PR_OPEN_ALLOWED)))
    assert isinstance(allow, cc.EvaluationResult)
    assert allow.decision is True and allow.decision_id == "0" and allow.record.seq == 0
    assert allow.context.spend.github_calls == 4 and allow.context.policy.bundle == "clearance-core"
    deny = c.evaluate(corpus_request(PR_OPEN_DENIED))  # a plain dict works too
    assert deny.decision is False and deny.context.rule == "R008" and deny.context.hint
    assert c.breaker_state == cc.CLOSED


def test_outcome_and_record(core):
    c = cc.CoreClient(core.url, token=GW, provider="autopilot-gateway")
    allow = c.evaluate(corpus_request(PR_OPEN_ALLOWED))
    ref = c.outcome(allow.decision_id, cc.OutcomeRequest(
        result="ok", effect=cc.Effect(repo="jfillman/gate-api", pr=32, commit=HEAD, branch="agent/fix",
                                      paths=["app.js"]), receipt={"id": "pr-32"}))
    assert ref.seq == 1 and len(ref.hash) == 64
    with pytest.raises(cc.CoreRequestError) as e:
        c.outcome(allow.decision_id, {"result": "ok"})
    assert e.value.status == 409 and not isinstance(e.value, cc.CoreUnavailable)

    rec = c.record("session.open", cc.ProviderEvent(session="s-1", task_id="t-1", principal="user:alice",
                                                    agent="coding-agent", result="opened"))
    assert rec.seq == 2
    with pytest.raises(cc.CoreRequestError) as e:
        c.record("run.anything", {"session": "s-1"})
    assert e.value.status == 400 and "is not one of" in e.value.message

    v = cc.CoreClient(core.url, token=CI).verify_provenance(
        {"repo": "jfillman/gate-api", "pr": 32, "head": HEAD, "paths": ["app.js"],
         "author": "hangar-autopilot-agents[bot]"})
    assert isinstance(v, cc.ProvenanceVerdict) and v.agent_pr and v.record is not None


def test_the_gateways_held_kinds_a_refusal_and_published_definitions(core):
    c = cc.CoreClient(core.url, token=GW, provider="autopilot-gateway")
    for kind in ("run.finish", "session.end", "trigger.release", "tool.call"):
        assert kind in cc.RECORD_KINDS
    assert not any(k.startswith("definition.") for k in cc.RECORD_KINDS)
    digest = "b" * 64
    c.record("run.finish", cc.ProviderEvent(session="s-1", task_id="t-1", principal="autopilot-runs/x", agent="x",
                                            decision="allow", args_sha256=digest, result="succeeded"))
    c.record("tool.call", {"session": "s-1", "task_id": "t-1", "principal": "user:alice", "agent": "coding-agent",
                           "tool": "catalog.read", "tier": 0, "decision": "allow", "args_sha256": digest,
                           "result": "ok", "coverage": "coverage-unavailable"})
    with pytest.raises(cc.CoreRequestError) as e:
        c.record("tool.call", {"session": "s-1", "task_id": "t-1", "principal": "user:alice", "agent": "a",
                               "tool": "repo.pr.open", "tier": 1, "args_sha256": digest, "result": "ok",
                               "coverage": "coverage-unavailable"})
    assert e.value.status == 400 and "T0" in e.value.message

    allow = c.evaluate(corpus_request(PR_OPEN_ALLOWED))
    ref = c.outcome(allow.decision_id, cc.OutcomeRequest(result="refused HR-003: not yours",
                                                         refusal=cc.Refusal(rule="HR-003", message="not yours")))
    assert ref.seq == 3

    pin = {"source": {"repo": "jfillman/gate-api", "path": "agents/x.yaml", "commit": "1a2b3c4", "namespace": "n",
                      "xr": "x"}, "owner": "group:default/t", "doc": {"name": "x"}}
    res = c.publish_definitions([pin], [{"name": "y", "source": {"xr": "y"}, "reason": "no spec.source"}])
    assert isinstance(res, cc.DefinitionsResult) and res.cluster == 0
    assert sorted(r.name for r in res.rejected) == ["x", "y"]
    assert res.rejected[0].reason.startswith("schema: ")
    again = c.publish_definitions([pin], [{"name": "y", "source": {"xr": "y"}, "reason": "no spec.source"}])
    assert again.rejected == [] and again.added == []


def test_publish_definitions_with_the_providers_bundled_set(core):
    c = cc.CoreClient(core.url, token=GW, provider="autopilot-gateway")
    bad = {"name": "parachute", "version": "gateway-v0.9.0", "doc": {"name": "parachute"}}
    res = c.publish_definitions([], bundled=[bad])
    assert not res.provided and [r.name for r in res.rejected] == ["parachute"]
    assert res.rejected[0].source.kind == "provider" and res.rejected[0].source.version == "gateway-v0.9.0"
    # None leaves the provider's set alone; [] clears it.
    assert c.publish_definitions([]).rejected == []
    assert [r.name for r in c.publish_definitions([], bundled=[]).cleared] == ["parachute"]


def test_publish_targets(core):
    c = cc.CoreClient(core.url, token="hangar-prod/gitops/targets")
    t = {"id": "gate-api-prod", "name": "gate-api", "kind": "k8s-namespace", "group": "hangar-prod", "env": "prod",
         "app": "gate-api", "scope": "hangar-prod",
         "gates": [{"type": "glidepath", "instance": "gate-api-cicd", "mode": "enforce"}],
         "observers": [{"provider": "observe-k8s", "source": "observe-k8s"}]}
    res = c.publish_targets("hangar-prod", [t])
    assert isinstance(res, cc.TargetsResult) and res.changed and res.targets == 1 and len(res.digest) == 64
    again = c.publish_targets("hangar-prod", [t])
    assert not again.changed and again.digest == res.digest and again.seq is None
    assert c.publish_targets("hangar-prod", []).targets == 0
    with pytest.raises(cc.CoreRequestError) as e:
        c.publish_targets("hangar-dev", [t])
    assert e.value.status == 403
    with pytest.raises(cc.CoreRequestError) as e:
        c.publish_targets("hangar-prod", [{**t, "kind": "vm"}])
    assert e.value.status == 400 and "kind" in e.value.message


def test_the_gate(core):
    change = {"app": "gate-api", "env": "prod", "cluster": "hangar-prod", "repo": "jfillman/gitops-gate-api",
              "pr": 7, "head": HEAD, "base": "b" * 40, "proposer": "user:dana", "proposerKind": "person",
              "owner": "group:default/team-gate", "protected": True, "treeDigest": "c" * 64,
              "paths": ["hangar-prod/prod/release.yaml"], "linesChanged": 4, "objects": [],
              "checks": {"ci": "pending", "provenance": "not-agent", "render": "ok", "admission": "pass"}}
    ch = cc.CoreClient(core.url, token=CI).register_change(change)
    assert isinstance(ch, cc.GateChange) and ch.id.startswith("ch-")
    admin = cc.CoreClient(core.url, token="user:admin")
    if ch.state == "holding":
        d = admin.deny_change(ch.id, "wrong replica count")
        assert isinstance(d, cc.GateChangeWithAuditSeq) and d.state == "denied" and d.audit_seq >= 0
    with pytest.raises(cc.CoreRequestError) as e:
        admin.deny_change(ch.id, "again")
    assert e.value.status in (403, 409)
    # The core's read of one change: the registering verifier may; a person may not (clearance-api is theirs). A
    # core without a signing key issues no token and publishes no key.
    got = cc.CoreClient(core.url, token=CI).get_clearance(ch.id)
    assert isinstance(got, cc.GateClearanceAnswer) and got.id == ch.id and got.token is None
    with pytest.raises(cc.CoreRequestError) as e:
        admin.get_clearance(ch.id)
    assert e.value.status == 403
    assert cc.CoreClient(core.url).keys().keys == []


def test_a_plan_outcome(core):
    """G-TF-2: a tag-only plan clears by policy; its registrant reports the apply once, and a second is DG-STATE."""
    digest = "e6" * 32
    plan = {"kind": "terraform-plan", "planDigest": digest, "planJsonDigest": "4f" * 32, "variableSetDigest": "1c" * 32,
            "workspace": {"backend": "s3", "key": "network/lab/terraform.tfstate", "name": "default"},
            "versions": {"terraform": "1.9.8", "providers": {}},
            "summary": {"create": 0, "update": 1, "replace": 0, "destroy": 0, "destroyedAddresses": []},
            "targeted": False,
            "resources": [{"address": "aws_vpc.lab", "type": "aws_vpc", "actions": ["update"], "fields": ["/tags/Owner"]}]}
    change = {"app": "network", "env": "lab", "repo": "jfillman/hangar-infra", "pr": 0, "head": HEAD,
              "proposer": "user:dana", "owner": "group:default/team-gate", "paths": ["network/lab/main.tf"],
              "checks": {"ci": "pass", "provenance": "not-agent"}, "subject": plan}
    ci = cc.CoreClient(core.url, token=CI)
    ch = ci.register_change(change)
    assert ch.state == "cleared" and ci.register_change(change).id == ch.id
    outcome = {"applied": True, "planDigest": "sha256:" + digest,
               "changes": [{"address": "aws_vpc.lab", "action": "update", "status": "complete"}],
               "startedAt": "2026-01-01T00:00:00Z", "finishedAt": "2026-01-01T00:00:09Z"}
    got = ci.record_change_outcome(ch.id, outcome)
    assert isinstance(got, cc.GateOutcomeResult) and got.matched is True and got.exception_seq is None
    assert got.change.outcome.seq == got.audit_seq
    with pytest.raises(cc.CoreRequestError) as e:
        ci.record_change_outcome(ch.id, outcome)
    assert e.value.status == 409
    with pytest.raises(cc.CoreRequestError) as e:
        cc.CoreClient(core.url, token="user:admin").record_change_outcome(ch.id, outcome)
    assert e.value.status == 403


def test_refusals_are_request_errors_not_outages(core):
    req = corpus_request(PR_OPEN_ALLOWED)
    for token, status in ((None, 401), ("someone/else", 403), ("user:alice", 403)):
        with pytest.raises(cc.CoreRequestError) as e:
            cc.CoreClient(core.url, token=token).evaluate(req)
        assert e.value.status == status


def test_probes(core):
    c = cc.CoreClient(core.url)
    assert c.healthz().ok is True
    r = c.readyz()
    assert r.ok is True and r.head == -1


def test_an_unreachable_core_is_core_unavailable(core):
    c = cc.CoreClient(core.url, token=GW)
    assert c.healthz().ok
    core.stop()
    for call in (lambda: c.evaluate(corpus_request(PR_OPEN_ALLOWED)), lambda: c.outcome("0", {"result": "ok"})):
        with pytest.raises(cc.CoreUnavailable) as e:
            call()
        assert e.value.reason == cc.CONNECTION and e.value.attempts == 2  # a refused connect sent nothing: retried


def test_the_breaker_against_a_stopped_core(core):
    c = cc.CoreClient(core.url, token=GW)
    req = corpus_request(PR_OPEN_ALLOWED)
    assert c.evaluate(req).decision
    core.stop()
    for _ in range(5):
        with pytest.raises(cc.CoreUnavailable) as e:
            c.evaluate(req)
        assert e.value.reason == cc.CONNECTION
    assert c.breaker_state == cc.OPEN
    start = time.monotonic()
    for _ in range(200):
        with pytest.raises(cc.CoreUnavailable) as e:
            c.evaluate(req)
        assert e.value.reason == cc.BREAKER_OPEN and e.value.attempts == 0
    assert time.monotonic() - start < 0.2


# -- every error class, against fakes ------------------------------------------------------------------------------

OK_EVAL = {"decision": True, "context": {"message": "allowed", "tier": 1, "spend": {},
                                         "policy": {"bundle": "b", "version": "v"}},
           "decision_id": "0", "record": {"seq": 0, "hash": "h"}}


class Fake:
    """An HTTP server answering every request with handle(handler) -> (status, body bytes) or None (hang)."""

    def __init__(self, handle):
        self.hits = 0
        self.headers: list[dict] = []
        self.release = threading.Event()
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.do_GET()

            def do_GET(self):
                fake.hits += 1
                fake.headers.append(dict(self.headers))
                out = handle(fake)
                if out is None:
                    fake.release.wait(10)
                    return
                status, body = out
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake():
    made = []

    def make(handle):
        f = Fake(handle)
        made.append(f)
        return f

    yield make
    for f in made:
        f.close()


def answer(status, body):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return lambda f: (status, raw)


def eval_req():
    return corpus_request(PR_OPEN_ALLOWED)


def test_a_timeout_is_honoured(fake):
    f = fake(lambda f: None)
    c = cc.CoreClient(f.url, token=GW, timeout=0.1)
    start = time.monotonic()
    with pytest.raises(cc.CoreUnavailable) as e:
        c.evaluate(eval_req())
    took = time.monotonic() - start
    assert e.value.reason == cc.TIMEOUT and e.value.attempts == 2 and f.hits == 2
    assert 0.2 <= took < 1.0
    # An outcome that timed out may have been recorded: not retried.
    with pytest.raises(cc.CoreUnavailable) as e:
        c.outcome("0", {"result": "ok"})
    assert e.value.reason == cc.TIMEOUT and e.value.attempts == 1
    # The default is 250 ms per attempt.
    start = time.monotonic()
    with pytest.raises(cc.CoreUnavailable):
        cc.CoreClient(f.url, token=GW, retries=0).evaluate(eval_req())
    assert 0.24 <= time.monotonic() - start < 1.5


@pytest.mark.parametrize("status,outcome,attempts", [
    (503, False, 2), (502, False, 2), (504, False, 2), (500, False, 1),
    (503, True, 2), (502, True, 1), (504, True, 1),
])
def test_server_errors(fake, status, outcome, attempts):
    f = fake(answer(status, {"error": "the decision could not be recorded"}))
    c = cc.CoreClient(f.url, token=GW)
    with pytest.raises(cc.CoreUnavailable) as e:
        c.outcome("0", {"result": "ok"}) if outcome else c.evaluate(eval_req())
    assert e.value.reason == cc.SERVER_ERROR and e.value.status == status and e.value.attempts == attempts
    assert f.hits == attempts and "could not be recorded" in str(e.value)


def test_a_retry_that_succeeds(fake):
    f = fake(lambda f: (503, b"{}") if f.hits == 1 else (200, json.dumps(OK_EVAL).encode()))
    assert cc.CoreClient(f.url, token=GW).evaluate(eval_req()).decision is True
    assert f.hits == 2


def test_client_errors_are_distinct_and_not_retried(fake):
    f = fake(answer(403, {"error": "not a verifier", "rule": "DG-ROLE", "hint": "ask"}))
    with pytest.raises(cc.CoreRequestError) as e:
        cc.CoreClient(f.url, token=GW, on_behalf_of_header="X-Lab-On-Behalf-Of").clear_change("ch-1", on_behalf_of="user:dana")
    assert (e.value.status, e.value.rule, e.value.hint) == (403, "DG-ROLE", "ask") and f.hits == 1
    assert f.headers[0]["X-Lab-On-Behalf-Of"] == "user:dana"
    assert not isinstance(e.value, cc.CoreUnavailable)


@pytest.mark.parametrize("body", [
    b"not json",
    json.dumps({**OK_EVAL, "extra": 1}).encode(),
    json.dumps({**OK_EVAL, "decision": "yes"}).encode(),
    json.dumps({k: v for k, v in OK_EVAL.items() if k != "decision"}).encode(),
    json.dumps(OK_EVAL).encode() + b" " * 2048,
])
def test_unreadable_answers(fake, body):
    f = fake(answer(200, body))
    c = cc.CoreClient(f.url, token=GW, max_response_bytes=1024)
    with pytest.raises(cc.BadResponse):
        c.evaluate(eval_req())
    assert c.breaker_state == cc.CLOSED and f.hits == 1


def test_allow_unknown_fields(fake):
    f = fake(answer(200, {**OK_EVAL, "extra": 1}))
    assert cc.CoreClient(f.url, token=GW, allow_unknown_fields=True).evaluate(eval_req()).decision


def test_the_token_file_is_read_on_every_request(fake, tmp_path: Path):
    f = fake(answer(200, OK_EVAL))
    tok = tmp_path / "token"
    tok.write_text("first\n")
    c = cc.CoreClient(f.url, token_file=tok)
    c.evaluate(eval_req())
    tok.write_text("second")
    c.evaluate(eval_req())
    assert [h["Authorization"] for h in f.headers] == ["Bearer first", "Bearer second"]
    tok.unlink()
    with pytest.raises(cc.TokenUnavailable):
        c.evaluate(eval_req())
    with pytest.raises(cc.TokenUnavailable):
        cc.CoreClient(f.url, token="two words").evaluate(eval_req())
    assert f.hits == 2


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_the_breaker_opens_after_five_failures_fails_fast_and_recovers(fake):
    state = {"down": True}
    f = fake(lambda f: (503, b'{"error": "down"}') if state["down"] else (200, json.dumps(OK_EVAL).encode()))
    clock = Clock()
    c = cc.CoreClient(f.url, token=GW, clock=clock)
    for i in range(5):
        assert c.breaker_state == cc.CLOSED, i
        with pytest.raises(cc.CoreUnavailable) as e:
            c.evaluate(eval_req())
        assert e.value.reason == cc.SERVER_ERROR
    assert c.breaker_state == cc.OPEN
    hits = f.hits
    start = time.monotonic()
    for _ in range(100):
        with pytest.raises(cc.CoreUnavailable) as e:
            c.evaluate(eval_req())
        assert e.value.reason == cc.BREAKER_OPEN
    assert f.hits == hits and time.monotonic() - start < 0.2
    with pytest.raises(cc.CoreUnavailable):
        c.healthz()  # probes bypass the breaker
    assert f.hits > hits
    clock.t += cc.DEFAULT_BREAKER_COOLDOWN
    assert c.breaker_state == cc.HALF_OPEN
    with pytest.raises(cc.CoreUnavailable) as e:
        c.evaluate(eval_req())
    assert e.value.reason == cc.SERVER_ERROR and c.breaker_state == cc.OPEN  # a failed probe reopens at once
    state["down"] = False
    clock.t += cc.DEFAULT_BREAKER_COOLDOWN
    assert c.evaluate(eval_req()).decision and c.breaker_state == cc.CLOSED


def test_only_one_half_open_probe(fake):
    state = {"mode": "down"}

    def handle(f):
        if state["mode"] == "down":
            return 503, b"{}"
        if state["mode"] == "hang":
            state["mode"] = "up"
            f.release.wait(5)
        return 200, json.dumps(OK_EVAL).encode()

    f = fake(handle)
    clock = Clock()
    c = cc.CoreClient(f.url, token=GW, clock=clock, breaker_threshold=1, retries=0, timeout=5)
    with pytest.raises(cc.CoreUnavailable):
        c.evaluate(eval_req())
    assert c.breaker_state == cc.OPEN
    clock.t += cc.DEFAULT_BREAKER_COOLDOWN
    state["mode"] = "hang"
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", c.evaluate(eval_req())))
    t.start()
    deadline = time.monotonic() + 2
    while f.hits < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    with pytest.raises(cc.CoreUnavailable) as e:
        c.evaluate(eval_req())
    assert e.value.reason == cc.BREAKER_OPEN
    f.release.set()
    t.join(5)
    assert out["r"].decision and c.breaker_state == cc.CLOSED and f.hits == 2


def test_a_closed_port_and_keepalive_reuse(fake):
    port = free_port()
    with pytest.raises(cc.CoreUnavailable) as e:
        cc.CoreClient(f"http://127.0.0.1:{port}", token=GW, retries=0).evaluate(eval_req())
    assert e.value.reason == cc.CONNECTION and e.value.attempts == 1
    f = fake(answer(200, OK_EVAL))
    c = cc.CoreClient(f.url, token=GW)
    for _ in range(5):
        assert c.evaluate(eval_req()).decision
    assert f.hits == 5
    c.close()


def test_base_url_checks():
    for bad in ("", "core:8080", "ftp://core", "http://", "http://u:p@core", "http://core?x=1"):
        with pytest.raises(ValueError):
            cc.CoreClient(bad)


def test_a_path_prefix_is_kept(fake):
    paths = []
    f = fake(answer(200, {"seq": 1, "hash": "h"}))
    orig = f.server.RequestHandlerClass.do_GET

    def spy(self):
        paths.append(self.path)
        orig(self)

    f.server.RequestHandlerClass.do_GET = spy
    cc.CoreClient(f.url + "/api/v1/namespaces/x/services/core:8080/proxy/", token=GW).outcome("12", {"result": "ok"})
    assert paths == ["/api/v1/namespaces/x/services/core:8080/proxy/v1/decisions/12/outcome"]


def test_the_async_client(core):
    async def run():
        c = cc.AsyncCoreClient(core.url, token=GW)
        res = await c.evaluate(corpus_request(PR_OPEN_ALLOWED))
        health = await c.healthz()
        await c.aclose()
        return res, health

    res, health = asyncio.run(run())
    assert res.decision and health.ok
