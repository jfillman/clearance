"""The fixture agents' calls, and edge probes, replayed through a Gateway for the golden corpus.

Collected only by record.py (it is not under tests/). Each fixture agent opens a session and calls every tool it
is granted with plausible arguments, a tool it is not granted, a tripwire, and an unknown tool; then the probes
cover the places cel-python and cel-go, or Python and Go, could disagree: integers outside int64, Unicode
lowercasing and stripping, `$` before a trailing newline, YAML 1.1 types, int/float/bool argument types.
"""
from __future__ import annotations

import dataclasses
from datetime import timedelta

import pytest

from clearance import profile
from clearance.audit import AuditLog
from clearance.backends import FakeArgo, FakeArtifacts, FakeGit, FakeHuman, FakeRead, FakeRunBackend, core_handlers
from clearance.control import Hold, MemoryHolds
from clearance.dispatch import Gateway, Principal
from clearance.modelproxy import ModelRoute
from clearance.packs.hangar import HANGAR
from clearance.session import SessionStore
from clearance.tiers import Tier

from conftest import AGENTS, Clock, StaticAuth

ROUTES = {"claude-sonnet-5": ModelRoute("claude-sonnet-5", "anthropic", "https://api.anthropic.com", "claude-sonnet-5")}
UUID = "0f8fad5b-d9cb-469f-a165-70867728950e"
CICD_BEFORE = "apiVersion: glidepath/v1\nkind: Cicd\ngovernance:\n  sast: yes\n  imageScan: on\ndeploy:\n  environments:\n  - {name: dev, tier: ground}\n  - {name: prod, tier: flight}\n"

ARGS = {
    "catalog.read": {"query": "kind=component"},
    "metrics.query": {"promql": "up"},
    "logs.query": {"logql": '{app="x"}'},
    "argo.app.get": {"app": "gate-api-dev"},
    "app.api.get": {"service": "gate-api", "path": "/health"},
    "repo.file.get": {"repo": "jfillman/gate-api", "path": "README.md"},
    "repo.pr.open": {"repo": "jfillman/gate-api", "branch": "agent/t-1", "title": "fix",
                     "files": [{"path": "src/app.py", "content": "x = 1\n"}]},
    "repo.pr.open_upper": {"repo": "jfillman/gitops-gate-api", "branch": "agent/t-1", "title": "bump",
                           "files": [{"path": "values.yaml", "content": "replicas: 2\n", "before": "replicas: 1\n"}]},
    "xr.request": {"app": "gate-api", "env": "dev", "kind": "Queue", "spec": {"size": 1}},
    "argo.sync.lower": {"app": "gate-api-dev", "project": "gate-api-lower"},
    "glidepath.run.rerun": {"app": "gate-api", "pipelinerun": "gate-api-pr-1"},
    "glidepath.run.cancel": {"app": "gate-api", "pipelinerun": "gate-api-pr-1"},
    "run.spawn": {"agent": "researcher", "limits": {"tool_calls": 10}},
    "run.close": {"run_id": "s-nope"},
    "human.request": {"question": "ok?"},
    "artifact.put": {"name": "a", "content": "x"},
    "chat.send": {"text": "hi"},
}


def gateway(clock, defs=None, **kw):
    counter = iter(range(1, 100000))
    store = SessionStore(id_gen=lambda: f"s-{next(counter):06x}")
    auth = StaticAuth({
        "alice": Principal("user:alice", "user", Tier.T1),
        "bob": Principal("user:bob", "user", Tier.T1),
        "ro": Principal("user:ro", "user", Tier.T0),
        "holmes": Principal("holmesgpt/holmes", "workload", Tier.T1),
        "nightly": Principal("autopilot-runs/nightly-reviewer", "workload", Tier.T1),
    })
    b = dict(git=FakeGit(), argo=FakeArgo(), read=FakeRead(), human=FakeHuman(), artifacts=FakeArtifacts())
    return Gateway(defs or profile.load_dir(AGENTS), store, AuditLog(), auth, clock, packs=(HANGAR,),
                   handlers=core_handlers(**b), runs=FakeRunBackend(), models=ROUTES, model_auth=auth, **kw)


TOKENS = {"coding-agent": "alice", "orchestrator": "alice", "researcher": "alice", "triage-agent": "holmes",
          "nightly-reviewer": "nightly"}


@pytest.mark.parametrize("agent", sorted(TOKENS))
def test_fixture_agent_calls(agent):
    clock = Clock()
    gw = gateway(clock)
    token = TOKENS[agent]
    r = gw.open_session(token, agent)
    assert r.ok, r
    sid = r.session
    d = gw.defs[agent]
    for tool in sorted(d.limits.tools):
        gw.call(token, sid, tool, dict(ARGS.get(tool, {"x": 1})))
    gw.call(token, sid, "repo.pr.open", {"repo": "someone/else", "branch": "b", "title": "t",
                                         "files": [{"path": ".tekton/x.yaml", "content": "x"}]})
    gw.call(token, sid, "artifact.put", ARGS["artifact.put"])
    gw.call(token, sid, "no.such.tool", {})
    gw.call("bob", sid, "catalog.read", {"query": "x"})
    gw.model_authorize(token, sid, "claude-sonnet-5", 100)
    gw.model_authorize(token, sid, "gpt-9", 100)
    gw.call(token, sid, "k8s.exec", {})          # trips the breaker
    gw.call(token, sid, "catalog.read", {"query": "x"})
    gw.model_authorize(token, sid, "claude-sonnet-5", 1)
    if d.identity_type == "workload":
        gw.open_triggered(agent, "cron", task_id="t-nightly")
        gw.open_triggered(agent, "cron", task_id="t-nightly")   # deduped onto the live one
    clock.advance(minutes=d.limits.ttl_minutes + 1)
    gw.call(token, sid, "catalog.read", {"query": "x"})
    gw.model_authorize(token, sid, "claude-sonnet-5", 1)


def test_denial_trip_after_five():
    gw = gateway(Clock())
    sid = gw.open_session("alice", "researcher").session
    for _ in range(6):
        gw.call("alice", sid, "repo.pr.open", ARGS["repo.pr.open"])
    gw.call("alice", sid, "k8s.apply", {})


def test_tripwire_trips_children():
    gw = gateway(Clock())
    sid = gw.open_session("alice", "orchestrator").session
    gw.call("alice", sid, "run.spawn", {"agent": "researcher", "limits": {}})
    for _ in range(3):
        gw.call("alice", sid, "catalog.read", {"query": "x"})
    gw.call("alice", sid, "secrets.read", {})


def test_spawn_edges():
    clock = Clock()
    gw = gateway(clock)
    sid = gw.open_session("alice", "orchestrator").session
    for args in ({"agent": "nobody", "limits": {}},
                 {"agent": "researcher", "limits": {"tool_calls": 10**6}},
                 {"agent": "researcher", "limits": {"tools": ["repo.pr.open"]}},
                 {"agent": "researcher", "limits": {"bogus": 1, "alpha": 2}},
                 {"agent": "researcher", "limits": {"network": "clearance-model"}},
                 {"agent": "researcher", "limits": {"network": "warp"}},
                 {"agent": "researcher", "limits": {"compute": "huge"}},
                 {"agent": "researcher", "limits": {"tier_ceiling": "T0", "ttl_minutes": 5}},
                 {"agent": "researcher", "limits": {"ttl_minutes": 0}},
                 {"agent": "researcher"},
                 {"agent": "researcher", "limits": {"children": 0}},
                 {"agent": "researcher", "limits": {"models": []}}):
        gw.call("alice", sid, "run.spawn", args)
    gw.call("alice", sid, "run.spawn", {"agent": "researcher", "limits": {}})   # children budget spent
    # depth: orchestrator -> orchestrator -> orchestrator -> orchestrator
    gw2 = gateway(Clock())
    s = gw2.open_session("alice", "orchestrator").session
    for _ in range(4):
        r = gw2.call("alice", s, "run.spawn", {"agent": "orchestrator", "limits": {"children": 3}})
        if not r.ok:
            break
        s = r.data["session"]
        gw2.runs.principal = None
    # time nearly up: the child gets what is left
    gw3 = gateway(clock)
    s3 = gw3.open_session("alice", "orchestrator").session
    clock.advance(minutes=59, seconds=30)
    gw3.call("alice", s3, "run.spawn", {"agent": "researcher", "limits": {}})


def test_open_edges():
    clock = Clock()
    holds = MemoryHolds()
    gw = gateway(clock, holds=holds)
    for token, agent, limits in (("alice", "nobody", None), ("alice", "triage-agent", None), ("holmes", "researcher", None),
                                 ("holmes", "triage-agent", {"tool_calls": 5}), ("alice", "coding-agent", {"tool_calls": 10**4}),
                                 ("alice", "coding-agent", {"zeta": 1, "beta": 2}), ("alice", "coding-agent", {"network": "Clearance+Model"}),
                                 ("alice", "coding-agent", {"network": "nope"}), ("alice", "coding-agent", {"compute": "GPU"}),
                                 ("alice", "coding-agent", {"tier_ceiling": "T2", "tools": ["k8s.exec"], "models": ["x"]}),
                                 ("alice", "coding-agent", {"ttl_minutes": 0}), ("alice", "coding-agent", {}),
                                 ("alice", "coding-agent", {"tools": [], "tier_ceiling": ""})):
        gw.open_session(token, agent, limits)
    gw.open_session("alice", "coding-agent", None, task_id="t-mine")
    gw.open_triggered("nobody", "cron")
    gw.open_triggered("researcher", "cron")
    holds.put(Hold("nightly-reviewer", "user:alice", None, "maintenance", clock(), clock() + timedelta(hours=2)))
    gw.open_triggered("nightly-reviewer", "cron")
    clock.advance(hours=3)
    gw.open_triggered("nightly-reviewer", "cron")


def test_model_edges():
    gw = gateway(Clock())
    sid = gw.open_session("alice", "coding-agent", {"model_tokens": 1000}).session
    for est in (0, 1000, 1001, -1, 10**30, 2**63, 2**63 - 1):
        gw.model_authorize("alice", sid, "claude-sonnet-5", est)
    sid2 = gw.open_session("alice", "coding-agent", {"models": []}).session
    gw.model_authorize("alice", sid2, "claude-sonnet-5", 1)
    gw.model_authorize("alice", "s-none", "claude-sonnet-5", 1)
    gw.model_authorize("alice", sid, "o'brien", 1)
    gw.model_authorize("alice", sid, 'say "x" é​\n', 1)


def _defs_with(**limits):
    defs = profile.load_dir(AGENTS)
    doc = {"name": "big", "description": "probe", "kind": "task", "identity": {"type": "delegated"},
           "profile": {"tierCeiling": "T1", "tools": ["catalog.read", "repo.pr.open"], "repos": {"allow": ["jfillman/*"]},
                       "limits": {"ttlMinutes": 30, "toolCalls": 10, "githubCalls": 10, "openPrs": 1, "modelTokens": 1,
                                  "children": 0, **limits}}}
    defs["big"] = profile.parse(doc)
    return defs


@pytest.mark.parametrize("limits", [{"toolCalls": 2**63}, {"toolCalls": 2**63 - 1}, {"githubCalls": 2**64},
                                    {"openPrs": 2**63 + 5}])
def test_integer_overflow(limits):
    gw = gateway(Clock(), defs=_defs_with(**limits))
    sid = gw.open_session("alice", "big").session
    gw.call("alice", sid, "catalog.read", {"query": "x"})
    gw.call("alice", sid, "no.such.tool", {})


FILES_YAML = [
    ("a: 1\n", "a: 1.0\n"), ("a: yes\n", "a: true\n"), ("a: on\n", "a: off\n"), ("a: 010\n", "a: 8\n"),
    ("a: 1:20\n", "a: 80\n"), ("a: 0x1F\n", "a: 31\n"), ("a: 1_000\n", "a: 1000\n"), ("a: 2024-01-01\n", "a: '2024-01-01'\n"),
    ("a: .nan\n", "a: .nan\n"), ("a: [.nan]\n", "a: [.nan]\n"), ("b: &x {c: 1}\na: *x\n", "b: {c: 1}\na: {c: 2}\n"),
    ("base: &b {x: 1}\nm:\n  <<: *b\n  y: 2\n", "base: {x: 1}\nm: {x: 1, y: 3}\n"), ("a: 1\na: 2\n", "a: 2\n"),
    ("release: {image: x}\n", "release: {image: y}\n"), ("extraManifests: []\n", "extraManifests: [1]\n"),
    ("a: 1e3\n", "a: 1000\n"), ("a: 1.e+3\n", "a: 1000\n"), ("a: ~\n", "a: null\n"), ("[1, 2]\n", "[1, 3]\n"),
    ("a: 2001-12-14t21:59:43.10-05:00\n", "a: 2001-12-15 2:59:43.1Z\n"), ("a: =\n", "a: 1\n"), ("? [1]\n: x\n", "a: 1\n"),
    ("a: !!str 1\n", "a: 1\n"), ("a: !foo x\n", "a: x\n"), ("a: '1'\nb: \"on\"\n", "a: 1\nb: on\n"),
    ("a: 9223372036854775808\n", "a: 9223372036854775809\n"), ("x: 1\n---\ny: 2\n", "x: 1\n"), (": bad: [\n", "a: 1\n"),
    ("a: 2024-02-29\n", "a: 2024-03-01\n"),
]


def test_yaml_bad_date_raises_in_python():
    """PyYAML raises ValueError (not a YAMLError) for a date that does not exist; the Python gateway does not catch
    it, so the call fails with no record. The Go engine denies it (R000 ValueError): internal/decide tests that."""
    gw = gateway(Clock())
    sid = gw.open_session("alice", "coding-agent").session
    with pytest.raises(ValueError):
        gw.call("alice", sid, "repo.pr.open_upper", {"repo": "jfillman/gitops-x", "branch": "b", "title": "t",
                                                     "files": [{"path": "values.yaml", "before": "a: 2024-02-30\n",
                                                                "content": "a: 1\n"}]})


@pytest.mark.parametrize("before,after", FILES_YAML)
def test_yaml_field_scope(before, after):
    gw = gateway(Clock())
    sid = gw.open_session("alice", "coding-agent").session
    gw.call("alice", sid, "repo.pr.open_upper", {"repo": "jfillman/gitops-x", "branch": "b", "title": "t",
                                                 "files": [{"path": "values.yaml", "before": before, "content": after}]})


CICD = [
    {"before": CICD_BEFORE, "content": CICD_BEFORE.replace("sast: yes", "sast: no")},
    {"before": CICD_BEFORE, "content": CICD_BEFORE.replace("imageScan: on", "imageScan: 'yes'")},
    {"before": CICD_BEFORE, "content": CICD_BEFORE.replace("- {name: prod, tier: flight}\n", "")},
    {"before": CICD_BEFORE, "content": CICD_BEFORE.replace("tier: ground", "tier: flight")},
    {"before": CICD_BEFORE, "content": CICD_BEFORE + "secrets: [a]\n"},
    {"before": CICD_BEFORE, "content": CICD_BEFORE + "notifications: {slack: '#x'}\n"},
    {"before": CICD_BEFORE, "op": "merge-patch", "content": {"governance": {"sast": None}}},
    {"before": CICD_BEFORE, "op": "merge-patch", "content": "governance: {sast: false}\n"},
    {"before": CICD_BEFORE, "op": "merge-patch", "content": "[1]\n"},
    {"content": CICD_BEFORE},
    {"before": "[1]\n", "content": "a: 1\n"},
    {"before": CICD_BEFORE, "content": "just text\n"},
    {"before": CICD_BEFORE, "content": ": [\n"},
    {"before": CICD_BEFORE, "content": CICD_BEFORE + "pipelines: [1]\n"},
    {"before": CICD_BEFORE + "pipelines: {pr: {steps: [{stage: test, role: check-ride}, {stage: test}]}}\n",
     "content": CICD_BEFORE + "pipelines: {pr: {steps: [{stage: test, required: false}]}}\n"},
    {"before": CICD_BEFORE + "pipelines: {pr: {steps: 5}}\n", "content": CICD_BEFORE},
    {"before": CICD_BEFORE + "pipelines: {7: {steps: []}, on: x}\n", "content": CICD_BEFORE + "pipelines: {7: x}\n"},
    {"before": CICD_BEFORE, "content": CICD_BEFORE.replace("deploy:", "deploy: 5\nold:")},
    {"before": CICD_BEFORE, "content": CICD_BEFORE + "test: {coverage: {min: 0.5}}\n"},
    {"before": CICD_BEFORE + "governance2: {x: 'it''s'}\n", "content": CICD_BEFORE + "governance2: {x: \"a\\tb\"}\n"},
]


@pytest.mark.parametrize("i", range(len(CICD)))
def test_cicd_scope_probe(i):
    gw = gateway(Clock())
    sid = gw.open_session("alice", "coding-agent").session
    f = {"path": "apps/x/cicd.yaml", **CICD[i]}
    gw.call("alice", sid, "repo.pr.open", {"repo": "jfillman/x", "branch": "b", "title": "t", "files": [f]})


ARG_PROBES = [
    ("repo.pr.open", {"repo": "jfillman/ΑΣ", "branch": "b", "title": "t", "files": [{"path": "a", "content": "x"}]}),
    ("repo.pr.open", {"repo": "jfillman/İx", "branch": "b", "title": "t", "files": [{"path": "a", "content": "x"}]}),
    ("repo.pr.open", {"repo": "jfillman/" + "A" * 120, "branch": "b", "title": "t", "files": [{"path": "a", "content": "x"}]}),
    ("repo.pr.open", {"repo": "jfillman/x\n", "branch": "b", "title": "t", "files": [{"path": "release.yaml\n", "content": "x"}]}),
    ("repo.pr.open", {"repo": "jfillman/x", "branch": "b", "title": "t", "files": [{"path": "a/../.tekton/p.yaml", "content": "x"}]}),
    ("repo.pr.open", {"repo": "jfillman/x", "branch": "b", "title": "t", "files": [{"path": 5}, {"content": "x"}, "nope"]}),
    ("repo.pr.open", {"repo": "jfillman/x", "branch": "", "title": "t", "files": []}),
    ("repo.pr.open", {"repo": "jfillman/x/y", "branch": "b", "title": None, "files": [{"path": "a", "content": "x"}]}),
    ("repo.pr.open", {"repo": "", "branch": "b", "title": "t", "files": [{"path": "a", "content": "x"}]}),
    ("xr.request", {"app": "x", "env": "prod", "kind": "Queue", "spec": {}}),
    ("xr.request", {"app": "x", "env": "pr-12", "kind": "Queue", "spec": {}}),
    ("argo.sync.lower", {"app": "x", "project": "x-upper"}),
    ("glidepath.run.rerun", {"app": "Gate", "pipelinerun": "p"}),
    ("glidepath.run.rerun", {"app": "gate-api\n", "pipelinerun": "p"}),
    ("glidepath.run.rerun", {"app": "gate-api", "pipelinerun": "p", "limit": 5.0, "sinceHours": True, "timeoutSeconds": 10**30}),
    ("glidepath.run.rerun", {"app": "gate-api", "pipelinerun": "p", "limit": 1000, "dryRun": 1, "reason": " \x1c "}),
    ("glidepath.run.rerun", {"app": "gate-api", "pipelinerun": "p", "title": "　t　", "body": "é" * 4000,
                             "branch": "a..b", "baseRef": "main", "patch": {"k": "é" * 10}}),
    ("glidepath.run.cancel", {"app": "gate-api", "pipelinerun": "p", "patch": [], "env": "prod"}),
    ("artifact.put", {"name": "a", "content": "é" * 1048577}),
    ("artifact.put", {"name": "a", "content": "x" * 1048576}),
    ("human.request", {"question": ""}),
    ("catalog.read", {"query": ["a"]}),
    ("catalog.read", {"query": 0}),
    ("catalog.read", {"query": False}),
    ("catalog.read", {"query": {}}),
]


@pytest.mark.parametrize("i", range(len(ARG_PROBES)))
def test_arg_probe(i):
    gw = gateway(Clock())
    sid = gw.open_session("alice", "coding-agent").session
    tool, args = ARG_PROBES[i]
    gw.call("alice", sid, tool, args)
    gw.call("ro", sid, tool, args)


AF_PROBES = [
    ("airframe.status", {"app": "x\n"}),
    ("airframe.status", {"app": "nope"}),
    ("airframe.describe", {"app": "x", "env": "Dev"}),
    ("airframe.validate", {"documents": [{"path": "a/b.yaml", "content": "x"}]}),
    ("airframe.validate", {"documents": [{"path": "a/b.yaml\n", "content": "x"}]}),
    ("airframe.validate", {"documents": [{"path": "../b.yaml", "content": "x"}]}),
    ("airframe.validate", {"documents": [{"path": "b.yaml", "content": "x", "extra": 1}]}),
    ("airframe.validate", {"documents": []}),
    ("airframe.capabilities", {"section": "chart"}),
    ("airframe.capabilities", {"section": 5}),
    ("airframe.plan", {"spec": [], "baseCicd": 5, "mode": "xr", "render": "yes"}),
    ("glidepath.promote", {"app": "x", "env": "prod", "cluster": "c", "sourceEnv": "dev"}),
    ("glidepath.promote", {"app": "x", "env": "prod", "cluster": "c", "sourceEnv": "dev", "sourceCluster": "c"}),
    ("glidepath.promote", {"app": "y", "env": "prod", "cluster": "c", "sourceImageRepo": "ghcr.io/a", "sourceImageTag": "v1"}),
    ("glidepath.cicd.propose", {"app": "x", "repo": "jfillman/x", "patch": {"a": 1}, "title": "t"}),
    ("glidepath.cicd.propose", {"app": "x", "repo": "other/x", "patch": "x", "title": "t"}),
]


@pytest.mark.parametrize("i", range(len(AF_PROBES)))
def test_pack_probe(i):
    defs = profile.load_dir(AGENTS)
    doc = {"name": "packer", "description": "probe", "kind": "session", "identity": {"type": "delegated"},
           "profile": {"tierCeiling": "T2", "tools": sorted({t for t, _ in AF_PROBES} | {"chat.send", "chat.recv", "app.api.get", "repo.file.get"}),
                       "repos": {"allow": ["jfillman/*"], "fieldAllow": ["/spec/**"]},
                       "apis": {"allow": ["gate-api"]},
                       "glidepath": {"apps": ["x", "gate-*"]}, "airframe": {"apps": ["x"]},
                       "limits": {"ttlMinutes": 30, "toolCalls": 100, "githubCalls": 100, "openPrs": 3,
                                  "modelTokens": 1, "children": 0}}}
    d = profile.parse(doc)
    # Allowlist patterns the schema would refuse, to probe fnmatch: a negated class, and a newline.
    raw = {**d.raw_profile, "glidepath": {"apps": ["x", "gate-*", "[!z]y*"]}, "airframe": {"apps": ["x", "x\n"]}}
    defs["packer"] = dataclasses.replace(d, raw_profile=raw)
    gw = gateway(Clock(), defs=defs)
    sid = gw.open_session("alice", "packer").session
    tool, args = AF_PROBES[i]
    gw.call("alice", sid, tool, args)
    if i == 0:
        for t, a in (("chat.send", {"text": "x"}), ("app.api.get", {"service": "gate-api", "path": "/a?b"}),
                     ("app.api.get", {"service": "other", "path": "/a"}), ("app.api.get", {"service": "gate-api", "path": "a"}),
                     ("repo.file.get", {"repo": "jfillman/x", "path": "../x"}), ("repo.file.get", {"repo": "jfillman/x", "path": 3}),
                     ("repo.file.get", {"repo": "jfillman/x"}), ("repo.file.get", {"repo": "jfillman/x", "path": "a\\b"})):
            gw.call("alice", sid, t, a)


def test_chat_and_artifact_rules():
    defs = profile.load_dir(AGENTS)
    for kind in ("task", "session"):
        doc = {"name": f"chatty-{kind}", "description": "probe", "kind": kind, "identity": {"type": "delegated"},
               "profile": {"tierCeiling": "T1", "tools": ["chat.send", "chat.recv", "artifact.put", "artifact.get"],
                           "limits": {"ttlMinutes": 30, "toolCalls": 100, "githubCalls": 0, "openPrs": 0,
                                      "modelTokens": 0, "children": 0}}}
        defs[doc["name"]] = profile.parse(doc)
    gw = gateway(Clock(), defs=defs)
    for kind in ("task", "session"):
        sid = gw.open_session("alice", f"chatty-{kind}").session
        gw.call("alice", sid, "chat.send", {"text": "hi"})
        gw.call("alice", sid, "chat.recv", {})
        gw.call("alice", sid, "artifact.put", {"name": "a", "content": "é" * 1048577})
        gw.call("alice", sid, "artifact.put", {"name": "a", "content": "é" * 1048576})


def test_r013_is_reachable_only_through_an_altered_context():
    """Every registered T2 tool is propose-only, so R013 cannot match a real call; a context altered by hand
    (recorded as an activation line) checks the rule still means the same under cel-go."""
    from clearance import policy
    gw = gateway(Clock())
    sid = gw.open_session("alice", "coding-agent", {"tier_ceiling": "T1"}).session
    s = gw.store.get(sid)
    for tier, propose, eff in ((2, False, 2), (2, True, 2), (3, False, 3), (2, False, 1)):
        c = policy.build_context(s, "user:alice", Tier.T2, "repo.pr.open_upper", ARGS["repo.pr.open_upper"],
                                 [], ["jfillman/*"], s.created_at)
        c["tool"]["tier"], c["tool"]["propose_only"], c["effective"]["tier"] = tier, propose, eff
        c["effective"]["tools"] = sorted(set(c["effective"]["tools"]) | {"repo.pr.open_upper"})
        policy.evaluate(c)


ACTIVATION_PROBES = [
    ("tool", "tier", None), ("tool", "tier", 1.5), ("tool", "tier", True), ("tool", "tier", 2**63),
    ("tool", "name", 5), ("effective", "tools", ["catalog.read", 7]), ("effective", "tools", "catalog.read"),
    ("session", "tool_calls_left", -2**63), ("session", "tool_calls_left", 0.5), ("ctx", "missing_args", False),
    ("ctx", "owns_session", 1), ("ctx", "known", None), ("ctx", "artifact_bytes", 1048577.0),
]


@pytest.mark.parametrize("i", range(len(ACTIVATION_PROBES)))
def test_cel_type_probes(i):
    """Values of the wrong CEL type, which a Go request cannot carry (its fields are typed) but a Python context
    altered by hand can: they show where cel-python and cel-go part, and that both fail closed or agree."""
    from clearance import policy
    gw = gateway(Clock())
    sid = gw.open_session("alice", "coding-agent").session
    s = gw.store.get(sid)
    c = policy.build_context(s, "user:alice", Tier.T1, "catalog.read", {"query": "x"}, [], ["jfillman/*"], s.created_at)
    group, key, value = ACTIVATION_PROBES[i]
    c[group][key] = value
    policy.evaluate(c)
