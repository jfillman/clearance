"""pytest plugin: record every decision the Python engine makes into the golden corpus the Go engine replays.

    cd tools/golden && PYTHONPATH=../../src HANGAR_TECH=/Users/jerf/tech \
        python -m pytest -p golden_recorder ../../tests test_fixture_calls.py

(record.py runs exactly that.) It wraps the four decision points, without changing what they do:

  tool.call      Policy.build_context + Policy.evaluate (and, inside Gateway.call, the record it writes)
  session.spawn  a Gateway.call of run.spawn with a run backend: the call's rules, then Gateway._spawn
  session.open   Gateway.open_session / Gateway.open_triggered
  model.call     ModelProxy.authorize, and Gateway.model_authorize's no-routes refusal

and writes one JSON line per decision to $GOLDEN_OUT (default ../../testdata/golden/corpus.jsonl): the Go
evaluation request built from the inputs Python saw, Python's decision, the session before and after (the
spend Python applied), the CEL activation Python built, and the record Python wrote. A context a test altered
after build_context (or built by hand) is recorded as kind "activation": the Go replay runs the rules over it.
The first line is the Python rule set and tool registry, so the Go test also catches a drifted bundle.
"""
from __future__ import annotations

import copy
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from clearance import audit as audit_mod, dispatch, modelproxy, pg, policy, session as session_mod

OUT = Path(os.environ.get("GOLDEN_OUT", Path(__file__).resolve().parents[2] / "testdata" / "golden" / "corpus.jsonl"))

_local = threading.local()
_lines: list[dict[str, Any]] = []
_lock = threading.Lock()
_current = {"node": None}
_built: dict[int, tuple[Any, dict[str, Any], Any]] = {}   # id(context) -> (context, inputs, snapshot)


def _frames() -> list[dict[str, Any]]:
    if not hasattr(_local, "frames"):
        _local.frames = []
    return _local.frames


def _emit(line: dict[str, Any]) -> None:
    line["source"] = _current["node"]
    if "test_cel_type_probes" in (line["source"] or "") and line.get("kind") == "activation":
        line["probe"] = "cel-type"      # an ill-typed activation: see internal/decide/CEL_DIFFERENCES.md
    with _lock:
        _lines.append(line)


# -- translation into the Go request -----------------------------------------------------------------------

def _t(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _session(s) -> dict[str, Any] | None:
    if s is None:
        return None
    return {"id": s.id, "principal": s.principal, "agent": s.agent, "task_id": s.task_id, "parent_id": s.parent_id,
            "depth": s.depth, "limits": s.limits.as_dict(), "used": dict(s.used), "reserved": dict(s.reserved),
            "expires_at": _t(s.expires_at), "closed": s.closed, "tripped": s.tripped, "denials": s.denials}


def _after(s) -> dict[str, Any] | None:
    if s is None:
        return None
    return {"used": dict(s.used), "reserved": dict(s.reserved), "denials": s.denials, "tripped": s.tripped,
            "trip_reason": s.trip_reason}


def _agent(d) -> dict[str, Any] | None:
    if d is None:
        return None
    return {"name": d.name, "kind": d.kind, "identity_type": d.identity_type, "service_account": d.service_account,
            "limits": d.limits.as_dict()}


def _json(v: Any) -> Any:
    """A JSON-safe deep copy (what the value looks like over the wire)."""
    return json.loads(json.dumps(v, default=str))


def _subject(pid: str, kind: str = "user", tier: int = 1, acting: str | None = None) -> dict[str, Any]:
    props: dict[str, Any] = {"kind": kind, "tier_ceiling": int(tier)}
    if acting and acting != pid:
        props["acting_as"] = acting
    return {"type": "principal", "id": pid, "properties": props}


def _decision(d) -> dict[str, Any]:
    if isinstance(d, dict):
        out = {k: d.get(k) for k in ("allow", "rule", "name", "message", "hint", "tier")}
        out["problems"] = d.get("problems") or []
        return out
    return {"allow": d.allow, "rule": d.rule, "name": getattr(d, "name", None), "message": d.message,
            "hint": getattr(d, "hint", None), "tier": getattr(d, "tier", None),
            "problems": [dict(p) for p in getattr(d, "problems", ()) or ()]}


def _tool_request(inp: dict[str, Any], subject: dict[str, Any]) -> dict[str, Any]:
    return {"subject": subject, "action": {"name": "tool.call", "properties": {"args": inp["args"]}},
            "resource": {"type": "tool", "id": inp["tool"]},
            "context": {"now": inp["now"], "session_id": inp["session"]["id"], "session": inp["session"],
                        "scope": inp["scope"]}}


# -- wrappers ---------------------------------------------------------------------------------------------

_orig: dict[str, Any] = {}


def _build_context(self, session, principal_id, principal_tier, tool, args, deny_globs, repo_allow, now,
                   api_allow=None, agent_kind="task", field_deny=None, field_allow=None, definition=None):
    ctx = _orig["build_context"](self, session, principal_id, principal_tier, tool, args, deny_globs, repo_allow, now,
                                 api_allow=api_allow, agent_kind=agent_kind, field_deny=field_deny,
                                 field_allow=field_allow, definition=definition)
    try:
        inp = {"tool": tool, "args": _json(args), "now": _t(now), "session": _session(session),
               "principal": principal_id, "tier": int(principal_tier),
               "scope": {"agent_kind": agent_kind, "deny_paths": list(deny_globs), "repos_allow": list(repo_allow),
                         "api_allow": list(api_allow or []), "field_deny": list(field_deny or []),
                         "field_allow": list(field_allow or []),
                         **({"profile": _json(definition.raw_profile)} if getattr(definition, "raw_profile", None) else {})},
               "packs": [p.name for p in self.packs]}
        _built[id(ctx)] = (ctx, inp, copy.deepcopy(ctx))
    except Exception as e:  # noqa: BLE001 - the recorder never changes what the code under test does
        _built[id(ctx)] = (ctx, {"error": repr(e)}, None)
    return ctx


def _evaluate(self, context):
    d = _orig["evaluate"](self, context)
    entry = _built.get(id(context))
    act = _json(context)
    # Compared as JSON, so a value swapped for an equal one of another type (True for 1) counts as altered.
    if (entry is not None and entry[0] is context and entry[2] is not None and "error" not in entry[1]
            and json.dumps(act, sort_keys=True) == json.dumps(_json(entry[2]), sort_keys=True)):
        inp = entry[1]
        line = {"kind": "tool.call", "packs": inp["packs"], "inp": inp, "activation": act, "python": _decision(d)}
    else:
        line = {"kind": "activation", "packs": [p.name for p in self.packs], "activation": act, "python": _decision(d)}
    frames = _frames()
    if frames and frames[-1]["kind"] == "call":
        frames[-1]["evals"].append(line)
    else:
        if line["kind"] == "tool.call":
            inp = line.pop("inp")
            line["request"] = _tool_request(inp, _subject(inp["principal"], "user", inp["tier"]))
            line["compare"] = {"record": False, "spend": False}
        _emit(line)
    return d


class _AuthProxy:
    def __init__(self, inner, sink):
        self._inner, self._sink = inner, sink

    def authenticate(self, token):
        p = self._inner.authenticate(token)
        self._sink.append(p)
        return p

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _with_auth(gw, attr, fn):
    seen: list = []
    inner = getattr(gw, attr)
    if inner is not None:
        setattr(gw, attr, _AuthProxy(inner, seen))
    try:
        return fn(), seen
    finally:
        if inner is not None:
            setattr(gw, attr, inner)


def _push(kind: str, **kw) -> dict[str, Any]:
    f = {"kind": kind, "events": [], "evals": [], "opened": [], **kw}
    _frames().append(f)
    return f


def _pop(f) -> None:
    fr = _frames()
    if fr and fr[-1] is f:
        fr.pop()


def _last_event(f, tool: str) -> dict[str, Any] | None:
    for ev in reversed(f["events"]):
        if ev.get("tool") == tool:
            return _json(ev)
    return None


def _call(self, token, session_id, tool, args):
    s = self.store.get(session_id)
    now = self.now()
    before = _session(s)
    f = _push("call")
    try:
        res, seen = _with_auth(self, "auth", lambda: _orig["call"](self, token, session_id, tool, args))
    finally:
        _pop(f)
    try:
        _record_call(self, f, res, seen, session_id, tool, args, now, before, s)
    except Exception as e:  # noqa: BLE001
        _emit({"kind": "error", "error": repr(e), "where": "call"})
    return res


def _record_call(gw, f, res, seen, session_id, tool, args, now, before, s):
    principal = seen[0] if seen else None
    if principal is None:
        return
    record = _last_event(f, tool)
    if not f["evals"]:
        if s is None:
            req = {"subject": _subject(principal.id, principal.kind, principal.tier_ceiling),
                   "action": {"name": "tool.call", "properties": {"args": _json(args)}},
                   "resource": {"type": "tool", "id": tool},
                   "context": {"now": _t(now), "session_id": session_id}}
            _emit({"kind": "tool.call", "packs": [p.name for p in gw.policy.packs], "request": req,
                   "python": _decision(res.decision), "record": record, "compare": {"record": True, "spend": False}})
        return
    line = f["evals"][0]
    if line["kind"] != "tool.call":
        _emit(line)
        return
    inp = line.pop("inp")
    req = _tool_request(inp, _subject(principal.id, principal.kind, inp["tier"], acting=inp["principal"]))
    eval_allow = line["python"]["allow"]
    compare = {"record": record is not None, "spend": True}
    spawn = tool == "run.spawn" and "run.spawn" in gw._handlers
    if spawn:
        line["kind"] = "session.spawn"
        req["action"]["name"] = "session.spawn"
        child_name = args.get("agent") if isinstance(args, dict) else None
        child = gw.defs.get(child_name) if isinstance(child_name, str) else None
        if child is not None:
            req["context"]["agent"] = _agent(child)
        req["context"]["new_session_id"] = f["opened"][0] if f["opened"] else "s-pending"
        line["python"] = _decision(res.decision)
        if f["opened"]:
            c = gw.store.get(f["opened"][0])
            if c is not None:
                line["grant"] = {"session": c.id, "task_id": c.task_id, "principal": c.principal, "agent": c.agent,
                                 "parent": c.parent_id, "depth": c.depth, "limits": c.limits.as_dict(),
                                 "expires_at": _t(c.expires_at)}
    else:
        if record is not None and eval_allow and record.get("decision") == "deny":
            # A handler refused an allowed call (human.request's HR-* rules, run.close): not this decision's record.
            compare = {"record": False, "spend": False, "note": "handler refused: " + str(record.get("rule"))}
    if tool == "run.close" or (record or {}).get("result") == "error:NoHandler":
        compare["spend"] = False
    line.update({"request": req, "record": record, "after": _after(gw.store.get(session_id)), "compare": compare,
                 "outcome": (record or {}).get("result")})
    _emit(line)


def _open_session(self, token, agent, limits=None, task_id=None):
    now = self.now()
    lim_in = _json(limits) if limits is not None else None
    f = _push("open")
    try:
        res, seen = _with_auth(self, "auth", lambda: _orig["open_session"](self, token, agent, limits, task_id))
    finally:
        _pop(f)
    try:
        if seen:
            p = seen[0]
            props: dict[str, Any] = {}
            if lim_in is not None:
                props["limits"] = lim_in
            if task_id:
                props["task_id"] = task_id
            req = {"subject": _subject(p.id, p.kind, p.tier_ceiling), "action": {"name": "session.open", "properties": props},
                   "resource": {"type": "agent", "id": agent},
                   "context": {"now": _t(now), "new_session_id": res.session if res.ok else "s-pending"}}
            d = self.defs.get(agent)
            if d is not None:
                req["context"]["agent"] = _agent(d)
            _emit_open(self, f, req, res)
    except Exception as e:  # noqa: BLE001
        _emit({"kind": "error", "error": repr(e), "where": "open"})
    return res


def _emit_open(gw, f, req, res):
    line = {"kind": "session.open", "packs": [p.name for p in gw.policy.packs], "request": req,
            "python": _decision({"allow": res.decision.get("allow"), "rule": res.decision.get("rule"),
                                 "message": res.decision.get("message")}),
            "record": _last_event(f, "session.open"), "compare": {"record": True, "spend": False}}
    if res.ok:
        s = gw.store.get(res.session)
        line["grant"] = {"session": s.id, "task_id": s.task_id, "principal": s.principal, "agent": s.agent,
                         "parent": s.parent_id, "depth": s.depth, "limits": s.limits.as_dict(),
                         "expires_at": _t(s.expires_at)}
    _emit(line)


def _open_triggered(self, agent, trigger, task_id=None):
    now = self.now()
    d = self.defs.get(agent)
    try:
        held = self.hold_for(agent) if d is not None else None
        live = self.store.find_live(agent, task_id, now) if task_id else None
    except Exception:  # noqa: BLE001
        held, live = None, None
    f = _push("open")
    try:
        res = _orig["open_triggered"](self, agent, trigger, task_id)
    finally:
        _pop(f)
    try:
        props: dict[str, Any] = {"trigger": trigger}
        if task_id:
            props["task_id"] = task_id
        ctx: dict[str, Any] = {"now": _t(now), "new_session_id": res.session if res.ok else "s-pending"}
        if d is not None:
            ctx["agent"] = _agent(d)
        if held is not None:
            ctx["hold"] = {"by": held.by, "until": _t(held.until), "reason": held.reason}
        if live is not None:
            ctx["live"] = _session(live)
        req = {"subject": _subject(f"trigger:{trigger}", "workload", 1), "action": {"name": "session.open", "properties": props},
               "resource": {"type": "agent", "id": agent}, "context": ctx}
        _emit_open(self, f, req, res)
    except Exception as e:  # noqa: BLE001
        _emit({"kind": "error", "error": repr(e), "where": "open_triggered"})
    return res


def _model_authorize(self, token, session_id, model, est_tokens):
    if self.models is None or self.model_auth is None:
        res = _orig["model_authorize"](self, token, session_id, model, est_tokens)
        req = {"subject": _subject("unknown", "workload", 1), "action": {"name": "model.call", "properties": {"est_tokens": est_tokens}},
               "resource": {"type": "model", "id": model}, "context": {"now": _t(self.now()), "session_id": session_id}}
        _emit({"kind": "model.call", "packs": [], "request": req, "python": _decision({"allow": res.allow, "rule": res.rule, "message": res.message}),
               "record": None, "compare": {"record": True, "spend": False}})
        return res
    return _orig["model_authorize"](self, token, session_id, model, est_tokens)


def _proxy_authorize(self, session_id, principal_id, model, est_tokens, acting=None):
    s = self.store.get(session_id)
    now = self.now()
    before = _session(s)
    f = _push("model")
    try:
        d = _orig["authorize"](self, session_id, principal_id, model, est_tokens, acting=acting)
    finally:
        _pop(f)
    try:
        ctx: dict[str, Any] = {"now": _t(now), "session_id": session_id, "models": {"routes": sorted(self.routes)}}
        if before is not None:
            ctx["session"] = before
        req = {"subject": _subject(principal_id, "workload", 1, acting=acting or principal_id),
               "action": {"name": "model.call", "properties": {"est_tokens": est_tokens}},
               "resource": {"type": "model", "id": model}, "context": ctx}
        _emit({"kind": "model.call", "packs": [], "request": req,
               "python": _decision({"allow": d.allow, "rule": d.rule, "message": d.message}),
               "record": _last_event(f, "model.call"), "after": _after(self.store.get(session_id)),
               "compare": {"record": True, "spend": True}})
    except Exception as e:  # noqa: BLE001
        _emit({"kind": "error", "error": repr(e), "where": "model"})
    return d


def _store_open(self, *a, **k):
    s = _orig["store_open"](self, *a, **k)
    fr = _frames()
    if fr:
        fr[-1]["opened"].append(s.id)
    return s


def _wrap_append(name):
    def append(self, event):
        fr = _frames()
        if fr:
            fr[-1]["events"].append(copy.deepcopy(event))
        return _orig[name](self, event)
    return append


def _bundle_line() -> dict[str, Any]:
    import importlib.util
    spec = importlib.util.spec_from_file_location("export_bundle", Path(__file__).with_name("export_bundle.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {"kind": "bundle", "core": mod.core(), "hangar": mod.hangar()}


def pytest_configure(config):
    _orig.update(build_context=policy.Policy.build_context, evaluate=policy.Policy.evaluate,
                 call=dispatch.Gateway.call, open_session=dispatch.Gateway.open_session,
                 open_triggered=dispatch.Gateway.open_triggered, model_authorize=dispatch.Gateway.model_authorize,
                 authorize=modelproxy.ModelProxy.authorize, store_open=session_mod.SessionStore.open,
                 audit_append=audit_mod.AuditLog.append, pg_append=pg.PgAuditLog.append)
    policy.Policy.build_context = _build_context
    policy.Policy.evaluate = _evaluate
    # The module-level helpers are bound methods of CORE, made before the patch: rebind them.
    policy.build_context = policy.CORE.build_context
    policy.evaluate = policy.CORE.evaluate
    dispatch.Gateway.call = _call
    dispatch.Gateway.open_session = _open_session
    dispatch.Gateway.open_triggered = _open_triggered
    dispatch.Gateway.model_authorize = _model_authorize
    modelproxy.ModelProxy.authorize = _proxy_authorize
    session_mod.SessionStore.open = _store_open
    audit_mod.AuditLog.append = _wrap_append("audit_append")
    pg.PgAuditLog.append = _wrap_append("pg_append")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    _current["node"] = item.nodeid.replace("../", "")
    _built.clear()
    yield
    _current["node"] = None


REPEAT = "__golden_repeat__"


def _squeeze(v: Any) -> Any:
    """A long string of one repeated character (the over-size artifact probes) as {REPEAT: [char, count]}, so the
    corpus stays small; the Go loader expands it back before decoding the request."""
    if isinstance(v, str) and len(v) > 4096 and len(set(v)) == 1:
        return {REPEAT: [v[0], len(v)]}
    if isinstance(v, list):
        return [_squeeze(x) for x in v]
    if isinstance(v, dict):
        return {k: _squeeze(x) for k, x in v.items()}
    return v


def pytest_unconfigure(config):
    lines = [_bundle_line()] + [_squeeze(l) for l in _lines if l.get("kind") != "error"]
    errors = [l for l in _lines if l.get("kind") == "error"]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w") as fh:
        for l in lines:
            fh.write(json.dumps(l, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"\ngolden_recorder: wrote {len(lines)} lines to {OUT} ({len(errors)} recorder errors)")
    for e in errors[:20]:
        print("  recorder error:", e)
