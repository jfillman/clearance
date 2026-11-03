"""The Clearance core stands alone (D16): it installs where there is no Airframe and no Glidepath.

Core is every module under src/clearance except packs/hangar. It may not import autopilot (Hangar's
backends) or the Hangar pack, directly or through anything it imports, and a Gateway built with no
packs is a working Clearance for the core tools.
"""
import ast
import asyncio
import json
import subprocess
import sys
from pathlib import Path

from clearance import profile
from clearance.audit import AuditLog
from clearance.backends import FakeHuman, FakeRead, FakeRunBackend, core_handlers
from clearance.dispatch import Gateway, Principal
from clearance.packs.hangar import HANGAR
from clearance.policy import RULES, Policy
from clearance.server import create_server
from clearance.session import SessionStore
from clearance.tiers import CORE_TOOLS, TOOLS, Tier

from conftest import AGENTS, ROOT, StaticAuth

SRC = ROOT / "src"
PKG = SRC / "clearance"
HANGAR_PACK = PKG / "packs" / "hangar"
FORBIDDEN = ("autopilot", "clearance.packs.hangar")


def _core_files() -> list[Path]:
    return sorted(p for p in PKG.rglob("*.py") if HANGAR_PACK not in p.parents)


def _module(path: Path) -> str:
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _imports(path: Path) -> set[str]:
    """Every module an import statement in `path` names, relative imports resolved."""
    mod = _module(path)
    package = mod if path.name == "__init__.py" else mod.rpartition(".")[0]
    out: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - (node.level - 1)]
                target = ".".join(base + ([node.module] if node.module else []))
            else:
                target = node.module or ""
            out.add(target)
            out.update(f"{target}.{a.name}" for a in node.names)
    return out


def _forbidden(name: str) -> bool:
    return any(name == f or name.startswith(f + ".") for f in FORBIDDEN)


def test_the_core_is_not_empty_and_excludes_the_hangar_pack():
    mods = {_module(p) for p in _core_files()}
    assert {"clearance.dispatch", "clearance.policy", "clearance.tiers", "clearance.server", "clearance.pack"} <= mods
    assert not any(m.startswith("clearance.packs.hangar") for m in mods)


def test_no_core_module_names_autopilot_or_the_hangar_pack():
    bad = {_module(p): sorted(i for i in _imports(p) if _forbidden(i)) for p in _core_files()}
    bad = {m: i for m, i in bad.items() if i}
    assert bad == {}, f"core modules importing Hangar code: {bad}"


def test_importing_the_whole_core_loads_nothing_from_hangar():
    """The AST scan sees import statements; this sees what actually loads, in a fresh interpreter."""
    mods = [_module(p) for p in _core_files()]
    assert len(mods) > 10
    code = ("import importlib, json, sys\n"
            f"for m in {mods!r}: importlib.import_module(m)\n"
            "print(json.dumps(sorted(sys.modules)))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         env={"PYTHONPATH": str(SRC)}, cwd=str(ROOT))
    loaded = json.loads(out.stdout)
    assert "clearance.dispatch" in loaded
    assert [m for m in loaded if _forbidden(m)] == []


def _bare_gateway(clock, **kw):
    auth = StaticAuth({"alice": Principal("user:alice", "user", Tier.T1)})
    return Gateway(profile.load_dir(AGENTS), SessionStore(), AuditLog(), auth, clock, **kw)


def test_a_gateway_with_no_packs_opens_a_session_and_calls_a_core_tool(clock):
    read = FakeRead()
    gw = _bare_gateway(clock, handlers=core_handlers(read=read))
    assert gw.tools == TOOLS and set(gw.tools) == {t.name for t in CORE_TOOLS}
    sid = gw.open_session("alice", "coding-agent").data["session"]
    r = gw.call("alice", sid, "catalog.read", {"query": "flight"})
    assert r.ok and read.names() == ["read.catalog"]
    # A Hangar tool is simply unknown without the pack, and a tripwire is still a tripwire.
    assert gw.call("alice", sid, "glidepath.runs.list", {"app": "gate-api"}).decision["rule"] == "R003"
    assert gw.call("alice", sid, "k8s.exec", {}).decision["rule"] == "R002"


def test_a_registered_tool_with_no_handler_is_refused_and_charged_nothing(clock):
    gw = _bare_gateway(clock, handlers=core_handlers(read=FakeRead()))     # no HumanBackend
    sid = gw.open_session("alice", "coding-agent").data["session"]
    r = gw.call("alice", sid, "human.request", {"question": "ship it?"})
    assert not r.ok and gw.audit.records[-1]["result"] == "error:NoHandler"
    assert gw.store.get(sid).used["tool_calls"] == 0


def test_the_run_tree_works_with_any_run_backend(clock):
    runs = FakeRunBackend()
    gw = _bare_gateway(clock, handlers=core_handlers(human=FakeHuman()), runs=runs)
    sid = gw.open_session("alice", "orchestrator").data["session"]
    r = gw.call("alice", sid, "run.spawn", {"agent": "researcher", "limits": {"tool_calls": 10}})
    assert r.ok, r.as_dict()
    assert r.data["run"] == runs.live[r.data["session"]]
    assert gw.call("alice", sid, "run.close", {"run_id": r.data["session"]}).ok and runs.live == {}


def test_tools_list_is_the_gateways_registry(clock):
    def listed(gw):
        mcp = create_server(gw, lambda: "alice")
        res = asyncio.run(mcp.call_tool("tools_list", {}))
        sc = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
        return {t["name"] for t in (sc.get("result", sc) if sc else json.loads(res.content[0].text))}
    bare = listed(_bare_gateway(clock))
    full = listed(_bare_gateway(clock, packs=(HANGAR,)))
    assert bare == set(TOOLS) and full == bare | {t.name for t in HANGAR.tools}


def test_handlers_and_packs_are_checked_when_the_gateway_is_built(clock):
    import pytest
    with pytest.raises(ValueError, match="not registered"):
        _bare_gateway(clock, handlers={"glidepath.runs.list": lambda s, a: None})
    with pytest.raises(ValueError, match="owns"):
        _bare_gateway(clock, handlers={"run.spawn": lambda s, a: None})
    with pytest.raises(ValueError, match="twice"):
        Policy((HANGAR, HANGAR))


def test_rule_order_with_the_hangar_pack_is_the_order_before_the_split():
    """First match wins, so the order is behaviour. This is the order RULES had when R021-R023 were core."""
    assert [r.id for r in RULES] == ["R001", "R002", "R003", "R004", "R005", "R006", "R007", "R008", "R009",
                                     "R010", "R011", "R012", "R013", "R014", "R015", "R016", "R017",
                                     "R019", "R018", "R020"]
    assert [r.id for r in Policy((HANGAR,)).rules] == [
        "R001", "R002", "R003", "R004", "R005", "R006", "R007", "R008", "R009", "R010", "R011", "R012",
        "R013", "R014", "R015", "R016", "R017", "R022", "R023", "R019", "R018", "R020", "R021"]


# ---- the Go core carries no Hangar vocabulary (R-5) -------------------------------------------------------------
# A data-level check over the Go core (internal/, cmd/, client/) and the Python client it publishes: no string
# literal or identifier in non-test source, and no line of an embedded data file, names Hangar or one of its
# products. Hangar's policy is a bundle the deployment loads (CLEARANCE_BUNDLES); its names are configuration
# (internal/vocab, CLEARANCE_ENV_*). Comments are not data: they may say where a port came from. Tests and the
# test-support packages (a directory ending in "test": decidetest, vocabtest, deftest, storetest) hold the lab
# deployment's values, which is what they test against.
import re as _re

HANGAR_NAMES = _re.compile(r"hangar|glidepath|airframe|autopilot|skyport|apron|people-dex|riley-roooo|gitops-|"
                           r"check-ride|\btower\b|\bflight\b", _re.I)
GO_DIRS = ("internal", "cmd", "client")
# file -> why it may still name Hangar. Each entry is a recorded exception, not a place to add more.
HANGAR_DATA_EXCEPTIONS = {
    "internal/profile/agent-definition.schema.json":
        "Autopilot's agent-definition schema (profile.glidepath/airframe, glidepath event sources), embedded byte for "
        "byte so the gate can tier a definition change; reading it from configuration is the follow-up to R-5",
}


def _go_tokens(src: str):
    """(line, text) of every string, rune and raw literal and every identifier in Go source, comments skipped."""
    i, n, line = 0, len(src), 1
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += src.count("\n", i, j)
            i = j
        elif c == "`":
            j = src.find("`", i + 1)
            yield line, src[i + 1:j]
            line += src.count("\n", i, j)
            i = j + 1
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            yield line, src[i + 1:j]
            i = j + 1
        elif c.isalpha() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            yield line, src[i:j]
            i = j
        else:
            line += c == "\n"
            i += 1


def _is_test_support(rel: Path) -> bool:
    return rel.name.endswith("_test.go") or any(p.endswith("test") for p in rel.parts[:-1])


def _hangar_names_in_the_core() -> list[str]:
    found = []
    for d in GO_DIRS:
        for p in sorted((ROOT / d).rglob("*")):
            rel = p.relative_to(ROOT)
            if not p.is_file() or "testdata" in rel.parts or _is_test_support(rel) or str(rel) in HANGAR_DATA_EXCEPTIONS:
                continue
            if p.suffix == ".go":
                found += [f"{rel}:{ln}: {t[:80]!r}" for ln, t in _go_tokens(p.read_text()) if HANGAR_NAMES.search(t)]
            elif p.suffix in (".json", ".yaml", ".yml", ".sql"):
                found += [f"{rel}:{ln}: {t.strip()[:80]}" for ln, t in enumerate(p.read_text().splitlines(), 1)
                          if HANGAR_NAMES.search(t)]
    for p in sorted((ROOT / "clients" / "python" / "src").rglob("*.py")):
        found += [f"{p.relative_to(ROOT)}:{ln}: {t.strip()[:80]}" for ln, t in enumerate(p.read_text().splitlines(), 1)
                  if HANGAR_NAMES.search(t)]
    return found


def test_the_go_core_source_contains_no_hangar_names():
    assert _hangar_names_in_the_core() == []


def test_the_hangar_names_check_sees_what_it_should():
    """A check that matches nothing proves nothing: it finds a Hangar name in a literal, not in a comment."""
    toks = [t for _, t in _go_tokens('// glidepath in a comment\nx := "a glidepath.runs.list call" + `airframe`\n')]
    assert [t for t in toks if HANGAR_NAMES.search(t)] == ["a glidepath.runs.list call", "airframe"]
    n = sum(1 for d in GO_DIRS for p in (ROOT / d).rglob("*.go") if not _is_test_support(p.relative_to(ROOT)))
    assert n > 100
    for f in HANGAR_DATA_EXCEPTIONS:
        assert (ROOT / f).exists(), f"{f} is gone: drop its exception"
