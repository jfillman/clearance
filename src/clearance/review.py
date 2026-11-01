"""Reviewing agent definitions before they are live: validation, and the tier of a change from one version to the next.

Autopilot M4's release flow (decided 2026-10-31): a definition is reviewed YAML in a repo; merging it changes
nothing; a pin (an Agent XR, definitions.py) makes one commit live. Two questions a CI check asks Clearance about a
definition, answered here without state and without a Hangar import:

  validate(doc, ...)   would Clearance load this file, and would its agent be able to do what it says? Schema,
                       the name and owner a pin will check, the workload identity, every tool known and not a
                       tripwire, no tool above the tier ceiling (the R007 rule, decided once here instead of at
                       every call), a repo-writing or repo-reading tool with a repo allowlist (R014), models the
                       deployment routes, and the runtime image pinned by digest from an allowed source.
  classify(old, new)   how much more (or less) may the agent do after the change? The tier the deployment gate
                       (gate.py) clears it by:
                         0  nothing that changes authority: instructions, description, framework label
                         1  narrows only: fewer tools, a lower ceiling, smaller limits, fewer repos, apps, models,
                            triggers, a smaller network or compute class, or the agent removed. Cleared by policy:
                            lowering authority is always safe.
                         2  widens what the agent spends or when it runs: larger limits, a new trigger or a higher
                            trigger cap, a new model, a new runtime image, a larger compute class, a new read tool
                         3  widens what the agent may touch: a higher tier ceiling, a new writing tool (tier T1 or
                            above), a new repo, app or API in scope, a wider network, sidecars, a different identity
                            or owner, a new agent with any writing tool
                       Every reason names the field and the change, so the gate can say "why this tier".

Errors carry DF-* rules: DF-SCHEMA, DF-NAME, DF-OWNER, DF-IDENTITY, DF-TOOL, DF-TRIPWIRE, DF-CEILING (R007),
DF-REPOS (R014), DF-MODEL, DF-IMAGE, DF-DESCRIPTION.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Iterable, Mapping, Sequence

from .definitions import RUN_IDENTITY_NAMESPACE
from .limits import ComputeClass, Network
from .profile import PLACEHOLDER_DIGEST, DefinitionError, parse
from .tiers import TRIPWIRES, Tier, ToolSpec

DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
TIER = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}
LIMIT_KEYS = ("ttlMinutes", "toolCalls", "githubCalls", "openPrs", "modelTokens", "children")


@dataclass(frozen=True)
class Problem:
    rule: str
    path: str
    message: str
    hint: str = ""

    def view(self) -> dict[str, Any]:
        return {"rule": self.rule, "path": self.path, "message": self.message, "hint": self.hint}


@dataclass(frozen=True)
class Change:
    field: str
    change: str      # e.g. "added repo.pr.open (T1)", "toolCalls 60 -> 120"
    tier: int

    def view(self) -> dict[str, Any]:
        return {"field": self.field, "change": self.change, "tier": self.tier}


def validate(doc: Any, tools: Mapping[str, ToolSpec], *, name: str | None = None, owner: str | None = None,
             models: Sequence[str] | None = None, image_allow: Sequence[str] = (), path: str | None = None) -> list[Problem]:
    """Every problem with this definition, empty when Clearance would load it and its agent could use every tool it
    lists. `name`/`owner` are the pin's (when known); `path` the file's (its stem must be the name); `models` the
    deployment's routes (None = not checked); `image_allow` prefix globs a runtime.image must match (empty = any
    digest-pinned image)."""
    if not isinstance(doc, Mapping):
        return [Problem("DF-SCHEMA", "", "the file is not a YAML mapping (an agent definition)")]
    desc = doc.get("description")
    if not isinstance(desc, str) or not desc.strip():
        return [Problem("DF-DESCRIPTION", "description", "the definition has no description",
                        "Add one line saying what the agent is for: `description: Explains why a Glidepath run failed.`")]
    img = (doc.get("runtime") or {}).get("image") if isinstance(doc.get("runtime"), Mapping) else None
    if isinstance(img, str) and PLACEHOLDER_DIGEST.search(img):
        return [Problem("DF-IMAGE", "runtime.image", f"{img} is a placeholder digest",
                        "Pick a runtime from the catalog (GET /v1/runtimes), or leave runtime.image out: the agent then runs in a person's MCP client.")]
    try:
        d = parse(dict(doc))
    except DefinitionError as e:
        return [Problem("DF-SCHEMA", "", str(e), "Fix the field the message names (clearance schemas/agent-definition.schema.json).")]
    out: list[Problem] = []
    if path:
        stem = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        if stem != d.name:
            out.append(Problem("DF-NAME", "name", f"the file is {path} but the agent is named {d.name!r}", f"Name the file {d.name}.yaml."))
    if name is not None and d.name != name:
        out.append(Problem("DF-NAME", "name", f"the pin is named {name!r} but the file's name is {d.name!r}"))
    if owner is not None and d.owner != owner:
        out.append(Problem("DF-OWNER", "owner", f"the pin's owner is {owner!r} but the file's is {d.owner!r}", "They must agree."))
    if d.identity_type == "workload" and d.service_account != f"{RUN_IDENTITY_NAMESPACE}/{d.name}":
        out.append(Problem("DF-IDENTITY", "identity.serviceAccount", f"a workload agent runs as {RUN_IDENTITY_NAMESPACE}/{d.name}, not {d.service_account!r}"))
    ceiling = int(d.limits.tier_ceiling)
    reads_or_writes_repo = []
    for t in sorted(doc["profile"]["tools"]):
        if t in TRIPWIRES:
            out.append(Problem("DF-TRIPWIRE", "profile.tools", f"{t} is a tripwire: calling it trips the session's breaker", "Remove it."))
            continue
        spec = tools.get(t)
        if spec is None:
            out.append(Problem("DF-TOOL", "profile.tools", f"{t} is not a tool this Clearance registers", "Pick a tool from GET /v1/policy."))
            continue
        if int(spec.tier) > ceiling and not (spec.propose_only and ceiling >= 1):
            out.append(Problem("DF-CEILING", "profile.tools", f"{t} is {spec.tier.name} above the ceiling {d.limits.tier_ceiling.name} (R007: every call would be denied)",
                               f"Raise tierCeiling to {spec.tier.name}, or drop the tool."))
        if spec.writes_files or spec.reads_repo:
            reads_or_writes_repo.append(t)
    if reads_or_writes_repo and not d.repos_allow:
        out.append(Problem("DF-REPOS", "profile.repos.allow", f"{', '.join(reads_or_writes_repo)} name a repo, and repos.allow is empty (R014: every call would be denied)",
                           "List the repos the agent may use."))
    if models is not None:
        for m in sorted(d.limits.models - set(models)):
            out.append(Problem("DF-MODEL", "profile.models", f"{m} is not a model this deployment routes", f"Use one of: {', '.join(sorted(models)) or 'none'}."))
    img = d.image
    if img:
        if not DIGEST.search(img):
            out.append(Problem("DF-IMAGE", "runtime.image", f"{img} is not pinned by digest", "Pin it: <registry>/<repo>@sha256:<64 hex>."))
        elif image_allow and not any(fnmatchcase(img, g) for g in image_allow):
            out.append(Problem("DF-IMAGE", "runtime.image", f"{img} is not from an allowed runtime source",
                               "Use an image from the runtime catalog, or one Glidepath built for this agent's own repository."))
    return out


def _tier_of(tools: Mapping[str, ToolSpec], t: str) -> int:
    spec = tools.get(t)
    return int(spec.tier) if spec else 3


def _set(doc: Mapping[str, Any] | None, *keys: str) -> set:
    cur: Any = doc or {}
    for k in keys:
        cur = cur.get(k) if isinstance(cur, Mapping) else None
    if isinstance(cur, Mapping):
        return {f"{k}={v}" for k, v in cur.items()}
    return set(cur or [])


def _get(doc: Mapping[str, Any] | None, *keys: str, default: Any = None) -> Any:
    cur: Any = doc or {}
    for k in keys:
        cur = cur.get(k) if isinstance(cur, Mapping) else None
    return default if cur is None else cur


def _scope_sets(doc: Mapping[str, Any] | None) -> dict[str, set]:
    p = _get(doc, "profile", default={}) or {}
    out = {"profile.repos.allow": set(_get(p, "repos", "allow", default=[]) or []),
           "profile.apis.allow": set(_get(p, "apis", "allow", default=[]) or [])}
    for k in ("glidepath", "airframe"):
        out[f"profile.{k}.apps"] = set(_get(p, k, "apps", default=[]) or [])
    return out


def _trigger_key(t: Mapping[str, Any]) -> str:
    return "|".join(f"{k}={t[k]}" for k in sorted(t) if k != "maxPerHour")


def classify(old: Mapping[str, Any] | None, new: Mapping[str, Any] | None, tools: Mapping[str, ToolSpec]) -> tuple[int, list[Change]]:
    """The tier of going from `old` to `new` (either may be None: a new agent, a removed one) and every reason. Both
    documents are assumed valid (validate() first)."""
    changes: list[Change] = []
    add = lambda f, c, t: changes.append(Change(f, c, t))  # noqa: E731
    if new is None:
        add("agent", "removed", 1)
        return 1, changes
    if old is None:
        tl = sorted(_get(new, "profile", "tools", default=[]))
        writers = [t for t in tl if _tier_of(tools, t) >= 1]
        add("agent", "new agent" + (f" with writing tools {', '.join(writers)}" if writers else " (read tools only)"), 3 if writers else 2)
        return max(c.tier for c in changes), changes
    # identity and owner
    if _get(old, "identity") != _get(new, "identity"):
        add("identity", f"{_get(old, 'identity')} -> {_get(new, 'identity')}", 3)
    if _get(old, "owner") != _get(new, "owner"):
        add("owner", f"{_get(old, 'owner')} -> {_get(new, 'owner')}", 3)
    if _get(old, "kind") != _get(new, "kind"):
        add("kind", f"{_get(old, 'kind')} -> {_get(new, 'kind')}", 2)
    # ceiling
    oc, nc = TIER.get(_get(old, "profile", "tierCeiling", default="T0"), 0), TIER.get(_get(new, "profile", "tierCeiling", default="T0"), 0)
    if nc > oc:
        add("profile.tierCeiling", f"T{oc} -> T{nc}", 3)
    elif nc < oc:
        add("profile.tierCeiling", f"T{oc} -> T{nc}", 1)
    # tools
    ot, nt = _set(old, "profile", "tools"), _set(new, "profile", "tools")
    for t in sorted(nt - ot):
        tier = _tier_of(tools, t)
        add("profile.tools", f"added {t} (T{tier})", 3 if tier >= 1 else 2)
    for t in sorted(ot - nt):
        add("profile.tools", f"removed {t}", 1)
    # scope
    os_, ns_ = _scope_sets(old), _scope_sets(new)
    for f in os_:
        for v in sorted(ns_[f] - os_[f]):
            add(f, f"added {v}", 3)
        for v in sorted(os_[f] - ns_[f]):
            add(f, f"removed {v}", 1)
    for f in ("denyPaths", "fieldDeny"):
        o, n = _set(old, "profile", "repos", f), _set(new, "profile", "repos", f)
        for v in sorted(o - n):
            add(f"profile.repos.{f}", f"removed {v}", 3)
        for v in sorted(n - o):
            add(f"profile.repos.{f}", f"added {v}", 1)
    o, n = _set(old, "profile", "repos", "fieldAllow"), _set(new, "profile", "repos", "fieldAllow")
    for v in sorted(n - o):
        add("profile.repos.fieldAllow", f"added {v}", 3)
    for v in sorted(o - n):
        add("profile.repos.fieldAllow", f"removed {v}", 1)
    # models
    om, nm = _set(old, "profile", "models"), _set(new, "profile", "models")
    for v in sorted(nm - om):
        add("profile.models", f"added {v}", 2)
    for v in sorted(om - nm):
        add("profile.models", f"removed {v}", 1)
    # network and compute
    try:
        on, nn = Network.parse(_get(old, "profile", "network", default="clearance")), Network.parse(_get(new, "profile", "network", default="clearance"))
        if nn > on:
            add("profile.network", f"{on.name.lower()} -> {nn.name.lower()}", 3)
        elif nn < on:
            add("profile.network", f"{on.name.lower()} -> {nn.name.lower()}", 1)
    except ValueError:
        pass
    try:
        oc2, nc2 = ComputeClass.parse(_get(old, "profile", "compute", default="small")), ComputeClass.parse(_get(new, "profile", "compute", default="small"))
        if nc2 > oc2:
            add("profile.compute", f"{oc2.name.lower()} -> {nc2.name.lower()}", 2)
        elif nc2 < oc2:
            add("profile.compute", f"{oc2.name.lower()} -> {nc2.name.lower()}", 1)
    except ValueError:
        pass
    # limits
    for k in LIMIT_KEYS:
        a, b = _get(old, "profile", "limits", k), _get(new, "profile", "limits", k)
        if a != b and a is not None and b is not None:
            add(f"profile.limits.{k}", f"{a} -> {b}", 2 if b > a else 1)
    # runtime
    if _get(old, "runtime", "image") != _get(new, "runtime", "image"):
        add("runtime.image", f"{_get(old, 'runtime', 'image')} -> {_get(new, 'runtime', 'image')}", 2)
    if _get(old, "runtime", "sandbox", default="standard") != _get(new, "runtime", "sandbox", default="standard"):
        hardened = _get(new, "runtime", "sandbox") == "hardened"
        add("runtime.sandbox", f"{_get(old, 'runtime', 'sandbox', default='standard')} -> {_get(new, 'runtime', 'sandbox', default='standard')}", 1 if hardened else 3)
    o, n = _get(old, "runtime", "sidecars", default=[]) or [], _get(new, "runtime", "sidecars", default=[]) or []
    if o != n:
        add("runtime.sidecars", f"{len(o)} -> {len(n)}", 3 if any(s not in o for s in n) else 1)
    if _get(old, "runtime", "instructions") != _get(new, "runtime", "instructions"):
        add("runtime.instructions", "changed", 0)
    if _get(old, "runtime", "framework") != _get(new, "runtime", "framework"):
        add("runtime.framework", f"{_get(old, 'runtime', 'framework')} -> {_get(new, 'runtime', 'framework')}", 0)
    # triggers
    ot2 = {_trigger_key(t): t for t in (_get(old, "triggers", default=[{"type": "manual"}]) or [])}
    nt2 = {_trigger_key(t): t for t in (_get(new, "triggers", default=[{"type": "manual"}]) or [])}
    for k in sorted(set(nt2) - set(ot2)):
        add("triggers", f"added {k}", 2)
    for k in sorted(set(ot2) - set(nt2)):
        add("triggers", f"removed {k}", 1)
    for k in sorted(set(nt2) & set(ot2)):
        a, b = ot2[k].get("maxPerHour"), nt2[k].get("maxPerHour")
        if a != b:
            add("triggers", f"{k} maxPerHour {a} -> {b}", 2 if (b or 0) > (a or 0) or b is None else 1)
    if not changes:
        add("definition", "no change in authority", 0)
    return max(c.tier for c in changes), changes
