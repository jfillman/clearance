"""PR provenance: is a pull request the one a Clearance session opened, and is what it changes inside that agent's
scope? The two answers back the `agent-identity` and `agent-scope` checks a CI gate posts on every PR.

The evidence is the receipt Clearance wrote when its own call opened the PR (the `effect` of a `repo.pr.open`
record: repo, PR number, the commit it made, the paths that commit carried). Nothing the PR says about itself is
trusted: its `Hangar-*` commit trailers and its author are compared with that receipt, never taken as proof.

  identity  confirmed   a receipt for this repo and PR, its commit is the PR's head, and any trailers match it
            not-agent   no receipt, no trailers, and not authored by an agents' login: a person's PR, nothing to check
            AI001       trailers name a task, but Clearance never opened this PR (forged, or copied from another PR)
            AI002       authored by an agents' login, but Clearance never opened this PR (the App used elsewhere)
            AI003       the PR's head is not the commit the agent made: commits were added after it
            AI004       the trailers name a different task or session than the receipt
  scope     in-scope    every changed path is one the agent's commit carried, and the agent's definition still
                        admits the repo and every path (its deny list, with the baseline denies)
            not-agent   as above
            AS001       a changed path the agent's commit did not carry
            AS002       a changed path the definition denies (R015's globs, re-read now: a deny added since counts)
            AS003       the repo is no longer in the definition's repos.allow
            AS004       the definition is gone from this deployment

Field-level scope (R020, R021) was decided on the content when the PR was opened. The receipt's commit being the
head is what carries that decision here, so a PR that fails identity with AI003 is not vouched for in scope either.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .profile import AgentDefinition
from .scope import BadPath, normalize, path_violations, repo_allowed

# Every tool whose receipt is a pull request: the core PR tools, and the Hangar pack's glidepath.cicd.propose (one
# commit of cicd.yaml, validated by glidepath-api first). policy.py's PR budget and api.py's listReceipts use it too.
PR_TOOLS = ("repo.pr.open", "repo.pr.open_upper", "glidepath.cicd.propose")
TRAILER_KEYS = ("task", "session", "run", "agent")
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_PATHS = 3000


class BadRequest(ValueError):
    pass


class NotVerifier(PermissionError):
    pass


def normal(path: str) -> str:
    try:
        return normalize(path)
    except BadPath:
        return path


@dataclass(frozen=True)
class Request:
    repo: str
    pr: int
    head: str
    paths: tuple[str, ...]
    author: str = ""
    trailers: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Any) -> "Request":
        if not isinstance(d, dict):
            raise BadRequest("the body is a JSON object")
        repo, pr, head, paths = d.get("repo"), d.get("pr"), d.get("head"), d.get("paths")
        if not isinstance(repo, str) or not REPO.match(repo):
            raise BadRequest("repo is owner/name")
        if not isinstance(pr, int) or isinstance(pr, bool) or pr < 1:
            raise BadRequest("pr is a positive integer")
        if not isinstance(head, str) or not SHA.match(head):
            raise BadRequest("head is a 40-character commit sha")
        if not isinstance(paths, list) or len(paths) > MAX_PATHS or not all(isinstance(p, str) for p in paths):
            raise BadRequest(f"paths is a list of at most {MAX_PATHS} strings")
        author = d.get("author", "")
        if not isinstance(author, str):
            raise BadRequest("author is a string")
        trailers = d.get("trailers") or {}
        if not isinstance(trailers, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                                     for k, v in trailers.items()):
            raise BadRequest("trailers is an object of strings")
        known = {k.lower(): v for k, v in trailers.items() if k.lower() in TRAILER_KEYS}
        return cls(repo.lower(), pr, head, tuple(paths), author, known)


def _check(ok: bool, status: str, message: str, hint: str = "", rule: str | None = None) -> dict[str, Any]:
    return {"ok": ok, "status": status, "rule": rule, "message": message, "hint": hint}


def verify(req: Request, receipts: Iterable[dict[str, Any]], defs: Mapping[str, AgentDefinition],
           agent_logins: Iterable[str] = ()) -> dict[str, Any]:
    """The verdict for one PR from the receipts Clearance holds for (repo, pr). The newest receipt wins (a PR number
    is opened once; more than one would mean a re-created repo)."""
    rec = max(receipts, key=lambda r: r["seq"], default=None)
    by_agent_login = req.author.lower() in {a.lower() for a in agent_logins}
    if rec is None:
        if req.trailers.get("task") or req.trailers.get("session"):
            ident = _check(False, "unrecorded",
                           f"the PR's commit trailers name task {req.trailers.get('task', '?')}, but Clearance has no "
                           "record of opening this PR",
                           "Only Clearance opens agent PRs. If a person wrote this change, remove the Hangar-* "
                           "trailers; otherwise treat the PR as forged.", "AI001")
        elif by_agent_login:
            ident = _check(False, "unrecorded",
                           f"the PR is authored by {req.author}, an agents' login, but Clearance has no record of "
                           "opening it",
                           "The agents' GitHub App was used outside Clearance. Close the PR and review the App's "
                           "credentials and installations.", "AI002")
        else:
            ident = _check(True, "not-agent", "not an agent PR: no Clearance record, no Hangar trailers, and not "
                                              "authored by an agents' login")
        scope = (_check(True, "not-agent", "not an agent PR") if ident["ok"]
                 else _check(False, "unknown", "no record to check the scope against", ident["hint"], ident["rule"]))
        return {"agent_pr": not ident["ok"], "identity": ident, "scope": scope, "record": None}

    eff = rec.get("effect") or {}
    summary = {k: rec.get(k) for k in ("seq", "hash", "ts", "task_id", "session", "agent", "principal", "tool")}
    mismatched = [k for k, want in (("task", rec.get("task_id")), ("session", rec.get("session")),
                                    ("agent", rec.get("agent")))
                  if req.trailers.get(k) and req.trailers[k] != want]
    if eff.get("commit") != req.head:
        ident = _check(False, "modified",
                       f"the PR's head {req.head[:12]} is not the commit the agent made "
                       f"({str(eff.get('commit'))[:12]}): commits were added after it",
                       "Review the added commits as a person's change. The agent gates vouch only for the agent's "
                       "own commit.", "AI003")
    elif mismatched:
        ident = _check(False, "mismatch",
                       f"the commit trailers' {', '.join(mismatched)} differ from Clearance's record of this PR",
                       "The trailers were edited after Clearance wrote them; treat the PR as tampered with.", "AI004")
    else:
        ident = _check(True, "confirmed",
                       f"opened by agent {rec.get('agent')} through Clearance (task {rec.get('task_id')}, session "
                       f"{rec.get('session')}, record {rec.get('seq')})")

    return {"agent_pr": True, "identity": ident, "scope": _scope(req, rec, eff, defs), "record": summary}


def _scope(req: Request, rec: dict[str, Any], eff: dict[str, Any], defs: Mapping[str, AgentDefinition]) -> dict:
    d = defs.get(rec.get("agent") or "")
    if d is None:
        return {**_check(False, "violations", f"agent definition {rec.get('agent')!r} is not in this deployment",
                         "A PR from a retired agent needs a person's review.", "AS004"), "violations": []}
    violations: list[dict[str, str]] = []
    if not repo_allowed(req.repo, [a.lower() for a in d.repos_allow]):
        violations.append({"path": "", "rule": "AS003", "message": f"{req.repo} is not in {d.name}'s repos.allow"})
    carried = set(eff.get("paths") or [])
    for p in req.paths:
        if normal(p) not in carried:
            violations.append({"path": p, "rule": "AS001", "message": "changed, but not in the agent's commit"})
    for p in path_violations(list(req.paths), list(d.deny_paths)):
        violations.append({"path": p, "rule": "AS002", "message": f"denied to {d.name} (path-not-allowed, R015)"})
    if not violations:
        return {**_check(True, "in-scope", f"{len(req.paths)} changed paths, all inside {d.name}'s scope"),
                "violations": []}
    first = violations[0]
    return {**_check(False, "violations", f"{len(violations)} scope violations; first: {first['path'] or req.repo} "
                                          f"({first['message']})",
                     "An agent may not change these paths. Revert them, or have a person make the change in a PR "
                     "of their own.", first["rule"]), "violations": violations}
