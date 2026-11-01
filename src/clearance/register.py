"""`clearance register`: a CI step that registers what a workflow is about to deploy with Clearance's deployment gate.

Phase 2b of the provenance App (docs/provenance-app.md). The Clearance GitHub App answers a GitHub Actions deployment
to a protected environment from the gate's change for that repository, commit and environment; this step is how a
customer's own CI makes that change, the way Glidepath's clearance-gate check does on Hangar:

    clearance register --url https://clearance.example --app shop --env prod --cluster prod-eu \\
        --before rendered/before --after rendered/after

`--before` and `--after` are directories of rendered manifests (multi-document YAML) for the environment, before and
after this commit; the change's objects are their difference (added, changed with the JSON pointers of every leaf
that differs, removed), each with the images it runs and a digest. In GitHub Actions the step authenticates with the
workflow's own OIDC ID token (the job needs `permissions: id-token: write`); Clearance accepts it as
`github:<sub>` and lets it register changes for its own repository only (DG-REPO). Elsewhere, `--token-file`.

Prints the change's id, state and tier. Exit 0 cleared, 3 holding for people (the protection rule keeps the
deployment waiting until they decide), 1 denied or refused, 2 a usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable

import yaml

from . import gate

EXIT_CLEARED, EXIT_DENIED, EXIT_USAGE, EXIT_HOLDING = 0, 1, 2, 3


class UsageError(Exception):
    pass


# -- manifests -----------------------------------------------------------------------------------------------------
def canonical(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)


def load_dir(directory: str | Path | None) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    """Every Kubernetes object in the directory's *.yaml / *.yml / *.json files, keyed by (apiVersion, kind,
    namespace, name). A missing directory is an empty set (a first deployment adds everything)."""
    out: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    if directory is None or not Path(directory).is_dir():
        return out
    for f in sorted(Path(directory).rglob("*")):
        if not f.is_file() or f.suffix not in (".yaml", ".yml", ".json"):
            continue
        for doc in yaml.safe_load_all(f.read_text()):
            if not isinstance(doc, dict) or not doc.get("kind") or not doc.get("apiVersion"):
                continue
            meta = doc.get("metadata") or {}
            if doc["kind"].endswith("List") and isinstance(doc.get("items"), list):
                docs = [d for d in doc["items"] if isinstance(d, dict)]
            else:
                docs = [doc]
            for d in docs:
                meta = d.get("metadata") or {}
                key = (str(d.get("apiVersion")), str(d.get("kind")), str(meta.get("namespace") or ""), str(meta.get("name") or ""))
                if key[3]:
                    out[key] = d
    return out


def _escape(k: Any) -> str:
    return str(k).replace("~", "~0").replace("/", "~1")


def diff_pointers(a: Any, b: Any, path: str = "") -> list[str]:
    """JSON pointers of every leaf that differs between a and b (a whole subtree when its type changed)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out: list[str] = []
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                out.append(f"{path}/{_escape(k)}")
            else:
                out += diff_pointers(a[k], b[k], f"{path}/{_escape(k)}")
        return out
    if isinstance(a, list) and isinstance(b, list):
        out = []
        for i in range(max(len(a), len(b))):
            if i >= len(a) or i >= len(b):
                out.append(f"{path}/{i}")
            else:
                out += diff_pointers(a[i], b[i], f"{path}/{i}")
        return out
    return [] if a == b else [path or "/"]


def images(doc: Any) -> list[str]:
    """Every string under an `image` key: containers, init and ephemeral containers, and CRDs that name one."""
    found: list[str] = []

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "image" and isinstance(v, str):
                    found.append(v)
                else:
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(doc)
    return list(dict.fromkeys(found))


def objects(before: dict, after: dict) -> list[dict[str, Any]]:
    out = []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old is not None and new is not None and canonical(old) == canonical(new):
            continue
        op = "added" if old is None else "removed" if new is None else "changed"
        fields = diff_pointers(old, new)[:gate.MAX_FIELDS] if op == "changed" else []
        doc = new if new is not None else old
        out.append({"apiVersion": key[0], "kind": key[1], "namespace": key[2], "name": key[3], "op": op,
                    "fields": fields, "images": images(new) if new is not None else [],
                    "digest": hashlib.sha256(canonical(doc).encode()).hexdigest()})
    if len(out) > gate.MAX_OBJECTS:
        raise UsageError(f"{len(out)} objects changed; Clearance takes at most {gate.MAX_OBJECTS} in one change")
    return out


def tree_digest(after: dict) -> str:
    h = hashlib.sha256()
    for key in sorted(after):
        h.update(canonical(after[key]).encode())
        h.update(b"\n")
    return h.hexdigest()


def changed_files(before_dir: str | None, after_dir: str | None) -> list[str]:
    """Files that differ between the two rendered directories (by relative path), when no git base is given."""
    def files(d: str | None) -> dict[str, bytes]:
        if not d or not Path(d).is_dir():
            return {}
        return {str(p.relative_to(d)): p.read_bytes() for p in Path(d).rglob("*") if p.is_file()}
    a, b = files(before_dir), files(after_dir)
    return sorted(p for p in set(a) | set(b) if a.get(p) != b.get(p))


def git_paths(base: str, head: str) -> list[str]:
    out = subprocess.run(["git", "diff", "--name-only", f"{base}...{head}"], check=True, capture_output=True, text=True)
    return [line for line in out.stdout.splitlines() if line]


# -- GitHub Actions --------------------------------------------------------------------------------------------------
def github_event(env: dict[str, str]) -> dict[str, Any]:
    p = env.get("GITHUB_EVENT_PATH")
    if p and Path(p).is_file():
        try:
            return json.loads(Path(p).read_text())
        except ValueError:
            return {}
    return {}


def actions_token(env: dict[str, str], audience: str) -> str:
    """The workflow's OIDC ID token for `audience` (the job needs `permissions: id-token: write`)."""
    url, bearer = env.get("ACTIONS_ID_TOKEN_REQUEST_URL"), env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise UsageError("no GitHub Actions OIDC token: give the job `permissions: id-token: write`, or pass --token-file")
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(f"{url}{sep}audience={urllib.request.quote(audience)}",
                                 headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 - GitHub's own token endpoint
        value = json.load(r).get("value")
    if not value:
        raise UsageError("GitHub returned no OIDC token")
    return value


# -- the request ---------------------------------------------------------------------------------------------------
def build_body(args: argparse.Namespace, env: dict[str, str]) -> dict[str, Any]:
    event = github_event(env)
    pr_doc = event.get("pull_request") or {}
    repo = (args.repo or env.get("GITHUB_REPOSITORY") or "").lower()
    head = args.head or (pr_doc.get("head") or {}).get("sha") or env.get("GITHUB_SHA") or ""
    pr = args.pr if args.pr is not None else int(pr_doc.get("number") or 0)
    base = args.base or (pr_doc.get("base") or {}).get("sha") or ""
    if not repo or not head:
        raise UsageError("the repository and commit come from GITHUB_REPOSITORY and GITHUB_SHA, or --repo and --head")
    before, after = load_dir(args.before), load_dir(args.after)
    if args.paths_from_git and base:
        paths = git_paths(base, head)
    else:
        paths = changed_files(args.before, args.after)
    checks = {"render": "ok"}
    for c in args.check or []:
        k, _, v = c.partition("=")
        if not k or not v:
            raise UsageError(f"--check is name=value, not {c!r}")
        checks[k] = v
    actor = args.proposer or (f"user:{env['GITHUB_ACTOR']}" if env.get("GITHUB_ACTOR") else "unknown")
    body: dict[str, Any] = {
        "app": args.app, "env": args.env.lower(), "cluster": args.cluster, "repo": repo, "pr": pr, "head": head,
        "proposer": actor, "proposerKind": args.proposer_kind, "treeDigest": tree_digest(after),
        "paths": paths[:gate.MAX_PATHS], "linesChanged": args.lines_changed, "objects": objects(before, after),
        "checks": checks}
    if base and len(base) == 40:
        body["base"] = base
    if args.owner:
        body["owner"] = args.owner
    return body


def user_agent() -> str:
    """Our own User-Agent: an edge in front of Clearance (Cloudflare's browser integrity check on Hangar) refuses
    Python's default `Python-urllib/x.y` with a 403 (error 1010) that never reaches Clearance."""
    try:
        from importlib.metadata import version
        return f"clearance-register/{version('clearance')}"
    except Exception:  # noqa: BLE001 - a version is a courtesy
        return "clearance-register"


def post(url: str, token: str, body: dict[str, Any], timeout: float = 30) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(url.rstrip("/") + "/v1/clearances", data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                          "User-Agent": user_agent()})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - the operator's Clearance
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        raw = e.read(64 << 10)
        try:
            return e.code, json.loads(raw)
        except ValueError:
            # Not Clearance's JSON: something in front of it answered (a proxy, a WAF). Say what it said.
            return e.code, {"error": f"not from Clearance: {raw[:200].decode(errors='replace').strip() or '(empty body)'}"}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="clearance register", description=__doc__.split("\n\n")[0])
    p.add_argument("--url", default=os.environ.get("CLEARANCE_URL"), help="Clearance's gateway (CLEARANCE_URL)")
    p.add_argument("--app", required=True)
    p.add_argument("--env", required=True, help="the GitHub environment's name; Clearance matches it lowercased")
    p.add_argument("--cluster", required=True)
    p.add_argument("--before", help="rendered manifests before this commit (missing: everything is added)")
    p.add_argument("--after", required=True, help="rendered manifests at this commit")
    p.add_argument("--owner", help="the app's owner group (group:<ns>/<name>); default: Clearance looks it up")
    p.add_argument("--audience", default="clearance", help="the OIDC token's audience")
    p.add_argument("--token-file", help="a bearer token Clearance accepts as a verifier, instead of GitHub's OIDC")
    p.add_argument("--repo"), p.add_argument("--head"), p.add_argument("--base")
    p.add_argument("--pr", type=int, help="default: the event's pull request, else 0 (a pushed commit)")
    p.add_argument("--paths-from-git", action="store_true", help="paths from `git diff --name-only base...head`")
    p.add_argument("--proposer", help="default: user:$GITHUB_ACTOR")
    p.add_argument("--proposer-kind", default="person", choices=list(gate.PROPOSER_KINDS))
    p.add_argument("--lines-changed", type=int, default=0)
    p.add_argument("--check", action="append", help="name=value, e.g. ci=pass (repeatable)")
    p.add_argument("--dry-run", action="store_true", help="print the request body and stop")
    return p


def main(argv: Iterable[str] | None = None, env: dict[str, str] | None = None, poster=post, token_fetcher=actions_token) -> int:
    env = dict(os.environ) if env is None else env
    try:
        args = parser().parse_args(list(argv) if argv is not None else None)
    except SystemExit as e:
        return EXIT_USAGE if e.code else 0
    try:
        body = build_body(args, env)
        gate.ChangeRequest.from_dict(body)      # the gate's own validation, before anything is sent
        if args.dry_run:
            print(json.dumps(body, indent=2))
            return EXIT_CLEARED
        if not args.url:
            raise UsageError("--url or CLEARANCE_URL is required")
        token = Path(args.token_file).read_text().strip() if args.token_file else token_fetcher(env, args.audience)
    except (UsageError, gate.BadChange, OSError, subprocess.CalledProcessError) as e:
        print(f"clearance register: {e}", file=sys.stderr)
        return EXIT_USAGE
    status, out = poster(args.url, token, body)
    if status >= 300:
        why = out.get("message") or out.get("error") or out.get("detail") or ""
        print(f"clearance register: refused ({status}) {out.get('rule') or ''} {why}".rstrip(), file=sys.stderr)
        return EXIT_DENIED
    state = out.get("state")
    print(f"{out.get('id')} {state} tier {out.get('tier')}" + (f" cleared_by {out['cleared_by']}" if out.get("cleared_by") else ""))
    if state == "cleared":
        return EXIT_CLEARED
    if state == "holding":
        req = out.get("requirement") or {}
        print(f"holding for people: {req.get('owner', 0)} from {req.get('ownerGroup', '?')}"
              + (f", {req['outside']} from {', '.join(req.get('outsideGroups') or [])}" if req.get("outside") else ""))
        return EXIT_HOLDING
    if out.get("deny_reason"):
        print(f"denied: {out['deny_reason']}", file=sys.stderr)
    return EXIT_DENIED


def cli() -> None:
    """The `clearance` console script: `clearance register ...`."""
    argv = sys.argv[1:]
    if not argv or argv[0] != "register":
        print("usage: clearance register --app APP --env ENV --cluster CLUSTER --after DIR [--before DIR] ...", file=sys.stderr)
        sys.exit(EXIT_USAGE)
    sys.exit(main(argv[1:]))
