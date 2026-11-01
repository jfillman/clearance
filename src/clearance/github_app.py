"""The Clearance GitHub App, phase 1: Clearance's own check runs on pull requests (docs/provenance-app.md).

The customer installs the App (named "Clearance") on their repositories. GitHub sends pull_request and check_run
webhooks to Clearance; Clearance verifies the signature, gathers what provenance.verify needs from GitHub itself with
an installation token scoped to that one repository, decides with the same provenance.verify every other caller gets,
records the verdict, and posts two check runs on the PR's head:

    Clearance / agent-identity   confirmed or not-agent: success; AI001-AI004: failure with the rule and the hint
    Clearance / agent-scope      in-scope or not-agent: success; AS001-AS004: failure, one annotation per path

The App never writes code: its token asks for checks write and contents, pull requests and metadata read (and issues
write only when PR comments are on). Decided 2026-11-01: PR comments are off by default; `comments="agent-failures"`
comments only on an agent PR that fails a check, the way Glidepath's agent-gates does.

The webhook answers at once and the work is queued (GitHub gives a delivery 10 seconds); a failed check is retried by
GitHub's "Re-run" (check_run rerequested) or the next push. Nothing here knows Hangar.

Phase 2 (docs/provenance-app.md): the App is also a **custom deployment protection rule**. A GitHub Actions job that
deploys to an environment protected by the App waits until Clearance answers: approved when the deployment gate has
cleared the change registered for that commit and environment, rejected when it was denied, expired or superseded,
or when nothing was registered. A change that holds for people keeps the deployment waiting (with a status report
saying who must clear it) and is answered the moment they decide. Answers are retried until GitHub takes them.
That needs two more permissions (deployments write, actions read) and the deployment_protection_rule event.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import jwt

from . import provenance

log = logging.getLogger("clearance.github_app")

API = "https://api.github.com"
IDENTITY_CHECK = "Clearance / agent-identity"
SCOPE_CHECK = "Clearance / agent-scope"
COMMENT_MARKER = "<!-- clearance:provenance -->"
PR_ACTIONS = frozenset({"opened", "synchronize", "reopened", "edited", "ready_for_review"})
COMMENT_MODES = ("off", "agent-failures")
TRAILER = re.compile(r"^Hangar-(Task|Session|Run|Agent): *([^ ]+) *$")
MAX_PAGES = 30
MAX_ANNOTATIONS = 50
SWEEP = "_sweep"                    # an internal queue item: deliver every answered deployment GitHub has not taken
SWEEP_SECONDS = 60.0
CALLBACK = re.compile(r"^/repos/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/actions/runs/([0-9]+)/deployment_protection_rule$")

Opener = Callable[[urllib.request.Request, float], tuple[int, bytes]]


def _urlopen(req: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:  # noqa: S310 - the URL is GitHub's API
            return res.status, res.read(8 << 20)
    except urllib.error.HTTPError as e:
        return e.code, e.read(64 << 10)


class GitHubAppError(RuntimeError):
    """GitHub failed or refused; logged, never shown on the PR."""


def verify_signature(secret: bytes, body: bytes, header: str | None) -> bool:
    """X-Hub-Signature-256: HMAC-SHA256 of the raw body with the webhook secret, compared in constant time."""
    if not header or not header.startswith("sha256="):
        return False
    want = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header[len("sha256="):])


@dataclass(frozen=True)
class AppConfig:
    app_id: str
    key_file: Path
    webhook_secret_file: Path
    comments: str = "off"
    api: str = API
    timeout: float = 20.0

    def __post_init__(self):
        if self.comments not in COMMENT_MODES:
            raise ValueError(f"comments is one of {COMMENT_MODES}")


class GitHubApp:
    """The App's GitHub client and its webhook handling. `gateway` is the Clearance Gateway (provenance_from_app)."""

    def __init__(self, cfg: AppConfig, gateway: Any, *, opener: Opener = _urlopen,
                 clock: Callable[[], float] = time.time):
        self.cfg, self.gateway, self._open, self.clock = cfg, gateway, opener, clock
        self._queue: "queue.Queue[tuple[str, dict[str, Any]] | None]" = queue.Queue(maxsize=1000)
        self._thread: threading.Thread | None = None
        self._sweeper: threading.Thread | None = None
        self._stopping = threading.Event()
        if hasattr(gateway, "deployment_listeners"):
            gateway.deployment_listeners.append(self.poke)

    # -- the webhook ------------------------------------------------------------------------------------------
    def secret(self) -> bytes:
        return self.cfg.webhook_secret_file.read_bytes().strip()

    def accept(self, event: str, body: bytes, signature: str | None) -> tuple[int, str]:
        """The webhook's answer: 401 on a bad signature, 202 queued, 200 ignored. Never does the work inline."""
        if not verify_signature(self.secret(), body, signature):
            return 401, "bad signature"
        try:
            payload = json.loads(body)
        except ValueError:
            return 400, "not JSON"
        if not self.wanted(event, payload):
            return 200, "ignored"
        try:
            self._queue.put_nowait((event, payload))
        except queue.Full:
            return 503, "busy"
        return 202, "queued"

    @staticmethod
    def wanted(event: str, payload: dict[str, Any]) -> bool:
        action = payload.get("action")
        if event == "pull_request":
            return action in PR_ACTIONS
        if event in ("check_run", "check_suite"):
            return action == "rerequested"
        if event == "deployment_protection_rule":
            return action == "requested"
        return event in ("installation", "installation_repositories")

    def poke(self) -> None:
        """Ask the worker to deliver answered deployments (the gateway calls this when people decide a change)."""
        try:
            self._queue.put_nowait((SWEEP, {}))
        except queue.Full:
            pass                         # the periodic sweep delivers it

    def start(self) -> "GitHubApp":
        self._thread = threading.Thread(target=self._loop, name="clearance-github-app", daemon=True)
        self._thread.start()
        self._sweeper = threading.Thread(target=self._tick, name="clearance-github-app-sweep", daemon=True)
        self._sweeper.start()
        return self

    def _tick(self) -> None:
        while not self._stopping.wait(SWEEP_SECONDS):
            self.poke()

    def stop(self) -> None:
        self._stopping.set()
        self._queue.put(None)
        if self._thread:
            self._thread.join(timeout=30)

    def _loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            try:
                self.handle(*item)
            except Exception as e:  # noqa: BLE001 - one bad delivery must not end the worker
                log.error("github app: %s failed: %s", item[0], type(e).__name__)

    # -- the work ---------------------------------------------------------------------------------------------
    def handle(self, event: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Process one delivery; returns the check runs posted, or the deployment answers (for tests and logs)."""
        if event == SWEEP:
            return self.deliver_answers()
        installation = (payload.get("installation") or {}).get("id")
        if event == "deployment_protection_rule":
            return self.protect(int(installation), payload)
        if event in ("installation", "installation_repositories"):
            repos = [r.get("full_name") for r in (payload.get("repositories") or payload.get("repositories_added") or [])]
            self.gateway.record_app_installation(str(installation), payload.get("action", ""),
                                                 ((payload.get("installation") or {}).get("account") or {}).get("login", ""),
                                                 [r for r in repos if r])
            return []
        repo = ((payload.get("repository") or {}).get("full_name") or "").lower()
        prs: list[int] = []
        if event == "pull_request":
            prs = [int(payload["pull_request"]["number"])]
        elif event == "check_run":
            run = payload.get("check_run") or {}
            if run.get("name") not in (IDENTITY_CHECK, SCOPE_CHECK):
                return []
            prs = [int(p["number"]) for p in run.get("pull_requests") or []]
        elif event == "check_suite":
            prs = [int(p["number"]) for p in (payload.get("check_suite") or {}).get("pull_requests") or []]
        if not installation or not repo or not prs:
            return []
        token = self.installation_token(int(installation), repo)
        out = []
        for pr in prs:
            out += self.check(token, int(installation), repo, pr)
        return out

    def check(self, token: str, installation: int, repo: str, pr: int) -> list[dict[str, Any]]:
        req = self.gather(token, repo, pr)
        verdict = self.gateway.provenance_from_app(str(installation), req)
        runs = [self._post_check(token, repo, req.head, IDENTITY_CHECK, verdict["identity"], [], verdict),
                self._post_check(token, repo, req.head, SCOPE_CHECK, verdict["scope"],
                                 verdict["scope"].get("violations") or [], verdict)]
        failed = not (verdict["identity"]["ok"] and verdict["scope"]["ok"])
        if self.cfg.comments == "agent-failures" and verdict.get("agent_pr") and failed:
            self._comment(token, repo, pr, verdict)
        return runs

    # -- deployments (phase 2) -------------------------------------------------------------------------------------
    def _callback(self, url: str) -> tuple[str, int] | None:
        """The repo and run of GitHub's callback URL, only when it is GitHub's own API: the App's token never goes
        anywhere a payload names."""
        if not isinstance(url, str) or not url.startswith(self.cfg.api + "/"):
            return None
        m = CALLBACK.match(url[len(self.cfg.api):])
        return (m.group(1).lower(), int(m.group(2))) if m else None

    def protect(self, installation: int, payload: dict[str, Any]) -> list[dict[str, Any]]:
        environment = payload.get("environment") or ""
        sha = ((payload.get("deployment") or {}).get("sha") or "").lower()
        url = payload.get("deployment_callback_url") or ""
        cb = self._callback(url)
        repo = ((payload.get("repository") or {}).get("full_name") or "").lower()
        if not environment or not re.match(r"^[0-9a-f]{40}$", sha) or cb is None or cb[0] != repo:
            log.warning("github app: deployment_protection_rule without a usable environment, sha or callback")
            return []
        out = self.gateway.deployment_requested(str(installation), repo, sha, environment, cb[1], url)
        if out.get("answer") is None:
            # Waiting on people: a status report (no state) so the run page says who must clear it. Best effort: the
            # answer itself is delivered (and retried) when people decide.
            try:
                self._review(self.deployment_token(installation, repo), repo, cb[1], environment, None, out["comment"])
            except GitHubAppError as e:
                log.warning("github app: status report for run %s not posted: %s", cb[1], e)
            return [{"run": cb[1], "environment": environment, "answer": None}]
        if out.get("change") is None:
            token = self.deployment_token(installation, repo)
            self._review(token, repo, cb[1], environment, "rejected", out["comment"])
            return [{"run": cb[1], "environment": environment, "answer": "rejected"}]
        return self.deliver_answers()

    def deliver_answers(self) -> list[dict[str, Any]]:
        """Deliver every answered deployment GitHub has not taken yet; a failure stays for the next sweep."""
        done = []
        for d in self.gateway.undelivered_deployments():
            try:
                cb = self._callback(d.get("callback_url", ""))
                if cb is None:
                    continue
                token = self.deployment_token(int(d["installation"]), d["repo"])
                self._review(token, d["repo"], cb[1], d["environment"], d["answer"], d["comment"])
            except GitHubAppError as e:
                log.warning("github app: deployment answer for run %s not delivered: %s", d.get("run_id"), e)
                continue
            self.gateway.deployment_delivered(d["change"], d["run_id"], d["environment"])
            done.append({"run": d["run_id"], "environment": d["environment"], "answer": d["answer"]})
        return done

    def deployment_token(self, installation: int, repo: str) -> str:
        return self._token(installation, repo, {"deployments": "write", "actions": "read", "metadata": "read"})

    def _review(self, token: str, repo: str, run: int, environment: str, state: str | None, comment: str) -> None:
        """POST .../actions/runs/{run}/deployment_protection_rule: approved or rejected, or (no state) a status report."""
        body: dict[str, Any] = {"environment_name": environment, "comment": comment[:1024]}
        if state:
            body["state"] = state
        status, doc = self._call("POST", f"/repos/{repo}/actions/runs/{run}/deployment_protection_rule", token, body)
        if status not in (200, 201, 204):
            raise GitHubAppError(f"deployment review {repo} run {run}: {status} {str(doc.get('message', ''))[:200]}")

    # -- GitHub ---------------------------------------------------------------------------------------------------
    def app_jwt(self) -> str:
        now = int(self.clock())
        key = self.cfg.key_file.read_text()
        return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": self.cfg.app_id}, key, algorithm="RS256")

    def _call(self, method: str, path: str, token: str, body: Any = None, scheme: str = "token") -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.cfg.api + path, data=data, method=method, headers={
            "Authorization": f"{scheme} {token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", **({"Content-Type": "application/json"} if data else {})})
        try:
            status, raw = self._open(req, self.cfg.timeout)
        except OSError as e:
            raise GitHubAppError(f"GitHub unreachable: {type(e).__name__}") from e
        try:
            return status, json.loads(raw) if raw else {}
        except ValueError:
            return status, {}

    def installation_token(self, installation: int, repo: str) -> str:
        """A token for this one repository: checks write, contents, pull requests and metadata read (issues write when
        comments are on)."""
        perms = {"checks": "write", "contents": "read", "pull_requests": "read", "metadata": "read"}
        if self.cfg.comments != "off":
            perms["issues"] = "write"
        return self._token(installation, repo, perms)

    def _token(self, installation: int, repo: str, perms: dict[str, str]) -> str:
        status, doc = self._call("POST", f"/app/installations/{installation}/access_tokens", self.app_jwt(),
                                 {"repositories": [repo.split("/", 1)[1]], "permissions": perms}, scheme="Bearer")
        if status != 201 or not doc.get("token"):
            raise GitHubAppError(f"installation token: {status} {str(doc.get('message', ''))[:200]}")
        return doc["token"]

    def gather(self, token: str, repo: str, pr: int) -> provenance.Request:
        """What provenance.verify needs, from GitHub: the head, the author, every changed path (and a rename's old
        name), the head commit's Hangar-* trailers. The same body Glidepath's agent-gates sends."""
        status, p = self._call("GET", f"/repos/{repo}/pulls/{pr}", token)
        if status != 200:
            raise GitHubAppError(f"pull {repo}#{pr}: {status}")
        head, author = p["head"]["sha"], (p.get("user") or {}).get("login", "")
        paths: list[str] = []
        for page in range(1, MAX_PAGES + 1):
            status, files = self._call("GET", f"/repos/{repo}/pulls/{pr}/files?per_page=100&page={page}", token)
            if status != 200 or not isinstance(files, list):
                raise GitHubAppError(f"files {repo}#{pr}: {status}")
            for f in files:
                paths.append(f["filename"])
                if f.get("previous_filename"):
                    paths.append(f["previous_filename"])
            if len(files) < 100:
                break
        status, c = self._call("GET", f"/repos/{repo}/commits/{head}", token)
        if status != 200:
            raise GitHubAppError(f"commit {head[:7]}: {status}")
        trailers = {}
        for line in ((c.get("commit") or {}).get("message") or "").splitlines():
            m = TRAILER.match(line.strip())
            if m:
                trailers[m.group(1).lower()] = m.group(2)
        return provenance.Request.from_dict({"repo": repo, "pr": pr, "head": head, "author": author,
                                             "paths": paths[:provenance.MAX_PATHS], "trailers": trailers})

    def _post_check(self, token: str, repo: str, head: str, name: str, result: dict[str, Any],
                    violations: list[dict[str, str]], verdict: dict[str, Any]) -> dict[str, Any]:
        ok = bool(result.get("ok"))
        rule = result.get("rule")
        title = f"{'Passed' if ok else 'Failed'}: {result.get('status')}{f' ({rule})' if rule else ''}"
        summary = result.get("message", "")
        if not ok and result.get("hint"):
            summary += f"\n\n**Fix:** {result['hint']}"
        rec = verdict.get("record") or {}
        if rec:
            summary += f"\n\nClearance opened this PR for agent `{rec.get('agent')}` (task `{rec.get('task_id')}`)."
        summary += f"\n\nClearance evidence record `{verdict.get('audit_seq')}`."
        annotations = [{"path": v["path"], "start_line": 1, "end_line": 1, "annotation_level": "failure",
                        "title": v["rule"], "message": v["message"]} for v in violations if v.get("path")][:MAX_ANNOTATIONS]
        body = {"name": name, "head_sha": head, "status": "completed", "conclusion": "success" if ok else "failure",
                "external_id": str(verdict.get("audit_seq", "")),
                "output": {"title": title[:255], "summary": summary[:60000], "annotations": annotations}}
        status, doc = self._call("POST", f"/repos/{repo}/check-runs", token, body)
        if status != 201:
            raise GitHubAppError(f"check run {name}: {status} {str(doc.get('message', ''))[:200]}")
        return {"name": name, "conclusion": body["conclusion"], "id": doc.get("id"), "annotations": len(annotations)}

    def _comment(self, token: str, repo: str, pr: int, verdict: dict[str, Any]) -> None:
        lines = [COMMENT_MARKER, "### ❌ Clearance: this agent PR is not vouched for", ""]
        for key, label in (("identity", "agent-identity"), ("scope", "agent-scope")):
            r = verdict[key]
            mark = "✅" if r["ok"] else "❌"
            lines.append(f"- {mark} **{label}**: {r.get('message', '')}" + (f" ({r['rule']})" if r.get("rule") else ""))
            if not r["ok"] and r.get("hint"):
                lines.append(f"  - Fix: {r['hint']}")
        body = "\n".join(lines)
        status, comments = self._call("GET", f"/repos/{repo}/issues/{pr}/comments?per_page=100", token)
        mine = [c for c in comments if isinstance(c, dict) and str(c.get("body", "")).startswith(COMMENT_MARKER)] if status == 200 and isinstance(comments, list) else []
        if mine:
            self._call("PATCH", f"/repos/{repo}/issues/comments/{mine[0]['id']}", token, {"body": body})
        else:
            self._call("POST", f"/repos/{repo}/issues/{pr}/comments", token, {"body": body})


def read_config(app_id: str | None, key_file: str | None, secret_file: str | None, comments: str | None = None,
                api: str | None = None) -> AppConfig | None:
    """The App's configuration, or None when it is not configured (all three of id, key and secret are needed)."""
    if not (app_id and key_file and secret_file):
        return None
    return AppConfig(app_id=str(app_id), key_file=Path(key_file), webhook_secret_file=Path(secret_file),
                     comments=comments or "off", api=(api or API).rstrip("/"))
