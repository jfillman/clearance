"""The transport: CoreClient (synchronous, thread-safe) and AsyncCoreClient (the same, off the event loop).

Standard library only (http.client). Outage policy defaults (2026-11-02): each attempt has `timeout` (0.25 s) for
the whole exchange, connect to last byte; a retryable failure is retried `retries` (1) time at once; after
`breaker_threshold` (5) consecutive unavailable calls the breaker opens and every call fails fast with
CoreUnavailable for `breaker_cooldown` (5 s), then one probe goes through: success closes it, failure opens it
again. evaluate, register_change and verify_provenance are retried on any connection failure, timeout, 502, 503 or
504; outcome, record, clear_change and deny_change only when nothing can have been acted on (a failed connect, or
a 503, which the core answers when it did not record). A 500 is unavailable and not retried. healthz and readyz
bypass the breaker.
"""

from __future__ import annotations

import asyncio
import functools
import http.client
import json
import os
import ssl
import threading
import time
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any

from . import _models as m
from ._codec import DecodeError, Model
from ._version import __version__
from .errors import (
    BREAKER_OPEN,
    CONNECTION,
    SERVER_ERROR,
    TIMEOUT,
    BadResponse,
    CoreRequestError,
    CoreUnavailable,
    TokenUnavailable,
)

DEFAULT_TIMEOUT = 0.25
DEFAULT_RETRIES = 1
DEFAULT_BREAKER_THRESHOLD = 5
DEFAULT_BREAKER_COOLDOWN = 5.0
DEFAULT_MAX_RESPONSE_BYTES = 4 << 20
MAX_TOKEN_BYTES = 64 << 10
ON_BEHALF_OF_HEADER = "X-Hangar-On-Behalf-Of"

# Breaker states (CoreClient.breaker_state).
CLOSED, OPEN, HALF_OPEN = "closed", "open", "half-open"

_RETRY_ANY, _RETRY_UNSENT = "any", "unsent"
# A reused keep-alive connection the core already closed: resent once on a fresh one (nothing was processed).
_STALE = (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError)


class _Breaker:
    def __init__(self, threshold: int, cooldown: float, clock: Callable[[], float]):
        self.threshold, self.cooldown, self.clock = threshold, cooldown, clock
        self._lock = threading.Lock()
        self._failures = 0
        self._open = False
        self._opened_at = 0.0
        self._probing = False

    def allow(self) -> tuple[bool, bool]:
        if self.threshold <= 0:
            return True, False
        with self._lock:
            if not self._open:
                return True, False
            if self._probing or self.clock() - self._opened_at < self.cooldown:
                return False, False
            self._probing = True
            return True, True

    def done(self, probe: bool, failed: bool) -> None:
        if self.threshold <= 0:
            return
        with self._lock:
            if probe:
                self._probing = False
            if not failed:
                self._failures, self._open = 0, False
                return
            self._failures += 1
            if probe or self._failures >= self.threshold:
                self._open, self._opened_at = True, self.clock()

    def cancel(self, probe: bool) -> None:
        if probe and self.threshold > 0:
            with self._lock:
                self._probing = False

    def state(self) -> str:
        if self.threshold <= 0:
            return CLOSED
        with self._lock:
            if not self._open:
                return CLOSED
            if self._probing or self.clock() - self._opened_at >= self.cooldown:
                return HALF_OPEN
            return OPEN


class _Unavailable(Exception):
    """One attempt's unavailability, before the retry decision."""

    def __init__(self, reason: str, retryable: bool, *, status: int | None = None, detail: str = ""):
        self.reason, self.retryable, self.status, self.detail = reason, retryable, status, detail


class _Unsent(Exception):
    """The connection could not be made: nothing was sent."""


def _token_source(token: str | Callable[[], str] | None, token_file: str | os.PathLike | None):
    if token is not None and token_file is not None:
        raise ValueError("give token or token_file, not both")
    if token_file is not None:
        path = os.fspath(token_file)

        def read() -> str:
            with open(path, "rb") as fh:
                raw = fh.read(MAX_TOKEN_BYTES + 1)
            if len(raw) > MAX_TOKEN_BYTES:
                raise ValueError(f"token file {path} is over {MAX_TOKEN_BYTES} bytes")
            return raw.decode("ascii").strip()

        return read
    if token is None or callable(token):
        return token
    fixed = token
    return lambda: fixed


class CoreClient:
    """Calls the Clearance core. Thread-safe; one client (one breaker, one connection pool) per core.

    token is the bearer token, or a callable returning it; token_file is a file re-read on every request (a
    projected service-account token the kubelet rotates). provider is the registered provider name record()
    sends (autopilot-gateway).
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str | Callable[[], str] | None = None,
        token_file: str | os.PathLike | None = None,
        provider: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        breaker_threshold: int = DEFAULT_BREAKER_THRESHOLD,
        breaker_cooldown: float = DEFAULT_BREAKER_COOLDOWN,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        allow_unknown_fields: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        user_agent: str = f"clearance-core-client/{__version__}",
        clock: Callable[[], float] = time.monotonic,
        max_idle: int = 16,
    ):
        u = urllib.parse.urlsplit(base_url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"base_url {base_url!r} is not an http(s) URL")
        if u.username or u.password or u.query or u.fragment:
            raise ValueError("base_url carries no credentials, query or fragment")
        if timeout <= 0:
            raise ValueError("timeout is positive")
        self._https = u.scheme == "https"
        self._host = u.hostname
        self._port = u.port or (443 if self._https else 80)
        self._prefix = u.path.rstrip("/")
        self._ssl = ssl_context if ssl_context is not None else (ssl.create_default_context() if self._https else None)
        self._token = _token_source(token, token_file)
        self.provider = provider
        self.timeout = timeout
        self.retries = max(retries, 0)
        self.max_response_bytes = max_response_bytes
        self.allow_unknown_fields = allow_unknown_fields
        self._user_agent = user_agent
        self._breaker = _Breaker(breaker_threshold, breaker_cooldown, clock)
        self._idle: list[http.client.HTTPConnection] = []
        self._idle_lock = threading.Lock()
        self._max_idle = max_idle

    # -- the routes ------------------------------------------------------------------------------------------------

    def evaluate(self, request: m.EvaluationRequest | Mapping[str, Any]) -> m.EvaluationResult:
        """Ask for a decision. A deny is a result with decision False, not an exception."""
        return self._call("evaluate", request, retry=_RETRY_ANY)

    def outcome(self, decision_id: str, request: m.OutcomeRequest | Mapping[str, Any]) -> m.RecordRef:
        """Report an allowed decision's result, once (a second is refused: CoreRequestError 409)."""
        if not decision_id:
            raise ValueError("no decision id (an unrecorded decision takes no outcome)")
        return self._call("recordOutcome", request, params={"id": decision_id}, retry=_RETRY_UNSENT)

    def record(
        self, kind: str, record: m.ProviderEvent | Mapping[str, Any], *, provider: str | None = None
    ) -> m.RecordRef:
        """Append the provider's own record (one of RECORD_KINDS)."""
        prov = provider or self.provider
        if not prov:
            raise ValueError("no provider: pass provider= or set it on the client")
        body = {"provider": prov, "kind": kind, "record": _as_dict(record)}
        return self._call("appendRecord", body, retry=_RETRY_UNSENT)

    def publish_definitions(
        self, pins: list[m.PinnedDefinition | Mapping[str, Any]],
        rejected: list[m.RejectedPin | Mapping[str, Any]] | None = None, *, provider: str | None = None
    ) -> m.DefinitionsResult:
        """Replace the core's cluster-pinned agent definitions with this provider's whole set (PUT /v1/definitions;
        the provider is registered with definitions: true). The core decides each pin itself and records what
        changed; publishing the same set again records nothing, so it is retried like an evaluation."""
        prov = provider or self.provider
        if not prov:
            raise ValueError("no provider: pass provider= or set it on the client")
        body: dict[str, Any] = {"provider": prov, "pins": [_as_dict(p) for p in pins]}
        if rejected:
            body["rejected"] = [_as_dict(r) for r in rejected]
        return self._call("publishDefinitions", body, retry=_RETRY_ANY)

    def register_change(self, change: Mapping[str, Any]) -> m.GateChange:
        """Register (or re-evaluate) a change to a protected environment; the caller is a verifier."""
        return self._call("registerChange", change, retry=_RETRY_ANY)

    def clear_change(self, change_id: str, *, on_behalf_of: str | None = None) -> m.GateChangeWithAuditSeq:
        """Approve a holding change as the caller, or as on_behalf_of when the caller is a delegate."""
        return self._call("clearChange", {}, params={"change_id": change_id}, on_behalf_of=on_behalf_of,
                          retry=_RETRY_UNSENT)

    def deny_change(
        self, change_id: str, reason: str, *, on_behalf_of: str | None = None
    ) -> m.GateChangeWithAuditSeq:
        """Deny a holding change, with a reason."""
        return self._call("denyChange", {"reason": reason}, params={"change_id": change_id},
                          on_behalf_of=on_behalf_of, retry=_RETRY_UNSENT)

    def verify_provenance(self, request: Mapping[str, Any]) -> m.ProvenanceVerdict:
        """A pull request's agent-identity and agent-scope verdicts; the caller is a verifier."""
        return self._call("verifyProvenance", request, retry=_RETRY_ANY)

    def healthz(self) -> m.Health:
        """GET /healthz; bypasses the breaker."""
        return self._call("healthz", None, retry=_RETRY_ANY, probe=True)

    def readyz(self) -> m.Ready:
        """GET /readyz; a not-ready core (503) is CoreUnavailable. Bypasses the breaker."""
        return self._call("readyz", None, retry=_RETRY_ANY, probe=True)

    @property
    def breaker_state(self) -> str:
        return self._breaker.state()

    def close(self) -> None:
        with self._idle_lock:
            idle, self._idle = self._idle, []
        for c in idle:
            c.close()

    def __enter__(self) -> CoreClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- the call --------------------------------------------------------------------------------------------------

    def _call(self, op_id: str, body: Any, *, params: Mapping[str, str] | None = None,
              on_behalf_of: str | None = None, retry: str, probe: bool = False):
        op = m.OPERATIONS[op_id]
        path = op.path
        for k, v in (params or {}).items():
            path = path.replace("{" + k + "}", urllib.parse.quote(str(v), safe=""))
        payload = None if body is None else json.dumps(_as_dict(body), separators=(",", ":")).encode()
        headers = {"Accept": "application/json", "User-Agent": self._user_agent}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if on_behalf_of:
            headers[ON_BEHALF_OF_HEADER] = on_behalf_of
        is_probe = False
        if not probe:
            ok, is_probe = self._breaker.allow()
            if not ok:
                raise CoreUnavailable(op_id, BREAKER_OPEN)
        last: _Unavailable | None = None
        attempts = 0
        for _ in range(1 + self.retries):
            attempts += 1
            try:
                self._authorize(headers)
            except Exception as e:
                self._breaker.cancel(is_probe)
                raise TokenUnavailable(f"{op_id}: {e}") from e
            try:
                status, raw = self._attempt(op.method, self._prefix + path, payload, headers, retry)
            except _Unavailable as u:
                last = u
                if u.retryable:
                    continue
                break
            except _TooLarge as e:
                if not probe:
                    self._breaker.done(is_probe, False)
                raise BadResponse(op_id, e.status, f"the body is over {self.max_response_bytes} bytes") from None
            except BaseException:
                self._breaker.cancel(is_probe)
                raise
            try:
                result = self._answer(op_id, op, status, raw, retry)
            except _Unavailable as u:
                last = u
                if u.retryable:
                    continue
                break
            except (CoreRequestError, BadResponse):
                # The core answered: it is reachable.
                if not probe:
                    self._breaker.done(is_probe, False)
                raise
            if not probe:
                self._breaker.done(is_probe, False)
            return result
        if not probe:
            self._breaker.done(is_probe, True)
        assert last is not None
        raise CoreUnavailable(op_id, last.reason, status=last.status, attempts=attempts, detail=last.detail)

    def _authorize(self, headers: dict[str, str]) -> None:
        if self._token is None:
            return
        tok = self._token()
        if not isinstance(tok, str) or not tok or any(c.isspace() or ord(c) < 0x21 or ord(c) == 0x7F for c in tok):
            raise ValueError("the token is empty or has whitespace or control characters")
        headers["Authorization"] = "Bearer " + tok

    def _answer(self, op_id: str, op, status: int, raw: bytes, retry: str):
        if status == 200:
            try:
                data = json.loads(raw)
            except ValueError as e:
                raise BadResponse(op_id, status, f"not JSON: {e}") from None
            if op.response is None:
                return data
            try:
                return op.response.from_dict(data, strict=not self.allow_unknown_fields)
            except DecodeError as e:
                raise BadResponse(op_id, status, str(e)) from None
        if 400 <= status < 500:
            body = _error_body(raw)
            raise CoreRequestError(op_id, status, body.get("error") or http.client.responses.get(status, "error"),
                                   rule=body.get("rule") or "", hint=body.get("hint") or "")
        if status >= 500:
            retryable = status == 503 or (retry == _RETRY_ANY and status in (502, 504))
            raise _Unavailable(SERVER_ERROR, retryable, status=status, detail=_error_body(raw).get("error", ""))
        raise BadResponse(op_id, status, "unexpected status")

    def _attempt(self, method: str, path: str, payload: bytes | None, headers: dict[str, str], retry: str):
        """One exchange under one deadline; returns (status, body) or raises _Unavailable."""
        deadline = time.monotonic() + self.timeout
        for fresh_try in (False, True):
            conn, reused = self._take(fresh_try)
            try:
                if conn.sock is None:
                    try:
                        conn.timeout = self._remaining(deadline)
                        conn.connect()
                    except (OSError, _Timeout) as e:
                        raise _Unsent(e) from e
                conn.sock.settimeout(self._remaining(deadline))
                conn.request(method, path, body=payload, headers=headers)
                conn.sock.settimeout(self._remaining(deadline))
                resp = conn.getresponse()
                raw = self._read(conn, resp, deadline)
            except _Unsent as e:
                conn.close()
                cause = e.args[0]
                reason = TIMEOUT if isinstance(cause, (TimeoutError, _Timeout)) else CONNECTION
                raise _Unavailable(reason, True, detail=str(cause) or type(cause).__name__) from None
            except _STALE as e:
                conn.close()
                if reused and not fresh_try:
                    continue
                raise _Unavailable(CONNECTION, retry == _RETRY_ANY, detail=str(e) or type(e).__name__) from None
            except (TimeoutError, _Timeout) as e:
                conn.close()
                raise _Unavailable(TIMEOUT, retry == _RETRY_ANY, detail=str(e) or "timed out") from None
            except _TooLarge as e:
                conn.close()
                e.status = resp.status
                raise
            except (OSError, http.client.HTTPException) as e:
                conn.close()
                raise _Unavailable(CONNECTION, retry == _RETRY_ANY, detail=str(e) or type(e).__name__) from None
            if resp.will_close:
                conn.close()
            else:
                self._give(conn)
            return resp.status, raw
        raise AssertionError("unreachable")

    def _read(self, conn: http.client.HTTPConnection, resp: http.client.HTTPResponse, deadline: float) -> bytes:
        chunks, total = [], 0
        while True:
            if conn.sock is not None:
                conn.sock.settimeout(self._remaining(deadline))
            chunk = resp.read1(65536)
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > self.max_response_bytes:
                raise _TooLarge()
            chunks.append(chunk)

    def _remaining(self, deadline: float) -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise _Timeout("timed out")
        return left

    # -- the pool --------------------------------------------------------------------------------------------------

    def _take(self, fresh: bool) -> tuple[http.client.HTTPConnection, bool]:
        if not fresh:
            with self._idle_lock:
                if self._idle:
                    return self._idle.pop(), True
        if self._https:
            return http.client.HTTPSConnection(self._host, self._port, timeout=self.timeout, context=self._ssl), False
        return http.client.HTTPConnection(self._host, self._port, timeout=self.timeout), False

    def _give(self, conn: http.client.HTTPConnection) -> None:
        with self._idle_lock:
            if len(self._idle) < self._max_idle:
                self._idle.append(conn)
                return
        conn.close()


class _Timeout(Exception):
    pass


class _TooLarge(Exception):
    status = 200


def _as_dict(v: Any) -> Any:
    if isinstance(v, Model):
        return v.to_dict()
    if isinstance(v, Mapping):
        return dict(v)
    raise TypeError(f"a model or a mapping is expected, not {type(v).__name__}")


def _error_body(raw: bytes) -> dict[str, Any]:
    try:
        body = json.loads(raw)
    except ValueError:
        return {}
    return {k: v for k, v in body.items() if isinstance(v, str)} if isinstance(body, dict) else {}


class AsyncCoreClient:
    """CoreClient's methods as coroutines, each run in a worker thread so the event loop never blocks on the core.
    The same client (breaker, pool) underneath: CoreClient(...) arguments, or wrap one with sync=."""

    def __init__(self, *args: Any, sync: CoreClient | None = None, **kwargs: Any):
        self.sync = sync if sync is not None else CoreClient(*args, **kwargs)

    def __getattr__(self, name: str):
        attr = getattr(self.sync, name)
        if name.startswith("_") or not callable(attr) or name == "close":
            return attr

        @functools.wraps(attr)
        async def run(*a: Any, **kw: Any):
            return await asyncio.to_thread(attr, *a, **kw)

        return run

    @property
    def breaker_state(self) -> str:
        return self.sync.breaker_state

    async def aclose(self) -> None:
        self.sync.close()
