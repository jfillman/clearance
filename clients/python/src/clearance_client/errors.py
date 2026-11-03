"""The client's exceptions. A deny is never one of them: it is an EvaluationResult with decision False."""

from __future__ import annotations

# Why the core is unavailable (CoreUnavailable.reason).
BREAKER_OPEN = "breaker_open"  # the breaker is open: nothing was sent
CONNECTION = "connection"  # connect or transport failure
TIMEOUT = "timeout"  # the attempt passed the client's timeout
SERVER_ERROR = "server_error"  # a 5xx answer


class ClearanceClientError(Exception):
    """The base of every exception this package raises."""


class CoreUnavailable(ClearanceClientError):
    """The core is unreachable: the breaker is open, the connection failed, an attempt timed out, or the core
    answered 5xx (after the retry, where the call is retried). The caller's outage policy acts on it: fail closed."""

    def __init__(self, op: str, reason: str, *, status: int | None = None, attempts: int = 0, detail: str = ""):
        self.op, self.reason, self.status, self.attempts, self.detail = op, reason, status, attempts, detail
        msg = f"clearance core unavailable: {op}: {reason}"
        if status is not None:
            msg += f" (HTTP {status})"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class CoreRequestError(ClearanceClientError):
    """A 4xx answer: the core refused the request (a bad body, a caller that is not a registered provider, a
    conflict). Retrying it unchanged gets the same answer. rule and hint are set by the gate's refusals."""

    def __init__(self, op: str, status: int, message: str, *, rule: str = "", hint: str = ""):
        self.op, self.status, self.message, self.rule, self.hint = op, status, message, rule, hint
        msg = f"clearance core refused {op}: HTTP {status}: {message}"
        if rule:
            msg += f" [{rule}]"
        super().__init__(msg)


class BadResponse(ClearanceClientError):
    """An answer the client could not read (a body that does not fit the contract, an unexpected status, an
    oversized body). The core answered, so the breaker does not count it; it is still no decision."""

    def __init__(self, op: str, status: int, detail: str):
        self.op, self.status, self.detail = op, status, detail
        super().__init__(f"clearance core: unreadable response to {op} (HTTP {status}): {detail}")


class TokenUnavailable(ClearanceClientError):
    """The bearer token could not be read; nothing was sent."""
