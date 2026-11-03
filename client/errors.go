package client

import (
	"errors"
	"fmt"
)

// ErrCoreUnavailable is the core being unreachable: the breaker is open, the connection failed, the attempt timed
// out, or the core answered 5xx (after the retry, where the call is retried). The caller's outage policy acts on
// it (errors.Is(err, ErrCoreUnavailable)); it is never a deny and never the caller's mistake.
var ErrCoreUnavailable = errors.New("clearance core unavailable")

// ErrBadResponse is an answer the client could not read: a 2xx body that does not decode strictly into the
// route's type, an unexpected status, or a body over Options.MaxResponseBytes. The core answered, so it does not
// count against the breaker; it is still not a decision, so fail closed.
var ErrBadResponse = errors.New("clearance core: unreadable response")

// ErrToken is the token source failing (a missing projected token file, say). Nothing was sent.
var ErrToken = errors.New("clearance client: no bearer token")

// Why the core is unavailable (UnavailableError.Reason).
const (
	ReasonBreakerOpen = "breaker_open" // the breaker is open: nothing was sent
	ReasonConnection  = "connection"   // dial or transport failure
	ReasonTimeout     = "timeout"      // the attempt passed Options.Timeout
	ReasonServerError = "server_error" // a 5xx answer
)

// UnavailableError is an ErrCoreUnavailable with its detail.
type UnavailableError struct {
	Op       string // the operation id (evaluate, recordOutcome, ...)
	Reason   string // one of the Reason* constants
	Status   int    // the HTTP status for ReasonServerError, else 0
	Attempts int    // how many attempts were made (0 when the breaker refused)
	Err      error  // the last transport error, if any
}

func (e *UnavailableError) Error() string {
	msg := fmt.Sprintf("clearance core unavailable: %s: %s", e.Op, e.Reason)
	if e.Status != 0 {
		msg += fmt.Sprintf(" (HTTP %d)", e.Status)
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Is makes errors.Is(err, ErrCoreUnavailable) true.
func (e *UnavailableError) Is(target error) bool { return target == ErrCoreUnavailable }

func (e *UnavailableError) Unwrap() error { return e.Err }

// APIError is a 4xx answer: the core refused the request (a bad body, a caller that is not a registered provider,
// a conflict). Fix the request; retrying it unchanged gets the same answer. Rule and Hint are set by the gate's
// refusals.
type APIError struct {
	Op      string
	Status  int
	Message string
	Rule    string
	Hint    string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("clearance core refused %s: HTTP %d: %s", e.Op, e.Status, e.Message)
	if e.Rule != "" {
		msg += " [" + e.Rule + "]"
	}
	return msg
}

// ResponseError is an ErrBadResponse with its detail.
type ResponseError struct {
	Op     string
	Status int
	Err    error
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("clearance core: unreadable response to %s (HTTP %d): %v", e.Op, e.Status, e.Err)
}

// Is makes errors.Is(err, ErrBadResponse) true.
func (e *ResponseError) Is(target error) bool { return target == ErrBadResponse }

func (e *ResponseError) Unwrap() error { return e.Err }
