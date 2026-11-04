package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Defaults: the outage policy of 2026-11-02 (spec R-3).
const (
	DefaultTimeout          = 250 * time.Millisecond
	DefaultRetries          = 1
	DefaultBreakerThreshold = 5
	DefaultBreakerCooldown  = 5 * time.Second
	DefaultMaxResponseBytes = 4 << 20
)

// DefaultOnBehalfOfHeader names the person a delegate acts for on the gate's clear and deny: the core's default
// CLEARANCE_ON_BEHALF_OF_HEADER (Options.OnBehalfOfHeader for a core configured otherwise).
const DefaultOnBehalfOfHeader = "X-Clearance-On-Behalf-Of"

// Options configure a Client. The zero value of each field is its default.
type Options struct {
	// BaseURL is the core's URL (http://clearance-core.clearance-system:8080). A path prefix is kept.
	BaseURL string
	// Token gives the bearer token, asked for on every request. Nil sends none (only /healthz and /readyz work).
	Token TokenSource
	// Provider is the registered provider name RecordRequest.Provider defaults to.
	Provider string
	// OnBehalfOfHeader is the header the core reads a delegate's person from; default DefaultOnBehalfOfHeader.
	OnBehalfOfHeader string
	// Timeout bounds each attempt (connect, send, the whole answer read). Default 250 ms.
	Timeout time.Duration
	// Retries is how many times a retryable failure is retried; default 1, negative is none.
	Retries int
	// BreakerThreshold is how many consecutive unavailable calls open the breaker; default 5, negative is none.
	BreakerThreshold int
	// BreakerCooldown is how long an open breaker fails calls fast before one probe goes through; default 5 s.
	BreakerCooldown time.Duration
	// MaxResponseBytes caps an answer's body; default 4 MiB.
	MaxResponseBytes int64
	// AllowUnknownFields relaxes strict response decoding (an answer with a field this client does not know is
	// otherwise ErrBadResponse). Off by default: a core newer than its client fails closed until the client is
	// bumped; turn it on only for a rolling upgrade.
	AllowUnknownFields bool
	// HTTPClient is the transport. Default: a client of its own with keep-alives, no proxy from the environment
	// and no redirects (a bearer token never follows one).
	HTTPClient *http.Client
	// UserAgent is sent as User-Agent; default "clearance-go-client".
	UserAgent string
	// Clock is the breaker's clock (tests); default time.Now.
	Clock func() time.Time
}

// Client calls the Clearance core. It is safe for concurrent use; one Client (one breaker) per core.
type Client struct {
	base    string
	opt     Options
	http    *http.Client
	breaker *breaker
}

// New checks opt and returns a Client.
func New(opt Options) (*Client, error) {
	u, err := url.Parse(opt.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("clearance client: BaseURL %q is not an http(s) URL", opt.BaseURL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("clearance client: BaseURL carries no credentials, query or fragment")
	}
	if opt.Timeout == 0 {
		opt.Timeout = DefaultTimeout
	}
	if opt.OnBehalfOfHeader == "" {
		opt.OnBehalfOfHeader = DefaultOnBehalfOfHeader
	}
	if opt.Timeout < 0 {
		return nil, errors.New("clearance client: Timeout is positive")
	}
	switch {
	case opt.Retries == 0:
		opt.Retries = DefaultRetries
	case opt.Retries < 0:
		opt.Retries = 0
	}
	switch {
	case opt.BreakerThreshold == 0:
		opt.BreakerThreshold = DefaultBreakerThreshold
	case opt.BreakerThreshold < 0:
		opt.BreakerThreshold = 0
	}
	if opt.BreakerCooldown <= 0 {
		opt.BreakerCooldown = DefaultBreakerCooldown
	}
	if opt.MaxResponseBytes <= 0 {
		opt.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if opt.UserAgent == "" {
		opt.UserAgent = "clearance-go-client"
	}
	if opt.Clock == nil {
		opt.Clock = time.Now
	}
	hc := opt.HTTPClient
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		tr.MaxIdleConnsPerHost = 32
		hc = &http.Client{Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &Client{base: strings.TrimRight(u.String(), "/"), opt: opt, http: hc,
		breaker: &breaker{threshold: opt.BreakerThreshold, cooldown: opt.BreakerCooldown, now: opt.Clock}}, nil
}

// BreakerState is the breaker's state now.
func (c *Client) BreakerState() BreakerState { return c.breaker.state() }

// Evaluate asks for a decision. A deny is a result with Decision false, not an error. Errors: ErrCoreUnavailable
// (act on the outage policy), *APIError (the request is wrong), ErrBadResponse, ErrToken. Retried on a timeout
// too: deciding is a pure function, and a retried request at worst leaves one more decision record that no
// outcome names.
func (c *Client) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResult, error) {
	var out EvaluationResult
	err := c.call(ctx, call{op: "evaluate", method: "POST", path: "/access/v1/evaluation", body: req,
		retry: retryAny}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Outcome reports an allowed decision's result, once. Retried only when the request cannot have been acted on (a
// failed dial, a 503): a second outcome is refused (409), so a blind retry could turn a success into an error.
func (c *Client) Outcome(ctx context.Context, decisionID string, req *OutcomeRequest) (*RecordRef, error) {
	if decisionID == "" {
		return nil, errors.New("clearance client: no decision id (an unrecorded decision takes no outcome)")
	}
	var out RecordRef
	err := c.call(ctx, call{op: "recordOutcome", method: "POST",
		path: "/v1/decisions/" + url.PathEscape(decisionID) + "/outcome", body: req, retry: retryUnsent}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Record appends the provider's own record (one of RecordKinds). req.Provider empty is Options.Provider. Retried
// only when the request cannot have been acted on, so a record is not written twice.
func (c *Client) Record(ctx context.Context, req *RecordRequest) (*RecordRef, error) {
	body := *req
	if body.Provider == "" {
		body.Provider = c.opt.Provider
	}
	var out RecordRef
	if err := c.call(ctx, call{op: "appendRecord", method: "POST", path: "/v1/records", body: &body,
		retry: retryUnsent}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PublishDefinitions replaces the core's set of cluster-pinned agent definitions with the provider's (the
// provider is registered with definitions: true). req.Provider empty is Options.Provider. A publish of the same
// set changes and records nothing, so it is retried as an evaluation is.
func (c *Client) PublishDefinitions(ctx context.Context, req *DefinitionsRequest) (*DefinitionsResult, error) {
	body := *req
	if body.Provider == "" {
		body.Provider = c.opt.Provider
	}
	if body.Pins == nil {
		body.Pins = []PinnedDefinition{}
	}
	var out DefinitionsResult
	if err := c.call(ctx, call{op: "publishDefinitions", method: "PUT", path: "/v1/definitions", body: &body,
		retry: retryAny}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RegisterChange registers (or re-evaluates) a change; the caller is a verifier. Registering is idempotent, so it
// is retried as an evaluation is.
func (c *Client) RegisterChange(ctx context.Context, req *ChangeRequest) (*Change, error) {
	var out Change
	if err := c.call(ctx, call{op: "registerChange", method: "POST", path: "/v1/clearances", body: req,
		retry: retryAny}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Clear approves a holding change as the caller, or as onBehalfOf when the caller is a delegate ("" = itself).
func (c *Client) Clear(ctx context.Context, changeID, onBehalfOf string) (*Decided, error) {
	var out Decided
	if err := c.call(ctx, call{op: "clearChange", method: "POST",
		path: "/v1/clearances/" + url.PathEscape(changeID) + "/clear", body: struct{}{}, onBehalfOf: onBehalfOf,
		retry: retryUnsent}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Deny denies a holding change with a reason.
func (c *Client) Deny(ctx context.Context, changeID, reason, onBehalfOf string) (*Decided, error) {
	var out Decided
	if err := c.call(ctx, call{op: "denyChange", method: "POST",
		path: "/v1/clearances/" + url.PathEscape(changeID) + "/deny", body: map[string]string{"reason": reason},
		onBehalfOf: onBehalfOf, retry: retryUnsent}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Provenance asks for a pull request's agent-identity and agent-scope verdicts; the caller is a verifier.
func (c *Client) Provenance(ctx context.Context, req *ProvenanceRequest) (*Verdict, error) {
	var out Verdict
	if err := c.call(ctx, call{op: "verifyProvenance", method: "POST", path: "/v1/provenance", body: req,
		retry: retryAny}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Clearance is a change's state and its live clearance token (Token nil when it has none). The caller is a
// registered provider or the verifier that registered the change. A read: retried as an evaluation is.
func (c *Client) Clearance(ctx context.Context, changeID string) (*ClearanceAnswer, error) {
	var out ClearanceAnswer
	if err := c.call(ctx, call{op: "getClearance", method: "GET", path: "/v1/clearances/" + url.PathEscape(changeID),
		retry: retryAny}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Keys is the clearance token verification keys (GET /v1/keys, a JWKS): what a verifier checks tokens with
// offline.
func (c *Client) Keys(ctx context.Context) (*JWKS, error) {
	var out JWKS
	if err := c.call(ctx, call{op: "getKeys", method: "GET", path: "/v1/keys", retry: retryAny}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Healthz is GET /healthz. Probes bypass the breaker and do not move it.
func (c *Client) Healthz(ctx context.Context) (*Health, error) {
	var out Health
	if err := c.call(ctx, call{op: "healthz", method: "GET", path: "/healthz", retry: retryAny, probe: true},
		&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Readyz is GET /readyz; a not-ready core (503) is ErrCoreUnavailable. Bypasses the breaker.
func (c *Client) Readyz(ctx context.Context) (*Ready, error) {
	var out Ready
	if err := c.call(ctx, call{op: "readyz", method: "GET", path: "/readyz", retry: retryAny, probe: true},
		&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// -- transport -----------------------------------------------------------------------------------------------------

type retryClass int

const (
	// retryAny: connection failures, timeouts and 502/503/504 (the call is safe to repeat).
	retryAny retryClass = iota
	// retryUnsent: only a failed dial (nothing was sent) and a 503 (the core said it did not act).
	retryUnsent
)

type call struct {
	op, method, path string
	body             any
	onBehalfOf       string
	retry            retryClass
	probe            bool // a health probe: no breaker
}

// attemptResult is one attempt's outcome: err is final unless unavailable is set.
type attemptResult struct {
	err         error
	unavailable *UnavailableError
	retryable   bool
	unsent      bool // err came before anything was sent
}

func (c *Client) call(ctx context.Context, cl call, out any) error {
	var payload []byte
	if cl.body != nil {
		var err error
		if payload, err = json.Marshal(cl.body); err != nil {
			return fmt.Errorf("clearance client: encoding the %s request: %w", cl.op, err)
		}
	}
	probe := false
	if !cl.probe {
		ok, isProbe := c.breaker.allow()
		if !ok {
			return &UnavailableError{Op: cl.op, Reason: ReasonBreakerOpen}
		}
		probe = isProbe
	}
	var last *UnavailableError
	for attempt := 1; attempt <= 1+c.opt.Retries; attempt++ {
		res := c.attempt(ctx, cl, payload, out)
		if res.unavailable != nil && ctx.Err() != nil {
			// The caller's context ended: no verdict on the core.
			c.breaker.cancel(probe)
			return fmt.Errorf("clearance client: %s: %w", cl.op, ctx.Err())
		}
		if res.unsent {
			// Nothing was sent (no token, a bad request): no verdict on the core either.
			c.breaker.cancel(probe)
			return res.err
		}
		if res.unavailable == nil {
			if !cl.probe {
				c.breaker.done(probe, false)
			}
			return res.err
		}
		res.unavailable.Attempts = attempt
		last = res.unavailable
		if !res.retryable {
			break
		}
	}
	if !cl.probe {
		c.breaker.done(probe, true)
	}
	return last
}

func (c *Client) attempt(ctx context.Context, cl call, payload []byte, out any) attemptResult {
	actx, cancel := context.WithTimeout(ctx, c.opt.Timeout)
	defer cancel()
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(actx, cl.method, c.base+cl.path, rd)
	if err != nil {
		return attemptResult{err: fmt.Errorf("clearance client: %s: %w", cl.op, err), unsent: true}
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.opt.UserAgent)
	if cl.onBehalfOf != "" {
		req.Header.Set(c.opt.OnBehalfOfHeader, cl.onBehalfOf)
	}
	if c.opt.Token != nil {
		tok, err := c.opt.Token.Token(ctx)
		if err == nil {
			err = validToken(tok)
		}
		if err != nil {
			return attemptResult{err: fmt.Errorf("%w: %s: %v", ErrToken, cl.op, err), unsent: true}
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		u := &UnavailableError{Op: cl.op, Reason: ReasonConnection, Err: err}
		if isTimeout(err) {
			u.Reason = ReasonTimeout
		}
		return attemptResult{unavailable: u, retryable: cl.retry == retryAny || isDialError(err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.opt.MaxResponseBytes+1))
	if err != nil {
		// The answer did not arrive whole: the core may have acted, so this is retried only as a timeout is.
		u := &UnavailableError{Op: cl.op, Reason: ReasonConnection, Err: err}
		if isTimeout(err) {
			u.Reason = ReasonTimeout
		}
		return attemptResult{unavailable: u, retryable: cl.retry == retryAny}
	}
	if int64(len(raw)) > c.opt.MaxResponseBytes {
		return attemptResult{err: &ResponseError{Op: cl.op, Status: resp.StatusCode,
			Err: fmt.Errorf("the body is over %d bytes", c.opt.MaxResponseBytes)}}
	}
	switch s := resp.StatusCode; {
	case s == http.StatusOK:
		if err := c.decode(raw, out); err != nil {
			return attemptResult{err: &ResponseError{Op: cl.op, Status: s, Err: err}}
		}
		return attemptResult{}
	case s >= 400 && s < 500:
		var eb errorBody
		msg := http.StatusText(s)
		if json.Unmarshal(raw, &eb) == nil && eb.Error != "" {
			msg = eb.Error
		}
		return attemptResult{err: &APIError{Op: cl.op, Status: s, Message: msg, Rule: eb.Rule, Hint: eb.Hint}}
	case s >= 500:
		retry := s == http.StatusServiceUnavailable ||
			(cl.retry == retryAny && (s == http.StatusBadGateway || s == http.StatusGatewayTimeout))
		var eb errorBody
		var cause error
		if json.Unmarshal(raw, &eb) == nil && eb.Error != "" {
			cause = errors.New(eb.Error)
		}
		return attemptResult{unavailable: &UnavailableError{Op: cl.op, Reason: ReasonServerError, Status: s,
			Err: cause}, retryable: retry}
	default:
		return attemptResult{err: &ResponseError{Op: cl.op, Status: s, Err: errors.New("unexpected status")}}
	}
}

// decode decodes exactly one JSON value into out, strictly unless AllowUnknownFields.
func (c *Client) decode(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if !c.opt.AllowUnknownFields {
		dec.DisallowUnknownFields()
	}
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isDialError is a failure to connect: the request was never sent.
func isDialError(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "dial"
}
