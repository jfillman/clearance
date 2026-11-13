package personcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Exit codes. coverage has its own meaning for 2 and 3 (degraded, blind or unavailable).
const (
	ExitOK           = 0
	ExitError        = 1
	ExitUsage        = 2
	ExitUnauthorized = 4 // 401: not signed in, or the token expired
	ExitForbidden    = 5 // 403
	ExitNotFound     = 6 // 404
	ExitUnavailable  = 7 // the api could not be reached, or answered 5xx
)

// Client calls clearance-api with the person's own bearer token.
type Client struct {
	Base      string
	Token     string
	HTTP      *http.Client
	UserAgent string
}

// APIError is a non-2xx answer.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message) }

// NetError is a request that got no answer.
type NetError struct{ Err error }

func (e *NetError) Error() string { return e.Err.Error() }
func (e *NetError) Unwrap() error { return e.Err }

// NewHTTP is the client's transport settings: a deadline, and no redirects (a redirect could carry the token to
// another host or down to http).
func NewHTTP(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *Client) request(ctx context.Context, path string, q url.Values, stream bool) (*http.Response, error) {
	u := c.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("User-Agent", c.UserAgent)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// url.Error repeats the URL (no token in it); keep only the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, &NetError{err}
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var body struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(b))
		if json.Unmarshal(b, &body) == nil && body.Error != "" {
			msg = body.Error
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, &APIError{resp.StatusCode, msg}
	}
	return resp, nil
}

// Get reads a JSON answer into out (a *json.RawMessage keeps it verbatim).
func (c *Client) Get(ctx context.Context, path string, q url.Values, out any) error {
	resp, err := c.request(ctx, path, q, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return &NetError{err}
	}
	return json.Unmarshal(b, out)
}

// Stream opens an event stream; the caller closes the body.
func (c *Client) Stream(ctx context.Context, path string, q url.Values, lastID string) (io.ReadCloser, error) {
	u := c.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "text/event-stream")
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, &NetError{err}
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var body struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &body)
		return nil, &APIError{resp.StatusCode, body.Error}
	}
	return resp.Body, nil
}

// exitError is a failure with the exit code and message a command ends with.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func fail(code int, f string, a ...any) *exitError { return &exitError{code, fmt.Sprintf(f, a...)} }

// mapError turns an API or network error into the message and exit code a person should see.
func mapError(err error) *exitError {
	var ee *exitError
	if errors.As(err, &ee) {
		return ee
	}
	var ae *APIError
	if errors.As(err, &ae) {
		switch {
		case ae.Status == 401:
			return fail(ExitUnauthorized, "not signed in, or the token was refused: run `clearance login`")
		case ae.Status == 403:
			return fail(ExitForbidden, "forbidden: %s", ae.Message)
		case ae.Status == 404:
			return fail(ExitNotFound, "not found: %s", ae.Message)
		case ae.Status == 429:
			return fail(ExitUnavailable, "rate limited by clearance-api (HTTP 429); retry shortly")
		case ae.Status >= 500:
			return fail(ExitUnavailable, "clearance-api is unavailable (HTTP %d: %s)", ae.Status, ae.Message)
		}
		return fail(ExitError, "request refused (HTTP %d): %s", ae.Status, ae.Message)
	}
	var ne *NetError
	if errors.As(err, &ne) {
		return fail(ExitUnavailable, "cannot reach clearance-api: %v", ne.Err)
	}
	return fail(ExitError, "%v", err)
}

// isMissingRoute is a 404 from the router (this api does not have the route), as opposed to a 404 about a change.
func isMissingRoute(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == 404 && ae.Message == "not found"
}
