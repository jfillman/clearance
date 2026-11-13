package slack

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/gate"
)

// Client talks to clearance-api (reads) and the core (writes) as this service's own principal: its projected
// service-account token, read from the file on every call (never cached), and, for what a person may see or do, the
// on-behalf-of header naming the linked person. The person is always the IdP-verified principal from the link.
type Client struct {
	API, Core       string
	TokenFile       string
	OnBehalfHeader  string
	HTTP            *http.Client
	UserAgent       string
	ForwardAuthTime bool
}

// CallError is a non-2xx answer from the api or the core, with the gate's refusal fields.
type CallError struct {
	Status              int
	Message, Rule, Hint string
	MaxAge, Age         string
	Core                bool // the core answered (a write), not clearance-api
}

func (e *CallError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message) }

func (c *Client) token() (string, error) {
	b, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return "", errors.New("cannot read the service-account token file")
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", errors.New("the service-account token file is empty")
	}
	return t, nil
}

func (c *Client) do(ctx context.Context, method, base, path string, q url.Values, body any, person string, hdr map[string]string, stream bool, lastID string) (*http.Response, error) {
	tok, err := c.token()
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", c.UserAgent)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
		if lastID != "" {
			req.Header.Set("Last-Event-ID", lastID)
		}
	} else {
		req.Header.Set("Accept", "application/json")
	}
	if person != "" {
		req.Header.Set(c.OnBehalfHeader, person)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("cannot reach %s: %w", base, err)
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var e struct {
			Error  string `json:"error"`
			Rule   string `json:"rule"`
			Hint   string `json:"hint"`
			MaxAge string `json:"max_age"`
			Age    string `json:"age"`
		}
		msg := strings.TrimSpace(string(b))
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, &CallError{Status: resp.StatusCode, Message: msg, Rule: e.Rule, Hint: e.Hint, MaxAge: e.MaxAge, Age: e.Age, Core: base == c.Core}
	}
	return resp, nil
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, person string, out any) error {
	resp, err := c.do(ctx, "GET", c.API, path, q, nil, person, nil, false, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// WhoAmI is what the api says of the person: groups and whether they are an admin.
type WhoAmI struct {
	Principal string   `json:"principal"`
	Person    string   `json:"person"`
	Admin     bool     `json:"admin"`
	Groups    []string `json:"groups"`
}

// Person asks who person (a principal the service names) is, as that person's viewer: their groups and admin flag.
func (c *Client) Person(ctx context.Context, person string) (WhoAmI, error) {
	var w WhoAmI
	return w, c.getJSON(ctx, "/v1/whoami", nil, person, &w)
}

type changePage struct {
	Items []json.RawMessage `json:"items"`
	Next  *string           `json:"next"`
}

func decodeChanges(raws []json.RawMessage) []gate.Change {
	var out []gate.Change
	for _, r := range raws {
		if c, err := gate.FromRecord(r); err == nil {
			out = append(out, *c)
		}
	}
	return out
}

// Changes lists the gate's changes (as the notifier: every one) matching q, following the cursor up to max.
func (c *Client) Changes(ctx context.Context, q url.Values, max int) ([]gate.Change, error) {
	var out []gate.Change
	q = cloneValues(q)
	q.Set("limit", "200")
	for len(out) < max {
		var p changePage
		if err := c.getJSON(ctx, "/v1/clearances", q, "", &p); err != nil {
			return out, err
		}
		out = append(out, decodeChanges(p.Items)...)
		if p.Next == nil || len(p.Items) == 0 {
			break
		}
		q.Set("after", *p.Next)
	}
	return out, nil
}

func cloneValues(q url.Values) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// Change reads one change as person sees it (the delegate path: GET /v1/clearances/{id}).
func (c *Client) Change(ctx context.Context, id, person string) (*gate.Change, error) {
	var raw json.RawMessage
	if err := c.getJSON(ctx, "/v1/clearances/"+url.PathEscape(id), nil, person, &raw); err != nil {
		return nil, err
	}
	return gate.FromRecord(raw)
}

// Count is one group of a counts answer.
type Count struct {
	Key   *string `json:"key"`
	Count int64   `json:"count"`
}

// Counts reads GET /v1/clearances/counts.
func (c *Client) Counts(ctx context.Context, q url.Values) ([]Count, error) {
	var out struct {
		Items []Count `json:"items"`
	}
	return out.Items, c.getJSON(ctx, "/v1/clearances/counts", q, "", &out)
}

// Record is an evidence record as the exceptions read serves it (a few fields are used).
type Record map[string]any

func (r Record) str(k string) string { s, _ := r[k].(string); return s }
func (r Record) seq() int64 {
	switch n := r["seq"].(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}

// Exceptions reads the newest page of exceptions (newest first).
func (c *Client) Exceptions(ctx context.Context, limit int) ([]Record, error) {
	var out struct {
		Items []Record `json:"items"`
	}
	return out.Items, c.getJSON(ctx, "/v1/exceptions", url.Values{"limit": {fmt.Sprint(limit)}}, "", &out)
}

// SourceHealth and ScopeStatement are the parts of a coverage statement the alerts read.
type SourceHealth struct {
	Source string `json:"source"`
	State  string `json:"state"` // the worst in the window: not what alerts use
	Now    string `json:"now"`   // the state at the window's end: what they use
	Stale  bool   `json:"stale"`
}

// ScopeStatement is one scope of GET /v1/coverage.
type ScopeStatement struct {
	Scope  string `json:"scope"`
	Health struct {
		Sources []SourceHealth `json:"sources"`
	} `json:"health"`
}

// Coverage reads every scope's statement for the window.
func (c *Client) Coverage(ctx context.Context, from, to time.Time) ([]ScopeStatement, bool, error) {
	var out struct {
		Scopes    []ScopeStatement `json:"scopes"`
		Truncated bool             `json:"truncated"`
	}
	q := url.Values{"from": {from.UTC().Format(time.RFC3339)}, "to": {to.UTC().Format(time.RFC3339)}}
	err := c.getJSON(ctx, "/v1/coverage", q, "", &out)
	return out.Scopes, out.Truncated, err
}

// WriteHeaders are what a person's write from Slack carries: the surface and, when it can be proven, the sign-in
// time. The on-behalf-of header is added by the call.
func (c *Client) WriteHeaders(permalink string, l *Link) map[string]string {
	h := map[string]string{"X-Clearance-Via": "slack", "X-Clearance-Surface-Ref": SurfaceRef(permalink)}
	if c.ForwardAuthTime && l != nil && l.AuthTime > 0 {
		h["X-Clearance-Auth-Time"] = fmt.Sprint(l.AuthTime)
	}
	return h
}

// SurfaceRef is the permalink as the core stores it: printable text of at most 512 bytes.
func SurfaceRef(p string) string {
	p = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, p)
	if len(p) > 512 {
		p = p[:512]
	}
	return p
}

// Post sends a person's write to the core, as the service, naming the person.
func (c *Client) Post(ctx context.Context, path string, body any, person string, hdr map[string]string, out any) error {
	resp, err := c.do(ctx, "POST", c.Core, path, nil, body, person, hdr, false, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

// SSEEvent is one server-sent event.
type SSEEvent struct {
	ID, Event, Data string
}

// OpenStream opens GET /v1/stream?types=clearances, resuming after lastID when set.
func (c *Client) OpenStream(ctx context.Context, lastID string) (io.ReadCloser, error) {
	resp, err := c.do(ctx, "GET", c.API, "/v1/stream", url.Values{"types": {"clearances"}}, nil, "", nil, true, lastID)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// ReadSSE parses a stream, calling fn for each event with data. Comments (the keepalive) are skipped. It returns
// when the stream ends (nil) or fn or the read fails.
func ReadSSE(r io.Reader, fn func(SSEEvent) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var ev SSEEvent
	var data []string
	flush := func() error {
		if len(data) == 0 && ev.Event == "" {
			ev = SSEEvent{}
			return nil
		}
		ev.Data = strings.Join(data, "\n")
		e := ev
		ev, data = SSEEvent{}, nil
		return fn(e)
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if err := flush(); err != nil {
				return err
			}
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "id:"):
			ev.ID = strings.TrimSpace(line[3:])
		case strings.HasPrefix(line, "event:"):
			ev.Event = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(line[5:], " "))
		}
	}
	return sc.Err()
}
