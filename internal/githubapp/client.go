package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jfillman/clearance/internal/pycompat"
)

// client is github_app's _call: GitHub's REST API with a deadline on every call. Redirects are followed only on
// the API's own host, so a token never leaves it.
type client struct {
	base    string
	host    string
	timeout time.Duration
	http    *http.Client
}

func newClient(base string, timeout time.Duration) *client {
	host := ""
	if u, err := url.Parse(base); err == nil {
		host = u.Host
	}
	c := &client{base: base, host: host, timeout: timeout}
	c.http = &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != c.host || len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	return c
}

// call returns the status and the decoded JSON body ({} when there is none or it is not JSON). A transport
// failure is an *Error naming only its kind.
func (c *client) call(ctx context.Context, method, path, scheme, token string, body any) (int, any, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", scheme+" "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "clearance-github-app")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		kind := "error"
		if errors.As(err, &ue) && ue.Timeout() {
			kind = "timeout"
		}
		return 0, nil, gherr("GitHub unreachable: %s", kind)
	}
	defer res.Body.Close()
	limit := int64(8 << 20)
	if res.StatusCode >= 400 {
		limit = 64 << 10
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit))
	if err != nil {
		return 0, nil, gherr("GitHub unreachable: read")
	}
	if len(raw) == 0 {
		return res.StatusCode, map[string]any{}, nil
	}
	v, err := pycompat.Decode(bytes.NewReader(raw))
	if err != nil {
		return res.StatusCode, map[string]any{}, nil
	}
	return res.StatusCode, v, nil
}

func decodeObject(b []byte) (map[string]any, error) {
	v, err := pycompat.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not a JSON object")
	}
	return m, nil
}

func asInt(v any) (int64, bool) { return pycompat.AsInt(v) }

func jsonNumber(s string) any { return json.Number(s) }

func pyStr(v any) string { return pycompat.Str(v) }

func truncate(s string, n int) string { return pycompat.Truncate(s, n) }
