package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
)

// maxBody caps what the agent reads from clearance-api (a feed lists at most 2000 tokens).
const maxBody = 32 << 20

// HTTPFeeds reads clearance-api as the agent's own identity: a bearer token read fresh for every request (the
// projected service-account token, audience clearance), nothing cached or written.
type HTTPFeeds struct {
	Base  string // clearance-api's URL
	Token client.TokenSource
	HTTP  *http.Client
}

func (f *HTTPFeeds) get(ctx context.Context, base, path string) ([]byte, error) {
	tok, err := f.Token.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the service-account token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(base, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "clearance-argocd-agent")
	hc := f.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("GET %s: the answer is over %d bytes", path, maxBody)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %d %s", path, resp.StatusCode, truncate(string(b), 200))
	}
	return b, nil
}

// Keys is GET /v1/keys.
func (f *HTTPFeeds) Keys(ctx context.Context) ([]byte, error) { return f.get(ctx, f.Base, "/v1/keys") }

// Feed is GET /v1/grant-feeds/{cluster}.
func (f *HTTPFeeds) Feed(ctx context.Context, cluster string) ([]byte, error) {
	return f.get(ctx, f.Base, "/v1/grant-feeds/"+url.PathEscape(cluster))
}

// HTTPCore is the core: records through the Go client (POST /v1/records, retried only when nothing was sent), and
// the open break-glass windows (GET /v1/breakglass).
type HTTPCore struct {
	*client.Client
	Feeds HTTPFeeds // Base is the core's URL here
}

// Breakglass is GET /v1/breakglass?cluster=.
func (c *HTTPCore) Breakglass(ctx context.Context, cluster string) ([]Window, error) {
	b, err := c.Feeds.get(ctx, c.Feeds.Base, "/v1/breakglass?cluster="+url.QueryEscape(cluster))
	if err != nil {
		return nil, err
	}
	var l struct {
		Items []Window `json:"items"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	return l.Items, nil
}
