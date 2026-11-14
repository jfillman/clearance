package grc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Vanta is the Vanta target. It was written against Vanta's public developer documentation (docs/grc-push.md lists
// each page and what is assumed), and has not been run against a real tenant.
//
//	auth:  POST {base}/oauth/token, JSON {client_id, client_secret, scope, grant_type: client_credentials}
//	       -> {access_token, expires_in}; one token per application, valid an hour.
//	sync:  PUT {base}/v1/resources/custom_resource, Authorization: Bearer <token>,
//	       JSON {resourceId, resources: [{displayName, uniqueId, externalUrl, customProperties}]}; the set is
//	       the whole current state of that resource (what is missing is deleted in Vanta).
type Vanta struct {
	// Base is the API origin ("https://api.vanta.com"): from configuration only, https (http on loopback in tests).
	Base     string
	ClientID string
	// SecretFile is read when a token is minted (never cached, never logged). There is no plaintext fallback.
	SecretFile string
	// EvidenceResourceID and ReportResourceID are the ids of the two custom resources defined in Vanta's developer
	// console. The report is off when its id is empty.
	EvidenceResourceID, ReportResourceID string
	HTTP                                 *http.Client
	Now                                  func() time.Time

	mu    sync.Mutex
	token string
	exp   time.Time
	// reqMu serialises requests, so the evidence and report loops share one token without minting over each other
	// (Vanta keeps one token per application). A retry's wait is outside it.
	reqMu sync.Mutex
}

// VantaScope is the scope a token asks for: write its own resources, nothing else.
const VantaScope = "connectors.self:write-resource"

// VantaOption changes how a Vanta target is built.
type VantaOption func(*vantaOpts)

type vantaOpts struct {
	loopback bool
	client   *http.Client
}

// InsecureLoopbackForTest lets the hub URL be http on a loopback host, for a fake in a test. It is an option of the
// constructor, not a setting: nothing in the environment or a config file reaches it.
func InsecureLoopbackForTest() VantaOption { return func(o *vantaOpts) { o.loopback = true } }

// WithHTTPClient replaces the default client (no proxy, no redirects, 30 second timeout).
func WithHTTPClient(c *http.Client) VantaOption { return func(o *vantaOpts) { o.client = c } }

// NewHTTPClient is the client every outbound call uses: it never follows a redirect (a token and a payload go to the
// configured host only), and it ignores the environment's proxy settings unless useProxy is set.
func NewHTTPClient(useProxy bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if !useProxy {
		tr.Proxy = nil
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// NewVanta checks the URL (https; nothing else unless InsecureLoopbackForTest) and returns the target.
func NewVanta(base, clientID, secretFile, evidenceRes, reportRes string, opts ...VantaOption) (*Vanta, error) {
	var o vantaOpts
	for _, f := range opts {
		f(&o)
	}
	base = strings.TrimRight(base, "/")
	if err := CheckURL(base, "CLEARANCE_GRC_VANTA_BASE_URL", o.loopback); err != nil {
		return nil, err
	}
	if o.client == nil {
		o.client = NewHTTPClient(false)
	}
	return &Vanta{Base: base, ClientID: clientID, SecretFile: secretFile,
		EvidenceResourceID: evidenceRes, ReportResourceID: reportRes, HTTP: o.client, Now: time.Now}, nil
}

// CheckURL is the outbound-URL rule: an absolute https URL with a host and no credentials, query or fragment; http
// only for a loopback host when allowLoopback (tests and a local fake).
func CheckURL(raw, name string, allowLoopback bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s is an absolute URL with a host and no credentials, query or fragment", name)
	}
	if u.Scheme == "https" || (allowLoopback && u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil
	}
	return fmt.Errorf("%s is an https URL", name)
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

func (v *Vanta) Name() string { return "vanta" }

// ReportEnabled is true when a report resource is configured.
func (v *Vanta) ReportEnabled() bool { return v.ReportResourceID != "" }

func (v *Vanta) err(class string, status int, retry bool) *Error {
	return &Error{Target: "vanta", Class: class, Status: status, Retryable: retry}
}

func (v *Vanta) secret() string {
	b, err := os.ReadFile(v.SecretFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// bearer returns a live token, minting one when there is none (one per sync run: Vanta limits /oauth/token and a new
// token invalidates the last). The token is held in memory only.
func (v *Vanta) bearer(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.token != "" && v.Now().Before(v.exp.Add(-time.Minute)) {
		return v.token, nil
	}
	sec := v.secret()
	if v.ClientID == "" || sec == "" {
		return "", v.err("config", 0, false)
	}
	body, _ := json.Marshal(map[string]string{"client_id": v.ClientID, "client_secret": sec, "scope": VantaScope, "grant_type": "client_credentials"})
	resp, raw, err := v.do(ctx, http.MethodPost, "/oauth/token", body, "")
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", v.statusErr(resp, true)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal(raw, &out) != nil || out.AccessToken == "" {
		return "", v.err("bad-response", resp.StatusCode, false)
	}
	if out.ExpiresIn <= 0 {
		out.ExpiresIn = 3600
	}
	v.token, v.exp = out.AccessToken, v.Now().Add(time.Duration(out.ExpiresIn)*time.Second)
	return v.token, nil
}

func (v *Vanta) forget() { v.mu.Lock(); v.token = ""; v.mu.Unlock() }

// do sends one request and reads at most MaxResponse of the answer.
func (v *Vanta) do(ctx context.Context, method, path string, body []byte, token string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, v.Base+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, v.err("config", 0, false)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "clearance-grc")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := v.HTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, v.err("network", 0, true) // the transport's text can carry the URL: not kept
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse))
	if err != nil {
		return nil, nil, v.err("network", resp.StatusCode, true)
	}
	return resp, raw, nil
}

// statusErr classifies a non-200 answer. authCall: a 4xx from the token endpoint is a credential problem.
func (v *Vanta) statusErr(resp *http.Response, authCall bool) *Error {
	st := resp.StatusCode
	switch {
	case st == http.StatusTooManyRequests:
		e := v.err("rate-limited", st, true)
		e.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), v.Now())
		return e
	case st >= 500:
		return v.err("unavailable", st, true)
	case st == http.StatusUnauthorized || st == http.StatusForbidden || (authCall && st/100 == 4):
		return v.err("auth", st, false)
	default:
		return v.err("rejected", st, false)
	}
}

func parseRetryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if n, err := strconv.Atoi(h); err == nil && n >= 0 {
		if n > 86400 { // a day: more would overflow the duration, and the caller caps the wait far lower
			n = 86400
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

func (v *Vanta) PushEvidence(ctx context.Context, items []Item) error {
	return v.sync(ctx, v.EvidenceResourceID, items)
}

func (v *Vanta) PushReport(ctx context.Context, items []Item) error {
	if v.ReportResourceID == "" {
		return ErrNoReport
	}
	return v.sync(ctx, v.ReportResourceID, items)
}

type vantaResource struct {
	DisplayName      string         `json:"displayName"`
	UniqueID         string         `json:"uniqueId"`
	ExternalURL      string         `json:"externalUrl"`
	CustomProperties map[string]any `json:"customProperties"`
}

func (v *Vanta) sync(ctx context.Context, resourceID string, items []Item) error {
	if resourceID == "" {
		return v.err("config", 0, false)
	}
	res := make([]vantaResource, 0, len(items))
	for _, it := range items {
		props := make(map[string]any, len(it.Props))
		for k, val := range it.Props {
			if t, ok := val.(time.Time); ok {
				val = t.UTC().Format(time.RFC3339)
			}
			props[k] = val
		}
		res = append(res, vantaResource{DisplayName: it.Title, UniqueID: it.ID, ExternalURL: it.Link, CustomProperties: props})
	}
	body, err := json.Marshal(map[string]any{"resourceId": resourceID, "resources": res})
	if err != nil {
		return v.err("config", 0, false)
	}
	v.reqMu.Lock()
	defer v.reqMu.Unlock()
	for attempt := 0; ; attempt++ {
		tok, err := v.bearer(ctx)
		if err != nil {
			return err
		}
		resp, raw, err := v.do(ctx, http.MethodPut, "/v1/resources/custom_resource", body, tok)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			v.forget() // the token was revoked (a new one replaces the last): mint once and go again
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return v.statusErr(resp, false)
		}
		var out struct {
			Success *bool `json:"success"`
		}
		if json.Unmarshal(raw, &out) != nil || out.Success == nil {
			return v.err("bad-response", resp.StatusCode, false)
		}
		if !*out.Success {
			return v.err("rejected", resp.StatusCode, false)
		}
		return nil
	}
}
