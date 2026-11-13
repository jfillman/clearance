// Package web is `clearance web`: the backend-for-frontend of the standalone web UI (docs/web.md). It serves the UI
// bundle, signs a person in at the people IdP (OIDC authorization code with PKCE), keeps the session in memory, and
// forwards the page's calls to clearance-api, the core and the agent gateway with the person's own ID token as
// the bearer. It decides nothing: every 401, 403 and refusal is Clearance's, passed through.
package web

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the server's settings (env CLEARANCE_WEB_*; the flags of `clearance web` override).
type Config struct {
	Listen           string        // CLEARANCE_WEB_LISTEN, default :8080
	PublicURL        string        // CLEARANCE_WEB_PUBLIC_URL: the origin people use; the redirect URI is under it
	Issuer           string        // CLEARANCE_WEB_ISSUER: the people IdP
	ClientID         string        // CLEARANCE_WEB_CLIENT_ID
	ClientSecretFile string        // CLEARANCE_WEB_CLIENT_SECRET_FILE: a file holding the confidential client's secret
	APIURL           string        // CLEARANCE_WEB_API_URL: clearance-api (reads)
	CoreURL          string        // CLEARANCE_WEB_CORE_URL: the core (writes)
	GatewayURL       string        // CLEARANCE_WEB_GATEWAY_URL: the agent gateway's person controls (optional)
	SessionTTL       time.Duration // CLEARANCE_WEB_SESSION_TTL: at most MaxSessionTTL
	IdleTimeout      time.Duration // CLEARANCE_WEB_IDLE_TIMEOUT
	MaxSessions      int           // CLEARANCE_WEB_MAX_SESSIONS
	FreshMaxAge      time.Duration // CLEARANCE_WEB_FRESH_MAX_AGE: max_age asked of the IdP when the core wants a fresh login
	MaxBodyBytes     int64         // CLEARANCE_WEB_MAX_BODY_BYTES: request body limit
	MaxResponseBytes int64         // CLEARANCE_WEB_MAX_RESPONSE_BYTES: non-stream answer limit
	RequestTimeout   time.Duration // CLEARANCE_WEB_REQUEST_TIMEOUT: deadline of a non-stream forwarded call
	TLSCertFile      string        // CLEARANCE_WEB_TLS_CERT: serve TLS here (else a gateway terminates it)
	TLSKeyFile       string        // CLEARANCE_WEB_TLS_KEY
}

// MaxSessionTTL is the longest a session may live, whatever the ID token's exp says (the CLI's rule).
const MaxSessionTTL = time.Hour

// FromEnv reads the settings from getenv and applies defaults.
func FromEnv(getenv func(string) string) (Config, error) {
	c := Config{
		Listen: getenv("CLEARANCE_WEB_LISTEN"), PublicURL: getenv("CLEARANCE_WEB_PUBLIC_URL"),
		Issuer: getenv("CLEARANCE_WEB_ISSUER"), ClientID: getenv("CLEARANCE_WEB_CLIENT_ID"),
		ClientSecretFile: getenv("CLEARANCE_WEB_CLIENT_SECRET_FILE"),
		APIURL:           getenv("CLEARANCE_WEB_API_URL"), CoreURL: getenv("CLEARANCE_WEB_CORE_URL"),
		GatewayURL:  getenv("CLEARANCE_WEB_GATEWAY_URL"),
		TLSCertFile: getenv("CLEARANCE_WEB_TLS_CERT"), TLSKeyFile: getenv("CLEARANCE_WEB_TLS_KEY"),
	}
	var errs []error
	dur := func(dst *time.Duration, name string) {
		if v := getenv(name); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %v", name, err))
			}
			*dst = d
		}
	}
	num := func(dst *int64, name string) {
		if v := getenv(name); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %v", name, err))
			}
			*dst = n
		}
	}
	dur(&c.SessionTTL, "CLEARANCE_WEB_SESSION_TTL")
	dur(&c.IdleTimeout, "CLEARANCE_WEB_IDLE_TIMEOUT")
	dur(&c.FreshMaxAge, "CLEARANCE_WEB_FRESH_MAX_AGE")
	dur(&c.RequestTimeout, "CLEARANCE_WEB_REQUEST_TIMEOUT")
	var ms int64
	num(&ms, "CLEARANCE_WEB_MAX_SESSIONS")
	c.MaxSessions = int(ms)
	num(&c.MaxBodyBytes, "CLEARANCE_WEB_MAX_BODY_BYTES")
	num(&c.MaxResponseBytes, "CLEARANCE_WEB_MAX_RESPONSE_BYTES")
	if err := errors.Join(errs...); err != nil {
		return c, err
	}
	return c, nil
}

// withDefaults fills what is unset.
func (c Config) withDefaults() Config {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.SessionTTL <= 0 || c.SessionTTL > MaxSessionTTL {
		c.SessionTTL = MaxSessionTTL
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 15 * time.Minute
	}
	if c.MaxSessions <= 0 {
		c.MaxSessions = 10000
	}
	if c.FreshMaxAge <= 0 {
		c.FreshMaxAge = 5 * time.Minute
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 1 << 20
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = 32 << 20
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 60 * time.Second
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	c.Issuer = strings.TrimRight(c.Issuer, "/")
	c.APIURL = strings.TrimRight(c.APIURL, "/")
	c.CoreURL = strings.TrimRight(c.CoreURL, "/")
	c.GatewayURL = strings.TrimRight(c.GatewayURL, "/")
	return c
}

// Validate refuses a configuration that cannot run safely.
func (c Config) Validate() error {
	var errs []error
	need := func(v, name string) {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	need(c.PublicURL, "CLEARANCE_WEB_PUBLIC_URL (--public-url)")
	need(c.Issuer, "CLEARANCE_WEB_ISSUER (--issuer)")
	need(c.ClientID, "CLEARANCE_WEB_CLIENT_ID (--client-id)")
	need(c.ClientSecretFile, "CLEARANCE_WEB_CLIENT_SECRET_FILE (--client-secret-file)")
	need(c.APIURL, "CLEARANCE_WEB_API_URL (--api-url)")
	need(c.CoreURL, "CLEARANCE_WEB_CORE_URL (--core-url)")
	for _, e := range []struct {
		name, u  string
		internal bool
	}{{"public URL", c.PublicURL, false}, {"issuer", c.Issuer, false}, {"API URL", c.APIURL, true},
		{"core URL", c.CoreURL, true}, {"gateway URL", c.GatewayURL, true}} {
		if e.u == "" {
			continue
		}
		if err := checkURL(e.u, e.internal); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", e.name, err))
		}
	}
	if c.PublicURL != "" {
		if u, err := url.Parse(c.PublicURL); err == nil && (u.Path != "" && u.Path != "/") {
			errs = append(errs, errors.New("public URL must be an origin (no path): the cookie is Path=/"))
		}
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New("set both CLEARANCE_WEB_TLS_CERT and CLEARANCE_WEB_TLS_KEY, or neither"))
	}
	return errors.Join(errs...)
}

// checkURL accepts an https URL with a host, or an http one for localhost only (anywhere when internal: the
// in-cluster Services the server forwards to), with no credentials, query or fragment.
func checkURL(s string, internal bool) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q must be an http(s) URL with a host and no credentials, query or fragment", s)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if internal {
			return nil
		}
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
		return fmt.Errorf("%q: plain http is for localhost only; use https", s)
	}
	return fmt.Errorf("%q must be an http(s) URL", s)
}

// readSecretFile reads the client secret from path (never from the environment or a flag value). One line, trimmed.
func readSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("client secret file: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("client secret file is empty")
	}
	return s, nil
}
