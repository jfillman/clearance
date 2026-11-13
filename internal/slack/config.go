// Package slack is clearance-slack: Clearance's Slack surface. A standalone service (cmd/clearance-slack) that is a
// delegate and a notifier/observer principal of the core and clearance-api, never a signer and never a store of
// evidence. It notifies (changes waiting on people, exceptions, break-glass, coverage, stuck attestations) and, for
// a person whose Slack account is linked to their IdP identity, clears (tier 2 by default) and denies in place.
// docs/slack.md is the operator's guide.
package slack

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Transports.
const (
	TransportSocket = "socket" // Socket Mode: an outbound websocket, no inbound surface (the default)
	TransportEvents = "events" // the Events API and interactivity over HTTPS, signature-verified
)

// Config is the service's configuration. Secrets are read from files (*_FILE) or, for a lab, the environment;
// they are never logged.
type Config struct {
	Transport string
	Listen    string // the link pages, /healthz, and (events transport) /slack/*
	// PublicURL is the base URL of the link pages as a browser reaches them (https; Sign in with Slack requires it).
	PublicURL string

	BotToken, AppToken, SigningSecret string
	// BotTokenFile and AppTokenFile, when set, are re-read on each use (the owner rotates the secret; nothing is held).
	BotTokenFile, AppTokenFile string

	// Sign in with Slack (the link flow's first proof).
	SlackClientID, SlackClientSecret string
	SlackBase                        string // https://slack.com
	SlackAPIBase                     string // SlackBase + /api
	SlackIssuer                      string // the issuer of Sign in with Slack's ID tokens (https://slack.com)
	// The people IdP (the link flow's second proof): the same issuer and user claim the core verifies.
	IdPIssuer, IdPClientID, IdPClientSecret, IdPUserClaim, IdPJWKSURL string
	IdPAllowed                                                        []string

	DSN string

	APIURL, CoreURL string
	// SATokenFile is the projected service-account token (audience CLEARANCE_AUDIENCE), read on every call.
	SATokenFile string
	// OnBehalfOfHeader names the person a delegate acts for (the deployment's CLEARANCE_ON_BEHALF_OF_HEADER).
	OnBehalfOfHeader string

	RoutesFile string
	// WebURL is where a person steps up: "https://clearance.example/changes/{id}" ({id} is the change id), the
	// standalone web UI or Tower. Empty: the message says to use the CLI.
	WebURL string

	// ClearMaxTier is the highest tier a person may clear from Slack (default 2). Deny is allowed at any tier.
	ClearMaxTier int
	// ForwardAuthTime sends the link's IdP sign-in time as X-Clearance-Auth-Time (the core uses it only when
	// CLEARANCE_FRESH_AUTH_DELEGATES=require).
	ForwardAuthTime bool
	RelinkAfter     time.Duration // a link older than this is re-verified (default 30 days)

	AlertInterval, ReconcileInterval time.Duration
	StuckAttestAfter                 time.Duration
	Tier3OutsideAfter                time.Duration
	// MinPostInterval is the least time between two posts to one channel (Slack allows about one a second).
	MinPostInterval time.Duration

	// Slack's own timing and test hooks.
	ReplayWindow time.Duration
}

// Routes is where messages go: owner group to channel, with fallbacks. Channel ids (C...), never names.
type Routes struct {
	// Groups maps an owner or outside group ("group:default/payments") to a channel id.
	Groups map[string]string `yaml:"groups"`
	// Apps maps an app to a channel id, for exceptions (which name an app, not a group).
	Apps map[string]string `yaml:"apps"`
	// Scopes maps a coverage scope (an account or cluster) to a channel id.
	Scopes map[string]string `yaml:"scopes"`
	// Default takes a hold with no group route.
	Default string `yaml:"default"`
	// Security takes break-glass, monitoring-protection exceptions and blind or degraded coverage, always.
	Security string `yaml:"security"`
	// Ops takes stuck attestations and the service's own problems.
	Ops string `yaml:"ops"`
}

// LoadRoutes reads the routes file; an empty path is no routes (everything goes by DM and nothing is posted).
func LoadRoutes(path string) (Routes, error) {
	var r Routes
	if path == "" {
		return r, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("routes file: %w", err)
	}
	return r, nil
}

// ForGroup is the channel of a group ("" when it has none and no default).
func (r Routes) ForGroup(g string) string {
	if c := r.Groups[g]; c != "" {
		return c
	}
	return r.Default
}

// ConfigFromEnv reads CLEARANCE_SLACK_* and the core's own CLEARANCE_OIDC_* names.
func ConfigFromEnv(env func(string) string) (Config, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(env(k)); v != "" {
			return v
		}
		return def
	}
	// secret reads NAME_FILE (a mounted file, trailing newline dropped) or, for a lab, NAME itself.
	var firstErr error
	secret := func(name string) string {
		if f := get(name+"_FILE", ""); f != "" {
			b, err := os.ReadFile(f)
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("%s_FILE: %w", name, err)
			}
			return strings.TrimSpace(string(b))
		}
		return get(name, "")
	}
	dur := func(k string, def time.Duration) time.Duration {
		v := get(k, "")
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s is a Go duration, not %q", k, v)
			}
			return def
		}
		return d
	}
	c := Config{
		Transport: get("CLEARANCE_SLACK_TRANSPORT", TransportSocket),
		Listen:    get("CLEARANCE_SLACK_LISTEN", ":8080"),
		PublicURL: strings.TrimRight(get("CLEARANCE_SLACK_PUBLIC_URL", ""), "/"),
		BotToken:  secret("CLEARANCE_SLACK_BOT_TOKEN"), AppToken: secret("CLEARANCE_SLACK_APP_TOKEN"),
		BotTokenFile: get("CLEARANCE_SLACK_BOT_TOKEN_FILE", ""), AppTokenFile: get("CLEARANCE_SLACK_APP_TOKEN_FILE", ""),
		SigningSecret: secret("CLEARANCE_SLACK_SIGNING_SECRET"),
		SlackClientID: get("CLEARANCE_SLACK_CLIENT_ID", ""), SlackClientSecret: secret("CLEARANCE_SLACK_CLIENT_SECRET"),
		SlackBase:   strings.TrimRight(get("CLEARANCE_SLACK_BASE_URL", "https://slack.com"), "/"),
		IdPIssuer:   strings.TrimRight(get("CLEARANCE_OIDC_ISSUER", ""), "/"),
		IdPClientID: get("CLEARANCE_SLACK_IDP_CLIENT_ID", ""), IdPClientSecret: secret("CLEARANCE_SLACK_IDP_CLIENT_SECRET"),
		IdPUserClaim: get("CLEARANCE_OIDC_USER_CLAIM", "email"), IdPJWKSURL: get("CLEARANCE_OIDC_JWKS_URL", ""),
		IdPAllowed: splitList(get("CLEARANCE_OIDC_ALLOWED_USERS", "")),
		DSN:        secret("CLEARANCE_SLACK_DSN"),
		APIURL:     strings.TrimRight(get("CLEARANCE_API_URL", ""), "/"), CoreURL: strings.TrimRight(get("CLEARANCE_URL", ""), "/"),
		SATokenFile:      get("CLEARANCE_SLACK_SA_TOKEN_FILE", "/var/run/secrets/tokens/clearance"),
		OnBehalfOfHeader: get("CLEARANCE_ON_BEHALF_OF_HEADER", "X-Clearance-On-Behalf-Of"),
		RoutesFile:       get("CLEARANCE_SLACK_ROUTES_FILE", ""), WebURL: get("CLEARANCE_SLACK_WEB_URL", ""),
		ClearMaxTier: 2, ForwardAuthTime: get("CLEARANCE_SLACK_FORWARD_AUTH_TIME", "true") != "false",
		RelinkAfter:   dur("CLEARANCE_SLACK_RELINK_AFTER", 30*24*time.Hour),
		AlertInterval: dur("CLEARANCE_SLACK_ALERT_INTERVAL", 120*time.Second), ReconcileInterval: dur("CLEARANCE_SLACK_RECONCILE_INTERVAL", 60*time.Second),
		StuckAttestAfter: dur("CLEARANCE_SLACK_STUCK_ATTESTATION_AFTER", 30*time.Minute), Tier3OutsideAfter: dur("CLEARANCE_SLACK_TIER3_OUTSIDE_AFTER", 15*time.Minute),
		MinPostInterval: dur("CLEARANCE_SLACK_MIN_POST_INTERVAL", 1100*time.Millisecond), ReplayWindow: 5 * time.Minute,
	}
	if v := get("CLEARANCE_SLACK_CLEAR_MAX_TIER", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 3 {
			return c, errors.New("CLEARANCE_SLACK_CLEAR_MAX_TIER is 0 to 3 (the default, 2, keeps a tier 3 clear a step-up elsewhere)")
		}
		c.ClearMaxTier = n
	}
	if firstErr != nil {
		return c, firstErr
	}
	return c, c.Validate()
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Validate refuses a configuration that cannot work, naming what is missing (never a value).
func (c *Config) Validate() error {
	if c.SlackBase == "" {
		c.SlackBase = "https://slack.com"
	}
	if c.SlackIssuer == "" {
		c.SlackIssuer = "https://slack.com"
	}
	if c.SlackAPIBase == "" {
		c.SlackAPIBase = c.SlackBase + "/api"
	}
	if c.OnBehalfOfHeader == "" {
		c.OnBehalfOfHeader = "X-Clearance-On-Behalf-Of"
	}
	var missing []string
	need := func(v, name string) {
		if v == "" {
			missing = append(missing, name)
		}
	}
	need(c.BotToken, "CLEARANCE_SLACK_BOT_TOKEN_FILE")
	switch c.Transport {
	case TransportSocket:
		need(c.AppToken, "CLEARANCE_SLACK_APP_TOKEN_FILE")
	case TransportEvents:
		need(c.SigningSecret, "CLEARANCE_SLACK_SIGNING_SECRET_FILE")
	default:
		return fmt.Errorf("CLEARANCE_SLACK_TRANSPORT is %q or %q", TransportSocket, TransportEvents)
	}
	need(c.DSN, "CLEARANCE_SLACK_DSN_FILE")
	need(c.APIURL, "CLEARANCE_API_URL")
	need(c.CoreURL, "CLEARANCE_URL")
	need(c.PublicURL, "CLEARANCE_SLACK_PUBLIC_URL")
	need(c.SlackClientID, "CLEARANCE_SLACK_CLIENT_ID")
	need(c.SlackClientSecret, "CLEARANCE_SLACK_CLIENT_SECRET_FILE")
	need(c.IdPIssuer, "CLEARANCE_OIDC_ISSUER")
	need(c.IdPClientID, "CLEARANCE_SLACK_IDP_CLIENT_ID")
	if len(missing) > 0 {
		return fmt.Errorf("missing configuration: %s", strings.Join(missing, ", "))
	}
	if len(c.IdPAllowed) == 0 {
		return errors.New("CLEARANCE_OIDC_ALLOWED_USERS is required: a link only names a person the IdP signs in and the core allows")
	}
	if u, err := url.Parse(c.PublicURL); err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopback(u.Hostname())) {
		return errors.New("CLEARANCE_SLACK_PUBLIC_URL is an https URL (Sign in with Slack accepts nothing else; http only on loopback)")
	}
	return nil
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }
