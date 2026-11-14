package grc

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrOff is ConfigFromEnv when no target is configured: the push is off and nothing is sent.
var ErrOff = errors.New("the GRC push is off: CLEARANCE_GRC_TARGET is not set")

// Config is clearance-grc's configuration: the environment, secrets as *_FILE mounts. Nothing here is a default that
// sends data: with no CLEARANCE_GRC_TARGET the service does nothing.
type Config struct {
	Target string // "vanta"

	VantaBaseURL, VantaClientID, VantaSecretFile string
	VantaEvidenceResource, VantaReportResource   string

	APIURL, CoreURL, SATokenFile, Provider string
	// LinkBase is the https base URL of the Clearance UI the evidence items link back to.
	LinkBase string
	Envs     []string // the environments whose changes are sent (default prod)
	Mappings []string // the control mappings the items are mapped to (default soc2/2017)
	Listen   string

	Interval, ReportInterval, Window time.Duration
	MaxItems                         int
	Attempts                         int
	BackoffBase, BackoffMax          time.Duration
	// AllowShrink lets a push replace the hub's set with an empty or much smaller one. Off: such a push is refused
	// and recorded, because the hub deletes whatever a push leaves out.
	AllowShrink bool
	// MinSetRatio is the least a set may be, as a fraction of the last set this process pushed, before it is refused.
	MinSetRatio float64
	// ResendEvery re-sends an unchanged evidence set this often, so data lost at the hub is restored.
	ResendEvery time.Duration
	// UnreadyAfter is how long a loop may keep failing before /readyz fails.
	UnreadyAfter time.Duration
	// UseProxy turns the environment's HTTP proxy settings on for outbound calls (off: they are ignored).
	UseProxy bool

	loopback bool // test only: ConfigLoopbackForTest
}

// ConfigOption changes how ConfigFromEnv validates.
type ConfigOption func(*Config)

// ConfigLoopbackForTest accepts http on loopback hosts for the hub and the Clearance URLs, for a fake in a test. It is
// not reachable from the environment.
func ConfigLoopbackForTest() ConfigOption { return func(c *Config) { c.loopback = true } }

// ConfigFromEnv reads CLEARANCE_GRC_*, CLEARANCE_API_URL and CLEARANCE_URL. A secret is only ever named
// (CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE); no value is echoed in an error.
func ConfigFromEnv(env func(string) string, opts ...ConfigOption) (Config, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(env(k)); v != "" {
			return v
		}
		return def
	}
	var firstErr error
	dur := func(k string, def time.Duration) time.Duration {
		v := get(k, "")
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s is a positive Go duration", k)
			}
			return def
		}
		return d
	}
	num := func(k string, def int) int {
		v := get(k, "")
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s is a positive number", k)
			}
			return def
		}
		return n
	}
	c := Config{
		Target:        strings.ToLower(get("CLEARANCE_GRC_TARGET", "")),
		VantaBaseURL:  get("CLEARANCE_GRC_VANTA_BASE_URL", "https://api.vanta.com"),
		VantaClientID: get("CLEARANCE_GRC_VANTA_CLIENT_ID", ""), VantaSecretFile: get("CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE", ""),
		VantaEvidenceResource: get("CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID", ""), VantaReportResource: get("CLEARANCE_GRC_VANTA_REPORT_RESOURCE_ID", ""),
		APIURL: strings.TrimRight(get("CLEARANCE_API_URL", ""), "/"), CoreURL: strings.TrimRight(get("CLEARANCE_URL", ""), "/"),
		SATokenFile: get("CLEARANCE_GRC_SA_TOKEN_FILE", "/var/run/secrets/tokens/clearance"),
		Provider:    get("CLEARANCE_GRC_PROVIDER", "clearance-grc"),
		LinkBase:    strings.TrimRight(get("CLEARANCE_GRC_LINK_BASE", ""), "/"),
		Envs:        splitList(get("CLEARANCE_GRC_ENVS", "prod")), Mappings: splitList(get("CLEARANCE_GRC_MAPPINGS", "soc2/2017")),
		Listen:   get("CLEARANCE_GRC_LISTEN", ":8080"),
		Interval: dur("CLEARANCE_GRC_INTERVAL", 5*time.Minute), ReportInterval: dur("CLEARANCE_GRC_REPORT_INTERVAL", 24*time.Hour),
		Window:   dur("CLEARANCE_GRC_WINDOW", 90*24*time.Hour),
		MaxItems: num("CLEARANCE_GRC_MAX_ITEMS", 5000), Attempts: num("CLEARANCE_GRC_MAX_ATTEMPTS", 5),
		BackoffBase: dur("CLEARANCE_GRC_BACKOFF_BASE", 2*time.Second), BackoffMax: dur("CLEARANCE_GRC_BACKOFF_MAX", 2*time.Minute),
		AllowShrink: get("CLEARANCE_GRC_ALLOW_SHRINK", "") == "true", MinSetRatio: 0.8,
		ResendEvery: dur("CLEARANCE_GRC_RESEND_EVERY", 6*time.Hour), UnreadyAfter: dur("CLEARANCE_GRC_UNREADY_AFTER", 30*time.Minute),
		UseProxy: get("CLEARANCE_GRC_USE_PROXY", "") == "true",
	}
	for _, o := range opts {
		o(&c)
	}
	if v := get("CLEARANCE_GRC_MIN_SET_RATIO", ""); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f <= 0 || f > 1 {
			return c, errors.New("CLEARANCE_GRC_MIN_SET_RATIO is a fraction above 0 and at most 1")
		}
		c.MinSetRatio = f
	}
	if c.Target == "" {
		return c, ErrOff
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

// Validate names what is missing or wrong, never a value.
func (c *Config) Validate() error {
	if c.Target != "vanta" {
		return errors.New(`CLEARANCE_GRC_TARGET is "vanta" (the only hub built)`)
	}
	var missing []string
	need := func(v, name string) {
		if v == "" {
			missing = append(missing, name)
		}
	}
	need(c.VantaClientID, "CLEARANCE_GRC_VANTA_CLIENT_ID")
	need(c.VantaSecretFile, "CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE")
	need(c.VantaEvidenceResource, "CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID")
	need(c.APIURL, "CLEARANCE_API_URL")
	need(c.CoreURL, "CLEARANCE_URL")
	need(c.LinkBase, "CLEARANCE_GRC_LINK_BASE")
	if len(missing) > 0 {
		return fmt.Errorf("missing configuration: %s", strings.Join(missing, ", "))
	}
	// The hub is https only. Loopback http exists for a fake in a test, through ConfigLoopbackForTest, never the environment.
	if err := CheckURL(c.VantaBaseURL, "CLEARANCE_GRC_VANTA_BASE_URL", c.loopback); err != nil {
		return err
	}
	// The service-account token goes to the core and the api: https, or http to an in-cluster service name.
	for _, u := range []struct{ v, name string }{{c.APIURL, "CLEARANCE_API_URL"}, {c.CoreURL, "CLEARANCE_URL"}} {
		if err := CheckClusterURL(u.v, u.name, c.loopback); err != nil {
			return err
		}
	}
	// The link back is an https URL always (Vanta requires an https external URL); only the hub's own API may be a
	// loopback http fake.
	if err := CheckURL(c.LinkBase, "CLEARANCE_GRC_LINK_BASE", false); err != nil {
		return err
	}
	if len(c.Envs) == 0 {
		return errors.New("CLEARANCE_GRC_ENVS names at least one environment")
	}
	if c.BackoffMax < c.BackoffBase {
		return errors.New("CLEARANCE_GRC_BACKOFF_MAX is at least CLEARANCE_GRC_BACKOFF_BASE")
	}
	if _, err := ControlsFor(c.Mappings); err != nil {
		return fmt.Errorf("CLEARANCE_GRC_MAPPINGS: %w", err)
	}
	return nil
}

// CheckClusterURL is the rule for a URL the service-account token is sent to: an absolute https URL, or http to an
// in-cluster service host (a single-label name, *.svc or *.svc.cluster.local), with no credentials, query or
// fragment; a loopback http host only when allowLoopback (a test).
func CheckClusterURL(raw, name string, allowLoopback bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s is an absolute URL with a host and no credentials, query or fragment", name)
	}
	h := u.Hostname()
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && (!strings.Contains(h, ".") && !isLoopback(h) || strings.HasSuffix(h, ".svc") || strings.HasSuffix(h, ".svc.cluster.local")):
		return nil
	case u.Scheme == "http" && allowLoopback && isLoopback(h):
		return nil
	}
	return fmt.Errorf("%s is an https URL (http only to an in-cluster service host)", name)
}

// AllowLoopback reports the test-only loopback option (ConfigLoopbackForTest); it is never set from the environment.
func (c Config) AllowLoopback() bool { return c.loopback }
