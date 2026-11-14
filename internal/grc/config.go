package grc

import (
	"errors"
	"fmt"
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

	VantaBaseURL, VantaClientID, VantaSecretFile, VantaSecret string
	VantaEvidenceResource, VantaReportResource                string

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
}

// ConfigFromEnv reads CLEARANCE_GRC_*, CLEARANCE_API_URL and CLEARANCE_URL. A secret is only ever named
// (CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE); no value is echoed in an error.
func ConfigFromEnv(env func(string) string) (Config, error) {
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
		VantaSecret:           get("CLEARANCE_GRC_VANTA_CLIENT_SECRET", ""),
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
	if c.VantaSecretFile == "" && c.VantaSecret == "" {
		missing = append(missing, "CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE")
	}
	need(c.VantaEvidenceResource, "CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID")
	need(c.APIURL, "CLEARANCE_API_URL")
	need(c.CoreURL, "CLEARANCE_URL")
	need(c.LinkBase, "CLEARANCE_GRC_LINK_BASE")
	if len(missing) > 0 {
		return fmt.Errorf("missing configuration: %s", strings.Join(missing, ", "))
	}
	if err := CheckURL(c.VantaBaseURL, "CLEARANCE_GRC_VANTA_BASE_URL", true); err != nil {
		return err
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
