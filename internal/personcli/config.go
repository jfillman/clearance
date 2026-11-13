// Package personcli is the person-facing CLI of the clearance binary: sign-in against the people IdP (OIDC device
// code), and the read commands, each calling clearance-api with the person's own ID token (never a delegate).
//
// The token rules (docs/cli.md): only the ID token is kept, in the OS keychain, never a refresh token and never a
// file; use is capped at one hour whatever the token's exp says; --token-stdin (or CLEARANCE_TOKEN) keeps a token
// in memory for one invocation; the token is never printed or logged.
package personcli

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Config is what the CLI needs to find things: URLs and the IdP, nothing secret.
type Config struct {
	URL      string // the core (CLEARANCE_URL); named for the write commands of a later phase
	APIURL   string // clearance-api (CLEARANCE_API_URL)
	Issuer   string // the people IdP's OIDC issuer (CLEARANCE_OIDC_ISSUER)
	ClientID string // its public client (CLEARANCE_OIDC_CLIENT_ID); no client secret exists
	Scopes   string // space-separated (CLEARANCE_OIDC_SCOPES)
}

// DefaultScopes is what login asks for when nothing names scopes.
const DefaultScopes = "openid profile email"

// fileConfig is ~/.config/clearance/config.yaml. Unknown keys are refused, so a token pasted there fails loudly
// instead of being quietly kept.
type fileConfig struct {
	URL      string `yaml:"url"`
	APIURL   string `yaml:"api_url"`
	Issuer   string `yaml:"oidc_issuer"`
	ClientID string `yaml:"oidc_client_id"`
	Scopes   string `yaml:"oidc_scopes"`
}

// ConfigPath is the config file's path: $XDG_CONFIG_HOME/clearance/config.yaml, else ~/.config/clearance/config.yaml.
func ConfigPath(getenv func(string) string) string {
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "clearance", "config.yaml")
	}
	if h := getenv("HOME"); h != "" {
		return filepath.Join(h, ".config", "clearance", "config.yaml")
	}
	return ""
}

// Flags are the command-line overrides (empty is unset).
type Flags struct{ URL, APIURL, Issuer, ClientID string }

// LoadConfig resolves flags > environment > the config file. A missing file is fine.
func LoadConfig(getenv func(string) string, path string, fl Flags) (Config, error) {
	var c Config
	if path != "" {
		raw, err := os.ReadFile(path)
		switch {
		case err == nil:
			var f fileConfig
			dec := yaml.NewDecoder(bytes.NewReader(raw))
			dec.KnownFields(true)
			if err := dec.Decode(&f); err != nil && err.Error() != "EOF" {
				return c, fmt.Errorf("%s: %v (the file holds url, api_url, oidc_issuer, oidc_client_id and oidc_scopes only; never a token)", path, err)
			}
			c = Config{URL: f.URL, APIURL: f.APIURL, Issuer: f.Issuer, ClientID: f.ClientID, Scopes: f.Scopes}
		case errors.Is(err, os.ErrNotExist):
		default:
			return c, err
		}
	}
	over := func(dst *string, env, flag string) {
		if v := getenv(env); v != "" {
			*dst = v
		}
		if flag != "" {
			*dst = flag
		}
	}
	over(&c.URL, "CLEARANCE_URL", fl.URL)
	over(&c.APIURL, "CLEARANCE_API_URL", fl.APIURL)
	over(&c.Issuer, "CLEARANCE_OIDC_ISSUER", fl.Issuer)
	over(&c.ClientID, "CLEARANCE_OIDC_CLIENT_ID", fl.ClientID)
	over(&c.Scopes, "CLEARANCE_OIDC_SCOPES", "")
	if c.Scopes == "" {
		c.Scopes = DefaultScopes
	}
	for k, v := range map[string]string{"url": c.URL, "api_url": c.APIURL, "oidc_issuer": c.Issuer} {
		if v != "" {
			if err := checkURL(v); err != nil {
				return c, fmt.Errorf("%s: %v", k, err)
			}
		}
	}
	c.URL, c.APIURL, c.Issuer = strings.TrimRight(c.URL, "/"), strings.TrimRight(c.APIURL, "/"), strings.TrimRight(c.Issuer, "/")
	return c, nil
}

// checkURL wants https with a host and no credentials, query or fragment; http only to a loopback address (a token
// must not cross a network in the clear).
func checkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q must be an http(s) URL with a host and no credentials, query or fragment", s)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
		return fmt.Errorf("%q: plain http is for localhost only; use https", s)
	}
	return fmt.Errorf("%q must be an http(s) URL", s)
}
