// Package hcprun is the HCP Terraform run task adapter (G-TF-6, docs/terraform-gate.md): POST /v1/terraform/run-task
// is HCP Terraform asking whether a plan may be applied. The request is authenticated by its HMAC signature
// (X-TFC-Task-Signature, HMAC-SHA512 over the body), the plan JSON is fetched with the run's access token, the
// terraform-plan subject is computed locally (internal/tfplan) and registered with the gate, and the run task's
// result is reported to HCP Terraform: running at once, then passed or failed when the change clears or is denied.
//
// Security: the route does nothing unless an installation is configured; the HMAC is compared in constant time;
// the body is capped before it is read; the plan URL and the callback URL must be https on the installation's own
// HCP Terraform host (never followed elsewhere), so the route is no SSRF primitive; and the run's access token lives
// in memory for one run, goes in one Authorization header to that host, and is never logged or stored.
package hcprun

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// DefaultHost is HCP Terraform's own host.
const DefaultHost = "app.terraform.io"

// DefaultRedirectHosts are the hosts HCP Terraform's API redirects a plan JSON download to, for the default host.
var DefaultRedirectHosts = []string{"archivist.terraform.io"}

// Principal is the gate principal a run task registers as: "hcp-run-task:<organization>". It must match
// CLEARANCE_VERIFIERS (for example "hcp-run-task:*"), like any registrant.
const PrincipalPrefix = "hcp-run-task:"

// PrincipalKind is the authn.Principal kind of a run task registrant.
const PrincipalKind = "hcp-run-task"

var (
	orgRx  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\z`)
	hostRx = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?\z`)
	envRx  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z`)
)

// Installation is one HCP Terraform organization that may call the route.
type Installation struct {
	// Organization is the HCP Terraform organization's name (the payload's organization_name).
	Organization string `json:"organization"`
	// Host is the HCP Terraform (or Terraform Enterprise) host the URLs in a payload must point at, with an optional
	// port. Default app.terraform.io.
	Host string `json:"host,omitempty"`
	// RedirectHosts are further hosts a plan JSON download may be redirected to (the access token is never sent to
	// them). Default for app.terraform.io: archivist.terraform.io.
	RedirectHosts []string `json:"redirectHosts,omitempty"`
	// HMACKeyFile is the file holding the run task's HMAC key; read on every request, never kept.
	HMACKeyFile string `json:"hmacKeyFile"`
	// Environment is the environment name its plans are registered under (the gate decides which are protected).
	Environment string `json:"environment"`
}

// Config is the run task adapter's configuration.
type Config struct {
	Installations []Installation `json:"installations"`
}

// ReadConfig reads the JSON config file; "" is no run task (nil, nil).
func ReadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hcp run task config: %w", err)
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("hcp run task config: %w", err)
	}
	return &c, c.Validate()
}

// Validate normalizes the installations and refuses a malformed one.
func (c *Config) Validate() error {
	if len(c.Installations) == 0 {
		return errors.New("hcp run task config: no installations")
	}
	seen := map[string]bool{}
	for i := range c.Installations {
		in := &c.Installations[i]
		if !orgRx.MatchString(in.Organization) {
			return fmt.Errorf("hcp run task config: installations[%d].organization is malformed", i)
		}
		if seen[in.Organization] {
			return fmt.Errorf("hcp run task config: organization %s is listed twice", in.Organization)
		}
		seen[in.Organization] = true
		in.Host = strings.ToLower(in.Host)
		if in.Host == "" {
			in.Host = DefaultHost
		}
		if !hostRx.MatchString(in.Host) {
			return fmt.Errorf("hcp run task config: installations[%d].host must be a host name with an optional port", i)
		}
		if in.HMACKeyFile == "" {
			return fmt.Errorf("hcp run task config: installations[%d].hmacKeyFile is required", i)
		}
		if !envRx.MatchString(in.Environment) {
			return fmt.Errorf("hcp run task config: installations[%d].environment is required (a lowercase name)", i)
		}
		if in.RedirectHosts == nil && in.Host == DefaultHost {
			in.RedirectHosts = DefaultRedirectHosts
		}
		for j, h := range in.RedirectHosts {
			in.RedirectHosts[j] = strings.ToLower(h)
			if !hostRx.MatchString(in.RedirectHosts[j]) {
				return fmt.Errorf("hcp run task config: installations[%d].redirectHosts[%d] is not a host", i, j)
			}
		}
	}
	return nil
}
