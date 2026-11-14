package core

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/jfillman/clearance/internal/ledger"
	"github.com/jfillman/clearance/internal/server"
)

// statementConfig reads the verification statement's settings (P-3):
//
//	CLEARANCE_VERIFY_LISTEN               the verify page's own listen address (e.g. :8081). Unset (the default): no listener,
//	                                      no port, no public page. Do not set it until the page has had its security review
//	                                      (docs/statement.md).
//	CLEARANCE_STATEMENT_LOG_KEYS_FILE     the log's public keys (signed-note vkeys, one per line, the key in use first): what the
//	                                      statement checks verify the checkpoint with. Unset: checks 3 and 4 are NOT CHECKED
//	CLEARANCE_STATEMENT_WITNESS_POLICY_FILE
//	                                      the witness policy the checks use (default: the ledger's own policy file contents)
//	CLEARANCE_STATEMENT_INDEPENDENT_WITNESSES
//	                                      comma-separated names of the log's witnesses this deployment asserts it does NOT run.
//	                                      Unset: none, so no statement can say its log is independently witnessed
//	CLEARANCE_VERIFY_PUBLIC_URL           an https base URL (no path) printed in the page's verify command; never taken from a request
//	CLEARANCE_VERIFY_RATE_PER_CLIENT, _BURST_PER_CLIENT, _RATE_GLOBAL, _BURST_GLOBAL
//	                                      the page's limits: requests a minute and the burst, per client and for the listener
//	                                      (defaults 30/10 and 600/100)
//	CLEARANCE_VERIFY_TRUSTED_PROXY_HOPS   how many trusted proxies sit in front of the listener (0: the connection's address is
//	                                      the client; N: the Nth address from the right of X-Forwarded-For)
//	CLEARANCE_VERIFY_MAX_CHECKS           how many statement verifications may run at once (default 2)
func statementConfig(getenv func(string) string, led *ledger.Config) (string, server.StatementOptions, error) {
	var o server.StatementOptions
	listen := getenv("CLEARANCE_VERIFY_LISTEN")
	if listen == "" {
		for _, k := range []string{"CLEARANCE_VERIFY_PUBLIC_URL", "CLEARANCE_VERIFY_RATE_PER_CLIENT", "CLEARANCE_VERIFY_BURST_PER_CLIENT",
			"CLEARANCE_VERIFY_RATE_GLOBAL", "CLEARANCE_VERIFY_BURST_GLOBAL", "CLEARANCE_VERIFY_TRUSTED_PROXY_HOPS", "CLEARANCE_VERIFY_MAX_CHECKS"} {
			if getenv(k) != "" {
				return "", o, fmt.Errorf("%s is set but CLEARANCE_VERIFY_LISTEN is not: the verify page is off, and is not enabled by its settings", k)
			}
		}
	}
	read := func(k string) ([]byte, error) {
		f := getenv(k)
		if f == "" {
			return nil, nil
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		if len(b) > 64<<10 {
			return nil, fmt.Errorf("%s is over 64 KiB", k)
		}
		return b, nil
	}
	var err error
	if o.LogKeys, err = read("CLEARANCE_STATEMENT_LOG_KEYS_FILE"); err != nil {
		return "", o, err
	}
	if o.WitnessPolicy, err = read("CLEARANCE_STATEMENT_WITNESS_POLICY_FILE"); err != nil {
		return "", o, err
	}
	if o.WitnessPolicy == nil && led != nil {
		o.WitnessPolicy = led.Log.Policy
	}
	for _, n := range strings.Split(getenv("CLEARANCE_STATEMENT_INDEPENDENT_WITNESSES"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			if len(n) > 128 || strings.ContainsAny(n, " \t\r\n") {
				return "", o, errors.New("CLEARANCE_STATEMENT_INDEPENDENT_WITNESSES is a comma-separated list of witness names without spaces")
			}
			o.IndependentWitnesses = append(o.IndependentWitnesses, n)
		}
	}
	if v := getenv("CLEARANCE_VERIFY_PUBLIC_URL"); v != "" {
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil || u.Fragment != "" || len(v) > 200 {
			return "", o, errors.New("CLEARANCE_VERIFY_PUBLIC_URL is an https URL with no path, query or credentials")
		}
		o.PublicBaseURL = strings.TrimSuffix(v, "/")
	}
	for _, f := range []struct {
		env      string
		into     *int
		min, max int
	}{{"CLEARANCE_VERIFY_RATE_PER_CLIENT", &o.ClientPerMinute, 1, 6000}, {"CLEARANCE_VERIFY_BURST_PER_CLIENT", &o.ClientBurst, 1, 1000},
		{"CLEARANCE_VERIFY_RATE_GLOBAL", &o.GlobalPerMinute, 1, 600000}, {"CLEARANCE_VERIFY_BURST_GLOBAL", &o.GlobalBurst, 1, 100000},
		{"CLEARANCE_VERIFY_TRUSTED_PROXY_HOPS", &o.TrustedProxyHops, 0, 8}, {"CLEARANCE_VERIFY_MAX_CHECKS", &o.MaxChecks, 1, 16}} {
		if v := getenv(f.env); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < f.min || n > f.max {
				return "", o, fmt.Errorf("%s is a whole number from %d to %d", f.env, f.min, f.max)
			}
			*f.into = n
		}
	}
	return listen, o, nil
}
