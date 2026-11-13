package slack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func goodEnv(t *testing.T) map[string]string {
	dir := t.TempDir()
	w := func(name, v string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(v+"\n"), 0o600)
		return p
	}
	return map[string]string{
		"CLEARANCE_SLACK_BOT_TOKEN_FILE": w("bot", "xoxb-SECRET-bot"), "CLEARANCE_SLACK_APP_TOKEN_FILE": w("app", "xapp-SECRET-app"),
		"CLEARANCE_SLACK_BOT_TOKEN": "", "CLEARANCE_SLACK_CLIENT_ID": "cid", "CLEARANCE_SLACK_CLIENT_SECRET_FILE": w("cs", "SECRET-client"),
		"CLEARANCE_SLACK_DSN_FILE": w("dsn", "postgres://u:SECRET-dsn@h/db"), "CLEARANCE_API_URL": "http://api:8080/", "CLEARANCE_URL": "http://core:8080",
		"CLEARANCE_SLACK_PUBLIC_URL": "https://slack.clearance.example/", "CLEARANCE_OIDC_ISSUER": "https://dex.example/dex/",
		"CLEARANCE_SLACK_IDP_CLIENT_ID": "clearance-slack", "CLEARANCE_OIDC_ALLOWED_USERS": "*@acme.example",
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := goodEnv(t)
	c, err := ConfigFromEnv(envOf(env))
	if err != nil {
		t.Fatal(err)
	}
	if c.BotToken != "xoxb-SECRET-bot" || c.AppToken != "xapp-SECRET-app" || c.DSN != "postgres://u:SECRET-dsn@h/db" {
		t.Errorf("secrets are read from their files, newline dropped: %q %q %q", c.BotToken, c.AppToken, c.DSN)
	}
	if c.Transport != TransportSocket || c.ClearMaxTier != 2 || !c.ForwardAuthTime || c.PublicURL != "https://slack.clearance.example" ||
		c.IdPIssuer != "https://dex.example/dex" || c.APIURL != "http://api:8080" || c.OnBehalfOfHeader != "X-Clearance-On-Behalf-Of" || c.SlackIssuer != "https://slack.com" {
		t.Errorf("defaults: %+v", c)
	}
}

func TestConfigRefusesWhatCannotWorkAndNeverPrintsASecret(t *testing.T) {
	for name, mod := range map[string]func(map[string]string){
		"no app token in socket mode": func(m map[string]string) { delete(m, "CLEARANCE_SLACK_APP_TOKEN_FILE") },
		"no signing secret on events": func(m map[string]string) { m["CLEARANCE_SLACK_TRANSPORT"] = "events" },
		"unknown transport":           func(m map[string]string) { m["CLEARANCE_SLACK_TRANSPORT"] = "carrier-pigeon" },
		"no DSN":                      func(m map[string]string) { delete(m, "CLEARANCE_SLACK_DSN_FILE") },
		"no core":                     func(m map[string]string) { delete(m, "CLEARANCE_URL") },
		"an http public URL":          func(m map[string]string) { m["CLEARANCE_SLACK_PUBLIC_URL"] = "http://slack.clearance.example" },
		"no allowlist":                func(m map[string]string) { delete(m, "CLEARANCE_OIDC_ALLOWED_USERS") },
		"a tier of 4":                 func(m map[string]string) { m["CLEARANCE_SLACK_CLEAR_MAX_TIER"] = "4" },
		"a bad duration":              func(m map[string]string) { m["CLEARANCE_SLACK_ALERT_INTERVAL"] = "soon" },
		"an unreadable secret file":   func(m map[string]string) { m["CLEARANCE_SLACK_CLIENT_SECRET_FILE"] = "/nonexistent/SECRET" },
	} {
		t.Run(name, func(t *testing.T) {
			env := goodEnv(t)
			mod(env)
			_, err := ConfigFromEnv(envOf(env))
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), "SECRET-") {
				t.Errorf("a secret in the error: %v", err)
			}
		})
	}
	env := goodEnv(t)
	env["CLEARANCE_SLACK_PUBLIC_URL"] = "http://localhost:8080"
	if _, err := ConfigFromEnv(envOf(env)); err != nil {
		t.Errorf("loopback http is allowed for a lab: %v", err)
	}
	env["CLEARANCE_SLACK_CLEAR_MAX_TIER"] = "3"
	if c, err := ConfigFromEnv(envOf(env)); err != nil || c.ClearMaxTier != 3 {
		t.Errorf("loosening the tier policy is a deployment's choice: %v %d", err, c.ClearMaxTier)
	}
}

func TestRoutesFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.yaml")
	os.WriteFile(p, []byte(testRoutes), 0o600)
	r, err := LoadRoutes(p)
	if err != nil || r.ForGroup("group:default/payments") != "C_PAY" || r.ForGroup("group:default/unknown") != "C_DEF" || r.Security != "C_SEC" {
		t.Fatalf("%+v %v", r, err)
	}
	os.WriteFile(p, []byte("grops: {}\n"), 0o600)
	if _, err := LoadRoutes(p); err == nil {
		t.Error("a misspelled key is an error, not silence")
	}
	if r, err := LoadRoutes(""); err != nil || r.ForGroup("x") != "" {
		t.Errorf("no file: %+v %v", r, err)
	}
}
