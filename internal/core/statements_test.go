package core

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The public verify page does not exist unless CLEARANCE_VERIFY_LISTEN is set: no listener, and no setting of it enables it.
func TestTheVerifyPageIsOffUnlessItsListenAddressIsSet(t *testing.T) {
	cfg, err := FromEnv(env(map[string]string{"CLEARANCE_DSN": "postgres://x"}))
	if err != nil || cfg.VerifyListen != "" || len(cfg.Statements.IndependentWitnesses) != 0 {
		t.Fatalf("%+v %v", cfg.VerifyListen, err)
	}
	for _, k := range []string{"CLEARANCE_VERIFY_PUBLIC_URL", "CLEARANCE_VERIFY_RATE_PER_CLIENT", "CLEARANCE_VERIFY_BURST_PER_CLIENT", "CLEARANCE_VERIFY_RATE_GLOBAL",
		"CLEARANCE_VERIFY_BURST_GLOBAL", "CLEARANCE_VERIFY_TRUSTED_PROXY_HOPS", "CLEARANCE_VERIFY_MAX_CHECKS"} {
		v := "5"
		if strings.HasSuffix(k, "URL") {
			v = "https://verify.example.com"
		}
		if _, err := FromEnv(env(map[string]string{"CLEARANCE_DSN": "postgres://x", k: v})); err == nil || !strings.Contains(err.Error(), "CLEARANCE_VERIFY_LISTEN") {
			t.Errorf("%s alone: %v", k, err)
		}
	}
}

func TestTheVerifySettingsAreValidated(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "log.pub")
	if err := os.WriteFile(keys, []byte("log+1+AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := map[string]string{"CLEARANCE_DSN": "postgres://x", "CLEARANCE_VERIFY_LISTEN": ":8081"}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	cfg, err := FromEnv(env(with("CLEARANCE_STATEMENT_LOG_KEYS_FILE", keys, "CLEARANCE_STATEMENT_INDEPENDENT_WITNESSES", "w-one, w-two",
		"CLEARANCE_VERIFY_PUBLIC_URL", "https://verify.example.com/", "CLEARANCE_VERIFY_RATE_PER_CLIENT", "12", "CLEARANCE_VERIFY_TRUSTED_PROXY_HOPS", "1")))
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.Statements
	if cfg.VerifyListen != ":8081" || string(o.LogKeys) != "log+1+AAAA\n" || len(o.IndependentWitnesses) != 2 || o.PublicBaseURL != "https://verify.example.com" || o.ClientPerMinute != 12 || o.TrustedProxyHops != 1 {
		t.Fatalf("%+v", cfg)
	}
	for name, kv := range map[string][]string{
		"http URL":           {"CLEARANCE_VERIFY_PUBLIC_URL", "http://verify.example.com"},
		"URL with a path":    {"CLEARANCE_VERIFY_PUBLIC_URL", "https://verify.example.com/x"},
		"URL credentials":    {"CLEARANCE_VERIFY_PUBLIC_URL", "https://u:p@verify.example.com"},
		"rate zero":          {"CLEARANCE_VERIFY_RATE_PER_CLIENT", "0"},
		"rate not a number":  {"CLEARANCE_VERIFY_RATE_GLOBAL", "many"},
		"hops too many":      {"CLEARANCE_VERIFY_TRUSTED_PROXY_HOPS", "99"},
		"missing key file":   {"CLEARANCE_STATEMENT_LOG_KEYS_FILE", filepath.Join(dir, "nope")},
		"witness with space": {"CLEARANCE_STATEMENT_INDEPENDENT_WITNESSES", "a b c"},
	} {
		if _, err := FromEnv(env(with(kv...))); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// Run starts the verify listener only when asked, and it serves the page's own paths (a health probe here) and none of the API's.
func TestRunServesTheVerifyListenerOnlyWhenAsked(t *testing.T) {
	free := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().String()
	}
	run := func(verify string) (string, func()) {
		ctx, cancel := context.WithCancel(context.Background())
		addr, done := make(chan string, 1), make(chan error, 1)
		cfg := Config{Memory: true, Listen: "127.0.0.1:0", VerifyListen: verify, Auth: DevAuthenticator(), ExpireEvery: 50 * time.Millisecond}
		go func() {
			done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func(a string) { addr <- a })
		}()
		select {
		case a := <-addr:
			return a, func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("Run did not stop")
				}
			}
		case err := <-done:
			t.Fatal(err)
		}
		return "", nil
	}
	// Off: nothing listens where the page would be.
	va := free()
	_, stop := run("")
	if c, err := net.DialTimeout("tcp", va, 300*time.Millisecond); err == nil {
		c.Close()
		t.Error("a listener exists with the verify page off")
	}
	stop()
	// On: its own port answers its own paths, and the API's paths are not there.
	va = free()
	api, stop := run(va)
	defer stop()
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ {
		if resp, err = http.Get("http://" + va + "/healthz"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(resp, err)
	}
	resp.Body.Close()
	for _, p := range []string{"/readyz", "/v1/keys", "/v1/statements", "/healthz/../v1/keys"} {
		r, err := http.Get("http://" + va + p)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != 404 {
			t.Errorf("%s on the verify port: %d", p, r.StatusCode)
		}
		r.Body.Close()
	}
	// And the API port does not serve the page.
	r, err := http.Get("http://" + api + "/s/st-00000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode == 200 {
		t.Errorf("the API port serves the page: %d", r.StatusCode)
	}
	r.Body.Close()
}
