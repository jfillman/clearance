package hcprun_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/hcprun"
)

type recorder struct {
	mu    sync.Mutex
	hosts []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, req.URL.Scheme+"://"+req.URL.Host)
	r.mu.Unlock()
	return nil, errors.New("fuzz: no network")
}

// FuzzRunTask: any body, signed or not, is answered without a panic; an unsigned or mis-signed one is 401 and
// calls nothing; and a correctly signed one, whatever URLs it names, only ever leads to https calls to the
// configured HCP Terraform host (the SSRF restriction), with the gate's own validation never skipped.
func FuzzRunTask(f *testing.F) {
	good, _ := os.ReadFile("testdata/post_plan_payload.json")
	f.Add(good, true)
	f.Add([]byte(strings.Replace(string(good), "https://app.terraform.io/api/v2/plans", "https://169.254.169.254/api/v2/plans", 1)), true)
	f.Add([]byte(strings.Replace(string(good), "https://app.terraform.io", "https://app.terraform.io@evil.example", 1)), true)
	f.Add([]byte(strings.Replace(string(good), `"post_plan"`, `"test"`, 1)), true)
	f.Add([]byte(`{"organization_name":"hashicorp","payload_version":1,"stage":[]}`), true)
	f.Add(good, false)
	f.Add([]byte(`[]`), true)
	key := []byte("fuzz-key")
	keyFile := filepath.Join(f.TempDir(), "key")
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body []byte, signed bool) {
		cfg := &hcprun.Config{Installations: []hcprun.Installation{{Organization: "hashicorp", HMACKeyFile: keyFile, Environment: "prod"}}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		rec := &recorder{}
		svc := &hcprun.Service{Config: cfg, Gate: newGate(gate.StateCleared), HTTP: &http.Client{Transport: rec}}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { svc.Run(ctx); close(done) }()
		sig := ""
		if signed {
			sig = hcprun.Sign(key, body)
		}
		status, _ := svc.Accept(body, sig)
		if !signed && status != 401 {
			t.Fatalf("unsigned body answered %d", status)
		}
		cancel()
		<-done
		rec.mu.Lock()
		defer rec.mu.Unlock()
		for _, h := range rec.hosts {
			h = strings.ToLower(h)
			if h != "https://app.terraform.io" && h != "https://app.terraform.io:443" {
				t.Fatalf("a call went to %q", h)
			}
		}
		if !signed && len(rec.hosts) > 0 {
			t.Fatal("an unsigned body led to a call")
		}
	})
}
