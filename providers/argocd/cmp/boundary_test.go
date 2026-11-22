package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
)

// At the boundary: a render that uses all the time it is given, then a core that does not answer. Every attempt of the
// real client still ends inside the run (the render's deadline keeps the core's whole budget and the plugin's own work),
// so the call fails as unavailable and the outage policy serves the cleared, allow-and-record tree: it is not cut by
// the run's deadline into a context error, which would skip the fallback.
func TestAnOutageAtTheBoundaryStillGetsTheOutagePolicy(t *testing.T) {
	e := newEnv(t)
	e.core.answer = &client.Change{ID: "ch-c", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(48 * time.Hour).Format(time.RFC3339Nano)}
	if _, _, err := e.generate(t); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Hour) // past the tree cache's lifetime: the core is asked again

	stop := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select { // never answers inside the client's timeout
		case <-r.Context().Done():
		case <-stop:
		}
	}))
	defer hung.Close()
	defer close(stop)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := e.cfg
	cfg.CoreURL, cfg.TokenFile, cfg.RegisterWait = hung.URL, tok, 200*time.Millisecond
	core, err := newCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	d := e.d
	d.Core = coreFunc(func(ctx context.Context, r *client.ChangeRequest) (*client.Change, error) {
		calls++
		ch, err := core.RegisterChange(ctx, r)
		if err != nil && !errors.Is(err, client.ErrCoreUnavailable) {
			t.Errorf("the call ended as %v, not as an outage: the run's deadline cut it", err)
		}
		return ch, err
	})
	d.Exec = func(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
		if name == "helm" { // the render takes all the time it has
			if dl, ok := ctx.Deadline(); ok {
				time.Sleep(time.Until(dl) - 20*time.Millisecond)
			}
		}
		return e.exec.run(ctx, dir, name, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), coreBudget(cfg.RegisterWait)+PostRenderReserve+300*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	o, err := Generate(ctx, d, cfg, e.src, &out)
	if err != nil || o != Cleared || calls != 1 {
		t.Fatalf("outcome %q, %d calls, %v: the outage policy did not serve the cleared tree", o, calls, err)
	}
}

type coreFunc func(context.Context, *client.ChangeRequest) (*client.Change, error)

func (f coreFunc) RegisterChange(ctx context.Context, r *client.ChangeRequest) (*client.Change, error) {
	return f(ctx, r)
}

// When the chart tag lookup cannot have a private scratch, it is skipped: it never runs unbudgeted, where a step may
// use the shared temp directory (review, CWE-732).
func TestTheLookupIsSkippedWithoutAPrivateScratch(t *testing.T) {
	e := cachedEnv(t) // a chart repository and the pre-render cache: the lookup would run
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if _, _, ok := lookupBudget(context.Background(), e.cfg); ok {
		t.Fatal("a lookup budget without a scratch")
	}
	var out bytes.Buffer
	Generate(context.Background(), e.d, e.cfg, e.src, &out) // fails: the render has no scratch either
	if n := e.exec.count("git", "ls-remote"); n != 0 {
		t.Fatalf("the lookup ran %d times without its private scratch", n)
	}
	// and with a scratch it does run, so the assertion above is not vacuous
	t.Setenv("TMPDIR", t.TempDir())
	e.gen(t)
	if e.exec.count("git", "ls-remote") == 0 {
		t.Fatal("control: the lookup never ran")
	}
}
