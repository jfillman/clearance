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

// A slow pre-render confirmation that leaves less time than the core's call and the plugin's own work need: the full
// render is not started into that time. The run fails at once as a timeout (a fault), and no second call is made that
// the run's deadline would cut.
func TestASlowConfirmationLeavesNoTimeToRender(t *testing.T) {
	e := cachedEnv(t)
	e.gen(t) // cleared and kept in the pre-render cache
	e.now = e.now.Add(5 * time.Minute)
	cfg := e.cfg
	cfg.RegisterWait = 100 * time.Millisecond // the core's budget plus the plugin's own work: about 2.3 s
	reserve := coreBudget(cfg.RegisterWait) + PostRenderReserve
	calls := 0
	d := e.d
	d.Core = coreFunc(func(ctx context.Context, r *client.ChangeRequest) (*client.Change, error) {
		calls++
		time.Sleep(600 * time.Millisecond) // a confirmation the core answers slowly, and not as cleared
		return &client.Change{ID: "ch-other", State: "holding", Tier: 2}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), reserve+400*time.Millisecond)
	defer cancel()
	helm := e.exec.count("helm", "")
	start := time.Now()
	var out bytes.Buffer
	_, err := Generate(ctx, d, cfg, e.src, &out)
	ce, ok := asCmp(err)
	if !ok || ce.Code != CodeFaultTimeout {
		t.Fatalf("want %s, got %v", CodeFaultTimeout, err)
	}
	if calls != 1 || e.exec.count("helm", "") != helm {
		t.Fatalf("%d core calls, %d renders after the slow confirmation: want one call and no render", calls, e.exec.count("helm", "")-helm)
	}
	if ctx.Err() != nil || time.Since(start) > reserve {
		t.Fatalf("it returned after %s, not at once", time.Since(start))
	}
}

// However long the work before it took, a call to the core that has not been answered when the run is about to end is
// an outage, so the outage policy decides; it never becomes the run's own deadline.
func TestACallThatRunsIntoTheRunsEndIsAnOutage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	hang := coreFunc(func(ctx context.Context, _ *client.ChangeRequest) (*client.Change, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	_, err := registerInTime(ctx, hang, &client.ChangeRequest{})
	if !errors.Is(err, client.ErrCoreUnavailable) || ctx.Err() != nil {
		t.Fatalf("want an outage before the run ends, got %v (run %v)", err, ctx.Err())
	}
	// an answer the core gave keeps its own class, even when the window closed just after it arrived (the call returns
	// only once the window is over, so a check of the context after the call would see it ended)
	refused := coreFunc(func(ctx context.Context, _ *client.ChangeRequest) (*client.Change, error) {
		<-ctx.Done()
		return nil, &client.APIError{Op: "registerChange", Status: 403, Message: "not a verifier"}
	})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel2()
	_, err = registerInTime(ctx2, refused, &client.ChangeRequest{})
	var ae *client.APIError
	if !errors.As(err, &ae) || errors.Is(err, client.ErrCoreUnavailable) {
		t.Fatalf("a refusal became %v", err)
	}
	// the run's own end (or a cancellation) is not this window's: it stays a context error
	ctx3, cancel3 := context.WithCancel(context.Background())
	cancel3()
	if _, err := registerInTime(ctx3, hang, &client.ChangeRequest{}); errors.Is(err, client.ErrCoreUnavailable) {
		t.Fatalf("a cancelled run became an outage: %v", err)
	}
	// an answer in time is passed through unchanged
	ok := coreFunc(func(context.Context, *client.ChangeRequest) (*client.Change, error) {
		return &client.Change{ID: "x"}, nil
	})
	if ch, err := registerInTime(context.Background(), ok, &client.ChangeRequest{}); err != nil || ch.ID != "x" {
		t.Fatal(ch, err)
	}
}

// The outage policy reads the clock after the call: a cleared entry that expired while the core was being waited for
// is not served (an entry is never served past its ExpiresAt).
func TestAnEntryThatExpiredDuringTheCallIsNotServed(t *testing.T) {
	e := newEnv(t)
	e.core.answer = &client.Change{ID: "ch-c", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(2 * time.Hour).Format(time.RFC3339Nano)}
	if _, _, err := e.generate(t); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Hour) // past the tree cache's lifetime, inside the clearance's
	e.d.Core = coreFunc(func(context.Context, *client.ChangeRequest) (*client.Change, error) {
		e.now = e.now.Add(2 * time.Hour) // the wait outlasted the clearance
		return nil, &client.UnavailableError{Op: "registerChange", Reason: client.ReasonTimeout}
	})
	if _, objs, err := e.generate(t); err == nil || len(objs) != 0 {
		t.Fatalf("an entry that expired during the call was served: %v", err)
	}
}
