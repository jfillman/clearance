package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
)

// fakeCore speaks the core's wait route: GET /v1/clearances/{id} and GET /v1/clearances/{id}/wait?state=&timeout=.
// A wait returns at once when the state differs from the given one, and otherwise when the change is moved or the
// poll runs out (a short one here).
type fakeCore struct {
	mu     sync.Mutex
	state  string
	by     string
	moved  chan struct{}
	calls  []string
	down   int    // fail this many calls with 503
	status int    // answer every call with this status (a refusal)
	auth   string // the bearer token last seen
}

func newFake(state string) *fakeCore { return &fakeCore{state: state, moved: make(chan struct{}, 1)} }

func (f *fakeCore) set(state, by string) {
	f.mu.Lock()
	f.state, f.by = state, by
	f.mu.Unlock()
	select {
	case f.moved <- struct{}{}:
	default:
	}
}

func (f *fakeCore) answer() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var by any
	if f.by != "" {
		by = f.by
	}
	return map[string]any{"id": "ch-1", "state": f.state, "app": "gate-api", "env": "prod", "cluster": "hangar-prod", "repo": "o/r", "pr": 0,
		"head": strings.Repeat("a", 40), "tree_digest": strings.Repeat("b", 64), "tier": 2, "cleared_by": by, "task_id": nil,
		"expires_at": "2030-01-01T00:00:00+00:00", "token": nil}
}

func (f *fakeCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.URL.RequestURI())
	f.auth = r.Header.Get("Authorization")
	down, status := f.down, f.status
	if f.down > 0 {
		f.down--
	}
	f.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"neither a registered provider nor the verifier that registered this change"}`))
		return
	}
	if down > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	a := f.answer()
	if strings.HasSuffix(r.URL.Path, "/wait") {
		known := r.URL.Query().Get("state")
		secs, _ := strconv.Atoi(r.URL.Query().Get("timeout"))
		changed := a["state"] != known
		if !changed {
			select {
			case <-f.moved:
			case <-time.After(time.Duration(secs) * time.Second / 30): // a poll of 30 s is 1 s here
			case <-r.Context().Done():
			}
			a = f.answer()
			changed = a["state"] != known
		}
		a["changed"] = changed
	}
	_ = json.NewEncoder(w).Encode(a)
}

func run(t *testing.T, f *fakeCore, o Options) (int, string, string) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := client.New(client.Options{BaseURL: srv.URL, Token: client.StaticToken("test-token"), Timeout: 5 * time.Second, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	o.ChangeID, o.Out = "ch-1", &out
	if o.Timeout == 0 {
		o.Timeout = time.Minute
	}
	if o.Poll == 0 {
		o.Poll = time.Second
	}
	if o.Backoff == 0 {
		o.Backoff = time.Millisecond
	}
	code, msg := Wait(context.Background(), c, o)
	return code, msg, out.String()
}

func TestAlreadyClearedExitsZeroAtOnce(t *testing.T) {
	f := newFake("cleared")
	f.set("cleared", "user:erin")
	code, msg, _ := run(t, f, Options{})
	if code != ExitCleared || !strings.Contains(msg, "cleared") || !strings.Contains(msg, "user:erin") || len(f.calls) != 1 {
		t.Fatal(code, msg, f.calls)
	}
	if f.auth != "Bearer test-token" {
		t.Fatal("the call carries the token")
	}
}

func TestHoldingThenClearedExitsZero(t *testing.T) {
	f := newFake("holding")
	go func() { time.Sleep(150 * time.Millisecond); f.set("cleared", "user:erin") }()
	code, msg, out := run(t, f, Options{})
	if code != ExitCleared || !strings.Contains(out, "is holding") || !strings.Contains(out, "is cleared") {
		t.Fatal(code, msg, out)
	}
	if !strings.Contains(f.calls[len(f.calls)-1], "/wait?state=holding") {
		t.Fatalf("it long-polls on the state it saw: %v", f.calls)
	}
}

func TestDeniedExpiredAndSupersededExitNonZero(t *testing.T) {
	for _, state := range []string{"denied", "expired", "superseded", "exception"} {
		f := newFake("holding")
		go func() { time.Sleep(100 * time.Millisecond); f.set(state, "") }()
		code, msg, _ := run(t, f, Options{})
		if code != ExitFailed || !strings.Contains(msg, "clearance "+state) || !strings.Contains(msg, "nothing was applied") {
			t.Errorf("%s: %d %q", state, code, msg)
		}
	}
	f := newFake("denied") // denied before the Job even started
	if code, _, _ := run(t, f, Options{}); code != ExitFailed || len(f.calls) != 1 {
		t.Fatal(code, f.calls)
	}
}

func TestTimeoutExitsNonZeroAndSaysAwaitingApproval(t *testing.T) {
	f := newFake("holding")
	now := time.Now()
	calls := 0
	code, msg, _ := run(t, f, Options{Timeout: 2 * time.Second, Now: func() time.Time {
		calls++
		return now.Add(time.Duration(calls) * 700 * time.Millisecond) // each look at the clock is 0.7 s later
	}})
	if code != ExitTimeout || !strings.HasPrefix(msg, "clearance awaiting approval:") || !strings.Contains(msg, `"holding"`) {
		t.Fatal(code, msg)
	}
}

func TestAnUnreachableCoreIsRetriedNotTreatedAsADecision(t *testing.T) {
	f := newFake("cleared")
	f.down = 4 // two attempts of the client each, two rounds
	code, msg, out := run(t, f, Options{})
	if code != ExitCleared || !strings.Contains(out, "unreachable") {
		t.Fatal(code, msg, out)
	}
}

func TestACoreRefusalExitsNonZeroWithoutRetrying(t *testing.T) {
	f := newFake("holding")
	f.status = http.StatusForbidden
	code, msg, _ := run(t, f, Options{})
	if code != ExitFailed || !strings.Contains(msg, "refused") || len(f.calls) != 1 {
		t.Fatal(code, msg, f.calls)
	}
}

func TestATokenOrResponseFailureIsNotCalledARefusal(t *testing.T) {
	f := newFake("holding")
	srv := httptest.NewServer(f)
	defer srv.Close()
	noToken := client.TokenFunc(func(context.Context) (string, error) { return "", os.ErrNotExist })
	c, _ := client.New(client.Options{BaseURL: srv.URL, Token: noToken, Timeout: time.Second})
	code, msg := Wait(context.Background(), c, Options{ChangeID: "ch-1", Timeout: time.Minute, Poll: time.Second})
	if code != ExitFailed || strings.Contains(msg, "refused") || !strings.Contains(msg, "no token") {
		t.Fatal(code, msg)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) }))
	defer bad.Close()
	c, _ = client.New(client.Options{BaseURL: bad.URL, Token: client.StaticToken("t"), Timeout: time.Second})
	code, msg = Wait(context.Background(), c, Options{ChangeID: "ch-1", Timeout: time.Minute, Poll: time.Second})
	if code != ExitFailed || strings.Contains(msg, "refused") || !strings.Contains(msg, "unreadable") {
		t.Fatal(code, msg)
	}
}
