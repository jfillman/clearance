package server_test

import (
	"context"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
)

func getBody(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// ---- 1: no anonymous request starts anything ----

func TestP3AnAnonymousStatementKeysRequestOnACoreThatNeverIssuedStartsNothingAndReadsNothing(t *testing.T) {
	cfg := config(t, "")
	s := signer(t)
	cfg.Signer, cfg.TokenIssuer, cfg.TokenTTL = s, "clearance", 15*time.Minute
	f := newFixture(t, cfg)
	if f.core.Server.StatementsSeenForTest() || f.core.Server.StatementLoopRunningForTest() {
		t.Fatal("a core that never issued a statement is running the statement loop")
	}
	calls := f.core.Server.CountStoreCallsForTest()
	before := runtime.NumGoroutine()
	for i := 0; i < 30; i++ {
		code, body := getBody(t, f.srv.URL+"/v1/statement-keys")
		if code != 200 || !strings.Contains(body, s.KeyID()) || strings.Count(body, `"kid"`) != 1 {
			t.Fatalf("%d %s: the answer is the key in use and nothing else", code, body)
		}
	}
	if n := calls(); n != 0 {
		t.Errorf("%d store calls for anonymous requests on a core with no statements", n)
	}
	if f.core.Server.StatementLoopRunningForTest() {
		t.Error("an anonymous request started the statement loop")
	}
	time.Sleep(1500 * time.Millisecond) // the loop, had it started, would have polled by now
	if n := calls(); n != 0 {
		t.Errorf("%d store calls a second later: something polls the chain", n)
	}
	if after := runtime.NumGoroutine(); after > before+3 {
		t.Errorf("goroutines %d -> %d", before, after)
	}
}

func TestP3ACoreRestartedWithStatementsAndThePageOffServesStatementKeysAfterTheBackgroundWarm(t *testing.T) {
	l := p3Lab(t, p3opts{noPage: true})
	if l.verifier != nil {
		t.Fatal("the page was built")
	}
	l.issue(t, l.req())
	if err := l.f.core.Server.RestartStatementsForTest(); err != nil {
		t.Fatal(err)
	}
	if !l.f.core.Server.StatementsSeenForTest() {
		t.Fatal("the startup pass did not see the statement")
	}
	waitFor(t, func() bool {
		code, body := getBody(t, l.f.srv.URL+"/v1/statement-keys")
		return code == 200 && strings.Contains(body, l.coreKey.KeyID())
	})
}

func TestP3AStartAfterStopDoesNothing(t *testing.T) {
	l := p3Lab(t, p3opts{})
	l.issue(t, l.req())
	l.f.core.Server.StopStatements()
	waitFor(t, func() bool { return !l.f.core.Server.StatementLoopRunningForTest() })
	before := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		l.f.core.Server.StartStatements()
		l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"policy_version": "gate-after-stop"}))
		l.f.do("GET", "/v1/statements?key="+l.coreKey.KeyID(), "user:admin", nil)
		l.f.core.Server.VerifyHandler()
	}
	time.Sleep(300 * time.Millisecond)
	if l.f.core.Server.StatementLoopRunningForTest() {
		t.Error("the loop was restarted after the core stopped it")
	}
	if after := runtime.NumGoroutine(); after > before+3 {
		t.Errorf("goroutines %d -> %d", before, after)
	}
}

// ---- 2: only the core's own statement records count ----

func TestP3ARecordsWithAStatementToolNameButNotTheCoresMarksAreIgnored(t *testing.T) {
	l := p3Lab(t, p3opts{})
	real := l.issue(t, l.req())
	rogue := evidence.Writer{Provider: evidence.Provider{Name: "rogue-provider", Version: "1"}, Verified: map[string]bool{"tool": true, "statement": true, "packet": true}}
	unmarked := evidence.Core("test") // the core's provider, but the statement is not a field it verified
	a, b := "st-"+strings.Repeat("e", 32), "st-"+strings.Repeat("f", 32)
	l.forgeWith(t, a, l.docFor(t, a), l.coreKey, rogue)
	l.forgeWith(t, b, l.docFor(t, b), l.coreKey, unmarked)
	// A revoke of the real statement by the same two.
	for _, w := range []evidence.Writer{rogue, unmarked} {
		w := w
		if err := l.f.core.Store.Atomic(context.Background(), func(tx store.Tx) error {
			_, err := tx.Append(context.Background(), revokeEvent(real.ID), w)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.f.core.Server.RefreshStatementsForTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if n := l.f.core.Server.StatementIndexSizeForTest(); n != 1 {
		t.Errorf("%d statements indexed: a record without the core's marks was believed", n)
	}
	for _, id := range []string{a, b} {
		if p := l.get(t, "/s/"+id); p.status != 404 {
			t.Errorf("%s: %d", id, p.status)
		}
	}
	if w := l.get(t, "/s/"+real.ID).word(); w == "REVOKED" {
		t.Error("a revoke written by someone who is not the core revoked the statement")
	}
}

// ---- 3: repeated downloads do not read the store ----

func TestP3RepeatedStatementDownloadsReadTheStoreOnce(t *testing.T) {
	l := p3Lab(t, p3opts{})
	st := l.issue(t, l.req())
	first := l.get(t, "/s/"+st.ID+"/statement.json")
	if first.status != 200 {
		t.Fatalf("%d", first.status)
	}
	time.Sleep(2500 * time.Millisecond) // the background read folds the issue record in once; after that it only asks the chain's head
	records := l.f.core.Server.CountReadsForTest()
	for i := 0; i < 10; i++ {
		if p := l.get(t, "/s/"+st.ID+"/statement.json"); p.status != 200 || p.body != first.body {
			t.Fatalf("download %d: %d", i, p.status)
		}
	}
	if n := records(); n != 0 {
		t.Errorf("%d reads of the chain for repeated downloads of an immutable statement", n)
	}
}

func revokeEvent(id string) store.Event {
	return store.Event{"ts": time.Now().UTC().Format(time.RFC3339), "task_id": nil, "session": nil, "parent": nil,
		"principal": "user:admin", "agent": nil, "tool": server.ToolStatementRevoke, "tier": nil, "decision": "allow", "rule": nil,
		"target": "statement:" + id, "args_sha256": p2hex('0'), "boundary": "deployment", "result": "forged revoke",
		"statement": map[string]any{"id": id, "reason": "forged"}}
}
