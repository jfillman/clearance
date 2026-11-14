package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/statement"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// ---- item 1 and 2: the client address and the budgets ----

func TestP3BehindAProxyEveryVisitorIsTheirOwnClientAndDirectIgnoresTheHeader(t *testing.T) {
	// Behind one trusted hop, visitors the proxy saw as different addresses have separate budgets.
	l := p3Lab(t, p3opts{stmt: func(o *server.StatementOptions) { o.ClientPerMinute, o.ClientBurst, o.TrustedProxyHops = 1, 2, 1 }})
	st := l.issue(t, l.req())
	for i := 0; i < 6; i++ {
		if p := l.getWith(t, "GET", "/s/"+st.ID, map[string]string{"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i)}); p.status != 200 {
			t.Fatalf("visitor %d: %d", i, p.status)
		}
	}
	// One visitor is still limited, whatever else the header carries to its left.
	n429 := 0
	for i := 0; i < 5; i++ {
		if p := l.getWith(t, "GET", "/s/"+st.ID, map[string]string{"X-Forwarded-For": fmt.Sprintf("10.9.9.%d, 203.0.113.7", i)}); p.status == 429 {
			n429++
		}
	}
	if n429 < 3 {
		t.Errorf("a visitor that prepends addresses to its header escaped its own budget (%d refusals)", n429)
	}
	// A listener with no proxy ignores the header altogether: changing it buys no new budget.
	d := p3Lab(t, p3opts{stmt: func(o *server.StatementOptions) { o.ClientPerMinute, o.ClientBurst, o.TrustedProxyHops = 1, 3, 0 }})
	ds := d.issue(t, d.req())
	n429 = 0
	for i := 0; i < 8; i++ {
		if p := d.getWith(t, "GET", "/s/"+ds.ID, map[string]string{"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i)}); p.status == 429 {
			n429++
		}
	}
	if n429 < 4 {
		t.Errorf("a direct listener believed X-Forwarded-For (%d refusals of 8)", n429)
	}
}

func TestP3ADrainOfCheapRequestsDoesNotStarveAnyoneElsesRead(t *testing.T) {
	l := p3Lab(t, p3opts{stmt: func(o *server.StatementOptions) {
		o.ClientPerMinute, o.ClientBurst, o.TrustedProxyHops, o.GlobalPerMinute, o.GlobalBurst = 6000, 1000, 1, 1, 2
	}})
	a := l.issue(t, l.req())
	b := l.issue(t, l.req(map[string]any{"policy_version": "gate-b"}))
	c := l.issue(t, l.req(map[string]any{"policy_version": "gate-c"}))
	xff := func(i int) map[string]string {
		return map[string]string{"X-Forwarded-For": fmt.Sprintf("203.0.113.%d", i%250)}
	}
	// Many addresses drain the cheap paths: 404s of every kind.
	for i := 0; i < 400; i++ {
		l.getWith(t, "GET", fmt.Sprintf("/s/st-%032x", i), xff(i))
		l.getWith(t, "GET", "/nope", xff(i))
	}
	// The listener's budget for computed work is untouched: two statements are computed for the first time...
	for _, id := range []string{a.ID, b.ID} {
		if p := l.getWith(t, "GET", "/s/"+id, xff(1)); p.status != 200 {
			t.Fatalf("%s: %d after a drain of 404s", id, p.status)
		}
	}
	// ...a third is refused (the budget is for work that costs something)...
	if p := l.getWith(t, "GET", "/s/"+c.ID, xff(2)); p.status != 429 || p.h.Get("Retry-After") == "" {
		t.Errorf("the budget for computed work is not bounded: %d", p.status)
	}
	// ...and reads that cost nothing (a cached page, a status, a download, a 404) are never refused for it.
	for i := 0; i < 20; i++ {
		for _, path := range []string{"/s/" + a.ID, "/s/" + b.ID + "/status.json", "/s/" + a.ID + "/statement.json", "/s/st-" + strings.Repeat("e", 32)} {
			if p := l.getWith(t, "GET", path, xff(i)); p.status != 200 && p.status != 404 {
				t.Fatalf("%s: %d", path, p.status)
			}
		}
	}
	if p := l.getWith(t, "GET", "/s/"+a.ID, xff(3)); p.status != 200 {
		t.Errorf("a cached page read: %d", p.status)
	}
}

// ---- item 3: the page never presents independence as verified ----

func TestP3TheOfflineVerifierTakesAWitnessKeyAndChecksItAgainstThePolicy(t *testing.T) {
	l := p3Lab(t, p3opts{independent: true})
	st := l.issue(t, l.req())
	var vkey string
	for _, ln := range strings.Split(string(l.policy), "\n") {
		if f := strings.Fields(ln); len(f) >= 3 && f[0] == "witness" && f[1] == "ind" {
			vkey = f[2]
		}
	}
	if vkey == "" {
		t.Fatal("no witness key in the policy")
	}
	if code, out := l.offline(t, st.ID, []string{"--independent-witness", "indep-witness=" + vkey}); code != 0 {
		t.Errorf("the right name and key: exit %d\n%s", code, out)
	}
	// A key the policy does not list under that name vouches for nothing.
	if code, out := l.offline(t, st.ID, []string{"--independent-witness", "indep-witness=" + strings.Replace(vkey, "indep-witness", "other", 1)}); code != 2 || !strings.Contains(out, "NOT INDEPENDENTLY WITNESSED") {
		t.Errorf("a wrong key: exit %d\n%s", code, out)
	}
	// The statement's own declaration, with no flag, is never a pass offline.
	if code, _ := l.offline(t, st.ID, nil); code != 2 {
		t.Errorf("unpinned: exit %d", code)
	}
}

// ---- item 4: the index and its locks ----

func TestP3PublicReadsProceedWhileAnIssueIsSlow(t *testing.T) {
	l := p3Lab(t, p3opts{})
	st := l.issue(t, l.req())
	l.get(t, "/s/"+st.ID) // computed and kept
	l.f.core.Server.SlowAtomicForTest(2500 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"policy_version": "gate-slow"}))
	}()
	time.Sleep(300 * time.Millisecond)
	began := time.Now()
	for i := 0; i < 8; i++ {
		for _, p := range []string{"/s/" + st.ID, "/s/" + st.ID + "/status.json", "/s/" + st.ID + "/statement.json", "/s/st-" + strings.Repeat("d", 32)} {
			if got := l.get(t, p); got.status != 200 && got.status != 404 {
				t.Fatalf("%s: %d", p, got.status)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Errorf("public reads were held up by an issue: %s for 32 reads", took)
	}
	select {
	case <-done:
		t.Error("the issue was not slow: the test proves nothing")
	default:
	}
	<-done
}

func TestP3AHungStoreIs503WithoutPilingUpGoroutines(t *testing.T) {
	l := p3Lab(t, p3opts{})
	st := l.issue(t, l.req())
	l.get(t, "/s/"+st.ID)
	l.f.core.Server.HangReadsForTest()
	before := runtime.NumGoroutine()
	var wg sync.WaitGroup
	codes := make([]int, 40)
	began := time.Now()
	for i := range codes {
		wg.Add(1)
		go func() { defer wg.Done(); codes[i] = l.get(t, "/s/"+st.ID).status }()
	}
	wg.Wait()
	for i, c := range codes {
		if c != 503 {
			t.Errorf("request %d: %d, want 503 (it must not say valid on a state it could not read)", i, c)
		}
	}
	if took := time.Since(began); took > 8*time.Second {
		t.Errorf("a hung store held requests for %s", took)
	}
	time.Sleep(500 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+15 {
		t.Errorf("goroutines went from %d to %d", before, after)
	}
	l.f.core.Server.HealReadsForTest()
}

func TestP3AColdIndexIs503AndNoRequestScansTheChain(t *testing.T) {
	l := p3Lab(t, p3opts{})
	st := l.issue(t, l.req())
	l.f.core.Server.ColdStatementIndexForTest()
	reads := l.f.core.Server.CountReadsForTest()
	for i := 0; i < 20; i++ {
		if p := l.get(t, "/s/"+st.ID); p.status != 503 {
			t.Fatalf("a cold index answered %d", p.status)
		}
		if p := l.get(t, "/s/st-"+strings.Repeat("b", 32)); p.status != 503 {
			t.Fatalf("a cold index answered an unknown id %d", p.status)
		}
	}
	if n := reads(); n != 0 {
		t.Errorf("%d reads of the chain on the request path of a cold index", n)
	}
}

func TestP3AFailedWarmIsRetriedInTheBackgroundAndThePageRecovers(t *testing.T) {
	l := p3Lab(t, p3opts{})
	st := l.issue(t, l.req())
	l.f.core.Server.ColdStatementIndexForTest()
	l.f.core.Server.BreakReadsForTest()
	if err := l.f.core.Server.WarmStatements(context.Background()); err == nil {
		t.Fatal("a warm over a store that cannot be read succeeded")
	}
	if p := l.get(t, "/s/"+st.ID); p.status != 503 {
		t.Fatalf("%d", p.status)
	}
	l.f.core.Server.HealReadsForTest()
	deadline := time.Now().Add(12 * time.Second)
	for {
		if p := l.get(t, "/s/"+st.ID); p.status == 200 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the background retry never warmed the index")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// ---- item 5: a statement outlives its key's window ----

func TestP3AStatementStillVerifiesAfterItsKeyLeavesTheRetirementWindow(t *testing.T) {
	l := p3Lab(t, p3opts{independent: true})
	st := l.issue(t, l.req())
	oldKid := l.coreKey.KeyID()
	keysHave := func(kid string) bool {
		resp := l.f.do("GET", "/v1/keys", "", nil)
		raw, _ := json.Marshal(resp.body)
		return strings.Contains(string(raw), kid)
	}
	next := signer(t)
	jwk, err := token.PublicJWK(next.Public())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(jwk)
	if err := l.f.core.Store.Atomic(context.Background(), func(tx store.Tx) error {
		return tx.UseSigningKey(context.Background(), store.SigningKey{KeyID: jwk.Kid, JWK: raw}, time.Now().Add(-60*24*time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	// The old key retired 60 days ago, past the window (31 days): it is still published, for the statement it signed.
	if !keysHave(oldKid) || !keysHave(jwk.Kid) {
		t.Fatal("the key that signed a standing statement is not published")
	}
	l.f.core.Server.ResetStatementIndexForTest()
	if pg := l.get(t, "/s/"+st.ID); pg.checkStatus(t, 0) != "PASS" || pg.checkStatus(t, 1) != "PASS" {
		t.Errorf("the page after the rotation: %s", pg.word())
	}
	if code, out := l.offline(t, st.ID, []string{"--independent-witness", "indep-witness"}); code != 0 {
		t.Errorf("offline after the rotation: exit %d\n%s", code, out)
	}
	// Once the statement is revoked it needs nothing: the old key leaves /v1/keys.
	l.f.do("POST", "/v1/statements/"+st.ID+"/revoke", "user:admin", map[string]any{"reason": "done"}).want(t, 200, "")
	if keysHave(oldKid) {
		t.Error("a key stays published for a statement that no longer stands")
	}
}

// ---- item 6: how old a status may be ----

func TestP3AStatusOlderThanAnHourIsNotAnExitZeroAndTheAsOfIsPrinted(t *testing.T) {
	l := p3Lab(t, p3opts{independent: true})
	st := l.issue(t, l.req())
	signed := func(age time.Duration) string {
		s := statement.Status{Type: statement.StatusSchema, ID: st.ID, State: statement.StateValid, AsOf: time.Now().Add(-age).UTC().Format(time.RFC3339)}
		pl, _ := s.Canonical()
		env, err := token.SignDSSE(context.Background(), l.coreKey, statement.StatusPayloadType, pl)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(env)
		return writeTemp(t, "status.json", b)
	}
	for _, age := range []time.Duration{2 * time.Hour, 25 * time.Hour} {
		code, out := l.offline(t, st.ID, []string{"--independent-witness", "indep-witness", "--status", signed(age)}, "status")
		if code != 2 || !strings.Contains(out, "[NOT CHECKED] 7.") {
			t.Errorf("a status %s old: exit %d\n%s", age, code, out)
		}
	}
	code, out := l.offline(t, st.ID, []string{"--independent-witness", "indep-witness", "--status", signed(20 * time.Minute)}, "status")
	if code != 0 || !strings.Contains(out, "CURRENT STATE AS OF") {
		t.Errorf("a fresh status: exit %d\n%s", code, out)
	}
	// The status the page serves is as of the index's read, never fresher than that.
	var env struct{ Payload string }
	_ = json.Unmarshal([]byte(l.get(t, "/s/"+st.ID+"/status.json").body), &env)
	pl, _ := decodeB64(env.Payload)
	var got statement.Status
	_ = json.Unmarshal(pl, &got)
	when, err := time.Parse(time.RFC3339, got.AsOf)
	if err != nil || time.Since(when) > 3*time.Second || when.After(time.Now().Add(time.Second)) {
		t.Errorf("as_of %q", got.AsOf)
	}
	if !strings.Contains(l.get(t, "/s/"+st.ID).body, "State read "+got.AsOf[:10]) {
		t.Error("the page does not print when its state was read")
	}
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// ---- item 7: what the page shows ----

// forge appends a statement.issue record under id holding a statement of another id, or one signed by another key.
func (l *p3lab) forge(t *testing.T, id string, doc *statement.Document, signWith token.Signer) {
	t.Helper()
	pl, err := doc.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	env, err := token.SignDSSE(context.Background(), signWith, statement.PayloadType, pl)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env)
	var obj any
	_ = json.Unmarshal(b, &obj)
	sum := sha256.Sum256(pl)
	if err := l.f.core.Store.Atomic(context.Background(), func(tx store.Tx) error {
		_, err := tx.Append(context.Background(), store.Event{"ts": time.Now().UTC().Format(time.RFC3339), "task_id": nil, "session": nil, "parent": nil,
			"principal": "user:admin", "agent": nil, "tool": server.ToolStatementIssue, "tier": nil, "decision": "allow", "rule": nil,
			"target": "statement:" + id, "args_sha256": hex.EncodeToString(sum[:]), "boundary": "deployment", "result": "forged for the test",
			"packet":    map[string]any{"id": l.pid, "digest": l.bundle.Digest},
			"statement": map[string]any{"id": id, "profile": "standard", "request_sha256": hex.EncodeToString(sum[:]), "payload_sha256": hex.EncodeToString(sum[:]), "envelope": obj}},
			evidence.Core("test"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (l *p3lab) docFor(t *testing.T, id string) *statement.Document {
	t.Helper()
	d, err := statement.Build(statement.Input{ID: id, Issuer: "clearance", IssuedAt: time.Now().UTC().Format(time.RFC3339), ScopeLabel: "Forged scope", PolicyVersion: "forged-1",
		PacketID: l.pid, PacketDigest: l.bundle.Digest, PacketJSON: l.bundle.Files["packet.json"], RecordsJSONL: l.bundle.Files[packet.FileRecords]})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestP3TheContentIsShownOnlyWhenTheSignatureHoldsAndTheIdIsTheStatementsOwn(t *testing.T) {
	l := p3Lab(t, p3opts{})
	good := l.issue(t, l.req())
	if pg := l.get(t, "/s/"+good.ID); !strings.Contains(pg.body, "Counts by coverage state") || pg.checkStatus(t, 1) != "PASS" {
		t.Fatal("the control shows no summary")
	}
	// A statement signed by the real key, for another id, put under this one.
	b := "st-" + strings.Repeat("b", 32)
	l.forge(t, b, l.docFor(t, "st-"+strings.Repeat("a", 32)), l.coreKey)
	// A statement for its own id, signed by a key the core does not publish.
	c := "st-" + strings.Repeat("c", 32)
	l.forge(t, c, l.docFor(t, c), signer(t))
	time.Sleep(1100 * time.Millisecond)
	for name, id := range map[string]string{"another id": b, "another key": c} {
		pg := l.get(t, "/s/"+id)
		if pg.status != 200 || pg.word() != "FAILED" || strings.Contains(pg.body, "Counts by coverage state") || strings.Contains(pg.body, "Forged scope") || !strings.Contains(pg.body, "did not verify") {
			t.Errorf("%s: %d word %q, the summary is shown or the failure is not", name, pg.status, pg.word())
		}
	}
	if pg := l.get(t, "/s/"+b); pg.checkStatus(t, 1) != "FAIL" {
		t.Errorf("another id: check 2 is %q", pg.checkStatus(t, 1))
	}
	if pg := l.get(t, "/s/"+c); pg.checkStatus(t, 0) != "FAIL" {
		t.Errorf("another key: check 1 is %q", pg.checkStatus(t, 0))
	}
}

// ---- item 8: the issuer is a public name ----

func TestP3AnInternalIssuerNameIsRefusedAtIssue(t *testing.T) {
	bad := p3Lab(t, p3opts{issuer: "https://clearance.hangar.internal"})
	a := bad.f.do("POST", "/v1/statements", "user:admin", bad.req())
	if a.status != 409 || !strings.Contains(fmt.Sprint(a.body["error"]), "CLEARANCE_TOKEN_ISSUER") {
		t.Errorf("an internal issuer: %d %v", a.status, a.body)
	}
	if n := len(bad.f.toolRecords(server.ToolStatementIssue)); n != 0 {
		t.Errorf("%d records", n)
	}
	good := p3Lab(t, p3opts{issuer: "https://clearance.example.com"})
	good.issue(t, good.req())
}

// ---- item 10: a revoked statement is not answered as if it stood ----

func TestP3ARevokedStatementIsNotAnsweredAgainAndCanBeReissuedOnPurpose(t *testing.T) {
	l := p3Lab(t, p3opts{})
	old := l.issue(t, l.req())
	l.f.do("POST", "/v1/statements/"+old.ID+"/revoke", "user:admin", map[string]any{"reason": "wrong policy version"}).want(t, 200, "")
	a := l.f.do("POST", "/v1/statements", "user:admin", l.req())
	if a.status != 409 || !strings.Contains(fmt.Sprint(a.body["error"]), "reissue") || !strings.Contains(fmt.Sprint(a.body["error"]), old.ID) {
		t.Fatalf("the same request after a revocation: %d %v", a.status, a.body)
	}
	if n := len(l.f.toolRecords(server.ToolStatementIssue)); n != 1 {
		t.Fatalf("%d issue records", n)
	}
	nw := l.issue(t, l.req(map[string]any{"reissue": old.ID}))
	if nw.ID == old.ID || !nw.Created || nw.State != "valid" {
		t.Fatalf("%+v", nw)
	}
	recs := l.f.toolRecords(server.ToolStatementIssue)
	last, _ := recs[len(recs)-1]["statement"].(map[string]any)
	if last["reissues"] != old.ID {
		t.Errorf("the record does not say which revoked statement it replaces: %v", last)
	}
	if again := l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"reissue": old.ID})).want(t, 200, ""); again.body["created"] != false || again.body["id"] != nw.ID {
		t.Errorf("a repeat of the reissue: %v", again.body)
	}
	l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"reissue": nw.ID, "policy_version": "gate-x"})).want(t, 409, "not revoked")
	l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"reissue": "st-" + strings.Repeat("9", 32), "policy_version": "gate-y"})).want(t, 404, "")
	l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"reissue": old.ID, "supersedes": nw.ID, "policy_version": "gate-z"})).want(t, 400, "")
	// The old statement still reads revoked.
	if l.get(t, "/s/"+old.ID).word() != "REVOKED" {
		t.Error("the revoked statement does not read revoked")
	}
}

func TestP3AStatementSupersededByOneThatWasRevokedDoesNotReadAsCleanlySuperseded(t *testing.T) {
	l := p3Lab(t, p3opts{})
	a := l.issue(t, l.req())
	b := l.issue(t, l.req(map[string]any{"policy_version": "gate-b", "supersedes": a.ID}))
	if pg := l.get(t, "/s/"+a.ID); pg.word() != "SUPERSEDED" || strings.Contains(pg.body, "itself revoked") {
		t.Fatalf("before: %q", pg.word())
	}
	l.f.do("POST", "/v1/statements/"+b.ID+"/revoke", "user:admin", map[string]any{"reason": "the correction was wrong"}).want(t, 200, "")
	pg := l.get(t, "/s/"+a.ID)
	if pg.word() != "SUPERSEDED" || !strings.Contains(pg.body, "was itself revoked") || !strings.Contains(pg.body, `class="word bad"`) {
		t.Errorf("after: word %q, the successor's revocation is not said", pg.word())
	}
	if !strings.Contains(l.get(t, "/s/"+a.ID+"/status.json").body, "payload") {
		t.Fatal("no status")
	}
	var env struct{ Payload string }
	_ = json.Unmarshal([]byte(l.get(t, "/s/"+a.ID+"/status.json").body), &env)
	pl, _ := decodeB64(env.Payload)
	var st statement.Status
	_ = json.Unmarshal(pl, &st)
	if st.State != "superseded" || st.SupersededBy != b.ID || !st.SuccessorRevoked {
		t.Errorf("%+v", st)
	}
	if code, out := l.offline(t, a.ID, nil); code != 1 || !strings.Contains(out, "SUPERSEDED by "+b.ID) || !strings.Contains(out, "REVOKED") {
		t.Errorf("offline: exit %d\n%s", code, out)
	}
}

// ---- item 11: a statement the packet does not support is never signed ----

func TestP3ADoctoredPacketIsRefusedAtIssueAndNothingIsSigned(t *testing.T) {
	l := p3Lab(t, p3opts{})
	dir := filepath.Join(t.TempDir(), "doctored")
	if err := copyDir(l.dir, dir); err != nil {
		t.Fatal(err)
	}
	// The admin edits a count in packet.json and rewrites the manifest to match: a packet that is a valid bundle and a lie.
	pj := filepath.Join(dir, "packet.json")
	raw, _ := os.ReadFile(pj)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	cov := doc["coverage_statement"].(map[string]any)
	cov["total_records"] = cov["total_records"].(float64) + 100
	edited, _ := json.Marshal(doc)
	if err := os.WriteFile(pj, edited, 0o644); err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(dir, "MANIFEST.json")
	mraw, _ := os.ReadFile(mp)
	var man map[string]any
	if err := json.Unmarshal(mraw, &man); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(edited)
	man["files"].(map[string]any)["packet.json"] = hex.EncodeToString(sum[:])
	mraw, _ = json.Marshal(man)
	if err := os.WriteFile(mp, mraw, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := packet.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.f.do("POST", "/v1/packets", "user:admin", b.JSON).want(t, 200, "")
	a := l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"packet": b.ID}))
	if a.status != 422 || !strings.Contains(fmt.Sprint(a.body["error"]), "so none was signed") {
		t.Fatalf("a doctored packet: %d %v", a.status, a.body)
	}
	if n := len(l.f.toolRecords(server.ToolStatementIssue)); n != 0 {
		t.Errorf("%d issue records for a statement that was refused", n)
	}
	// The undoctored packet is issued.
	l.issue(t, l.req())
}

var _ = bytes.Equal
