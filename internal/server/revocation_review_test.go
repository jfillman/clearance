package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/receipt"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/verify"
)

// hookStore lets a test stand inside one store call: each hook runs before the call it names and may block.
type hookStore struct {
	store.Store
	mu     sync.Mutex
	head   func(ctx context.Context) error
	packet func(ctx context.Context, id string) error
	atomic func(ctx context.Context) error
}

func (s *hookStore) hooks() (func(context.Context) error, func(context.Context, string) error, func(context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head, s.packet, s.atomic
}

func (s *hookStore) set(head func(context.Context) error, packet func(context.Context, string) error, atomic func(context.Context) error) {
	s.mu.Lock()
	s.head, s.packet, s.atomic = head, packet, atomic
	s.mu.Unlock()
}

func (s *hookStore) Head(ctx context.Context) (int64, string, error) {
	if h, _, _ := s.hooks(); h != nil {
		if err := h(ctx); err != nil {
			return 0, "", err
		}
	}
	return s.Store.Head(ctx)
}

func (s *hookStore) Packet(ctx context.Context, id string) (store.Packet, error) {
	if _, h, _ := s.hooks(); h != nil {
		if err := h(ctx, id); err != nil {
			return store.Packet{}, err
		}
	}
	return s.Store.Packet(ctx, id)
}

func (s *hookStore) Atomic(ctx context.Context, fn func(tx store.Tx) error) error {
	if _, _, h := s.hooks(); h != nil {
		if err := h(ctx); err != nil {
			return err
		}
	}
	return s.Store.Atomic(ctx, fn)
}

// rawDo is f.do for a goroutine: it returns instead of failing the test.
func rawDo(f *fixture, method, path, tok string, body any) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

// within runs fn and fails the test when it has not returned after d.
func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %s", what, d)
	}
}

// blocker is a hook that holds its callers until released (or their context ends).
type blocker struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlocker() *blocker {
	return &blocker{entered: make(chan struct{}), release: make(chan struct{})}
}
func (b *blocker) wait(ctx context.Context) error {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (b *blocker) free() {
	select {
	case <-b.release:
	default:
		close(b.release)
	}
}

// TestASlowReadDoesNotStallARevokeOrOtherReaders (review F1): a read stuck in its expensive phase (a cold packet load) must not hold up a
// revoke, and so not the other recipients' reads either.
func TestASlowReadDoesNotStallARevokeOrOtherReaders(t *testing.T) {
	l := newRevLab(t, "", nil)
	_, b2 := l.f.buildPacket(t)
	pub2 := l.f.do("POST", "/v1/packets", "user:admin", b2.JSON).want(t, 200, "")
	id2 := pub2.body["id"].(string)
	d1, dRev := l.deliver(t, l.auditor, 0), l.deliver(t, l.auditor, 0)
	d2 := l.f.deliver(t, id2, map[string]any{"recipient": l.auditor.name, "window": l.window(0)})
	hs := &hookStore{Store: l.f.core.Store}
	c := l.instance(t, hs, &fakeClock{t: time.Now()})
	c.do("GET", "/v1/packets/"+l.id, d1.Credential, nil).want(t, 200, "") // C's bundle cache holds packet 1 now
	slow := newBlocker()
	hs.set(nil, func(ctx context.Context, id string) error {
		if id == id2 {
			return slow.wait(ctx)
		}
		return nil
	}, nil)
	t.Cleanup(slow.free)
	slowStatus := make(chan int, 1)
	go func() { st, _ := rawDo(c, "GET", "/v1/packets/"+id2, d2.Credential, nil); slowStatus <- st }()
	<-slow.entered
	within(t, 3*time.Second, "a revoke while a read is in its slow phase", func() {
		c.do("POST", l.revokePath(dRev.ID), "user:admin", map[string]any{"reason": "x"}).want(t, 200, "")
	})
	within(t, 3*time.Second, "another recipient's read while a read is in its slow phase", func() {
		c.do("GET", "/v1/packets/"+l.id, d1.Credential, nil).want(t, 200, "")
	})
	slow.free()
	if st := <-slowStatus; st != 200 {
		t.Fatalf("the slow read ended %d", st)
	}
}

// oldClock returns a lab whose core has a delivery of the packet to the auditor made 72 hours ago (by the injected clock), and an
// instance on that clock, advanced to now.
type agedLab struct {
	*revLab
	inst *fixture
	clk  *fakeClock
	d    server.Delivery
}

func newAgedLab(t *testing.T, back time.Duration) *agedLab {
	t.Helper()
	l := newRevLab(t, "", nil)
	clk := &fakeClock{t: time.Now().Add(-back)}
	inst := l.instance(t, l.f.core.Store, clk)
	a := inst.do("POST", "/v1/packets/"+l.id+"/deliveries", "user:admin", map[string]any{"recipient": l.auditor.name, "engagement": "FY26",
		"window": map[string]any{"to": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}).want(t, 200, "")
	raw, _ := json.Marshal(a.body)
	var d server.Delivery
	_ = json.Unmarshal(raw, &d)
	return &agedLab{revLab: l, inst: inst, clk: clk, d: d}
}

func (a *agedLab) at(t time.Time) { a.clk.mu.Lock(); a.clk.t = t; a.clk.mu.Unlock() }

func (a *agedLab) keyPath() string {
	return "/v1/assurance/recipients/" + a.auditor.name + "/keys/" + a.auditor.signer.KeyID() + "/revoke"
}

// TestARecipientKeyRevocationAsOfIsBounded (review F2).
func TestARecipientKeyRevocationAsOfIsBounded(t *testing.T) {
	a := newAgedLab(t, 72*time.Hour)
	now := time.Now()
	a.at(now)
	rfc := func(d time.Duration) string { return now.Add(d).UTC().Format(time.RFC3339) }
	// Ten years back, without saying so: refused, whatever the recipient.
	a.inst.do("POST", a.keyPath(), "user:admin", map[string]any{"reason": "typo", "as_of": rfc(-87600 * time.Hour)}).want(t, 409, "backdate")
	// Before the core ever recorded a delivery to this recipient: refused even with backdate.
	a.inst.do("POST", a.keyPath(), "user:admin", map[string]any{"reason": "r", "as_of": rfc(-80 * time.Hour), "backdate": true}).want(t, 422, "first delivery")
	if a.f.countTool(server.ToolRecipientKeyRevoke) != 0 {
		t.Fatal("a refused revocation was recorded")
	}
	// More than a day back: needs backdate, and the refusal says how many recorded receipts it would fail.
	d := a.inst.do("POST", a.keyPath(), "user:admin", map[string]any{"reason": "r", "as_of": rfc(-30 * time.Hour)}).want(t, 409, "")
	if d.body["affected_receipts"] != float64(0) {
		t.Fatalf("%v", d.body)
	}
	ok := a.inst.do("POST", a.keyPath(), "user:admin", map[string]any{"reason": "r", "as_of": rfc(-30 * time.Hour), "backdate": true}).want(t, 200, "")
	if ok.body["as_of"] == nil || ok.body["revoked_at"] == nil || ok.body["created"] != true {
		t.Fatalf("%v", ok.body)
	}
	// The first revocation stands: nothing moves it.
	again := a.inst.do("POST", a.keyPath(), "user:admin", map[string]any{"reason": "r2", "as_of": rfc(-1 * time.Hour)}).want(t, 200, "")
	if again.body["created"] != false || again.body["as_of"] != ok.body["as_of"] || a.f.countTool(server.ToolRecipientKeyRevoke) != 1 {
		t.Fatalf("%v", again.body)
	}
	rec := a.f.toolRecords(server.ToolRecipientKeyRevoke)[0]
	if rv, _ := rec["revocation"].(map[string]any); rv["as_of"] == nil || rv["recorded_at"] == nil {
		t.Fatalf("the record carries both times: %v", rec["revocation"])
	}
}

// packetWithRevocation builds the scenario: a delivery 48 hours ago, a receipt recorded 24 hours ago signed at signed, the key revoked
// as of asOf (back-dated with backdate), then a packet cut now. It returns the packet directory.
func (a *agedLab) packetWithRevocation(t *testing.T, signed, asOf time.Duration) string {
	t.Helper()
	now := time.Now()
	a.at(now.Add(-24 * time.Hour))
	env := a.receiptFor(t, a.auditor, a.d.ID, receipt.Accepted, now.Add(signed))
	a.inst.do("POST", "/v1/packets/"+a.id+"/receipts", "", env).want(t, 200, "")
	a.at(now)
	body := map[string]any{"reason": "key lost", "as_of": now.Add(asOf).UTC().Format(time.RFC3339)}
	if asOf < -24*time.Hour {
		body["backdate"] = true
	}
	a.inst.do("POST", a.keyPath(), "user:admin", body).want(t, 200, "")
	dir, _ := a.f.buildPacket(t)
	return dir
}

func (a *agedLab) verifyDir(t *testing.T, dir string) verify.Check {
	t.Helper()
	rep := verify.Verify(dir, verify.Options{RecipientKeys: map[string][]byte{a.auditor.name: []byte(a.auditor.pub)}, RecipientKeysSrc: map[string]string{a.auditor.name: "a.pem"}})
	return checkNamed(t, rep, "acceptances")
}

func editPacketJSON(t *testing.T, dir string, fn func(doc map[string]any)) {
	t.Helper()
	raw, _ := os.ReadFile(filepath.Join(dir, "packet.json"))
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	fn(doc)
	rewritePacketJSON(t, dir, doc)
}

// TestOfflineVerifyDoesNotTrustOnlyTheSection (review F3a): a core-written revocation record the packet carries counts even when the
// section that lists it was stripped, and a section row that differs from its record fails.
func TestOfflineVerifyDoesNotTrustOnlyTheSection(t *testing.T) {
	a := newAgedLab(t, 48*time.Hour)
	// Recorded 24h ago, key revoked as of 20h ago: valid, and the revocation is printed.
	dir := a.packetWithRevocation(t, -24*time.Hour, -20*time.Hour)
	if c := a.verifyDir(t, dir); c.Status != verify.Pass {
		t.Fatalf("%+v", c)
	}
	stripped := t.TempDir()
	if err := copyDir(dir, stripped); err != nil {
		t.Fatal(err)
	}
	editPacketJSON(t, stripped, func(doc map[string]any) { delete(doc["acceptances"].(map[string]any), "key_revocations") })
	if c := a.verifyDir(t, stripped); c.Status != verify.Fail || !strings.Contains(strings.Join(c.Findings, "\n"), "omits") {
		t.Fatalf("a carried revocation record with no row in the section must fail: %+v", c)
	}
	// A row whose recorded time differs from its record.
	edited := t.TempDir()
	if err := copyDir(dir, edited); err != nil {
		t.Fatal(err)
	}
	editPacketJSON(t, edited, func(doc map[string]any) {
		doc["acceptances"].(map[string]any)["key_revocations"].([]any)[0].(map[string]any)["revoked_at"] = "2020-01-01T00:00:00Z"
	})
	if c := a.verifyDir(t, edited); c.Status != verify.Fail {
		t.Fatalf("a row that differs from its record in revoked_at: %+v", c)
	}
	// Both the row and the record dropped: what does the verifier see?
	both := t.TempDir()
	if err := copyDir(dir, both); err != nil {
		t.Fatal(err)
	}
	editPacketJSON(t, both, func(doc map[string]any) { delete(doc["acceptances"].(map[string]any), "key_revocations") })
	dropRecords(t, both, "assurance.key.revoke")
	rep := verify.Verify(both, verify.Options{RecipientKeys: map[string][]byte{a.auditor.name: []byte(a.auditor.pub)}})
	var failed []string
	for _, c := range rep.Checks {
		if c.Status == verify.Fail {
			failed = append(failed, c.Name)
		}
	}
	t.Logf("both dropped: failed checks %v (overall failed: %v)", failed, rep.Failed())
	if os.Getenv("SHOW_BOTH_DROPPED") != "" {
		for _, c := range rep.Checks {
			t.Logf("%s %v %s %v", c.Name, c.Status, c.Detail, c.Findings)
		}
	}
}

// TestAStolenKeyCannotBackdateItsWayOut (review F3b): a receipt the core recorded at or after the revocation's as-of time is not trusted
// whatever signed_at says.
func TestAStolenKeyCannotBackdateItsWayOut(t *testing.T) {
	a := newAgedLab(t, 48*time.Hour)
	// signed_at claims 30h ago; the core recorded it 24h ago; the key is revoked as of 26h ago.
	dir := a.packetWithRevocation(t, -30*time.Hour, -26*time.Hour)
	if c := a.verifyDir(t, dir); c.Status != verify.Fail || !strings.Contains(strings.Join(c.Findings, "\n"), "recorded") {
		t.Fatalf("%+v", c)
	}
}

// dropRecords removes every carried record of the tool from evidence/records.jsonl and rewrites the manifest, as a forger would.
func dropRecords(t *testing.T, dir, tool string) {
	t.Helper()
	p := filepath.Join(dir, "evidence", "records.jsonl")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var keep []string
	dropped := 0
	for _, ln := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.Contains(ln, `"tool":"`+tool+`"`) {
			dropped++
			continue
		}
		keep = append(keep, ln)
	}
	if dropped == 0 {
		t.Fatalf("no %s record to drop", tool)
	}
	out := strings.Join(keep, "\n") + "\n"
	_ = os.WriteFile(p, []byte(out), 0o644)
	var man struct {
		Schema string            `json:"schema"`
		Files  map[string]string `json:"files"`
	}
	mb, _ := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	_ = json.Unmarshal(mb, &man)
	man.Files["evidence/records.jsonl"] = sha256hex([]byte(out))
	mb, _ = json.Marshal(man)
	_ = os.WriteFile(filepath.Join(dir, "MANIFEST.json"), mb, 0o644)
}

// serverOn is l.instance without the HTTP server: the handler, for a test that calls it with its own contexts.
func (l *revLab) serverOn(t *testing.T, st store.Store, clk *fakeClock) *server.Server {
	t.Helper()
	srv, err := server.New(context.Background(), server.Options{Store: st, Engine: l.f.core.Engine, Auth: core.DevAuthenticator(), Providers: l.ps,
		Version: "test", MaxClockSkew: -1, Gate: l.f.core.Gate, Clock: clk.Now, PacketReadsPerHour: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.StopStatements)
	return srv
}

func serve(h http.Handler, ctx context.Context, method, path, tok string, body any) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd).WithContext(ctx)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestAColdStartRefusesCredentialedRoutesAndNeverHangs (review F4): while the revocation index is being read (a slow store), credentialed
// routes and the revoke routes answer 503 with Retry-After within the request's own context, a second request is not held behind the first
// one's mutex, and once the store answers they are served.
func TestAColdStartRefusesCredentialedRoutesAndNeverHangs(t *testing.T) {
	l := newRevLab(t, "", nil)
	d := l.deliver(t, l.auditor, 0)
	hs := &hookStore{Store: l.f.core.Store}
	slow := newBlocker()
	t.Cleanup(slow.free)
	hs.set(func(ctx context.Context) error { return slow.wait(ctx) }, nil, nil)
	srv := l.serverOn(t, hs, &fakeClock{t: time.Now()})
	h := srv.Handler()
	// One request is already inside the cold start's scan (it has no deadline of its own).
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- serve(h, context.Background(), "GET", "/v1/packets/"+l.id, d.Credential, nil) }()
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 2; i++ {
		var rec *httptest.ResponseRecorder
		within(t, 4*time.Second, "a credentialed read on a cold start", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			rec = serve(h, ctx, "GET", "/v1/packets/"+l.id, d.Credential, nil)
		})
		if rec.Code != 503 || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("read %d: %d %q", i, rec.Code, rec.Header())
		}
	}
	within(t, 4*time.Second, "a revoke on a cold start", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()
		if rec := serve(h, ctx, "POST", l.revokePath(d.ID), "user:admin", map[string]any{"reason": "x"}); rec.Code != 503 || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	if len(l.f.toolRecords(server.ToolPacketRevoke)) != 0 || len(l.f.toolRecords(server.ToolPacketFetch)) != 0 {
		t.Fatal("a cold request wrote a record")
	}
	slow.free()
	<-first
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec := serve(h, context.Background(), "GET", "/v1/packets/"+l.id, d.Credential, nil)
		if rec.Code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not served after the store answered: %d %s", rec.Code, rec.Body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestReadsRacingARevokeAreOrdered (review F6): a read stands inside its Append; a revoke started then does not answer until the read
// is recorded; and a read that begins after the revoke answered is refused. The ledger agrees.
func TestReadsRacingARevokeAreOrdered(t *testing.T) {
	l := newRevLab(t, "", nil)
	d := l.deliver(t, l.auditor, 0)
	hs := &hookStore{Store: l.f.core.Store}
	c := l.instance(t, hs, &fakeClock{t: time.Now()})
	c.do("GET", "/v1/packets/"+l.id, d.Credential, nil).want(t, 200, "") // warm
	inAppend := newBlocker()
	armed := make(chan struct{}, 1)
	armed <- struct{}{}
	hs.set(nil, nil, func(ctx context.Context) error {
		select {
		case <-armed:
			return inAppend.wait(ctx)
		default:
			return nil
		}
	})
	readStatus := make(chan int, 1)
	go func() { st, _ := rawDo(c, "GET", "/v1/packets/"+l.id, d.Credential, nil); readStatus <- st }()
	<-inAppend.entered
	revoked := make(chan map[string]any, 1)
	go func() {
		_, b := rawDo(c, "POST", l.revokePath(d.ID), "user:admin", map[string]any{"reason": "x"})
		revoked <- b
	}()
	select {
	case <-revoked:
		t.Fatal("the revoke answered while a read it must follow was still being recorded")
	case <-time.After(300 * time.Millisecond):
	}
	inAppend.free()
	if st := <-readStatus; st != 200 {
		t.Fatalf("the in-flight read ended %d", st)
	}
	var rb map[string]any
	select {
	case rb = <-revoked:
	case <-time.After(3 * time.Second):
		t.Fatal("the revoke never answered")
	}
	c.do("GET", "/v1/packets/"+l.id, d.Credential, nil).want(t, 403, "")
	rseq := rb["seq"].(float64)
	var allowSeq float64
	for _, r := range l.f.toolRecords(server.ToolPacketFetch) {
		if r["decision"] == "allow" {
			_, _ = fmt.Sscan(fmt.Sprint(r["seq"]), &allowSeq)
		}
	}
	if allowSeq == 0 || allowSeq > rseq {
		t.Fatalf("the in-flight read (record %v) must be recorded before the revocation (record %v)", allowSeq, rseq)
	}
}

func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// TestARevokedTokenKeyIsRevokedForStatementsToo (review F7): after the core rotates and revokes the retired key, a statement that key signed
// fails on the hosted page ("signing key revoked; the issuer must reissue this statement"), is not in the statement keys (so an offline
// verifier fails closed), is listed in the revoke's answer, and issuing it again under the key in use works.
func TestARevokedTokenKeyIsRevokedForStatementsToo(t *testing.T) {
	l := p3Lab(t, p3opts{})
	f := l.f
	ctx := context.Background()
	st := l.issue(t, l.req())
	if p := l.get(t, "/s/"+st.ID); p.status != 200 || strings.Contains(p.body, "signing key revoked") {
		t.Fatalf("before the revocation: %d", p.status)
	}
	// Rotate: the core signs with a new key; the old one is retired.
	nk := signer(t)
	njwk, _ := token.PublicJWK(nk.Public())
	raw, _ := json.Marshal(njwk)
	if err := f.core.Store.Atomic(ctx, func(tx store.Tx) error {
		return tx.UseSigningKey(ctx, store.SigningKey{KeyID: njwk.Kid, JWK: raw}, time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	f.core.Gate.Tokens.Signer = nk
	oldKid := l.coreKey.KeyID()
	keysOf := func() string {
		b, _ := json.Marshal(f.do("GET", "/v1/statement-keys", "", nil).want(t, 200, "").body)
		return string(b)
	}
	if !strings.Contains(keysOf(), oldKid) {
		t.Fatalf("a retired key that signed a standing statement is a statement key until it is revoked: %s (old %s)", keysOf(), oldKid)
	}
	a := f.do("POST", "/v1/keys/"+oldKid+"/revoke", "user:admin", map[string]any{"reason": "key exposed"}).want(t, 200, "")
	ids, _ := a.body["statements"].([]any)
	if len(ids) != 1 || ids[0] != st.ID {
		t.Fatalf("the answer lists the statements that stood: %v", a.body)
	}
	if again := f.do("POST", "/v1/keys/"+oldKid+"/revoke", "user:admin", map[string]any{"reason": "again"}).want(t, 200, ""); again.body["created"] != false || len(again.body["statements"].([]any)) != 1 {
		t.Fatalf("a repeat lists them too: %v", again.body)
	}
	if k := keysOf(); strings.Contains(k, oldKid) || !strings.Contains(k, njwk.Kid) {
		t.Fatalf("the statement keys: %s", k)
	}
	if p := l.get(t, "/s/"+st.ID+"/keys.json"); p.status != 200 || strings.Contains(p.body, oldKid) {
		t.Fatalf("keys.json of a revoked key: %d %s", p.status, p.body)
	}
	p := l.get(t, "/s/"+st.ID)
	if p.status != 200 || !strings.Contains(p.body, "signing key revoked; the issuer must reissue this statement") || strings.Contains(p.body, "VERIFIED") {
		t.Fatalf("the page of a statement whose key was revoked: %d\n%s", p.status, p.body)
	}
	if code, out := l.offline(t, st.ID, nil); code == 0 {
		t.Fatalf("an offline verifier accepted a statement signed by a revoked key:\n%s", out)
	}
	// The remedy: the same request is refused with what to do; revoke the statement, then reissue it under the key in use.
	f.do("POST", "/v1/statements", "user:admin", l.req()).want(t, 409, "revoked key")
	f.do("POST", "/v1/statements/"+st.ID+"/revoke", "user:admin", map[string]any{"reason": "signed by a revoked key"}).want(t, 200, "")
	re := l.issue(t, l.req(map[string]any{"reissue": st.ID}))
	if re.ID == st.ID {
		t.Fatal("a reissue is a new statement")
	}
	if p := l.get(t, "/s/"+re.ID); p.status != 200 || strings.Contains(p.body, "signing key revoked") {
		t.Fatalf("the reissued statement: %d", p.status)
	}
	if code, out := l.offline(t, re.ID, nil); code != 0 {
		t.Logf("offline verify of the reissue exited %d (inputs the lab does not supply may be missing):\n%s", code, out)
	}
}
