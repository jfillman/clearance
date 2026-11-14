package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/assurance"
	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/receipt"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// revLab is a core with a signing key, two registered recipients, a published packet and, on demand, deliveries.
type revLab struct {
	f       *fixture
	coreKey *token.KeySigner
	auditor *fakeRecipient
	grc     *fakeRecipient
	ps      []server.Provider
	id      string
	bundle  *packet.Bundle
}

// onStores runs fn on the in-memory store and, when CLEARANCE_TEST_DSN is set, on Postgres.
func onStores(t *testing.T, fn func(t *testing.T, dsn string)) {
	t.Run("memory", func(t *testing.T) { fn(t, "") })
	t.Run("postgres", func(t *testing.T) { fn(t, pgDSN(t)) })
}

func newRevLab(t *testing.T, dsn string, mut func(*core.Config)) *revLab {
	t.Helper()
	a, b := newFakeRecipient(t, "lab-auditor"), newFakeRecipient(t, "lab-grc-hub")
	var base []map[string]any
	if err := json.Unmarshal([]byte(providersJSON), &base); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(append(base, a.registration(), b.registration()))
	ps, err := server.ParseProviders(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, dsn)
	cfg.Providers = ps
	s := signer(t)
	cfg.Signer, cfg.TokenIssuer, cfg.TokenTTL = s, "clearance", 15*time.Minute
	if mut != nil {
		mut(&cfg)
	}
	f := newFixture(t, cfg)
	f.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "")
	_, orig := f.buildPacket(t)
	pub := f.do("POST", "/v1/packets", "user:admin", orig.JSON).want(t, 200, "")
	return &revLab{f: f, coreKey: s, auditor: a, grc: b, ps: ps, id: pub.body["id"].(string), bundle: orig}
}

func (l *revLab) window(from time.Duration) map[string]any {
	return map[string]any{"from": time.Now().Add(from).UTC().Format(time.RFC3339), "to": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
}

func (l *revLab) deliver(t *testing.T, r *fakeRecipient, from time.Duration) server.Delivery {
	t.Helper()
	return l.f.deliver(t, l.id, map[string]any{"recipient": r.name, "window": l.window(from), "engagement": "FY26"})
}

func (l *revLab) read(cred string) answer { return l.f.do("GET", "/v1/packets/"+l.id, cred, nil) }

func (l *revLab) revokePath(did string) string {
	return "/v1/packets/" + l.id + "/deliveries/" + did + "/revoke"
}

// receiptFor signs a receipt for the delivery with r's key, at signedAt, with the verdict.
func (l *revLab) receiptFor(t *testing.T, r *fakeRecipient, did, verdict string, signedAt time.Time) []byte {
	t.Helper()
	p, err := assurance.Payload(l.bundle, assurance.Review{Delivery: did, Recipient: r.name, Engagement: "FY26", Verdict: verdict, Now: signedAt})
	if err != nil {
		t.Fatal(err)
	}
	env, err := receipt.Sign(context.Background(), r.signer, p)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (l *revLab) submit(env []byte) answer {
	return l.f.do("POST", "/v1/packets/"+l.id+"/receipts", "", env)
}

func ruleOf(a answer) string { s, _ := a.body["rule"].(string); return s }

func (f *fixture) countTool(tool string) int { return len(f.toolRecords(tool)) }

func (f *fixture) denyCount(tool, rule string) int {
	n := 0
	for _, r := range f.toolRecords(tool) {
		if r["decision"] == "deny" && r["rule"] == rule {
			n++
		}
	}
	return n
}

func chainOK(t *testing.T, f *fixture) {
	t.Helper()
	if ok, bad := evidence.Verify(f.records()); !ok {
		t.Fatalf("the chain breaks at %d", bad)
	}
}

// TestRevokeDelivery pins the delivery revoke route: who may call it, the ids it validates, that the record is written before the
// answer and only once, that every read and sample under the credential is then refused PK-REVOKED and recorded, that a receipt
// for it is refused and one already recorded stays, and that another delivery is untouched. On both stores.
func TestRevokeDelivery(t *testing.T) {
	onStores(t, func(t *testing.T, dsn string) {
		l := newRevLab(t, dsn, nil)
		f := l.f
		d := l.deliver(t, l.auditor, 0)
		other := l.deliver(t, l.auditor, 0) // a second delivery to the same recipient, same packet
		grc := l.deliver(t, l.grc, 0)
		l.read(d.Credential).want(t, 200, "")

		// A receipt recorded before the revoke stays recorded.
		before := l.receiptFor(t, l.auditor, d.ID, receipt.Accepted, time.Now())
		l.submit(before).want(t, 200, "")

		path := l.revokePath(d.ID)
		body := map[string]any{"reason": "credential posted in a ticket"}
		// Who: an admin only. A non-admin, nobody, and a recipient credential (not an authenticator token) cannot.
		f.do("POST", path, "user:erin", body).want(t, 403, "")
		f.do("POST", path, "", body).want(t, 401, "")
		f.do("POST", path, d.Credential, body).want(t, 401, "")
		// Ids: a malformed or unknown delivery or packet is one 404, whatever it is.
		f.do("POST", "/v1/packets/not-a-packet/deliveries/"+d.ID+"/revoke", "user:admin", body).want(t, 404, "no such delivery")
		f.do("POST", l.revokePath("dl-x"), "user:admin", body).want(t, 404, "no such delivery")
		f.do("POST", l.revokePath("dl-99999"), "user:admin", body).want(t, 404, "no such delivery")
		f.do("POST", "/v1/packets/pk-00000000000000000000000000000000/deliveries/"+d.ID+"/revoke", "user:admin", body).want(t, 404, "no such delivery")
		// The id of a record that is not a delivery (the packet.publish record is seq 1 or 2: any record that is not a delivery).
		f.do("POST", l.revokePath("dl-0"), "user:admin", body).want(t, 404, "no such delivery")
		// The body: a reason is required and bounded; nothing else is accepted.
		f.do("POST", path, "user:admin", map[string]any{}).want(t, 400, "reason")
		f.do("POST", path, "user:admin", map[string]any{"reason": strings.Repeat("x", 201)}).want(t, 400, "reason")
		f.do("POST", path, "user:admin", map[string]any{"reason": "bad\nline"}).want(t, 400, "reason")
		f.do("POST", path, "user:admin", map[string]any{"reason": "x", "extra": 1}).want(t, 400, "")
		if f.countTool(server.ToolPacketRevoke) != 0 {
			t.Fatal("a refused request wrote a revocation")
		}

		// The revoke: one record, in the chain before the answer.
		a := f.do("POST", path, "user:admin", body).want(t, 200, "")
		if a.body["state"] != "revoked" || a.body["created"] != true || a.body["recipient"] != l.auditor.name || a.body["reason"] != body["reason"] {
			t.Fatalf("%v", a.body)
		}
		rr := f.toolRecords(server.ToolPacketRevoke)
		if len(rr) != 1 || fmt.Sprint(rr[0]["seq"]) != fmt.Sprint(a.body["seq"]) || rr[0]["hash"] != a.body["hash"] || rr[0]["principal"] != "user:admin" {
			t.Fatalf("the revocation is a record of its own: %v", rr)
		}
		// Repeated: the same answer, one record.
		again := f.do("POST", path, "user:admin", map[string]any{"reason": "a different reason"}).want(t, 200, "")
		if again.body["created"] != false || again.body["seq"] != a.body["seq"] || again.body["hash"] != a.body["hash"] || again.body["reason"] != body["reason"] ||
			f.countTool(server.ToolPacketRevoke) != 1 {
			t.Fatalf("a repeat is the first revocation's answer and writes nothing: %v", again.body)
		}

		// A read under the credential is refused, with its rule, and the refusal is a record.
		fetches := f.countTool(server.ToolPacketFetch)
		r := l.read(d.Credential).want(t, 403, "")
		if ruleOf(r) != server.RulePacketRevoked {
			t.Fatalf("%v", r.body)
		}
		if f.countTool(server.ToolPacketFetch) != fetches+1 || f.denyCount(server.ToolPacketFetch, server.RulePacketRevoked) != 1 {
			t.Fatal("the refusal is a record")
		}
		if ruleOf(f.do("GET", "/v1/packets/"+l.id+"?part=summary", d.Credential, nil).want(t, 403, "")) != server.RulePacketRevoked {
			t.Fatal("a part read is refused too")
		}
		// The sample route is refused the same way, and that refusal is a packet.sample record.
		s := f.do("GET", "/v1/packets/"+l.id+"/sample?seed=audit-2026&n=1", d.Credential, nil).want(t, 403, "")
		if ruleOf(s) != server.RulePacketRevoked || f.denyCount(server.ToolPacketSample, server.RulePacketRevoked) != 1 {
			t.Fatalf("%v", s.body)
		}
		// The scope check still comes first on the sample route too: a credential cut to one part gets PK-SCOPE whether or not it was revoked.
		sc := l.f.deliver(t, l.id, map[string]any{"recipient": l.auditor.name, "window": l.window(0), "scope": []string{"summary"}})
		live := f.do("GET", "/v1/packets/"+l.id+"/sample?seed=s", sc.Credential, nil).want(t, 403, "")
		f.do("POST", l.revokePath(sc.ID), "user:admin", map[string]any{"reason": "x"}).want(t, 200, "")
		dead := f.do("GET", "/v1/packets/"+l.id+"/sample?seed=s", sc.Credential, nil).want(t, 403, "")
		if ruleOf(live) != server.RulePacketScope || ruleOf(dead) != server.RulePacketScope {
			t.Fatalf("live %v, revoked %v", live.body, dead.body)
		}
		// It does not say whether a packet exists: asked for another packet, a revoked credential gets the answer any credential gets.
		unknown := "/v1/packets/pk-00000000000000000000000000000000"
		ra := f.do("GET", unknown, d.Credential, nil).want(t, 403, "")
		rb := f.do("GET", unknown, other.Credential, nil).want(t, 403, "")
		if ruleOf(ra) != server.RulePacketScope || ruleOf(rb) != server.RulePacketScope {
			t.Fatalf("revoked %v, live %v", ra.body, rb.body)
		}

		// A receipt: a new one for the revoked delivery is refused and not recorded; the one recorded before stays, and sent again is the same record.
		receipts := f.countTool(packet.ToolReceipt)
		nw := l.submit(l.receiptFor(t, l.auditor, d.ID, receipt.Questioned, time.Now())).want(t, 403, "revoked")
		if ruleOf(nw) != server.RulePacketRevoked || f.countTool(packet.ToolReceipt) != receipts {
			t.Fatalf("%v", nw.body)
		}
		if same := l.submit(before).want(t, 200, ""); same.body["created"] != false || f.countTool(packet.ToolReceipt) != receipts {
			t.Fatalf("a recorded receipt stays: %v", same.body)
		}
		// Another delivery of the same packet, even to the same recipient, is untouched, and so is the recipient's receipt under it.
		l.read(other.Credential).want(t, 200, "")
		l.read(grc.Credential).want(t, 200, "")
		l.submit(l.receiptFor(t, l.auditor, other.ID, receipt.Accepted, time.Now())).want(t, 200, "")
		chainOK(t, f)
		// Nothing secret is in a record.
		for _, rec := range f.records() {
			if b, _ := json.Marshal(rec); strings.Contains(string(b), d.Credential) {
				t.Fatal("a credential is in the chain")
			}
		}
	})
}

// TestARevokedDeliveryCannotFillTheChain: an attacker holding a revoked credential writes at most the per-delivery refusal cap of
// records an hour; past it the answer is 429 and nothing is written.
func TestARevokedDeliveryCannotFillTheChain(t *testing.T) {
	l := newRevLab(t, "", nil)
	d := l.deliver(t, l.auditor, 0)
	l.f.do("POST", l.revokePath(d.ID), "user:admin", map[string]any{"reason": "leaked"}).want(t, 200, "")
	n := len(l.f.records())
	var ok403, tooMany int
	for i := 0; i < 150; i++ {
		switch a := l.read(d.Credential); a.status {
		case 403:
			ok403++
		case 429:
			tooMany++
			if ruleOf(a) != server.RulePacketRevoked {
				t.Fatalf("the cap still says why: %v", a.body)
			}
		default:
			t.Fatalf("%d %v", a.status, a.body)
		}
	}
	// And the sample route shares the cap.
	for i := 0; i < 10; i++ {
		l.f.do("GET", "/v1/packets/"+l.id+"/sample?seed=s", d.Credential, nil).want(t, 429, "")
	}
	if ok403 != 60 || tooMany != 90 || len(l.f.records())-n != 60 {
		t.Fatalf("refused %d, capped %d, records written %d: at most 60 records an hour per delivery", ok403, tooMany, len(l.f.records())-n)
	}
}

// TestManyReadsAndARevokeStayOrdered (run with -race): readers hammer one delivery while an admin revokes it. After the revoke's answer,
// no read that starts succeeds; and in the chain, no allowed read is recorded after the revocation record.
func TestManyReadsAndARevokeStayOrdered(t *testing.T) {
	l := newRevLab(t, "", func(c *core.Config) { c.PacketReadsPerHour = -1 })
	d := l.deliver(t, l.auditor, 0)
	var acked atomic.Bool
	var served, refused, late atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	client := l.f.srv.Client()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				afterRevoke := acked.Load() // the revoke had already answered when this read started
				req, _ := http.NewRequest("GET", l.f.srv.URL+"/v1/packets/"+l.id, nil)
				req.Header.Set("Authorization", "Bearer "+d.Credential)
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				switch resp.StatusCode {
				case 200:
					served.Add(1)
					if afterRevoke {
						late.Add(1)
					}
				case 403, 429:
					refused.Add(1)
				}
			}
		}()
	}
	for served.Load() < 20 {
		time.Sleep(time.Millisecond)
	}
	a := l.f.do("POST", l.revokePath(d.ID), "user:admin", map[string]any{"reason": "race"}).want(t, 200, "")
	acked.Store(true)
	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
	if late.Load() != 0 {
		t.Fatalf("%d reads that began after the revoke answered were served", late.Load())
	}
	rseq := int64(a.body["seq"].(float64))
	for _, r := range l.f.toolRecords(server.ToolPacketFetch) {
		seq := int64(0)
		_, _ = fmt.Sscan(fmt.Sprint(r["seq"]), &seq)
		if r["decision"] == "allow" && seq > rseq {
			t.Fatalf("an allowed read (record %d) was recorded after the revocation (record %d)", seq, rseq)
		}
	}
	if refused.Load() == 0 {
		t.Fatal("no read was refused: the race did not happen")
	}
	chainOK(t, l.f)
}

// fakeClock is a clock a test moves by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// flakyStore fails the chain reads the revocation index makes when told to.
type flakyStore struct {
	store.Store
	fail atomic.Bool
}

var errFlaky = errors.New("flaky store")

func (s *flakyStore) Head(ctx context.Context) (int64, string, error) {
	if s.fail.Load() {
		return 0, "", errFlaky
	}
	return s.Store.Head(ctx)
}

func (s *flakyStore) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	if s.fail.Load() {
		return nil, errFlaky
	}
	return s.Store.Records(ctx, from, limit)
}

func (l *revLab) instance(t *testing.T, st store.Store, clk *fakeClock) *fixture {
	t.Helper()
	srv, err := server.New(context.Background(), server.Options{Store: st, Engine: l.f.core.Engine, Auth: core.DevAuthenticator(), Providers: l.ps,
		Version: "test", MaxClockSkew: -1, Gate: l.f.core.Gate, Clock: clk.Now, PacketReadsPerHour: -1})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &fixture{t: t, core: l.f.core, srv: ts}
}

// TestASecondServerObjectSeesARevocationWithinTheIndexAge: two server objects over one store object. The revoke is taken by A; B has the
// delivery cached as good, serves at most for the index's age (1 second), and refuses after it. It proves the index is refreshed from the
// store (the chain) by a second server object on an injected clock; it does not prove two processes work: the Postgres store takes a
// single-writer advisory lock, so a second process cannot serve credentialed reads today (docs/assurance.md).
func TestASecondServerObjectSeesARevocationWithinTheIndexAge(t *testing.T) {
	onStores(t, func(t *testing.T, dsn string) {
		l := newRevLab(t, dsn, nil)
		d := l.deliver(t, l.auditor, 0)
		clk := &fakeClock{t: time.Now()}
		a, b := l.instance(t, l.f.core.Store, clk), l.instance(t, l.f.core.Store, clk)
		get := func(f *fixture) answer { return f.do("GET", "/v1/packets/"+l.id, d.Credential, nil) }
		get(a).want(t, 200, "")
		get(b).want(t, 200, "") // B's index is warm and says: not revoked
		a.do("POST", l.revokePath(d.ID), "user:admin", map[string]any{"reason": "replica test"}).want(t, 200, "")
		get(a).want(t, 403, "") // the process that took the revoke: at once
		// B, inside the cache's age: still served. This is the whole of the staleness.
		clk.Advance(900 * time.Millisecond)
		get(b).want(t, 200, "")
		// B, past it: it reads the chain's tail first and refuses.
		clk.Advance(200 * time.Millisecond)
		if r := get(b).want(t, 403, ""); ruleOf(r) != server.RulePacketRevoked {
			t.Fatalf("%v", r.body)
		}
		// A revoke of the other kind propagates the same way: a recipient key revoked on B is seen by A.
		kid := l.auditor.signer.KeyID()
		b.do("POST", "/v1/assurance/recipients/"+l.auditor.name+"/keys/"+kid+"/revoke", "user:admin", map[string]any{"reason": "replica test"}).want(t, 200, "")
		other := l.deliver(t, l.auditor, 0)
		env := l.receiptFor(t, l.auditor, other.ID, receipt.Accepted, time.Now())
		clk.Advance(2 * time.Second)
		if r := a.do("POST", "/v1/packets/"+l.id+"/receipts", "", env).want(t, 403, ""); ruleOf(r) != server.RuleRecipientKeyGone {
			t.Fatalf("%v", r.body)
		}
	})
}

// TestAnUnreadableRevocationStateRefusesTheRead: when the chain cannot be read, a read is not served and not recorded (503), and a
// revoke is not taken; when the store is back, the read is served again.
func TestAnUnreadableRevocationStateRefusesTheRead(t *testing.T) {
	l := newRevLab(t, "", nil)
	d := l.deliver(t, l.auditor, 0)
	clk := &fakeClock{t: time.Now()}
	flaky := &flakyStore{Store: l.f.core.Store}
	c := l.instance(t, flaky, clk)
	get := func() answer { return c.do("GET", "/v1/packets/"+l.id, d.Credential, nil) }
	get().want(t, 200, "")
	clk.Advance(2 * time.Second) // the index is older than it may be relied on
	flaky.fail.Store(true)
	n := len(l.f.records())
	get().want(t, 503, "revocation state")
	c.do("GET", "/v1/packets/"+l.id+"/sample?seed=s", d.Credential, nil).want(t, 503, "revocation state")
	c.do("POST", "/v1/packets/"+l.id+"/receipts", "", l.receiptFor(t, l.auditor, d.ID, receipt.Accepted, time.Now())).want(t, 503, "")
	c.do("POST", l.revokePath(d.ID), "user:admin", map[string]any{"reason": "x"}).want(t, 503, "")
	if len(l.f.records()) != n {
		t.Fatal("an unreadable state still wrote records")
	}
	flaky.fail.Store(false)
	get().want(t, 200, "")
}

// TestRevokeRecipientKey: the route's rules, and that a receipt signed with the revoked key is refused at submit while one already
// recorded stays.
func TestRevokeRecipientKey(t *testing.T) {
	onStores(t, func(t *testing.T, dsn string) {
		l := newRevLab(t, dsn, nil)
		f := l.f
		d := l.deliver(t, l.auditor, 0)
		kid := l.auditor.signer.KeyID()
		path := "/v1/assurance/recipients/" + l.auditor.name + "/keys/" + kid + "/revoke"
		first := l.receiptFor(t, l.auditor, d.ID, receipt.Accepted, time.Now().Add(-time.Minute))
		l.submit(first).want(t, 200, "")

		f.do("POST", path, "user:erin", map[string]any{"reason": "r"}).want(t, 403, "")
		f.do("POST", path, "", map[string]any{"reason": "r"}).want(t, 401, "")
		f.do("POST", path, d.Credential, map[string]any{"reason": "r"}).want(t, 401, "")
		f.do("POST", "/v1/assurance/recipients/nobody/keys/"+kid+"/revoke", "user:admin", map[string]any{"reason": "r"}).want(t, 404, "")
		f.do("POST", "/v1/assurance/recipients/lab-auditor/keys/"+strings.Repeat("A", 43)+"/revoke", "user:admin", map[string]any{"reason": "r"}).want(t, 404, "")
		f.do("POST", "/v1/assurance/recipients/lab-auditor/keys/a%2Fb/revoke", "user:admin", map[string]any{"reason": "r"}).want(t, 404, "")
		f.do("POST", path, "user:admin", map[string]any{}).want(t, 400, "reason")
		f.do("POST", path, "user:admin", map[string]any{"reason": "r", "as_of": "yesterday"}).want(t, 400, "RFC 3339")
		f.do("POST", path, "user:admin", map[string]any{"reason": "r", "as_of": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)}).want(t, 400, "ahead")
		f.do("POST", path, "user:admin", map[string]any{"reason": "bad\u200bzero"}).want(t, 400, "reason")
		f.do("POST", path, "user:admin", map[string]any{"reason": "bad\u0085c1"}).want(t, 400, "reason")
		f.do("POST", path, "user:admin", map[string]any{"reason": "bad\u202esep"}).want(t, 400, "reason")
		f.do("POST", path, "user:admin", map[string]any{"reason": "bad\u2028sep"}).want(t, 400, "reason")
		if f.countTool(server.ToolRecipientKeyRevoke) != 0 {
			t.Fatal("a refused request wrote a revocation")
		}

		a := f.do("POST", path, "user:admin", map[string]any{"reason": "laptop lost"}).want(t, 200, "")
		if a.body["created"] != true || a.body["as_of"] != a.body["revoked_at"] || a.body["key_id"] != kid || f.countTool(server.ToolRecipientKeyRevoke) != 1 {
			t.Fatalf("%v", a.body)
		}
		if again := f.do("POST", path, "user:admin", map[string]any{"reason": "again"}).want(t, 200, ""); again.body["created"] != false || again.body["as_of"] != a.body["as_of"] ||
			again.body["seq"] != a.body["seq"] || f.countTool(server.ToolRecipientKeyRevoke) != 1 {
			t.Fatalf("%v", again.body)
		}
		// A new receipt signed with the key is refused and not recorded; the recorded one stays, and is idempotent; the other recipient is unaffected.
		receipts := f.countTool(packet.ToolReceipt)
		r := l.submit(l.receiptFor(t, l.auditor, d.ID, receipt.Rejected, time.Now())).want(t, 403, "revoked")
		if ruleOf(r) != server.RuleRecipientKeyGone || f.countTool(packet.ToolReceipt) != receipts {
			t.Fatalf("%v", r.body)
		}
		l.submit(first).want(t, 200, "")
		gd := l.deliver(t, l.grc, 0)
		l.submit(l.receiptFor(t, l.grc, gd.ID, receipt.Accepted, time.Now())).want(t, 200, "")
		// The credential of the delivery is not the key's: reads still work.
		l.read(d.Credential).want(t, 200, "")
		chainOK(t, f)
	})
}

// TestRevokeTokenKey: a retired token key is revoked; its credentials stop verifying; GET /v1/keys stops listing it and a verifier
// that re-reads it refuses what the key signed (a grant feed, a credential); the key in use cannot be revoked; the rules of the route.
func TestRevokeTokenKey(t *testing.T) {
	onStores(t, func(t *testing.T, dsn string) {
		l := newRevLab(t, dsn, nil)
		f := l.f
		ctx := context.Background()
		d := l.deliver(t, l.auditor, 0)
		// The core once signed with `old` and now signs with its key.
		old := signer(t)
		oldJWK, _ := token.PublicJWK(old.Public())
		curJWK, _ := token.PublicJWK(l.coreKey.Public())
		use := func(j token.JWK, at time.Time) {
			raw, _ := json.Marshal(j)
			if err := f.core.Store.Atomic(ctx, func(tx store.Tx) error {
				return tx.UseSigningKey(ctx, store.SigningKey{KeyID: j.Kid, JWK: raw}, at)
			}); err != nil {
				t.Fatal(err)
			}
		}
		use(oldJWK, time.Now().Add(-2*time.Hour))
		use(curJWK, time.Now().Add(-time.Hour))
		now := time.Now()
		mint := func() string {
			c, err := token.IssueAccess(ctx, old, token.AccessClaims{Type: token.AccessType, Issuer: "clearance", Audience: token.AccessAudience, Subject: d.ID, Packet: l.id,
				Digest: l.bundle.Digest, Recipient: l.auditor.name, Scope: []string{"summary", "evidence"}, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()})
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
		cred := mint()
		jwks := func() token.KeySet {
			raw, _ := json.Marshal(f.do("GET", "/v1/keys", "", nil).want(t, 200, "").body)
			ks, err := token.ParseJWKS(raw)
			if err != nil {
				t.Fatal(err)
			}
			return ks
		}
		if _, ok := jwks()[oldJWK.Kid]; !ok {
			t.Fatal("a retired key is listed until it is revoked")
		}
		l.read(cred).want(t, 200, "") // a retired key still verifies credentials it signed
		feed, err := token.SignFeed(ctx, old, token.Feed{Type: token.FeedType, Issuer: "clearance", Cluster: "prod-1", Seq: 1, IssuedAt: now.Unix(), Expires: now.Add(5 * time.Minute).Unix(), RecordsSeq: 1})
		if err != nil {
			t.Fatal(err)
		}
		rawFeed, _ := json.Marshal(feed)
		fo := token.FeedOptions{Issuer: "clearance", Cluster: "prod-1", Now: func() time.Time { return now }}
		if _, err := token.VerifyFeed(rawFeed, jwks(), fo); err != nil {
			t.Fatalf("before the revocation the feed verifies: %v", err)
		}

		path := "/v1/keys/" + oldJWK.Kid + "/revoke"
		f.do("POST", path, "user:erin", map[string]any{"reason": "r"}).want(t, 403, "")
		f.do("POST", path, "", map[string]any{"reason": "r"}).want(t, 401, "")
		f.do("POST", path, cred, map[string]any{"reason": "r"}).want(t, 401, "")
		f.do("POST", "/v1/keys/"+strings.Repeat("B", 43)+"/revoke", "user:admin", map[string]any{"reason": "r"}).want(t, 404, "")
		f.do("POST", "/v1/keys/a%2Fb/revoke", "user:admin", map[string]any{"reason": "r"}).want(t, 404, "")
		f.do("POST", path, "user:admin", map[string]any{}).want(t, 400, "reason")
		// The key in use: refused, with what to do.
		f.do("POST", "/v1/keys/"+curJWK.Kid+"/revoke", "user:admin", map[string]any{"reason": "r"}).want(t, 409, "rotate")
		if f.countTool(server.ToolTokenKeyRevoke) != 0 {
			t.Fatal("a refused request wrote a revocation")
		}
		a := f.do("POST", path, "user:admin", map[string]any{"reason": "key exposed"}).want(t, 200, "")
		if a.body["created"] != true || a.body["state"] != "revoked" || f.countTool(server.ToolTokenKeyRevoke) != 1 {
			t.Fatalf("%v", a.body)
		}
		if again := f.do("POST", path, "user:admin", map[string]any{"reason": "again"}).want(t, 200, ""); again.body["created"] != false || f.countTool(server.ToolTokenKeyRevoke) != 1 {
			t.Fatalf("%v", again.body)
		}
		// The credential the revoked key signed: a bare 401, and nothing is written.
		n := len(f.records())
		l.read(cred).want(t, 401, "")
		if len(f.records()) != n {
			t.Fatal("a credential of a revoked key wrote a record")
		}
		// GET /v1/keys: the revoked key is gone (not flagged), the key in use is there; a verifier that re-reads it fails closed.
		ks := jwks()
		if _, ok := ks[oldJWK.Kid]; ok {
			t.Fatal("GET /v1/keys still lists a revoked key")
		}
		if _, ok := ks[curJWK.Kid]; !ok {
			t.Fatal("GET /v1/keys lost the key in use")
		}
		if _, err := token.VerifyFeed(rawFeed, ks, fo); !errors.Is(err, token.ErrUnknownKey) {
			t.Fatalf("a feed signed by a revoked key must not verify: %v", err)
		}
		if _, err := token.ParseAccess(cred, ks); !errors.Is(err, token.ErrUnknownKey) {
			t.Fatalf("a credential signed by a revoked key must not verify: %v", err)
		}
		// Credentials of the key in use are unaffected.
		l.read(d.Credential).want(t, 200, "")
		// A revoked key is never used again: the store refuses it, so the core cannot be started with it.
		if err := f.core.Store.Atomic(ctx, func(tx store.Tx) error {
			raw, _ := json.Marshal(oldJWK)
			return tx.UseSigningKey(ctx, store.SigningKey{KeyID: oldJWK.Kid, JWK: raw}, time.Now())
		}); !errors.Is(err, store.ErrKeyRevoked) {
			t.Fatalf("%v", err)
		}
		chainOK(t, f)
	})
}
