package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/assurance"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/receipt"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/verify"
)

// A fake assurance provider: a registered recipient with its own key and nothing else. It is everything a real firm
// has in P-1: a credential, the packet it unlocks, and a key.
type fakeRecipient struct {
	name   string
	signer *token.KeySigner
	pub    string // PKIX PEM
}

func newFakeRecipient(t *testing.T, name string) *fakeRecipient {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := token.NewKeySigner(k)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return &fakeRecipient{name: name, signer: s, pub: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
}

func (r *fakeRecipient) registration() map[string]any {
	return map[string]any{"name": r.name, "version": "1", "class": "assurance", "keys": []string{r.pub}}
}

// p1Fixture is a core with a signing key, an admin, and two assurance providers registered.
func p1Fixture(t *testing.T) (*fixture, *token.KeySigner, *fakeRecipient, *fakeRecipient) {
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
	cfg := config(t, "")
	cfg.Providers = ps
	s := signer(t)
	cfg.Signer, cfg.TokenIssuer, cfg.TokenTTL = s, "clearance", 15*time.Minute
	return newFixture(t, cfg), s, a, b
}

func (f *fixture) buildPacket(t *testing.T) (string, *packet.Bundle) {
	t.Helper()
	now := time.Now().UTC().Add(2 * time.Second)
	res, err := packet.Build(context.Background(), f.core.Store, packet.Params{From: now.Add(-24 * time.Hour), To: now, Now: now, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "packet")
	if _, err := packet.Write(context.Background(), dir, res, []string{"json"}, nil); err != nil {
		t.Fatal(err)
	}
	b, err := packet.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, b
}

func (f *fixture) toolRecords(tool string) []store.Record {
	var out []store.Record
	for _, r := range f.records() {
		if r["tool"] == tool {
			out = append(out, r)
		}
	}
	return out
}

func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dir, p)
			s := sha256.Sum256(b)
			out[filepath.ToSlash(rel)] = hex.EncodeToString(s[:])
		}
		return nil
	})
	return out
}

func (f *fixture) deliver(t *testing.T, id string, body map[string]any) server.Delivery {
	t.Helper()
	a := f.do("POST", "/v1/packets/"+id+"/deliveries", "user:admin", body).want(t, 200, "")
	raw, _ := json.Marshal(a.body)
	var d server.Delivery
	if err := json.Unmarshal(raw, &d); err != nil || d.Credential == "" {
		t.Fatalf("%v %v", d, err)
	}
	return d
}

// TestP1AssuranceProviderEndToEnd is the P-1 gate: one command, `go test ./internal/server -run TestP1`. A fake
// assurance provider pulls a lab packet under a time-boxed credential, signs a receipt, and the next packet's
// Acceptances section carries it and verifies offline; an expired credential is refused and the refusal is a record; a
// GRC lead forwards the packet unchanged to a second recipient through the same route.
func TestP1AssuranceProviderEndToEnd(t *testing.T) {
	f, coreKey, auditor, grc := p1Fixture(t)
	f.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "")
	dir, orig := f.buildPacket(t)
	ctx := context.Background()

	// Publishing and delivering are the subscriber's: an admin, and nobody else.
	f.do("POST", "/v1/packets", "user:erin", orig.JSON).want(t, 403, "")
	f.do("POST", "/v1/packets", "", orig.JSON).want(t, 401, "")
	pub := f.do("POST", "/v1/packets", "user:admin", orig.JSON).want(t, 200, "")
	id := pub.body["id"].(string)
	if id != orig.ID || pub.body["created"] != true {
		t.Fatalf("%v", pub.body)
	}
	if again := f.do("POST", "/v1/packets", "user:admin", orig.JSON).want(t, 200, ""); again.body["created"] != false || len(f.toolRecords(server.ToolPacketPublish)) != 1 {
		t.Fatal("the same packet is the same id and records nothing", again.body)
	}
	f.do("POST", "/v1/packets/"+id+"/deliveries", "user:erin", map[string]any{"recipient": auditor.name, "window": map[string]any{"to": time.Now().Add(time.Hour).Format(time.RFC3339)}}).want(t, 403, "")
	window := map[string]any{"to": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	f.do("POST", "/v1/packets/"+id+"/deliveries", "user:admin", map[string]any{"recipient": "nobody", "window": window}).want(t, 400, "not a registered assurance provider")
	f.do("POST", "/v1/packets/"+id+"/deliveries", "user:admin", map[string]any{"recipient": auditor.name, "window": map[string]any{"to": time.Now().Add(-time.Hour).Format(time.RFC3339)}}).want(t, 400, "past")
	f.do("POST", "/v1/packets/"+id+"/deliveries", "user:admin", map[string]any{"recipient": auditor.name, "window": window, "scope": []string{"everything"}}).want(t, 400, "scope")
	d := f.deliver(t, id, map[string]any{"recipient": auditor.name, "window": window, "engagement": "FY26 SOC 2"})
	if dr := f.toolRecords(server.ToolPacketDeliver); len(dr) != 1 || fmt.Sprint(dr[0]["seq"]) != strings.TrimPrefix(d.ID, "dl-") {
		t.Fatalf("the delivery is a ledger record: %v", dr)
	}
	// The credential is not stored: it is in no record.
	for _, r := range f.records() {
		if b, _ := json.Marshal(r); strings.Contains(string(b), d.Credential) {
			t.Fatal("the credential is in the chain")
		}
	}

	// The fake provider pulls under the credential, with no account.
	cl := &assurance.Client{Base: f.srv.URL}
	got, err := cl.Pull(ctx, id, d.Credential, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != orig.Digest || string(got.JSON) != string(orig.JSON) {
		t.Fatal("the recipient got a different packet")
	}
	if fetches := f.toolRecords(server.ToolPacketFetch); len(fetches) != 1 || fetches[0]["decision"] != "allow" {
		t.Fatalf("every fetch is a record: %v", fetches)
	}
	pulled := filepath.Join(t.TempDir(), "pulled")
	if err := got.Unpack(pulled); err != nil {
		t.Fatal(err)
	}
	if a, b := readTree(t, dir), readTree(t, pulled); fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatalf("unpacked packet differs from the original:\n%v\n%v", a, b)
	}
	if rep := verify.Verify(pulled, verify.Options{}); rep.Failed() {
		t.Fatalf("the pulled packet does not verify:\n%+v", rep.Checks)
	}

	// Refusals: expired, not yet good, another packet, a part outside the scope, no longer scoped. Each is a record.
	mint := func(c token.AccessClaims) string {
		t.Helper()
		c.Type, c.Issuer, c.Audience, c.Digest, c.Recipient = token.AccessType, "clearance", token.AccessAudience, orig.Digest, auditor.name
		if c.Packet == "" {
			c.Packet = id
		}
		if c.Scope == nil {
			c.Scope = []string{packet.PartSummary, packet.PartEvidence}
		}
		s, err := token.IssueAccess(ctx, coreKey, c)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	now := time.Now()
	denied := func(cred, path string, status int, rule string) {
		t.Helper()
		before := len(f.toolRecords(server.ToolPacketFetch))
		a := f.do("GET", path, cred, nil).want(t, status, "")
		if a.body["rule"] != rule {
			t.Fatalf("%s: %v", rule, a.body)
		}
		fr := f.toolRecords(server.ToolPacketFetch)
		if len(fr) != before+1 || fr[len(fr)-1]["decision"] != "deny" || fr[len(fr)-1]["rule"] != rule {
			t.Fatalf("the refusal is a record: %v", fr)
		}
	}
	expired := mint(token.AccessClaims{Subject: "dl-1", IssuedAt: now.Add(-2 * time.Hour).Unix(), NotBefore: now.Add(-2 * time.Hour).Unix(), Expires: now.Add(-time.Hour).Unix()})
	denied(expired, "/v1/packets/"+id, 401, server.RulePacketExpired)
	future := mint(token.AccessClaims{Subject: "dl-1", IssuedAt: now.Unix(), NotBefore: now.Add(time.Hour).Unix(), Expires: now.Add(2 * time.Hour).Unix()})
	denied(future, "/v1/packets/"+id, 403, server.RulePacketNotYet)
	summaryOnly := mint(token.AccessClaims{Subject: "dl-1", Scope: []string{packet.PartSummary}, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()})
	denied(summaryOnly, "/v1/packets/"+id+"?part=evidence", 403, server.RulePacketScope)
	denied(d.Credential, "/v1/packets/pk-00000000000000000000000000000000", 403, server.RulePacketScope)
	// A credential cut to the summary serves only the summary, and says so.
	if b, err := cl.Pull(ctx, id, summaryOnly, ""); err != nil || b.Files["evidence/records.jsonl"] != nil || b.Files["packet.json"] == nil {
		t.Fatalf("scoped read: %v %v", b, err)
	}
	// What the core did not sign is nobody: a bare 401 and no record.
	before := len(f.records())
	f.do("GET", "/v1/packets/"+id, "", nil).want(t, 401, "")
	f.do("GET", "/v1/packets/"+id, "not-a-credential", nil).want(t, 401, "")
	other := signer(t)
	forged, _ := token.IssueAccess(ctx, other, token.AccessClaims{Type: token.AccessType, Issuer: "clearance", Audience: token.AccessAudience, Subject: "dl-1", Packet: id,
		Digest: orig.Digest, Recipient: auditor.name, Scope: []string{"summary"}, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix()})
	f.do("GET", "/v1/packets/"+id, forged, nil).want(t, 401, "")
	if len(f.records()) != before {
		t.Fatal("an unsigned or forged credential wrote a record")
	}
	// A clearance token is not a packet credential.
	f.do("GET", "/v1/packets/"+id, ci, nil).want(t, 401, "")

	// The receipt: signed with the recipient's own key, checked against the key it registered.
	review := func(r *fakeRecipient, deliv, engagement, verdict string, notes map[string]string) []byte {
		t.Helper()
		p, err := assurance.Payload(got, assurance.Review{Delivery: deliv, Recipient: r.name, Engagement: engagement, Verdict: verdict, Notes: notes})
		if err != nil {
			t.Fatal(err)
		}
		env, err := receipt.Sign(ctx, r.signer, p)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	// Not the registered key; the wrong engagement; a note on a row the mappings do not have.
	if _, err := cl.Submit(ctx, id, review(&fakeRecipient{name: auditor.name, signer: signer(t)}, d.ID, "FY26 SOC 2", receipt.Accepted, nil)); !isStatus(err, 403) {
		t.Fatalf("unregistered key: %v", err)
	}
	if _, err := cl.Submit(ctx, id, review(auditor, d.ID, "FY27", receipt.Accepted, nil)); !isStatus(err, 400) {
		t.Fatalf("engagement: %v", err)
	}
	if _, err := cl.Submit(ctx, id, review(auditor, d.ID, "FY26 SOC 2", receipt.AcceptedWithNotes, map[string]string{"no-such-row": "x"})); !isStatus(err, 400) {
		t.Fatalf("note key: %v", err)
	}
	if _, err := cl.Submit(ctx, id, review(grc, d.ID, "FY26 SOC 2", receipt.Accepted, nil)); !isStatus(err, 400) {
		t.Fatalf("a delivery to another recipient: %v", err)
	}
	row := packetAssertion(t, got)
	rec, err := cl.Submit(ctx, id, review(auditor, d.ID, "FY26 SOC 2", receipt.AcceptedWithNotes, map[string]string{row: "tested a sample of 25: no exception"}))
	if err != nil || rec.Verdict != receipt.AcceptedWithNotes {
		t.Fatal(rec, err)
	}
	if rr := f.toolRecords(packet.ToolReceipt); len(rr) != 1 || fmt.Sprint(rr[0]["seq"]) != fmt.Sprint(rec.Seq) {
		t.Fatalf("the receipt is a ledger record of its own: %v", rr)
	}

	// The GRC lead forwards the packet unchanged: a second delivery of the same id to another recipient, the same bytes.
	d2 := f.deliver(t, id, map[string]any{"recipient": grc.name, "window": window})
	got2, err := cl.Pull(ctx, id, d2.Credential, "")
	if err != nil || got2.Digest != orig.Digest || string(got2.JSON) != string(orig.JSON) || got2.ID != id {
		t.Fatalf("the forwarded packet is not the original: %v", err)
	}
	if d2.Credential == d.Credential {
		t.Fatal("a delivery is its own credential")
	}
	// The recipient's credential is its own: the first recipient's credential does not open the second's delivery record.
	tampered := string(orig.JSON)
	tampered = strings.Replace(tampered, `"files":{`, `"files":{"extra.txt":"eA==",`, 1)
	if _, err := packet.ParseBundle([]byte(tampered)); err == nil {
		t.Fatal("a packet altered in transit parsed")
	}
	if _, err := cl.Submit(ctx, id, review(grc, d2.ID, "grc-questionnaire", receipt.Questioned, map[string]string{"CC8.1": "who approves the tier 3 exceptions?"})); err != nil {
		t.Fatal(err)
	}

	// The next packet carries both receipts, and the verifier checks them offline.
	dir2, next := f.buildPacket(t)
	if next.ID == id {
		t.Fatal("the next packet is the same packet")
	}
	var pk struct {
		Acceptances struct {
			Status   string `json:"status"`
			Receipts []struct {
				Recipient, Verdict string
				PacketID           string `json:"packet_id"`
			} `json:"receipts"`
		} `json:"acceptances"`
	}
	raw, _ := os.ReadFile(filepath.Join(dir2, "packet.json"))
	_ = json.Unmarshal(raw, &pk)
	if pk.Acceptances.Status != "recorded" || len(pk.Acceptances.Receipts) != 2 || pk.Acceptances.Receipts[0].Recipient != auditor.name ||
		pk.Acceptances.Receipts[0].Verdict != receipt.AcceptedWithNotes || pk.Acceptances.Receipts[1].PacketID != id {
		t.Fatalf("%+v", pk.Acceptances)
	}
	keys := filepath.Join(t.TempDir(), "recipients.pem")
	_ = os.WriteFile(keys, []byte(auditor.pub+grc.pub), 0o644)
	kb, _ := os.ReadFile(keys)
	rep := verify.Verify(dir2, verify.Options{RecipientKeys: kb, RecipientKeysSrc: keys})
	if c := checkNamed(t, rep, "acceptances"); c.Status != verify.Pass || rep.Failed() {
		t.Fatalf("%+v\n%+v", c, rep.Checks)
	}
	if c := checkNamed(t, verify.Verify(dir2, verify.Options{}), "acceptances"); c.Status != verify.SelfVouched {
		t.Fatalf("without the recipients' keys the receipts are self-vouched: %+v", c)
	}
	// Someone else's key does not vouch for the receipt (the carried copy then does, and is labelled).
	otherPEM := newFakeRecipient(t, "x").pub
	if c := checkNamed(t, verify.Verify(dir2, verify.Options{RecipientKeys: []byte(otherPEM)}), "acceptances"); c.Status != verify.SelfVouched {
		t.Fatalf("%+v", c)
	}
	// A section that says something the signed receipt does not fails, even with the manifest rewritten to match.
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	doc["acceptances"].(map[string]any)["receipts"].([]any)[0].(map[string]any)["verdict"] = "accepted"
	forgedPacket, _ := json.Marshal(doc)
	_ = os.WriteFile(filepath.Join(dir2, "packet.json"), forgedPacket, 0o644)
	var man struct {
		Schema string            `json:"schema"`
		Files  map[string]string `json:"files"`
	}
	mb, _ := os.ReadFile(filepath.Join(dir2, "MANIFEST.json"))
	_ = json.Unmarshal(mb, &man)
	sum := sha256.Sum256(forgedPacket)
	man.Files["packet.json"] = hex.EncodeToString(sum[:])
	mb, _ = json.Marshal(man)
	_ = os.WriteFile(filepath.Join(dir2, "MANIFEST.json"), mb, 0o644)
	if c := checkNamed(t, verify.Verify(dir2, verify.Options{RecipientKeys: kb}), "acceptances"); c.Status != verify.Fail {
		t.Fatalf("a rewritten verdict passed: %+v", c)
	}
	if ok, bad := evidence.Verify(f.records()); !ok {
		t.Fatalf("the chain breaks at %d", bad)
	}
}

func isStatus(err error, status int) bool {
	var e *assurance.Error
	return errors.As(err, &e) && e.Status == status
}

func checkNamed(t *testing.T, rep *verify.Report, prefix string) verify.Check {
	t.Helper()
	for _, c := range rep.Checks {
		if strings.HasPrefix(c.Name, prefix) {
			return c
		}
	}
	t.Fatalf("no %q check in %+v", prefix, rep.Checks)
	return verify.Check{}
}

func packetAssertion(t *testing.T, b *packet.Bundle) string {
	t.Helper()
	if len(b.Meta.Assertions) == 0 {
		t.Fatal("the packet has no mapping rows")
	}
	return b.Meta.Assertions[0]
}

func TestAnAssuranceProviderIsNotAnAccount(t *testing.T) {
	good := newFakeRecipient(t, "firm")
	reg := func(m map[string]any) error {
		raw, _ := json.Marshal([]any{m})
		_, err := server.ParseProviders(string(raw))
		return err
	}
	if err := reg(good.registration()); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(map[string]any){
		"principals": func(m map[string]any) { m["principals"] = []string{"user:*"} },
		"kinds":      func(m map[string]any) { m["kinds"] = []string{"deploy.outcome"} },
		"no keys":    func(m map[string]any) { delete(m, "keys") },
		"bad key":    func(m map[string]any) { m["keys"] = []string{"not a key"} },
		"targets":    func(m map[string]any) { m["targets"] = []string{"*"} },
	} {
		m := good.registration()
		mut(m)
		if reg(m) == nil {
			t.Errorf("%s: an assurance provider with this was accepted", name)
		}
	}
	if reg(map[string]any{"name": "x", "version": "1", "principals": []string{"a/b"}, "keys": []string{good.pub}}) == nil {
		t.Error("keys on an enforcement provider")
	}
	// A recipient is never a caller: its name is no principal.
	f, _, _, _ := p1Fixture(t)
	f.do("POST", "/v1/records", "lab-auditor", map[string]any{"provider": "lab-auditor", "kind": "run.launch", "record": map[string]any{}}).want(t, 403, "")
}
