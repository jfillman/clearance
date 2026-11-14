package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/assurance"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/receipt"
	"github.com/jfillman/clearance/internal/server"
)

func p1Published(t *testing.T, readsPerHour int) (*fixture, *fakeRecipient, *fakeRecipient, *packet.Bundle, server.Delivery) {
	t.Helper()
	a, b := newFakeRecipient(t, "lab-auditor"), newFakeRecipient(t, "lab-grc-hub")
	var base []map[string]any
	_ = json.Unmarshal([]byte(providersJSON), &base)
	raw, _ := json.Marshal(append(base, a.registration(), b.registration()))
	ps, err := server.ParseProviders(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config(t, "")
	cfg.Providers, cfg.Signer, cfg.TokenIssuer, cfg.TokenTTL = ps, signer(t), "clearance", 15*time.Minute
	cfg.PacketReadsPerHour = readsPerHour
	f := newFixture(t, cfg)
	f.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "")
	_, bundle := f.buildPacket(t)
	f.do("POST", "/v1/packets", "user:admin", bundle.JSON).want(t, 200, "")
	d := f.deliver(t, bundle.ID, map[string]any{"recipient": a.name, "window": map[string]any{"to": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}})
	return f, a, b, bundle, d
}

// A path id that is not a packet id is 404 and writes nothing: no control characters or oversized text reach a signed record.
func TestP1APathThatIsNotAPacketIDWritesNoRecord(t *testing.T) {
	f, _, _, _, d := p1Published(t, 0)
	before := len(f.records())
	for _, id := range []string{"x", "pk-zz", strings.Repeat("a", 3000), "pk-" + strings.Repeat("A", 32), "%00%01bad", "%ff%fe", "pk-0123456789abcdef0123456789abcdef%0a"} {
		f.do("GET", "/v1/packets/"+id, d.Credential, nil).want(t, 404, "")
	}
	if len(f.records()) != before {
		t.Fatal("a bad packet id wrote a record")
	}
}

// Allowed reads are capped per delivery per hour: the extras are 429 with Retry-After and write no record.
func TestP1AllowedReadsAreCappedPerDelivery(t *testing.T) {
	f, _, _, b, d := p1Published(t, 2)
	cl := &assurance.Client{Base: f.srv.URL}
	for i := 0; i < 2; i++ {
		if _, err := cl.Pull(context.Background(), b.ID, d.Credential, ""); err != nil {
			t.Fatal(err)
		}
	}
	before := len(f.records())
	req, _ := http.NewRequest("GET", f.srv.URL+"/v1/packets/"+b.ID, nil)
	req.Header.Set("Authorization", "Bearer "+d.Credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	if len(f.records()) != before {
		t.Fatal("a capped read wrote a record")
	}
	if n := len(f.toolRecords(server.ToolPacketFetch)); n != 2 {
		t.Fatalf("%d fetch records", n)
	}
}

// The same signed receipt twice is one record; a receipt signed by B naming A is refused.
func TestP1ReceiptsAreIdempotentAndBoundToTheirRecipient(t *testing.T) {
	f, a, b, bundle, d := p1Published(t, 0)
	ctx := context.Background()
	cl := &assurance.Client{Base: f.srv.URL}
	got, err := cl.Pull(ctx, bundle.ID, d.Credential, "")
	if err != nil {
		t.Fatal(err)
	}
	sign := func(r *fakeRecipient, named string) []byte {
		p, err := assurance.Payload(got, assurance.Review{Delivery: d.ID, Recipient: named, Engagement: "FY26", Verdict: receipt.Accepted})
		if err != nil {
			t.Fatal(err)
		}
		env, err := receipt.Sign(ctx, r.signer, p)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	// B signs, naming A: not a key registered for A.
	if _, err := cl.Submit(ctx, bundle.ID, sign(b, a.name)); !isStatus(err, 403) {
		t.Fatalf("B's receipt naming A: %v", err)
	}
	env := sign(a, a.name)
	first, err := cl.Submit(ctx, bundle.ID, env)
	if err != nil || !first.Created {
		t.Fatal(first, err)
	}
	before := len(f.records())
	again, err := cl.Submit(ctx, bundle.ID, env)
	if err != nil || again.Created || again.Seq != first.Seq || again.Hash != first.Hash {
		t.Fatalf("%+v %v", again, err)
	}
	if len(f.records()) != before || len(f.toolRecords(packet.ToolReceipt)) != 1 {
		t.Fatal(fmt.Sprint("a resubmitted receipt wrote a record: ", len(f.toolRecords(packet.ToolReceipt))))
	}
}
