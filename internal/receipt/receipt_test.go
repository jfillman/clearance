package receipt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/receipt"
	"github.com/jfillman/clearance/internal/token"
)

func payload() receipt.Payload {
	d := strings.Repeat("ab", 32)
	return receipt.Payload{Type: receipt.Type, PacketID: "pk-" + d[:32], PacketDigest: d, Delivery: "dl-12", Recipient: "firm", Engagement: "FY26",
		Mappings: []string{"soc2/2017"}, Verdict: receipt.Accepted, SignedAt: "2026-11-14T10:00:00Z"}
}

func TestSignVerifyAndRefuse(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := token.NewKeySigner(k)
	env, err := receipt.Sign(context.Background(), s, payload())
	if err != nil {
		t.Fatal(err)
	}
	v, err := receipt.Verify(env, token.KeySet{s.KeyID(): s.Public()})
	if err != nil || v.Payload.Verdict != receipt.Accepted || v.KeyID != s.KeyID() {
		t.Fatal(v, err)
	}
	o, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	os, _ := token.NewKeySigner(o)
	if _, err := receipt.Verify(env, token.KeySet{s.KeyID(): os.Public()}); !errors.Is(err, token.ErrSignature) {
		t.Fatalf("another key under the same id: %v", err)
	}
	if _, err := receipt.Verify(env, token.KeySet{os.KeyID(): os.Public()}); !errors.Is(err, token.ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	for name, mut := range map[string]func(*receipt.Payload){
		"verdict":          func(p *receipt.Payload) { p.Verdict = "maybe" },
		"id not digest":    func(p *receipt.Payload) { p.PacketID = "pk-" + strings.Repeat("c", 32) },
		"notes required":   func(p *receipt.Payload) { p.Verdict = receipt.AcceptedWithNotes },
		"no mappings":      func(p *receipt.Payload) { p.Mappings = nil },
		"bad time":         func(p *receipt.Payload) { p.SignedAt = "yesterday" },
		"bad note key":     func(p *receipt.Payload) { p.ControlNotes = map[string]string{"a b": "x"} },
		"empty engagement": func(p *receipt.Payload) { p.Engagement = "" },
	} {
		p := payload()
		mut(&p)
		if _, err := receipt.Sign(context.Background(), s, p); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func FuzzRead(f *testing.F) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := token.NewKeySigner(k)
	env, _ := receipt.Sign(context.Background(), s, payload())
	f.Add(env)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = receipt.Read(b); _, _ = receipt.Verify(b, nil) })
}
