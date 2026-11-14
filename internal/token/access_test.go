package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/token"
)

func TestParseAccessRefusesWhatTheCoreDidNotIssue(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := token.NewKeySigner(k)
	keys := token.KeySet{s.KeyID(): s.Public()}
	now := time.Now().Unix()
	c := token.AccessClaims{Type: token.AccessType, Issuer: "clearance", Audience: token.AccessAudience, Subject: "dl-1", Packet: "pk-" + strings.Repeat("a", 32),
		Digest: strings.Repeat("a", 64), Recipient: "firm", Scope: []string{"summary"}, IssuedAt: now, NotBefore: now, Expires: now + 60}
	good, err := token.IssueAccess(context.Background(), s, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := token.ParseAccess(good, keys); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")
	enc := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }
	hdr := func(alg, typ, kid string) string {
		return enc(`{"alg":"` + alg + `","kid":"` + kid + `","typ":"` + typ + `"}`)
	}
	sig := parts[2]
	for name, jwt := range map[string]string{
		"alg none":      hdr("none", token.AccessJWTType, s.KeyID()) + "." + parts[1] + ".",
		"alg none+sig":  hdr("none", token.AccessJWTType, s.KeyID()) + "." + parts[1] + "." + sig,
		"alg HS256":     hdr("HS256", token.AccessJWTType, s.KeyID()) + "." + parts[1] + "." + sig,
		"wrong typ":     hdr("ES256", "JWT", s.KeyID()) + "." + parts[1] + "." + sig,
		"clearance typ": hdr("ES256", token.JWTType, s.KeyID()) + "." + parts[1] + "." + sig,
		"oversized":     good + strings.Repeat("A", token.MaxAccessBytes),
		"two parts":     parts[0] + "." + parts[1],
	} {
		if _, err := token.ParseAccess(jwt, keys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A valid signature under a key id the verifier does not know.
	if _, err := token.ParseAccess(good, token.KeySet{"other": s.Public()}); !errors.Is(err, token.ErrUnknownKey) {
		t.Errorf("unknown kid: %v", err)
	}
	// A header naming a known kid but signed by another key.
	o, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	os, _ := token.NewKeySigner(o)
	forged, _ := token.IssueAccess(context.Background(), os, c)
	fp := strings.Split(forged, ".")
	h := hdr("ES256", token.AccessJWTType, s.KeyID())
	if _, err := token.ParseAccess(h+"."+fp[1]+"."+fp[2], keys); !errors.Is(err, token.ErrSignature) {
		t.Errorf("wrong key: %v", err)
	}
	_ = sha256.Sum256
}
