package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/token"
)

func idToken() string {
	enc := base64.RawURLEncoding.EncodeToString
	b, _ := json.Marshal(map[string]any{"iss": "https://idp.example", "exp": time.Now().Add(30 * time.Minute).Unix(), "iat": time.Now().Unix()})
	return enc([]byte(`{"alg":"ES256"}`)) + "." + enc(b) + "." + enc([]byte("s"))
}

// The registered commands reach clearance-api with the person's own token, and `attest verify <change>` hands the
// downloaded bundle to the same offline verifier `attest verify --file` uses.
func TestPersonCommandsAreWiredIntoTheBinary(t *testing.T) {
	const tree = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sg, _ := token.NewKeySigner(k)
	st := attest.Statement{Type: attest.StatementType, PredicateType: attest.PredicateType,
		Subject:   []attest.Subject{{Name: "manifest-tree:o/r/a/prod", Digest: map[string]string{"sha256": tree}}},
		Predicate: attest.Predicate{Clearance: token.Clearance{ID: "chg-1"}, Limitations: []string{"x"}}}
	payload, _ := json.Marshal(st)
	signed, err := (&attest.Static{Signer: sg}).Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ := json.Marshal(signed.Bundle)
	der, _ := x509.MarshalPKIXPublicKey(sg.Public())
	pub := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	tok := idToken()
	var bearer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/v1/whoami":
			_, _ = w.Write([]byte(`{"principal":"user:erin","person":"user:erin","roles":["person"],"admin":false,"groups":[],"apps":[]}`))
		case "/v1/clearances/chg-1/attestation":
			_, _ = w.Write(bundle)
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		}
	}))
	defer srv.Close()
	t.Setenv("CLEARANCE_API_URL", srv.URL)
	t.Setenv("CLEARANCE_TOKEN", tok)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	code, out, errs := runCLI("whoami", "-o", "json")
	if code != 0 || !strings.Contains(out, `"user:erin"`) || bearer != "Bearer "+tok {
		t.Fatalf("whoami: %d %q %q (bearer %q)", code, out, errs, bearer)
	}
	// offline verification of the api's bundle with the person's own key: the verdict is the local code's
	code, out, errs = runCLI("attest", "verify", "chg-1", "--key", pub, "--subject", "sha256:"+tree)
	if code != 0 || !strings.Contains(out, "ok: static attestation of change chg-1") {
		t.Fatalf("attest verify <change>: %d %q %q", code, out, errs)
	}
	code, _, errs = runCLI("attest", "verify", "--change", "chg-1", "--key", pub, "--subject", "sha256:"+strings.Repeat("f", 64))
	if code != 1 || !strings.Contains(errs, "does not name subject") {
		t.Fatalf("--change with a wrong subject: %d %q", code, errs)
	}
	// without a change id it is still the file verifier
	if code, _, _ := runCLI("attest", "verify"); code != 2 {
		t.Fatalf("usage: %d", code)
	}
	// the token never appears in what the commands print
	if strings.Contains(out+errs, tok) {
		t.Errorf("token printed")
	}
}
