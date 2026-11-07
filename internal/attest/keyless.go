package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// DefaultOIDCTokenFile is where the core's OIDC identity token is mounted: a projected service account token whose
// audience is the one Fulcio expects (C-2a). It is re-read on every signing, never cached.
const DefaultOIDCTokenFile = "/var/run/clearance/attest-oidc-token"

// Keyless signs with Fulcio and logs in Rekor. For each attestation it makes an ephemeral P-256 key (in memory,
// never stored), proves possession of it to Fulcio with the core's OIDC identity token, receives a short-lived
// certificate that binds the key to that identity, signs, and discards the key. Rekor's entry is what makes the
// short-lived certificate verifiable later.
type Keyless struct {
	Fulcio    string // Fulcio base URL (CheckURL)
	Rekor     *Rekor
	TokenFile string // the OIDC identity token; "" is DefaultOIDCTokenFile
	HTTP      *http.Client
}

// Name implements Backend.
func (*Keyless) Name() string { return "keyless" }

// Sign implements Backend.
func (k *Keyless) Sign(ctx context.Context, payload []byte) (Signed, error) {
	if k.Rekor == nil {
		return Signed{}, errors.New("attest: keyless signing needs a Rekor")
	}
	tf := k.TokenFile
	if tf == "" {
		tf = DefaultOIDCTokenFile
	}
	raw, err := os.ReadFile(tf)
	if err != nil {
		return Signed{}, fmt.Errorf("attest: the OIDC identity token: %w", err)
	}
	idToken := strings.TrimSpace(string(raw))
	sub, err := jwtSubject(idToken)
	if err != nil {
		return Signed{}, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Signed{}, err
	}
	chain, err := k.certify(ctx, priv, idToken, sub)
	if err != nil {
		return Signed{}, err
	}
	env, err := signEnvelope(ctx, payload, "", func(_ context.Context, digest []byte) ([]byte, error) {
		return ecdsa.SignASN1(rand.Reader, priv, digest)
	})
	if err != nil {
		return Signed{}, err
	}
	out := Signed{Backend: k.Name(), Bundle: Bundle{MediaType: BundleMediaType, DSSEEnvelope: env}}
	cc := &CertChain{}
	for _, c := range chain {
		cc.Certificates = append(cc.Certificates, RawBytes{RawBytes: c.Raw})
	}
	out.Bundle.VerificationMaterial.X509CertificateChain = cc
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0].Raw})
	if err := logEntry(ctx, k.Rekor, env, leafPEM, &out); err != nil {
		return Signed{}, err
	}
	return out, nil
}

// certify asks Fulcio (v2 signingCert) for a certificate for priv's public key and returns the chain, leaf first.
func (k *Keyless) certify(ctx context.Context, priv *ecdsa.PrivateKey, idToken, sub string) ([]*x509.Certificate, error) {
	u, err := CheckURL("the Fulcio URL", k.Fulcio)
	if err != nil {
		return nil, err
	}
	pub, err := pemPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	// Proof of possession: a signature by the key over the SHA-256 of the identity's subject.
	h := sha256.Sum256([]byte(sub))
	pop, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"credentials": map[string]any{"oidcIdentityToken": idToken},
		"publicKeyRequest": map[string]any{
			"publicKey":         map[string]any{"algorithm": "ECDSA", "content": string(pub)},
			"proofOfPossession": base64.StdEncoding.EncodeToString(pop),
		},
	}
	hc := k.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: DefaultTimeout}
	}
	var resp struct {
		Embedded *fulcioChain `json:"signedCertificateEmbeddedSct"`
		Detached *fulcioChain `json:"signedCertificateDetachedSct"`
	}
	if err := postJSON(ctx, hc, u.String()+"/api/v2/signingCert", nil, req, &resp); err != nil {
		return nil, fmt.Errorf("fulcio: %w", err)
	}
	fc := resp.Embedded
	if fc == nil {
		fc = resp.Detached
	}
	if fc == nil || len(fc.Chain.Certificates) == 0 {
		return nil, errors.New("fulcio: the answer carries no certificate chain")
	}
	var chain []*x509.Certificate
	for _, p := range fc.Chain.Certificates {
		for rest := []byte(p); ; {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("fulcio: a certificate in the chain: %w", err)
			}
			chain = append(chain, c)
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("fulcio: the chain holds no PEM certificate")
	}
	leafKey, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafKey.Equal(&priv.PublicKey) {
		return nil, errors.New("fulcio: the certificate is for another key")
	}
	return chain, nil
}

type fulcioChain struct {
	Chain struct {
		Certificates []string `json:"certificates"`
	} `json:"chain"`
}

// jwtSubject is the sub claim of a JWT, read without verifying it (Fulcio verifies the token).
func jwtSubject(tok string) (string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", errors.New("attest: the OIDC identity token is not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("attest: the OIDC identity token is not a JWT")
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(b, &c); err != nil || c.Sub == "" {
		return "", errors.New("attest: the OIDC identity token has no sub")
	}
	return c.Sub, nil
}
