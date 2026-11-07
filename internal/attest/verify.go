package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/token"
)

// Fulcio's certificate extensions: the OIDC issuer, v1 (raw string) and v2 (DER UTF8String).
var (
	oidIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// VerifyOptions is what a verifier trusts and expects. Everything is offline: the bundle and these.
type VerifyOptions struct {
	// Subjects are digests ("sha256:<hex>", "gitCommit:<hex>") the statement must name among its subjects.
	Subjects []string
	// Keys verify a static-key bundle (the signing key's public half: PEM, or the core's JWKS).
	Keys token.KeySet
	// Roots, Identity and Issuer verify a keyless bundle: the Fulcio certificates to trust, the identity the
	// certificate's SAN must name and the OIDC issuer it must record. RekorKey checks the log's entry; a keyless
	// bundle is refused without it (the certificate lives minutes: only Rekor's time says it was valid).
	Roots    *x509.CertPool
	Identity string
	Issuer   string
	RekorKey *ecdsa.PublicKey
	// Trust is a Sigstore TrustedRoot (`clearance trust-root build`): every Fulcio chain and Rekor key with its
	// window. It replaces Roots and RekorKey for a keyless bundle: the entry's log id picks the key, Rekor's signed
	// time picks the chains, so a bundle signed under a retired root still verifies while the root was valid.
	Trust *TrustedRoot
}

// Result is what a good bundle says.
type Result struct {
	Statement *Statement
	Digest    string // EnvelopeDigest
	Mode      string // static | keyless
	KeyID     string
	Identity  string // keyless: the certificate's identity
	Issuer    string
	// LogIndex is the Rekor index the entry was verified at (nil: no entry, or no Rekor key to check it with).
	LogIndex *int64
	// LogVerified says the signed entry timestamp checked against RekorKey.
	LogVerified bool
}

// ParseBundle reads a Sigstore bundle, or a bare DSSE envelope (a static-key attestation without verification
// material), refusing anything over token.MaxEnvelopeBytes.
func ParseBundle(raw []byte) (*Bundle, error) {
	if len(raw) > token.MaxEnvelopeBytes {
		return nil, errors.New("attest: the bundle is too large")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("attest: not JSON: %w", err)
	}
	var b Bundle
	if _, ok := probe["dsseEnvelope"]; ok {
		if err := strictJSON(raw, &b); err != nil {
			return nil, fmt.Errorf("attest: the bundle: %w", err)
		}
		return &b, nil
	}
	if _, ok := probe["payloadType"]; ok {
		if err := strictJSON(raw, &b.DSSEEnvelope); err != nil {
			return nil, fmt.Errorf("attest: the envelope: %w", err)
		}
		return &b, nil
	}
	return nil, errors.New("attest: neither a Sigstore bundle nor a DSSE envelope")
}

// Verify checks a bundle: the envelope's payload type, the signature over its PAE (by a key in opts.Keys, or by the
// leaf of a Fulcio chain to opts.Roots whose identity and issuer match), Rekor's entry when there is one, the
// statement's shape and that it names every digest in opts.Subjects. Any failure is an error: do not rely on it.
func Verify(raw []byte, opts VerifyOptions) (*Result, error) {
	b, err := ParseBundle(raw)
	if err != nil {
		return nil, err
	}
	env := b.DSSEEnvelope
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("attest: payloadType is %q, want %s", env.PayloadType, PayloadType)
	}
	if len(env.Signatures) != 1 {
		return nil, errors.New("attest: the envelope carries not exactly one signature")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, errors.New("attest: the payload is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil || len(sig) == 0 {
		return nil, errors.New("attest: the signature is not base64")
	}
	digest := sha256.Sum256(token.PAE(env.PayloadType, payload))
	res := &Result{Digest: EnvelopeDigest(env)}
	vm := b.VerificationMaterial

	switch {
	case vm.X509CertificateChain != nil:
		res.Mode = "keyless"
		if err := verifyKeyless(b, env, payload, sig, digest[:], opts, res); err != nil {
			return nil, err
		}
	default:
		res.Mode = "static"
		if len(opts.Keys) == 0 {
			return nil, errors.New("attest: a static-key attestation needs the public key to verify against")
		}
		kid := env.Signatures[0].KeyID
		pub, ok := opts.Keys[kid]
		if !ok {
			return nil, token.ErrUnknownKey
		}
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return nil, token.ErrSignature
		}
		res.KeyID = kid
		if len(vm.TlogEntries) > 0 && opts.RekorKey != nil {
			if err := checkLog(vm.TlogEntries, env, payload, opts.RekorKey, res); err != nil {
				return nil, err
			}
		}
	}

	st, err := decodeStatement(payload)
	if err != nil {
		return nil, err
	}
	for _, want := range opts.Subjects {
		if !st.HasSubject(want) {
			return nil, fmt.Errorf("attest: the statement does not name subject %s", want)
		}
	}
	res.Statement = st
	return res, nil
}

func checkLog(entries []TlogEntry, env token.Envelope, payload []byte, key *ecdsa.PublicKey, res *Result) error {
	if len(entries) != 1 {
		return errors.New("attest: the bundle carries not exactly one Rekor entry")
	}
	idx, _, err := verifySET(entries[0], env, payload, key)
	if err != nil {
		return fmt.Errorf("attest: Rekor entry: %w", err)
	}
	res.LogIndex, res.LogVerified = &idx, true
	return nil
}

func verifyKeyless(b *Bundle, env token.Envelope, payload, sig, digest []byte, opts VerifyOptions, res *Result) error {
	if opts.Trust == nil && (opts.Roots == nil || opts.RekorKey == nil) || opts.Identity == "" || opts.Issuer == "" {
		return errors.New("attest: a keyless attestation needs the trust root, the expected identity and issuer, and Rekor's public key")
	}
	certs := b.VerificationMaterial.X509CertificateChain.Certificates
	if len(certs) == 0 || len(certs) > 8 {
		return errors.New("attest: the certificate chain is empty or too long")
	}
	var chain []*x509.Certificate
	for _, c := range certs {
		x, err := x509.ParseCertificate(c.RawBytes)
		if err != nil {
			return fmt.Errorf("attest: a certificate: %w", err)
		}
		chain = append(chain, x)
	}
	leaf := chain[0]
	if opts.Trust != nil {
		if _, err := verifyUnderTrust(b, chain, env, payload, opts.Trust, res); err != nil {
			return err
		}
	} else {
		if err := checkLog(b.VerificationMaterial.TlogEntries, env, payload, opts.RekorKey, res); err != nil {
			return err
		}
		at, _ := parseInt(b.VerificationMaterial.TlogEntries[0].IntegratedTime)
		inter := x509.NewCertPool()
		for _, c := range chain[1:] {
			inter.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: opts.Roots, Intermediates: inter,
			CurrentTime: time.Unix(at, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
			return fmt.Errorf("attest: the certificate does not verify to the trust root at Rekor's time: %w", err)
		}
	}
	if got := certIssuer(leaf); got != opts.Issuer {
		return fmt.Errorf("attest: the certificate's OIDC issuer is %q, want %q", got, opts.Issuer)
	}
	ids := certIdentities(leaf)
	ok := false
	for _, id := range ids {
		if id == opts.Identity {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("attest: the certificate's identity is %v, want %q", ids, opts.Identity)
	}
	pub, isEC := leaf.PublicKey.(*ecdsa.PublicKey)
	if !isEC || !ecdsa.VerifyASN1(pub, digest, sig) {
		return token.ErrSignature
	}
	res.Identity, res.Issuer = opts.Identity, opts.Issuer
	return nil
}

// verifyUnderTrust checks the Rekor entry against the trusted root's key for its log id, with the entry's signed
// time inside that key's window, then the leaf against each Fulcio chain whose window holds that time. It returns the
// signed integration time.
func verifyUnderTrust(b *Bundle, chain []*x509.Certificate, env token.Envelope, payload []byte, tr *TrustedRoot, res *Result) (int64, error) {
	entries := b.VerificationMaterial.TlogEntries
	if len(entries) != 1 {
		return 0, errors.New("attest: the bundle carries not exactly one Rekor entry")
	}
	var logErr error = errors.New("no Rekor key in the trusted root matches the entry's log id")
	var at int64
	for _, l := range tr.Logs {
		if !bytes.Equal(l.LogID, entries[0].LogID.KeyID) {
			continue
		}
		idx, t, err := verifySET(entries[0], env, payload, l.Key)
		if err != nil {
			logErr = fmt.Errorf("Rekor entry: %w", err)
			continue
		}
		if !l.Window.Contains(time.Unix(t, 0)) {
			logErr = fmt.Errorf("Rekor entry: signed at %s, outside the key's window", time.Unix(t, 0).UTC().Format(time.RFC3339))
			continue
		}
		res.LogIndex, res.LogVerified, at, logErr = &idx, true, t, nil
		break
	}
	if logErr != nil {
		return 0, fmt.Errorf("attest: %w", logErr)
	}
	when := time.Unix(at, 0)
	var last error = errors.New("no Fulcio chain in the trusted root was valid at Rekor's time")
	for _, ca := range tr.CAs {
		if !ca.Window.Contains(when) {
			continue
		}
		roots, inter := x509.NewCertPool(), x509.NewCertPool()
		for _, c := range ca.Chain {
			if bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
				roots.AddCert(c)
			} else {
				inter.AddCert(c)
			}
		}
		for _, c := range chain[1:] {
			inter.AddCert(c)
		}
		_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: when,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
		if err == nil {
			return at, nil
		}
		last = err
	}
	return 0, fmt.Errorf("attest: the certificate does not verify to the trusted root at Rekor's time: %w", last)
}

func parseInt(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func certIdentities(c *x509.Certificate) []string {
	var out []string
	out = append(out, c.EmailAddresses...)
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	return out
}

func certIssuer(c *x509.Certificate) string {
	for _, e := range c.Extensions {
		switch {
		case e.Id.Equal(oidIssuerV2):
			var s string
			if _, err := asn1.Unmarshal(e.Value, &s); err == nil {
				return s
			}
		case e.Id.Equal(oidIssuerV1):
			return string(e.Value)
		}
	}
	return ""
}

// ParseKeys reads the keys to verify a static attestation against: a PEM public key (or a certificate), or the
// core's JWKS (GET /v1/keys).
func ParseKeys(raw []byte) (token.KeySet, error) {
	if t := strings.TrimSpace(string(raw)); strings.HasPrefix(t, "{") {
		return token.ParseJWKS(raw)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("attest: neither a PEM public key nor a JWKS")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		cert, cerr := x509.ParseCertificate(blk.Bytes) // a certificate: its public key
		if cerr != nil {
			return nil, fmt.Errorf("attest: neither a public key nor a certificate: %w", err)
		}
		pub = cert.PublicKey
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("attest: the public key is not ECDSA")
	}
	kid, err := token.KeyID(ec)
	if err != nil {
		return nil, err
	}
	return token.KeySet{kid: ec}, nil
}

// ParseRekorKey reads Rekor's public key (PEM, ECDSA).
func ParseRekorKey(raw []byte) (*ecdsa.PublicKey, error) {
	ks, err := ParseKeys(raw)
	if err != nil {
		return nil, err
	}
	for _, k := range ks {
		return k, nil
	}
	return nil, errors.New("attest: no key")
}

// ParseRoots reads the Fulcio certificates to trust (PEM).
func ParseRoots(raw []byte) (*x509.CertPool, error) {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(raw) {
		return nil, errors.New("attest: no PEM certificate in the trust root")
	}
	return p, nil
}
