// Package token is the clearance token (C-1): a signed, short-lived statement by the core that a change is cleared,
// bound to what was cleared. One set of claims (Claims) is signed twice by one Signer: as a DSSE envelope (the
// format the attestation signer, C-2, also uses, so one signing path serves tokens and attestations) and as a
// compact JWS (the JWT projection, for the Argo CD PreSync hook and anything else that speaks JWT).
//
// Crypto is the standard library's only: ECDSA P-256 with SHA-256 (ES256). A DSSE signature is ASN.1 DER, as
// Sigstore writes and verifies it; the JWS signature is the fixed-width r||s RFC 7518 asks for. Both come from one
// DER signature of the Signer, so a KMS that signs a digest and returns DER (AWS KMS ECDSA_SHA_256, Google Cloud
// KMS EC_SIGN_P256_SHA256, Vault transit with marshaling_algorithm=asn1) is a Signer without code here changing.
//
// Verification is offline: Verify and VerifyJWT need the core's public keys (KeySet, from GET /v1/keys) and
// nothing else. Replay and invalidation are the NonceChecker's: the core keeps each token's nonce with its
// clearance (a new head on the change's pull request revokes it), and a one-shot consumer can keep a NonceCache.
package token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// Type is the claims' _type: the token format and its version.
const Type = "clearance.token/v1"

// PayloadType is the DSSE payloadType of a clearance token.
const PayloadType = "application/vnd.clearance.token.v1+json"

// JWTType is the JWS header's typ.
const JWTType = "clearance-token+jwt"

// Algorithm is the only signature algorithm: ECDSA P-256 with SHA-256.
const Algorithm = "ES256"

// Limits on what a verifier parses. A token lists every object of the change (at most 2000), so a payload can be
// large; past these it is refused before any JSON or base64 work.
const (
	MaxEnvelopeBytes = 8 << 20
	MaxJWTBytes      = 12 << 20
	MaxSignatures    = 4
	// MaxLifetime bounds exp - iat: a token claiming a longer life is refused, whoever signed it.
	MaxLifetime = 24 * time.Hour
	// DefaultLeeway is the clock skew Verify allows on iat and exp.
	DefaultLeeway = 30 * time.Second
)

// The errors Verify returns, told apart with errors.Is. Every one of them means: do not act on this token.
var (
	ErrMalformed      = errors.New("token: malformed")
	ErrUnknownKey     = errors.New("token: signed by no key in the key set")
	ErrSignature      = errors.New("token: bad signature")
	ErrExpired        = errors.New("token: expired")
	ErrNotYetValid    = errors.New("token: issued in the future")
	ErrIssuer         = errors.New("token: wrong issuer")
	ErrReplay         = errors.New("token: replayed or revoked (the nonce is not the clearance's live one)")
	ErrDigestMismatch = errors.New("token: bound to a different digest")
	ErrNotCovered     = errors.New("token: the object is not one the clearance lists")
)

// Claims are what a token says. Field order is the JSON order; the payload is encoding/json of this struct.
type Claims struct {
	Type    string `json:"_type"`
	Issuer  string `json:"iss"`
	Subject string `json:"sub"` // the clearance (change) id
	// IssuedAt and Expires are NumericDate seconds, as JWT has them.
	IssuedAt int64 `json:"iat"`
	Expires  int64 `json:"exp"`
	// Nonce identifies this clearance's issuance: kept by the core with the clearance, the same across the
	// token's refreshes, replaced when the change is cleared again, revoked when a new head supersedes it.
	Nonce      string     `json:"nonce"`
	Clearance  Clearance  `json:"clearance"`
	Subjects   Subjects   `json:"subjects"`
	Objects    []Object   `json:"objects"`
	Target     Target     `json:"target"`
	Tier       int        `json:"tier"`
	Policy     Policy     `json:"policy"`
	Provenance Provenance `json:"provenance"`
	Approvals  []Approval `json:"approvals"`
}

// Clearance is the decision the token carries.
type Clearance struct {
	ID string `json:"id"`
	// ClearedBy is "policy" (tiers 0 and 1 when the checks hold) or "people" (the requirement was met).
	ClearedBy string `json:"cleared_by"`
	DecidedAt string `json:"decided_at"`
}

// Subjects are what the clearance is bound to. TreeRoot (a gitops change) or PlanDigest (a Terraform plan, G-TF-1)
// is the binding; Commit and Images are cross-references.
type Subjects struct {
	Kind       string   `json:"kind"` // manifest-tree | terraform-plan
	Repo       string   `json:"repo"`
	PR         int64    `json:"pr"`
	Commit     string   `json:"commit"`
	Base       string   `json:"base,omitempty"`
	TreeRoot   string   `json:"tree_root,omitempty"`
	PlanDigest string   `json:"plan_digest,omitempty"`
	Images     []string `json:"images"`
}

// Object is one rendered object of the change: its identity, its rendered hash, and whether this change touches it.
type Object struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	Rendered   string `json:"rendered"`
	Changed    bool   `json:"changed"`
	Op         string `json:"op"`
}

// Target is where the change deploys.
type Target struct {
	Cluster string `json:"cluster"`
	Env     string `json:"env"`
	App     string `json:"app"`
}

// Policy is the policy the gate decided with and its verdict.
type Policy struct {
	Ref              string `json:"ref"`
	RepoPolicyDigest string `json:"repo_policy_digest,omitempty"`
	Engine           string `json:"engine"`
	EngineVersion    string `json:"engine_version"`
	// Verdict is the engine's: "clear" (by policy) or "hold" (for people, then met).
	Verdict string `json:"verdict"`
}

// Provenance is who proposed the change and how sure Clearance is of it.
type Provenance struct {
	// Level is one of the evidence schema's: confirmed-agent, probable-agent, confirmed-human, unknown.
	Level        string `json:"level"`
	Check        string `json:"check,omitempty"` // the provenance check as the verifier reported it
	Proposer     string `json:"proposer"`
	ProposerKind string `json:"proposer_kind"`
	Agent        string `json:"agent,omitempty"`
	TaskID       string `json:"task_id,omitempty"`
}

// Approval is one person's approval: the IdP subject and issuer, the person, and the delegate it came through.
type Approval struct {
	Sub    string `json:"sub"`
	Iss    string `json:"iss"`
	Person string `json:"person"`
	Via    string `json:"via,omitempty"`
	Role   string `json:"role"`
	At     string `json:"at"`
}

// Signer signs a SHA-256 digest with ECDSA P-256 and returns the ASN.1 DER signature. A file key (KeySigner) is
// the lab's; a KMS key is the same interface (docs/core.md, The clearance token).
type Signer interface {
	KeyID() string
	Public() *ecdsa.PublicKey
	Sign(ctx context.Context, digest []byte) ([]byte, error)
}

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Token is an issued token: both encodings of one set of claims.
type Token struct {
	Claims   Claims
	Envelope Envelope
	JWT      string
	KeyID    string
}

// PAE is DSSE's pre-authentication encoding: "DSSEv1 <len(type)> <type> <len(body)> <body>".
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// Check is what Issue and Verify require of the claims themselves.
func (c *Claims) Check() error {
	switch {
	case c.Type != Type:
		return fmt.Errorf("%w: _type is %q", ErrMalformed, c.Type)
	case c.Issuer == "" || c.Subject == "" || c.Nonce == "":
		return fmt.Errorf("%w: iss, sub and nonce are required", ErrMalformed)
	case c.IssuedAt <= 0 || c.Expires <= c.IssuedAt:
		return fmt.Errorf("%w: exp must follow iat", ErrMalformed)
	case time.Duration(c.Expires-c.IssuedAt)*time.Second > MaxLifetime:
		return fmt.Errorf("%w: a token lives at most %s", ErrMalformed, MaxLifetime)
	case c.Subjects.TreeRoot == "" && c.Subjects.PlanDigest == "":
		return fmt.Errorf("%w: a token is bound to a tree root or a plan digest", ErrMalformed)
	case c.Clearance.ID != c.Subject:
		return fmt.Errorf("%w: clearance.id is not sub", ErrMalformed)
	}
	return nil
}

// Issue signs claims as a DSSE envelope and as a JWT.
func Issue(ctx context.Context, s Signer, c Claims) (Token, error) {
	if err := c.Check(); err != nil {
		return Token{}, err
	}
	if c.Objects == nil {
		c.Objects = []Object{}
	}
	if c.Approvals == nil {
		c.Approvals = []Approval{}
	}
	if c.Subjects.Images == nil {
		c.Subjects.Images = []string{}
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return Token{}, err
	}
	kid := s.KeyID()
	d := sha256.Sum256(PAE(PayloadType, payload))
	der, err := s.Sign(ctx, d[:])
	if err != nil {
		return Token{}, fmt.Errorf("token: signing: %w", err)
	}
	env := Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{KeyID: kid, Sig: base64.StdEncoding.EncodeToString(der)}}}
	header, _ := json.Marshal(map[string]string{"alg": Algorithm, "kid": kid, "typ": JWTType})
	input := b64url(header) + "." + b64url(payload)
	jd := sha256.Sum256([]byte(input))
	jder, err := s.Sign(ctx, jd[:])
	if err != nil {
		return Token{}, fmt.Errorf("token: signing: %w", err)
	}
	raw, err := derToRaw(jder)
	if err != nil {
		return Token{}, fmt.Errorf("token: the signer's signature: %w", err)
	}
	return Token{Claims: c, Envelope: env, JWT: input + "." + b64url(raw), KeyID: kid}, nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type ecdsaSig struct{ R, S *big.Int }

// derToRaw is an ASN.1 DER ECDSA P-256 signature as JWS's 64-byte r||s.
func derToRaw(der []byte) ([]byte, error) {
	var sig ecdsaSig
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 ||
		sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		return nil, errors.New("not a DER ECDSA P-256 signature")
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}

// NonceChecker decides whether a verified token's nonce may be acted on: the clearance's live nonce (the core), or
// one not seen before (a NonceCache). It returns ErrReplay (wrapped) when not.
type NonceChecker interface {
	CheckNonce(ctx context.Context, c *Claims) error
}

// Expect is what the caller knows the token must be bound to; empty fields are not checked.
type Expect struct {
	ClearanceID string
	TreeRoot    string
	PlanDigest  string
	Commit      string
	Cluster     string
}

// Options are a verification's inputs. Issuer is required.
type Options struct {
	Issuer string
	Now    func() time.Time // nil: time.Now
	Leeway time.Duration    // 0: DefaultLeeway; negative: none
	Expect Expect
	Nonces NonceChecker // nil: replay is not checked (an offline grant-sync relies on the feed instead)
}

// Verify checks a DSSE envelope (its JSON) against keys and opts and returns its claims.
func Verify(ctx context.Context, raw []byte, keys KeySet, opts Options) (*Claims, error) {
	env, err := ParseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	payload, err := decodeB64(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64", ErrMalformed)
	}
	d := sha256.Sum256(PAE(env.PayloadType, payload))
	if err := keys.verifyAny(env.Signatures, d[:]); err != nil {
		return nil, err
	}
	return check(ctx, payload, opts)
}

// VerifyJWT checks the JWT projection against keys and opts and returns its claims.
func VerifyJWT(ctx context.Context, jwt string, keys KeySet, opts Options) (*Claims, error) {
	if len(jwt) > MaxJWTBytes {
		return nil, fmt.Errorf("%w: over %d bytes", ErrMalformed, MaxJWTBytes)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrMalformed)
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header is not base64url", ErrMalformed)
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := strictJSON(hb, &h); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	if h.Alg != Algorithm || h.Typ != JWTType {
		return nil, fmt.Errorf("%w: alg must be %s and typ %s", ErrMalformed, Algorithm, JWTType)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url", ErrMalformed)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, fmt.Errorf("%w: signature is not a 64-byte ES256 signature", ErrMalformed)
	}
	pub, ok := keys[h.Kid]
	if !ok {
		return nil, ErrUnknownKey
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, d[:], r, s) {
		return nil, ErrSignature
	}
	return check(ctx, payload, opts)
}

// check decodes the signed payload strictly and checks the claims against opts.
func check(ctx context.Context, payload []byte, opts Options) (*Claims, error) {
	var c Claims
	if err := strictJSON(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrMalformed, err)
	}
	if err := c.Check(); err != nil {
		return nil, err
	}
	if opts.Issuer == "" || c.Issuer != opts.Issuer {
		return nil, fmt.Errorf("%w: %q", ErrIssuer, c.Issuer)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	leeway := opts.Leeway
	if leeway == 0 {
		leeway = DefaultLeeway
	} else if leeway < 0 {
		leeway = 0
	}
	t := now()
	if !t.Before(time.Unix(c.Expires, 0).Add(leeway)) {
		return nil, ErrExpired
	}
	if t.Add(leeway).Before(time.Unix(c.IssuedAt, 0)) {
		return nil, ErrNotYetValid
	}
	e := opts.Expect
	for _, p := range [][3]string{{"clearance", e.ClearanceID, c.Subject}, {"tree root", e.TreeRoot, c.Subjects.TreeRoot},
		{"plan digest", e.PlanDigest, c.Subjects.PlanDigest}, {"commit", e.Commit, c.Subjects.Commit},
		{"cluster", e.Cluster, c.Target.Cluster}} {
		if p[1] != "" && p[1] != p[2] {
			return nil, fmt.Errorf("%w: the %s is %q, not %q", ErrDigestMismatch, p[0], p[2], p[1])
		}
	}
	if opts.Nonces != nil {
		if err := opts.Nonces.CheckNonce(ctx, &c); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// Covers says whether the claims list the object with this rendered hash: nil, ErrNotCovered (not listed) or
// ErrDigestMismatch (listed with another hash). What admission asks of a grant (G-ARGO-2).
func (c *Claims) Covers(apiVersion, kind, namespace, name, rendered string) error {
	for _, o := range c.Objects {
		if o.APIVersion == apiVersion && o.Kind == kind && o.Namespace == namespace && o.Name == name {
			if o.Rendered != rendered || rendered == "" {
				return fmt.Errorf("%w: %s %s/%s is %q in the clearance", ErrDigestMismatch, kind, namespace, name, o.Rendered)
			}
			return nil
		}
	}
	return fmt.Errorf("%w: %s %s/%s", ErrNotCovered, kind, namespace, name)
}

// ParseEnvelope decodes a DSSE envelope strictly: size-capped, unknown fields refused, the clearance payloadType,
// one to MaxSignatures signatures.
func ParseEnvelope(raw []byte) (*Envelope, error) {
	if len(raw) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: over %d bytes", ErrMalformed, MaxEnvelopeBytes)
	}
	var env Envelope
	if err := strictJSON(raw, &env); err != nil {
		return nil, fmt.Errorf("%w: envelope: %v", ErrMalformed, err)
	}
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("%w: payloadType is %q", ErrMalformed, env.PayloadType)
	}
	if len(env.Signatures) == 0 || len(env.Signatures) > MaxSignatures {
		return nil, fmt.Errorf("%w: 1 to %d signatures", ErrMalformed, MaxSignatures)
	}
	return &env, nil
}

// decodeB64 reads DSSE base64: standard or URL-safe, padded or not (the DSSE spec allows either).
func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

// strictJSON decodes exactly one JSON value into v, refusing unknown fields and trailing data.
func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

// KeySet is the verification keys by key id (GET /v1/keys).
type KeySet map[string]*ecdsa.PublicKey

func (ks KeySet) verifyAny(sigs []Signature, digest []byte) error {
	known := false
	for _, s := range sigs {
		pub, ok := ks[s.KeyID]
		if !ok {
			continue
		}
		known = true
		der, err := decodeB64(s.Sig)
		if err != nil {
			continue
		}
		if ecdsa.VerifyASN1(pub, digest, der) {
			return nil
		}
	}
	if !known {
		return ErrUnknownKey
	}
	return ErrSignature
}

// KeyID is a P-256 public key's RFC 7638 JWK thumbprint (base64url SHA-256): the DSSE keyid and the JWS kid.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	x, y, err := coords(pub)
	if err != nil {
		return "", err
	}
	// RFC 7638: the required members in lexicographic order, no whitespace.
	canon := `{"crv":"P-256","kty":"EC","x":"` + b64url(x) + `","y":"` + b64url(y) + `"}`
	d := sha256.Sum256([]byte(canon))
	return b64url(d[:]), nil
}

func coords(pub *ecdsa.PublicKey) ([]byte, []byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, nil, errors.New("token: not a P-256 public key")
	}
	k, err := pub.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("token: %w", err)
	}
	b := k.Bytes() // 0x04 || X || Y
	return b[1:33], b[33:65], nil
}

// JWK is one key of a JWKS.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// JWKS is GET /v1/keys's answer.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWK is pub as a JWK with its thumbprint as kid.
func PublicJWK(pub *ecdsa.PublicKey) (JWK, error) {
	x, y, err := coords(pub)
	if err != nil {
		return JWK{}, err
	}
	kid, err := KeyID(pub)
	if err != nil {
		return JWK{}, err
	}
	return JWK{Kty: "EC", Crv: "P-256", X: b64url(x), Y: b64url(y), Kid: kid, Alg: Algorithm, Use: "sig"}, nil
}

// MaxJWKSBytes caps a key set a verifier reads.
const MaxJWKSBytes = 64 << 10

// ParseJWKS reads a key set: P-256 ES256 signing keys only, each kid its thumbprint (a kid that is not is refused,
// so a key set cannot alias one key under another's id).
func ParseJWKS(raw []byte) (KeySet, error) {
	if len(raw) > MaxJWKSBytes {
		return nil, fmt.Errorf("%w: key set over %d bytes", ErrMalformed, MaxJWKSBytes)
	}
	var set JWKS
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("%w: key set: %v", ErrMalformed, err)
	}
	ks := KeySet{}
	for _, k := range set.Keys {
		pub, err := k.Public()
		if err != nil {
			return nil, err
		}
		ks[k.Kid] = pub
	}
	return ks, nil
}

// Public is the JWK's key, checked: EC P-256, ES256, signing use, a point on the curve, kid its thumbprint.
func (k JWK) Public() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" || (k.Alg != "" && k.Alg != Algorithm) || (k.Use != "" && k.Use != "sig") {
		return nil, fmt.Errorf("%w: key %q is not an EC P-256 ES256 signing key", ErrMalformed, k.Kid)
	}
	x, errX := base64.RawURLEncoding.DecodeString(k.X)
	y, errY := base64.RawURLEncoding.DecodeString(k.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("%w: key %q coordinates", ErrMalformed, k.Kid)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, fmt.Errorf("%w: key %q is not on P-256", ErrMalformed, k.Kid)
	}
	kid, err := KeyID(pub)
	if err != nil || kid != k.Kid {
		return nil, fmt.Errorf("%w: key %q: kid is not the key's thumbprint", ErrMalformed, k.Kid)
	}
	return pub, nil
}

var _ crypto.PublicKey = (*ecdsa.PublicKey)(nil)
