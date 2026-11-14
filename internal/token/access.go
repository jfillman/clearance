package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// The packet access credential (P-1): what a subscriber hands a recipient so it can read one packet, and nothing
// else, for a window. It is a compact JWS (ES256) signed by the same core key as the clearance token and verified
// with the same key set (GET /v1/keys), so there is one signing path and one rotation. It is minted in the delivery
// call's answer and never stored: the core keeps the delivery record, not the secret.
const (
	// AccessType is the credential's _type; AccessJWTType its JOSE typ.
	AccessType    = "clearance.packet-access/v1"
	AccessJWTType = "clearance-packet-access+jwt"
	// AccessAudience is the credential's aud: it is good for the packet routes of the core that issued it and for nothing
	// else (not a clearance token, not any other route). It is self-contained, so a service that only passes it through
	// to the core (a hosted front that keeps its own register of grants) needs nothing but the string.
	AccessAudience = "clearance-packets"
	// MaxAccessLifetime bounds exp - nbf whoever signed it.
	MaxAccessLifetime = 30 * 24 * time.Hour
	// MaxAccessBytes caps a credential the core will parse.
	MaxAccessBytes = 4 << 10
)

// AccessClaims is the credential's payload.
type AccessClaims struct {
	Type     string `json:"_type"`
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	// Subject is the delivery's id (dl-<seq of the packet.deliver record>).
	Subject string `json:"sub"`
	// Packet and Digest name the one packet it opens; Recipient is the registered recipient it was granted to.
	Packet    string `json:"packet"`
	Digest    string `json:"digest"`
	Recipient string `json:"recipient"`
	// Scope is the parts of the packet it opens (the packet package's parts).
	Scope     []string `json:"scope"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	Expires   int64    `json:"exp"`
}

// Check is what IssueAccess and ParseAccess require of the claims themselves (not the time: the caller compares
// that, so it can say why it refused).
func (c *AccessClaims) Check() error {
	switch {
	case c.Type != AccessType:
		return fmt.Errorf("%w: _type is %q", ErrMalformed, c.Type)
	case c.Audience != AccessAudience:
		return fmt.Errorf("%w: aud is %q, not %s", ErrMalformed, c.Audience, AccessAudience)
	case c.Issuer == "" || c.Subject == "" || c.Packet == "" || c.Recipient == "" || len(c.Digest) != 64:
		return fmt.Errorf("%w: iss, sub, packet, digest and recipient are required", ErrMalformed)
	case len(c.Scope) == 0 || len(c.Scope) > 8:
		return fmt.Errorf("%w: scope names 1 to 8 parts", ErrMalformed)
	case c.IssuedAt <= 0 || c.NotBefore <= 0 || c.Expires <= c.NotBefore:
		return fmt.Errorf("%w: exp must follow nbf", ErrMalformed)
	case time.Duration(c.Expires-c.NotBefore)*time.Second > MaxAccessLifetime:
		return fmt.Errorf("%w: a packet credential lives at most %s", ErrMalformed, MaxAccessLifetime)
	}
	return nil
}

// IssueAccess signs the claims as a compact JWS.
func IssueAccess(ctx context.Context, s Signer, c AccessClaims) (string, error) {
	if err := c.Check(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	header, _ := json.Marshal(map[string]string{"alg": Algorithm, "kid": s.KeyID(), "typ": AccessJWTType})
	input := b64url(header) + "." + b64url(payload)
	d := sha256.Sum256([]byte(input))
	der, err := s.Sign(ctx, d[:])
	if err != nil {
		return "", fmt.Errorf("token: signing: %w", err)
	}
	raw, err := derToRaw(der)
	if err != nil {
		return "", fmt.Errorf("token: the signer's signature: %w", err)
	}
	return input + "." + b64url(raw), nil
}

// ParseAccess checks the credential's form and signature against keys and returns its claims. It does not read the
// clock or the scope: ErrMalformed, ErrUnknownKey and ErrSignature are the only refusals, and each means the bearer
// presented something this core did not sign.
func ParseAccess(jwt string, keys KeySet) (*AccessClaims, error) {
	if len(jwt) > MaxAccessBytes {
		return nil, fmt.Errorf("%w: over %d bytes", ErrMalformed, MaxAccessBytes)
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
	if h.Alg != Algorithm || h.Typ != AccessJWTType {
		return nil, fmt.Errorf("%w: alg must be %s and typ %s", ErrMalformed, Algorithm, AccessJWTType)
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
	if !ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, ErrSignature
	}
	var c AccessClaims
	if err := strictJSON(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrMalformed, err)
	}
	if err := c.Check(); err != nil {
		return nil, err
	}
	return &c, nil
}
