package authn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"strings"
	"time"
)

// MaxTokenBytes caps a bearer token before it is decoded. Real ID and service-account tokens are a few KiB.
const MaxTokenBytes = 16 << 10

// JWT is a compact JWS split and decoded, not verified: its header and claims (numbers as json.Number), and what
// the signature covers.
type JWT struct {
	Header       map[string]any
	Claims       map[string]any
	signingInput string
	signature    []byte
}

// ParseJWT splits and decodes a compact JWS without verifying it (PyJWT's decode with verify_signature off): three
// base64url segments, a JSON object header whose kid, when present, is a string, and a JSON object payload.
func ParseJWT(token string) (*JWT, error) {
	if len(token) > MaxTokenBytes {
		return nil, refuse("token too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, refuse("not a JWT")
	}
	var segs [3][]byte
	for i, p := range parts {
		b, err := b64(p)
		if err != nil {
			return nil, refuse("not a JWT")
		}
		segs[i] = b
	}
	header, err := object(segs[0])
	if err != nil {
		return nil, refuse("not a JWT")
	}
	if kid, ok := header["kid"]; ok {
		if _, isStr := kid.(string); !isStr {
			return nil, refuse("not a JWT")
		}
	}
	claims, err := object(segs[1])
	if err != nil {
		return nil, refuse("not a JWT")
	}
	return &JWT{Header: header, Claims: claims, signingInput: parts[0] + "." + parts[1], signature: segs[2]}, nil
}

// b64 is PyJWT's base64url_decode: unpadded base64url, trailing padding tolerated.
func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(strings.TrimRight(s, "="))
}

func object(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return m, nil
}

// Alg is the token's alg header ("" when absent or not a string).
func (t *JWT) Alg() string { s, _ := t.Header["alg"].(string); return s }

// Kid is the token's kid header ("" when absent).
func (t *JWT) Kid() string { s, _ := t.Header["kid"].(string); return s }

// verifySignature checks the signature with key under alg, which must be one of algs and match the key's type:
// RS256 (RSASSA-PKCS1-v1_5, SHA-256) with an RSA key, ES256 (ECDSA P-256, SHA-256, r||s) with a P-256 key. No
// other algorithm is implemented, so none, HMAC and every other alg are refused whatever algs says.
func (t *JWT) verifySignature(key crypto.PublicKey, algs []string) error {
	alg := t.Alg()
	if !contains(algs, alg) {
		return refuse("the specified alg value is not allowed")
	}
	if _, crit := t.Header["crit"]; crit {
		return refuse("unsupported critical header")
	}
	digest := sha256.Sum256([]byte(t.signingInput))
	switch alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return refuse("key does not fit the algorithm")
		}
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], t.signature) != nil {
			return refuse("signature verification failed")
		}
		return nil
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return refuse("key does not fit the algorithm")
		}
		if len(t.signature) != 64 {
			return refuse("signature verification failed")
		}
		r, s := new(big.Int).SetBytes(t.signature[:32]), new(big.Int).SetBytes(t.signature[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return refuse("signature verification failed")
		}
		return nil
	}
	return refuse("the specified alg value is not allowed")
}

// claimInt is PyJWT's int(payload[name]) for a JSON number: truncated toward zero; anything else is an error.
func claimInt(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return math.Trunc(f), true
}

// claimChecks are the claim checks every ID-token verifier here runs (PyJWT's decode with
// require=[exp, iat, iss, aud, sub], an issuer, an audience and a leeway).
type claimChecks struct {
	Issuer   string
	Audience string
	Leeway   time.Duration
}

func (c claimChecks) verify(claims map[string]any, now time.Time) error {
	for _, k := range []string{"exp", "iat", "iss", "aud", "sub"} {
		if claims[k] == nil {
			return refuse("token is missing the " + k + " claim")
		}
	}
	ts := float64(now.UnixNano()) / 1e9
	lee := c.Leeway.Seconds()
	exp, ok := claimInt(claims["exp"])
	if !ok {
		return refuse("exp must be an integer")
	}
	if exp <= ts-lee {
		return refuse("token has expired")
	}
	iat, ok := claimInt(claims["iat"])
	if !ok {
		return refuse("iat must be an integer")
	}
	if iat > ts+lee {
		return refuse("token is not yet valid (iat)")
	}
	if nbfv, present := claims["nbf"]; present {
		nbf, ok := claimInt(nbfv)
		if !ok {
			return refuse("nbf must be an integer")
		}
		if nbf > ts+lee {
			return refuse("token is not yet valid (nbf)")
		}
	}
	if _, ok := claims["sub"].(string); !ok {
		return refuse("sub must be a string")
	}
	if jti, present := claims["jti"]; present {
		if _, ok := jti.(string); !ok {
			return refuse("jti must be a string")
		}
	}
	if iss, ok := claims["iss"].(string); !ok || iss != c.Issuer {
		return refuse("invalid issuer")
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != c.Audience {
			return refuse("audience doesn't match")
		}
	case []any:
		if len(aud) == 0 {
			return refuse("token is missing the aud claim")
		}
		found := false
		for _, a := range aud {
			s, ok := a.(string)
			if !ok {
				return refuse("invalid audience claim")
			}
			found = found || s == c.Audience
		}
		if !found {
			return refuse("audience doesn't match")
		}
	default:
		return refuse("invalid audience claim")
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
