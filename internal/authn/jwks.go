package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// MaxJWKSBytes caps an issuer's JWKS response.
const MaxJWKSBytes = 1 << 20

// JWKS is an issuer's signing keys, fetched from its JWKS URL and refreshed when a token names a key not seen yet,
// at most once per MinRefresh, so a stream of bad kids can't hammer the issuer (auth.JWKS).
type JWKS struct {
	URL        string
	MinRefresh time.Duration
	// Fetch returns the JWKS document; nil means an HTTP GET with Client.
	Fetch  func(ctx context.Context, url string) ([]byte, error)
	Client *http.Client
	Now    func() time.Time

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetched   bool
	fetchedAt time.Time
}

// NewJWKS is a JWKS over HTTP with a one-minute minimum refresh and a 10 s fetch deadline.
func NewJWKS(url string) *JWKS {
	return &JWKS{URL: url, MinRefresh: time.Minute, Client: &http.Client{Timeout: 10 * time.Second}}
}

func (j *JWKS) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

func (j *JWKS) get(ctx context.Context, url string) ([]byte, error) {
	c := j.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxJWKSBytes {
		return nil, fmt.Errorf("JWKS fetch: response over %d bytes", MaxJWKSBytes)
	}
	return b, nil
}

// Key returns the signing key named kid ("" for a token without one), refreshing the set first if kid is unknown
// and the last fetch is at least MinRefresh old. A failed fetch counts as a fetch (the Python sets the time first)
// and leaves the keys as they were; it is a refusal like an unknown key.
func (j *JWKS) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.keys[kid]; !ok && (!j.fetched || j.now().Sub(j.fetchedAt) >= j.MinRefresh) {
		j.fetched, j.fetchedAt = true, j.now()
		fetch := j.Fetch
		if fetch == nil {
			fetch = j.get
		}
		raw, err := fetch(ctx, j.URL)
		if err != nil {
			return nil, refuse("signing keys unavailable")
		}
		keys, err := parseJWKS(raw)
		if err != nil {
			return nil, refuse("signing keys unavailable")
		}
		j.keys = keys
	}
	k, ok := j.keys[kid]
	if !ok {
		return nil, refuse("unknown signing key")
	}
	return k, nil
}

type jwk struct {
	Kid *string `json:"kid"`
	Kty string  `json:"kty"`
	Use *string `json:"use"`
	N   string  `json:"n"`
	E   string  `json:"e"`
	Crv string  `json:"crv"`
	X   string  `json:"x"`
	Y   string  `json:"y"`
}

// parseJWKS reads {"keys": [...]}: the signing keys (use absent or "sig") by kid. Only RSA and P-256 keys are kept,
// the two key types RS256 and ES256 verify with; a key of another type, or one that does not decode, is skipped
// (PyJWK would fail the whole refresh on a malformed key; a skipped key can never verify a token either way).
func parseJWKS(raw []byte) (map[string]crypto.PublicKey, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := map[string]crypto.PublicKey{}
	for _, r := range doc.Keys {
		var k jwk
		if json.Unmarshal(r, &k) != nil {
			continue
		}
		if k.Use != nil && *k.Use != "sig" {
			continue
		}
		pub, err := k.public()
		if err != nil {
			continue
		}
		kid := ""
		if k.Kid != nil {
			kid = *k.Kid
		}
		out[kid] = pub
	}
	return out, nil
}

func (k jwk) public() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64(k.N)
		if err != nil || len(n) == 0 {
			return nil, fmt.Errorf("bad n")
		}
		e, err := b64(k.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, fmt.Errorf("bad e")
		}
		ei := new(big.Int).SetBytes(e).Int64()
		if ei < 3 || ei%2 == 0 {
			return nil, fmt.Errorf("bad e")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ei)}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported curve")
		}
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
			return nil, fmt.Errorf("bad point")
		}
		pt := append(append([]byte{4}, x...), y...)
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	}
	return nil, fmt.Errorf("unsupported key type")
}
