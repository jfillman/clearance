package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// KeySigner is a Signer on an ECDSA P-256 private key held in memory: the lab's key file.
type KeySigner struct {
	key *ecdsa.PrivateKey
	kid string
}

// NewKeySigner wraps a P-256 private key.
func NewKeySigner(key *ecdsa.PrivateKey) (*KeySigner, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("token: the signing key must be ECDSA P-256")
	}
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &KeySigner{key: key, kid: kid}, nil
}

// KeyID is the key's thumbprint.
func (s *KeySigner) KeyID() string { return s.kid }

// Public is the verification key.
func (s *KeySigner) Public() *ecdsa.PublicKey { return &s.key.PublicKey }

// Sign signs a SHA-256 digest (ASN.1 DER).
func (s *KeySigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("token: a SHA-256 digest is 32 bytes")
	}
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

// MaxKeyFileBytes caps the key file.
const MaxKeyFileBytes = 64 << 10

// LoadKeyFile reads a PEM ECDSA P-256 private key ("EC PRIVATE KEY", SEC 1, as `openssl ecparam -genkey` writes
// it, or "PRIVATE KEY", PKCS #8). Errors never quote the file.
func LoadKeyFile(path string) (*KeySigner, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("token: the signing key file: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("token: reading the signing key file: %w", err)
	}
	if len(raw) > MaxKeyFileBytes {
		return nil, errors.New("token: the signing key file is too large")
	}
	return ParseKeyPEM(raw)
}

// ParseKeyPEM is LoadKeyFile on bytes.
func ParseKeyPEM(raw []byte) (*KeySigner, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("token: the signing key is not PEM")
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("token: the signing key is not a SEC 1 EC private key")
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("token: the signing key is not a PKCS #8 private key")
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("token: the signing key must be ECDSA P-256")
		}
		key = ek
	default:
		return nil, fmt.Errorf("token: a %q PEM block is not an EC private key", block.Type)
	}
	return NewKeySigner(key)
}

// NonceCache is a NonceChecker for a one-shot consumer: a nonce is accepted once, until its token expires. It
// holds at most Max nonces (0: DefaultCacheMax); when full it refuses new ones (fail closed) rather than forget.
type NonceCache struct {
	Max int
	Now func() time.Time

	mu   sync.Mutex
	seen map[string]int64 // nonce -> exp
}

// DefaultCacheMax is NonceCache's default capacity.
const DefaultCacheMax = 100000

// ErrCacheFull is returned (wrapping ErrReplay) when a NonceCache is full of live nonces.
var ErrCacheFull = fmt.Errorf("%w: the nonce cache is full", ErrReplay)

// CheckNonce accepts a nonce the first time only.
func (n *NonceCache) CheckNonce(_ context.Context, c *Claims) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now
	if n.Now != nil {
		now = n.Now
	}
	t := now().Unix()
	if n.seen == nil {
		n.seen = map[string]int64{}
	}
	key := c.Subject + "/" + c.Nonce
	if exp, ok := n.seen[key]; ok && exp >= t-int64(DefaultLeeway/time.Second) {
		return fmt.Errorf("%w: nonce already used", ErrReplay)
	}
	max := n.Max
	if max <= 0 {
		max = DefaultCacheMax
	}
	if len(n.seen) >= max {
		for k, exp := range n.seen {
			if exp < t-int64(DefaultLeeway/time.Second) {
				delete(n.seen, k)
			}
		}
		if len(n.seen) >= max {
			return ErrCacheFull
		}
	}
	n.seen[key] = c.Expires
	return nil
}
