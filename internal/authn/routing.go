package authn

import (
	"context"
	"crypto/sha256"
	"sort"
	"sync"
	"time"
)

// RoutingAuthenticator chooses the verifier by the token's unverified issuer: a listed issuer's verifier, else
// Workload. The choice is not trust: the chosen verifier checks everything, the issuer included, and a token that
// names a listed issuer and fails its verifier never falls through to Workload.
type RoutingAuthenticator struct {
	ByIssuer map[string]Authenticator
	Workload Authenticator // nil: tokens of no listed issuer are refused
}

// Authenticate routes token.
func (r *RoutingAuthenticator) Authenticate(ctx context.Context, token string) (Principal, error) {
	t, err := ParseJWT(token)
	if err != nil {
		return Principal{}, err
	}
	var v Authenticator
	if iss, ok := t.Claims["iss"].(string); ok {
		v = r.ByIssuer[iss]
	}
	if v == nil {
		v = r.Workload
	}
	if v == nil {
		return Principal{}, refuse("no verifier for this token")
	}
	return v.Authenticate(ctx, token)
}

// CachingAuthenticator remembers a verified token by its SHA-256 for TTL, never past its own exp. Failures are not
// cached. Bounded: once MaxEntries is reached the quarter of the entries that expire soonest go first.
type CachingAuthenticator struct {
	Inner      Authenticator
	TTL        time.Duration
	MaxEntries int
	Now        func() time.Time

	mu    sync.Mutex
	cache map[[32]byte]cacheEntry
}

type cacheEntry struct {
	p     Principal
	until time.Time
}

// NewCachingAuthenticator has the Python defaults: 60 s, 4096 entries.
func NewCachingAuthenticator(inner Authenticator) *CachingAuthenticator {
	return &CachingAuthenticator{Inner: inner, TTL: 60 * time.Second, MaxEntries: 4096}
}

func (c *CachingAuthenticator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Authenticate answers from the cache or from Inner.
func (c *CachingAuthenticator) Authenticate(ctx context.Context, token string) (Principal, error) {
	key := sha256.Sum256([]byte(token))
	now := c.now()
	c.mu.Lock()
	if hit, ok := c.cache[key]; ok && hit.until.After(now) {
		c.mu.Unlock()
		return hit.p, nil
	}
	c.mu.Unlock()
	p, err := c.Inner.Authenticate(ctx, token)
	if err != nil {
		return Principal{}, err
	}
	t, err := ParseJWT(token)
	if err != nil {
		return Principal{}, err
	}
	until := now.Add(c.TTL)
	if exp, ok := claimInt(t.Claims["exp"]); ok {
		if exp < float64(until.UnixNano())/1e9 {
			until = time.Unix(int64(exp), 0) // a Python exp may be a float; whole seconds suffice here
		}
	}
	max := c.MaxEntries
	if max <= 0 {
		max = 4096
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[[32]byte]cacheEntry{}
	}
	if len(c.cache) >= max {
		keys := make([][32]byte, 0, len(c.cache))
		for k := range c.cache {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return c.cache[keys[i]].until.Before(c.cache[keys[j]].until) })
		n := max / 4
		if n == 0 {
			n = 1
		}
		for _, k := range keys[:n] {
			delete(c.cache, k)
		}
	}
	c.cache[key] = cacheEntry{p, until}
	return p, nil
}
