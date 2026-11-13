package slack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Slack's request signature (https://api.slack.com/authentication/verifying-requests-from-slack): v0=HMAC-SHA256 of
// "v0:<timestamp>:<body>" under the signing secret, compared in constant time, refused outside the replay window.

// Verification refusals.
var (
	ErrNoSignature  = errors.New("slack: no signature")
	ErrBadSignature = errors.New("slack: signature does not match")
	ErrStale        = errors.New("slack: request timestamp outside the replay window")
)

// Sign is the v0 signature of a body at a timestamp (what Slack sends, and what the tests send).
func Sign(secret string, ts int64, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("v0:" + strconv.FormatInt(ts, 10) + ":"))
	m.Write(body)
	return "v0=" + hex.EncodeToString(m.Sum(nil))
}

// VerifyRequest checks a request's timestamp header, signature header and body. now is the clock (window is the
// replay window, 5 minutes by Slack's guidance). A future timestamp is as bad as a past one.
func VerifyRequest(secret, tsHeader, sigHeader string, body []byte, now time.Time, window time.Duration) error {
	if secret == "" || sigHeader == "" || tsHeader == "" {
		return ErrNoSignature
	}
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return ErrNoSignature
	}
	if d := now.Sub(time.Unix(ts, 0)); d > window || d < -window {
		return ErrStale
	}
	want := Sign(secret, ts, body)
	if !strings.HasPrefix(sigHeader, "v0=") || !hmac.Equal([]byte(want), []byte(sigHeader)) {
		return ErrBadSignature
	}
	return nil
}

// Dedupe remembers keys for a while: an event Slack redelivers (a retry, a socket envelope sent again, a replayed
// signed request inside the window) is processed once. Bounded: it drops the oldest past max.
type Dedupe struct {
	mu   sync.Mutex
	ttl  time.Duration
	max  int
	seen map[string]time.Time
	now  func() time.Time
}

// NewDedupe is a Dedupe that keeps keys for ttl, at most max of them.
func NewDedupe(ttl time.Duration, max int) *Dedupe {
	return &Dedupe{ttl: ttl, max: max, seen: map[string]time.Time{}, now: time.Now}
}

// First reports whether key is new (true) and remembers it; false means a duplicate.
func (d *Dedupe) First(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if at, ok := d.seen[key]; ok && now.Sub(at) < d.ttl {
		return false
	}
	if len(d.seen) >= d.max {
		for k, at := range d.seen {
			if now.Sub(at) >= d.ttl {
				delete(d.seen, k)
			}
		}
		for len(d.seen) >= d.max { // still full of live keys: drop the oldest
			var oldK string
			var oldT time.Time
			for k, at := range d.seen {
				if oldK == "" || at.Before(oldT) {
					oldK, oldT = k, at
				}
			}
			delete(d.seen, oldK)
		}
	}
	d.seen[key] = now
	return true
}
