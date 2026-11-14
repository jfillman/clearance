package server

import (
	"hash/maphash"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// limiter is the public listener's abuse limit: a token bucket per client and one for everyone, in fixed memory. A client
// is a bucket chosen by a keyed hash of its address (the key is random per process), so the table cannot be grown by
// sending from many addresses and one address cannot aim at another's bucket; two clients that collide share a bucket,
// which costs them a slower page, never a lockout (a bucket refills with time, and nothing is ever blocked for longer than
// its refill).
type limiter struct {
	mu       sync.Mutex
	seed     maphash.Seed
	buckets  [limiterBuckets]bucket
	global   bucket
	perSec   float64 // a client's refill
	burst    float64
	gPerSec  float64
	gBurst   float64
	hops     int
	nowFn    func() time.Time
	rejected int64
}

const limiterBuckets = 4096

type bucket struct {
	tokens float64
	last   time.Time
	init   bool
}

// newLimiter: clientPerMin requests a minute per client with a burst, and globalPerMin for the whole listener.
func newLimiter(clientPerMin, clientBurst, globalPerMin, globalBurst, hops int, now func() time.Time) *limiter {
	return &limiter{seed: maphash.MakeSeed(), perSec: float64(clientPerMin) / 60, burst: float64(clientBurst),
		gPerSec: float64(globalPerMin) / 60, gBurst: float64(globalBurst), hops: hops, nowFn: now}
}

func (b *bucket) take(now time.Time, perSec, burst float64) (ok bool, wait time.Duration) {
	if !b.init {
		b.tokens, b.last, b.init = burst, now, true
	}
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(burst, b.tokens+d*perSec)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / perSec * float64(time.Second))
}

// allow charges one request to the client and then to the whole listener. A client already over its own limit does not
// draw down the global bucket.
func (l *limiter) allow(client string) (bool, time.Duration) {
	now := l.nowFn()
	var h maphash.Hash
	h.SetSeed(l.seed)
	h.WriteString(client)
	i := h.Sum64() % limiterBuckets
	l.mu.Lock()
	defer l.mu.Unlock()
	if ok, wait := l.buckets[i].take(now, l.perSec, l.burst); !ok {
		l.rejected++
		return false, wait
	}
	if ok, wait := l.global.take(now, l.gPerSec, l.gBurst); !ok {
		l.rejected++
		return false, wait
	}
	return true, 0
}

// clientOf is who the request is from: the connection's address, or, behind a configured number of trusted proxies, the
// address the outermost trusted proxy saw (X-Forwarded-For, counted from the right, so what a client prepends is never
// read). IPv6 addresses count by their /64.
func (l *limiter) clientOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if l.hops > 0 {
		parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		if i := len(parts) - l.hops; i >= 0 {
			if ip := net.ParseIP(strings.TrimSpace(parts[i])); ip != nil {
				host = ip.String()
			}
		}
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String()
	}
	return host
}
