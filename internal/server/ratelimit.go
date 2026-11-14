package server

import (
	"hash/maphash"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// limiter is the public listener's abuse limit: a token bucket per client and one for the expensive work, in fixed memory. A client
// is a bucket chosen by a keyed hash of its address (the key is random per process), so the table cannot be grown by
// sending from many addresses and one address cannot aim at another's bucket; two clients that collide share a bucket,
// which costs them a slower page, never a lockout (a bucket refills with time, and nothing is ever blocked for longer than
// its refill).
type limiter struct {
	mu      sync.Mutex
	seed    maphash.Seed
	buckets [limiterBuckets]bucket
	global  bucket
	perSec  float64 // a client's refill
	burst   float64
	gPerSec float64
	gBurst  float64
	hops    int
	nowFn   func() time.Time
	// unattr is the one bucket every request that cannot be attributed to a client shares (a header shorter than the trusted
	// hops, or an entry that is not an address), with a tighter budget than a client's; warn is told, at most once a minute.
	unattr  bucket
	warn    func()
	lastLog time.Time
}

// unattributed is the key allowClient is given for a request nobody can be named for.
const unattributed = "\x00unattributed"

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

// allowClient charges one request to the client's own bucket. Every request is charged here, whatever it asks for, so a
// guesser pays for each guess; a refused client is told how long to wait.
func (l *limiter) allowClient(client string) (bool, time.Duration) {
	now := l.nowFn()
	if client == unattributed {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.warn != nil && now.Sub(l.lastLog) > time.Minute {
			l.lastLog = now
			go l.warn()
		}
		return l.unattr.take(now, l.perSec/4, max(1, l.burst/4))
	}
	var h maphash.Hash
	h.SetSeed(l.seed)
	h.WriteString(client)
	i := h.Sum64() % limiterBuckets
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buckets[i].take(now, l.perSec, l.burst)
}

// chargeGlobal charges one verification to the listener's bucket. Only work that costs something is charged here (a result
// that must be computed, which the verification semaphore also bounds): a 404, a cached page and a status are cheap and are
// limited per client only, so addresses that drain the cheap paths cannot starve everyone else's reads.
func (l *limiter) chargeGlobal() (bool, time.Duration) {
	now := l.nowFn()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.global.take(now, l.gPerSec, l.gBurst)
}

// clientOf is who the request is from: the connection's address with no proxy in front, or, behind a configured number of trusted
// proxies, the address the outermost trusted proxy saw (X-Forwarded-For counted from the RIGHT, so what a client prepends is never
// read; entries may be `ip`, `ip:port`, `[v6]:port` or `[v6]`). IPv6 clients count by their /64. A request that cannot be
// attributed (fewer entries than hops, or an entry that is not an address) is `unattributed`, never the proxy's address: that
// would put every such visitor in the proxy's one bucket. Set hops to the real number of proxies: too low names a proxy, too high
// lets a client pick the entry (it can prepend addresses to reach it) and so pick its own bucket.
func (l *limiter) clientOf(r *http.Request) string {
	if l.hops <= 0 {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip != nil {
			return clientKey(ip)
		}
		return host
	}
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	i := len(parts) - l.hops
	if i < 0 {
		return unattributed
	}
	if ip := parseForwarded(parts[i]); ip != nil {
		return clientKey(ip)
	}
	return unattributed
}

func clientKey(ip net.IP) string {
	if ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String()
	}
	return ip.String()
}

func parseForwarded(s string) net.IP {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return net.ParseIP(s[1 : len(s)-1])
	}
	return nil
}
