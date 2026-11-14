package server

import (
	"net/http"
	"testing"
	"time"
)

func TestTheClientIsTheConnectionUnlessProxiesAreTrusted(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	req := func(remote string, xff ...string) *http.Request {
		r, _ := http.NewRequest("GET", "http://x/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	l0 := newLimiter(60, 3, 6000, 100, 0, clock)
	if got := l0.clientOf(req("192.0.2.1:5", "203.0.113.9")); got != "192.0.2.1" {
		t.Errorf("hops 0 reads a header: %s", got)
	}
	l1 := newLimiter(60, 3, 6000, 100, 1, clock)
	// What the one trusted proxy appended is the client; whatever the client prepended is never read.
	if got := l1.clientOf(req("10.0.0.1:5", "198.51.100.7, 203.0.113.9")); got != "203.0.113.9" {
		t.Errorf("hops 1: %s", got)
	}
	if got := l1.clientOf(req("10.0.0.1:5", "not an ip")); got != "10.0.0.1" {
		t.Errorf("a garbage header: %s", got)
	}
	if got := l1.clientOf(req("10.0.0.1:5")); got != "10.0.0.1" {
		t.Errorf("no header: %s", got)
	}
	// An IPv6 client is its /64: rotating addresses inside it does not buy a new bucket.
	if a, b := l1.clientOf(req("[2001:db8::1]:5")), l1.clientOf(req("[2001:db8::ffff]:5")); a != b {
		t.Errorf("%s %s", a, b)
	}
	if a, b := l1.clientOf(req("[2001:db8::1]:5")), l1.clientOf(req("[2001:db9::1]:5")); a == b {
		t.Errorf("two /64s are one client: %s", a)
	}
}

func TestABucketRefillsAndNothingStaysBlocked(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(60, 3, 6000, 100, 0, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("request %d refused inside the burst", i)
		}
	}
	ok, wait := l.allow("a")
	if ok || wait <= 0 || wait > 2*time.Second {
		t.Fatalf("%v %v", ok, wait)
	}
	now = now.Add(wait)
	if ok, _ := l.allow("a"); !ok {
		t.Error("still blocked after the stated wait: a lockout")
	}
	// The table is a fixed array: a million distinct clients add no memory, and a refused client does not spend the global budget.
	g := newLimiter(6000, 1, 60, 2, 0, func() time.Time { return now })
	g.allow("x")
	before := g.global.tokens
	g.allow("x") // over x's own burst
	if g.global.tokens != before {
		t.Error("a refused client drew down the listener's bucket")
	}
	if len(g.buckets) != limiterBuckets {
		t.Fatal("the table is not fixed")
	}
}
