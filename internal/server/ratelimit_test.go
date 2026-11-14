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
	if got := l1.clientOf(req("10.0.0.1:5", "not an ip")); got != unattributed {
		t.Errorf("a garbage header: %q", got)
	}
	if got := l1.clientOf(req("10.0.0.1:5")); got != unattributed {
		t.Errorf("no header: %q (the proxy's own address must never be the client)", got)
	}
	// An IPv6 client is its /64: rotating addresses inside it does not buy a new bucket.
	if a, b := l0.clientOf(req("[2001:db8::1]:5")), l0.clientOf(req("[2001:db8::ffff]:5")); a != b {
		t.Errorf("%s %s", a, b)
	}
	if a, b := l0.clientOf(req("[2001:db8::1]:5")), l0.clientOf(req("[2001:db9::1]:5")); a == b {
		t.Errorf("two /64s are one client: %s", a)
	}
}

func TestABucketRefillsAndNothingStaysBlocked(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(60, 3, 6000, 100, 0, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if ok, _ := l.allowClient("a"); !ok {
			t.Fatalf("request %d refused inside the burst", i)
		}
	}
	ok, wait := l.allowClient("a")
	if ok || wait <= 0 || wait > 2*time.Second {
		t.Fatalf("%v %v", ok, wait)
	}
	now = now.Add(wait)
	if ok, _ := l.allowClient("a"); !ok {
		t.Error("still blocked after the stated wait: a lockout")
	}
	if len(l.buckets) != limiterBuckets {
		t.Fatal("the table is not fixed")
	}
}

// The listener's own budget is for work that costs something: a client's cheap requests never draw it down.
func TestTheGlobalBudgetIsOnlyChargedWhereItIsCharged(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(6000, 1000, 60, 2, 0, func() time.Time { return now })
	for i := 0; i < 500; i++ {
		l.allowClient("x")
	}
	if ok, _ := l.chargeGlobal(); !ok {
		t.Fatal("cheap requests spent the expensive budget")
	}
	l.chargeGlobal()
	if ok, _ := l.chargeGlobal(); ok {
		t.Error("the expensive budget is not bounded")
	}
}

// With trusted hops 2 and a header that is shorter (or a client that forges extra entries on the left), the client is never what
// a visitor chose: it is read from the right, and a header too short for the hops falls back to the connection.
func TestForgedForwardedForIsNeverBelievedBeyondTheTrustedHops(t *testing.T) {
	clock := func() time.Time { return time.Unix(1000, 0) }
	l := newLimiter(60, 3, 6000, 100, 2, clock)
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.RemoteAddr = "10.0.0.1:5"
	r.Header.Add("X-Forwarded-For", "198.51.100.1")
	if got := l.clientOf(r); got != unattributed {
		t.Errorf("a header shorter than the hops is attributed to %q, not unattributed", got)
	}
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 203.0.113.5, 10.1.1.1")
	if got := l.clientOf(r); got != "203.0.113.5" {
		t.Errorf("the second from the right: %s", got)
	}
}

func TestEveryFormOfAForwardedEntryIsParsedAndTheRestIsUnattributed(t *testing.T) {
	l := newLimiter(60, 3, 6000, 100, 1, func() time.Time { return time.Unix(1000, 0) })
	at := func(xff string) string {
		r, _ := http.NewRequest("GET", "http://x/", nil)
		r.RemoteAddr = "10.0.0.1:5"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return l.clientOf(r)
	}
	for in, want := range map[string]string{
		"203.0.113.7":               "203.0.113.7",
		"203.0.113.7:51234":         "203.0.113.7",
		" 203.0.113.7 ":             "203.0.113.7",
		"198.51.100.1, 203.0.113.7": "203.0.113.7",
		"2001:db8::1":               "2001:db8::",
		"[2001:db8::1]":             "2001:db8::",
		"[2001:db8::1]:443":         "2001:db8::",
		"[2001:db8:0:1::5]:443":     "2001:db8:0:1::",
		"::ffff:203.0.113.7":        "203.0.113.7",
		"unknown":                   unattributed,
		"":                          unattributed,
		"[2001:db8::1":              unattributed,
		"198.51.100.1, unknown":     unattributed,
		"203.0.113.7, ":             unattributed,
		"999.1.1.1":                 unattributed,
		"203.0.113.7:99999999999:1": unattributed,
	} {
		if got := at(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestUnattributedVisitorsShareOneTighterBucketAndNeverTheProxys(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(60, 8, 6000, 100, 1, func() time.Time { return now })
	warned := make(chan struct{}, 10)
	l.warn = func() { warned <- struct{}{} }
	granted := 0
	for i := 0; i < 20; i++ {
		if ok, _ := l.allowClient(unattributed); ok {
			granted++
		}
	}
	if granted != 2 { // a quarter of the client burst of 8
		t.Errorf("%d unattributed requests were allowed, want 2 (a quarter of a client's burst)", granted)
	}
	// The proxy's own address was never charged: a visitor that IS attributed is untouched by the unattributed drain.
	if ok, _ := l.allowClient("203.0.113.7"); !ok {
		t.Error("an attributed visitor was refused because unattributed ones drained their bucket")
	}
	select {
	case <-warned:
	case <-time.After(time.Second):
		t.Error("no log line for an unattributed request")
	}
	// The log line is rate limited.
	time.Sleep(50 * time.Millisecond)
	if len(warned) != 0 {
		t.Errorf("%d more log lines inside a minute", len(warned))
	}
}
