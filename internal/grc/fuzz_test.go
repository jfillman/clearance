package grc

import (
	"net/url"
	"testing"
	"time"
)

// FuzzCheckURL: whatever CheckURL accepts is https (or loopback http when allowed), has a host and no credentials.
func FuzzCheckURL(f *testing.F) {
	for _, s := range []string{"https://api.vanta.com", "http://127.0.0.1:1", "https://u:p@h", "http://[::1]", "", "https://", "ftp://x"} {
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, raw string, loop bool) {
		if CheckURL(raw, "U", loop) != nil {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("accepted %q", raw)
		}
		if u.Scheme != "https" && !(loop && u.Scheme == "http" && isLoopback(u.Hostname())) {
			t.Fatalf("accepted the scheme of %q", raw)
		}
	})
}

// FuzzRetryAfter never panics and never returns a negative wait.
func FuzzRetryAfter(f *testing.F) {
	for _, s := range []string{"7", "0", "-1", "Fri, 14 Nov 2026 12:00:00 GMT", "", "99999999999999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		if d := parseRetryAfter(h, time.Unix(0, 0)); d < 0 {
			t.Fatalf("%q -> %s", h, d)
		}
	})
}

// FuzzLink: a link is only ever LinkBase + /changes/ + a plain identifier.
func FuzzLink(f *testing.F) {
	for _, s := range []string{"chg-1", "../x", "a?b", "a b", ""} {
		f.Add(s)
	}
	b := Builder{LinkBase: "https://c.example"}
	f.Fuzz(func(t *testing.T, id string) {
		l, ok := b.Link(id)
		if !ok {
			return
		}
		if l != "https://c.example/changes/"+id || !safeID.MatchString(id) {
			t.Fatalf("%q -> %q", id, l)
		}
	})
}
