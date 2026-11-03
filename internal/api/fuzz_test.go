package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzQuery throws arbitrary query strings at every route: never a 5xx, never a panic.
func FuzzQuery(f *testing.F) {
	for _, s := range []string{"", "limit=5&after=3", "since=2026-10-30T12:00:00Z", "args=%7B%7D&agent=coding-agent&tool=x",
		"repo=a/b&pr=1", "a=1&a=2", "%zz", "outcomes=only", "tier=99999999999999999999"} {
		f.Add(s)
	}
	h := newHarness(&testing.T{}, backends[0], world{events: fixtureEvents(), changes: fixtureChanges()})
	f.Fuzz(func(t *testing.T, q string) {
		for _, rt := range Routes() {
			path := rt.Path
			for _, p := range []string{"{seq}", "{id}"} {
				path = strings.ReplaceAll(path, p, "1")
			}
			req := httptest.NewRequest("GET", "/", nil)
			req.URL.Path, req.URL.RawQuery = path, q
			req.Header.Set("Authorization", "Bearer audit")
			rec := httptest.NewRecorder()
			h.srv.Handler().ServeHTTP(rec, req)
			if rec.Code >= 500 {
				t.Fatalf("%s?%s: %d %s", path, q, rec.Code, rec.Body)
			}
		}
	})
}
