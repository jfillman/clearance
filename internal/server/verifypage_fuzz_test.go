package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/server"
)

// The public handler takes a method, a path, a query and headers from anyone: whatever they are it answers a status from a short
// list, with the security headers, never reflects the input, never sets a cookie and never writes to the chain.
func FuzzVerifyPageRequest(f *testing.F) {
	cfg := config(f, "")
	cfg.Statements = server.StatementOptions{ClientPerMinute: 6000000, ClientBurst: 100000, GlobalPerMinute: 6000000, GlobalBurst: 1000000}
	fx := newFixture(f, cfg)
	h := fx.core.Server.VerifyHandler()
	f.Add("GET", "/s/st-00000000000000000000000000000000", "", "")
	f.Add("GET", "/s/st-00000000000000000000000000000000/statement.json", "a=1", "x")
	f.Add("POST", "/s/", "", "")
	f.Add("GET", "/s/../../etc/passwd", "%00", "<script>")
	f.Fuzz(func(t *testing.T, method, path, query, header string) {
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path+method+query, " \r\n\x00#?") || method == "" {
			t.Skip()
		}
		u := "http://verify.invalid" + path
		if query != "" {
			u += "?" + query
		}
		req, err := http.NewRequest(method, u, nil)
		if err != nil {
			t.Skip()
		}
		req.Header.Set("X-Probe", strings.Map(func(r rune) rune {
			if r < 0x20 || r > 0x7e {
				return -1
			}
			return r
		}, header))
		req.RemoteAddr = "192.0.2.1:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		switch rec.Code {
		case 200, 304, 400, 404, 405, 429, 503:
		default:
			t.Fatalf("%s %q: status %d", method, u, rec.Code)
		}
		if rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("Content-Security-Policy") == "" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s %q: headers %v", method, u, rec.Header())
		}
		body := rec.Body.String()
		for _, in := range []string{path, header} {
			if len(in) > 3 && strings.Contains(body, in) && !strings.Contains("No such statement.\nok\nGET only.\n", in) {
				t.Fatalf("the answer reflects %q", in)
			}
		}
		if n := fx.core.Server.StatementIndexSizeForTest(); n != 0 {
			t.Fatalf("%d statements from nothing", n)
		}
	})
}
