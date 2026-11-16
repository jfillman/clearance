package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPprofListenerMustBeLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:6060": true, "[::1]:6060": true, "localhost:6060": true,
		":6060": false, "0.0.0.0:6060": false, "10.1.2.3:6060": false, "example.test:6060": false, "6060": false, "127.0.0.1": false} {
		if err := LoopbackOnly(addr); (err == nil) != ok {
			t.Errorf("%q: %v, want ok=%v", addr, err, ok)
		}
		if _, err := PprofServer(addr); (err == nil) != ok {
			t.Errorf("PprofServer(%q): %v", addr, err)
		}
	}
	env := func(m map[string]string) func(string) string {
		base := map[string]string{"CLEARANCE_API_DSN": "postgres://x"}
		for k, v := range m {
			base[k] = v
		}
		return func(k string) string { return base[k] }
	}
	if c, err := FromEnv(env(nil)); err != nil || c.MetricsListen != "" || c.PprofListen != "" {
		t.Errorf("default: %+v %v", c, err)
	}
	if _, err := FromEnv(env(map[string]string{"CLEARANCE_API_PPROF_LISTEN": ":6060"})); err == nil {
		t.Error("a non-loopback pprof address was accepted")
	}
	if c, err := FromEnv(env(map[string]string{"CLEARANCE_API_PPROF_LISTEN": "127.0.0.1:6060", "CLEARANCE_API_METRICS_LISTEN": ":9102"})); err != nil || c.PprofListen == "" || c.MetricsListen != ":9102" {
		t.Errorf("set: %+v %v", c, err)
	}
}

func TestPprofAndMetricsServeOnTheirOwnListenersOnly(t *testing.T) {
	h := newHarness(t, backends[0], world{})
	ps, err := PprofServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	ps.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/debug/pprof/heap?debug=1", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "heap profile") {
		t.Errorf("heap profile: %d", rec.Code)
	}
	ms := h.srv.MetricsServer("127.0.0.1:0")
	rec = httptest.NewRecorder()
	ms.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, name := range []string{"go_memstats_heap_inuse_bytes", "go_memstats_heap_released_bytes", "go_goroutines", "go_gc_cycles_total", "clearance_api_coverage_waiting"} {
		if !strings.Contains(body, "\n"+name+" ") && !strings.HasPrefix(body, name) {
			t.Errorf("/metrics has no %s", name)
		}
	}
	rec = httptest.NewRecorder()
	ms.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/debug/pprof/heap", nil))
	if rec.Code != 404 {
		t.Errorf("the metrics listener served pprof: %d", rec.Code)
	}
	// neither is on the service port
	for _, p := range []string{"/metrics", "/debug/pprof/", "/debug/pprof/heap"} {
		if r := h.get(p, "audit"); r.status == 200 {
			t.Errorf("the service port answered 200 for %s", p)
		}
	}
}
