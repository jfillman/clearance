package api

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strings"
	"time"
)

// Two opt-in listeners for seeing the process's memory, both off by default and never on the service port:
//
//	CLEARANCE_API_METRICS_LISTEN  /metrics in the Prometheus text format: the Go runtime's memory and goroutine
//	                              numbers and the coverage gauges. Numbers only; no memory contents, no request data.
//	                              It is unauthenticated: bind it to the pod network only where the scrape needs it.
//	CLEARANCE_API_PPROF_LISTEN    net/http/pprof (heap, goroutine, allocs, CPU profiles). A profile shows what the
//	                              process holds, so it must be a loopback address (127.0.0.1:PORT, [::1]:PORT or
//	                              localhost:PORT), reached with `kubectl port-forward`; anything else is refused at start.

// LoopbackOnly says whether addr (host:port) names a loopback host: an IP that is loopback, or the name localhost.
func LoopbackOnly(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("%q is not host:port", addr)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%q is not a loopback address (127.0.0.1:PORT, [::1]:PORT or localhost:PORT)", addr)
}

// MetricsHandler writes the runtime and coverage numbers as Prometheus text. The names are the ones the Go client's
// collector uses, so an existing dashboard for them works.
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		var b strings.Builder
		g := func(name, typ, help string, v float64) {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, typ, name, v)
		}
		g("go_goroutines", "gauge", "Goroutines that currently exist.", float64(runtime.NumGoroutine()))
		g("go_memstats_alloc_bytes", "gauge", "Bytes allocated and still in use.", float64(m.Alloc))
		g("go_memstats_heap_alloc_bytes", "gauge", "Heap bytes allocated and still in use.", float64(m.HeapAlloc))
		g("go_memstats_heap_inuse_bytes", "gauge", "Heap bytes in in-use spans.", float64(m.HeapInuse))
		g("go_memstats_heap_idle_bytes", "gauge", "Heap bytes in idle spans.", float64(m.HeapIdle))
		g("go_memstats_heap_released_bytes", "gauge", "Heap bytes released to the OS.", float64(m.HeapReleased))
		g("go_memstats_heap_sys_bytes", "gauge", "Heap bytes obtained from the system.", float64(m.HeapSys))
		g("go_memstats_stack_inuse_bytes", "gauge", "Bytes in stack spans.", float64(m.StackInuse))
		g("go_memstats_sys_bytes", "gauge", "Bytes obtained from the system.", float64(m.Sys))
		g("go_memstats_next_gc_bytes", "gauge", "Heap size at which the next GC starts.", float64(m.NextGC))
		g("go_memstats_mallocs_total", "counter", "Heap objects allocated.", float64(m.Mallocs))
		g("go_memstats_alloc_bytes_total", "counter", "Bytes allocated, including those freed.", float64(m.TotalAlloc))
		g("go_gc_cycles_total", "counter", "Completed GC cycles.", float64(m.NumGC))
		g("go_gc_pause_seconds_total", "counter", "Total GC stop-the-world pause.", float64(m.PauseTotalNs)/float64(time.Second))
		g("clearance_api_coverage_inflight", "gauge", "Coverage computations running.", float64(len(s.covSem)))
		g("clearance_api_coverage_waiting", "gauge", "Coverage reads waiting for a slot.", float64(s.covWaiters.Load()))
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	})
}

// MetricsServer serves /metrics on addr.
func (s *Server) MetricsServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", s.MetricsHandler())
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: ReadHeaderLimit, ReadTimeout: ReadTimeout,
		WriteTimeout: WriteTimeout, IdleTimeout: IdleTimeout, MaxHeaderBytes: MaxHeaderBytes}
}

// PprofServer serves net/http/pprof on its own mux at /debug/pprof/, on a loopback addr only (LoopbackOnly). A profile
// of up to a minute is allowed (CPU: ?seconds=).
func PprofServer(addr string) (*http.Server, error) {
	if err := LoopbackOnly(addr); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: ReadHeaderLimit, ReadTimeout: ReadTimeout,
		WriteTimeout: 2 * time.Minute, IdleTimeout: IdleTimeout, MaxHeaderBytes: MaxHeaderBytes}, nil
}
