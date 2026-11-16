package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"strings"
	"time"
)

// Two opt-in listeners for seeing the process's memory, both off by default and never on the service port:
//
//	CLEARANCE_API_METRICS_LISTEN  /metrics in the Prometheus text format: the Go runtime's memory and goroutine
//	                              numbers and the coverage gauges. Numbers only; no memory contents, no request data.
//	                              It is unauthenticated: bind it to the pod network only where the scrape needs it.
//	CLEARANCE_API_PPROF_LISTEN    the pprof profiles (heap, goroutine, allocs, CPU, trace). A profile shows what the
//	                              process holds, so the address must be a loopback IP literal (127.0.0.1:PORT or
//	                              [::1]:PORT), reached with `kubectl port-forward`; anything else is refused at start.
//
// The pprof handlers are built here from runtime/pprof, not by importing net/http/pprof, whose init registers them on
// http.DefaultServeMux for every binary that links this package (a later ListenAndServe(addr, nil) would serve them).

// LoopbackOnly says whether addr (host:port) is a loopback IP literal: 127.0.0.0/8 or ::1. The name localhost is
// refused (it depends on the pod's /etc/hosts), and so is an IPv4-mapped IPv6 literal ([::ffff:127.0.0.1]): say 127.0.0.1.
func LoopbackOnly(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("%q is not host:port", addr)
	}
	ip := net.ParseIP(host)
	switch {
	case host == "localhost":
		return fmt.Errorf("%q: use 127.0.0.1 (the name localhost depends on the pod's /etc/hosts)", addr)
	case ip == nil || !ip.IsLoopback():
		return fmt.Errorf("%q is not a loopback IP literal (127.0.0.1:PORT or [::1]:PORT)", addr)
	case strings.Contains(host, ":") && ip.To4() != nil:
		return fmt.Errorf("%q is an IPv4-mapped address: use 127.0.0.1", addr)
	}
	return nil
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

// PprofServer serves the pprof profiles on its own mux at /debug/pprof/, on a loopback addr only (LoopbackOnly). A
// profile of up to a minute is allowed (CPU and trace: ?seconds=).
func PprofServer(addr string) (*http.Server, error) {
	if err := LoopbackOnly(addr); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/cmdline", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(strings.Join(osArgs(), "\x00")))
	})
	mux.HandleFunc("/debug/pprof/profile", func(w http.ResponseWriter, r *http.Request) {
		secs := pprofSeconds(r)
		w.Header().Set("Content-Type", "application/octet-stream")
		if err := pprof.StartCPUProfile(w); err != nil {
			http.Error(w, "cpu profile: "+err.Error(), http.StatusInternalServerError)
			return
		}
		sleepOrDone(r, secs)
		pprof.StopCPUProfile()
	})
	mux.HandleFunc("/debug/pprof/trace", func(w http.ResponseWriter, r *http.Request) {
		secs := pprofSeconds(r)
		w.Header().Set("Content-Type", "application/octet-stream")
		if err := trace.Start(w); err != nil {
			http.Error(w, "trace: "+err.Error(), http.StatusInternalServerError)
			return
		}
		sleepOrDone(r, secs)
		trace.Stop()
	})
	// /debug/pprof/ lists the profiles; /debug/pprof/<name> writes one (heap, allocs, goroutine, ...): ?debug=1 as text,
	// ?debug=2 for goroutine as full stacks, none for the protobuf `go tool pprof` reads.
	mux.HandleFunc("/debug/pprof/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/debug/pprof/")
		if name == "" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			for _, p := range pprof.Profiles() {
				fmt.Fprintf(w, "%s\t%d\n", p.Name(), p.Count())
			}
			return
		}
		p := pprof.Lookup(name)
		if p == nil {
			http.NotFound(w, r)
			return
		}
		debug, _ := strconv.Atoi(r.URL.Query().Get("debug"))
		if name == "heap" && r.URL.Query().Get("gc") == "1" {
			runtime.GC()
		}
		if debug != 0 {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		_ = p.WriteTo(w, debug)
	})
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: ReadHeaderLimit, ReadTimeout: ReadTimeout,
		WriteTimeout: 2 * time.Minute, IdleTimeout: IdleTimeout, MaxHeaderBytes: MaxHeaderBytes}, nil
}

func pprofSeconds(r *http.Request) time.Duration {
	n, err := strconv.Atoi(r.URL.Query().Get("seconds"))
	if err != nil || n < 1 {
		n = 30
	}
	return time.Duration(min(n, 60)) * time.Second
}

func sleepOrDone(r *http.Request, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-r.Context().Done():
	}
}

func osArgs() []string { return os.Args }
