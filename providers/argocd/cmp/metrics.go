package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jfillman/clearance/client"
)

// Metrics (hardening F6). Every `generate` is its own process, started by the cmp-server and gone when it answers, so
// nothing in one render can hold a counter for the next. The plugin keeps them in a file-backed aggregate instead:
//
//   - each run, as it ends, adds itself to one small JSON file, MetricsStoreFile under CLEARANCE_CMP_METRICS_DIR: its
//     outcome, its error's class and code, its duration (a histogram with fixed buckets) and its calls to the core;
//   - `clearance-cmp metrics`, a long-lived process in a container of its own in the repo-server pod (the same image,
//     the same emptyDir mounted), serves that file as Prometheus text on CLEARANCE_CMP_METRICS_ADDR.
//
// Why a file and not a server the renders report to: a render must never wait on, or fail because of, its metrics. A
// file under a lock needs nothing else running; a render that finds no server would lose its numbers, and one that
// finds a slow server would be slowed. The server is stateless, so it can restart, crash or be absent without a count
// being lost or counted twice; the counters survive it (and survive the plugin sidecar's restarts) for as long as the
// emptyDir lives, which is the pod's life, and a new pod is a counter reset Prometheus already handles.
//
// Correctness under concurrent renders: the read-modify-write of the file is serialised by an exclusive flock on a
// separate lock file (renders of one sidecar, and the canary sidecar's when it shares the volume, are separate
// processes on one kernel). Crash safety: the new content goes to a temporary file in the same directory that is then
// renamed over the old one, so a reader (the server takes no lock) and the next writer always see a whole file: a run
// killed mid-write leaves a stray temporary file, which the next writer removes while it holds the lock, and the kernel
// drops a dead process's flock. A file that does not parse (it should not happen) is started again and the reset is
// counted, so it shows as clearance_cmp_metrics_store_resets_total and a counter reset, never as a broken scrape.
//
// What the file holds is a closed set of labels, never a setting's value or a message: the plugin's version (from the
// build), the outcome, the error class and its stable code (errors.go), the core call's result. No token, URL,
// Application, repository or error text is written, so the endpoint has nothing to leak. The write is bounded in time
// (metricsLockWait) and its failure only prints a warning: recording never changes what a render answers.
//
// Off by default: with CLEARANCE_CMP_METRICS_DIR unset a render writes nothing, and with CLEARANCE_CMP_METRICS_ADDR
// unset `clearance-cmp metrics` refuses to start, so nothing listens.

// The settings.
const (
	MetricsDirEnv  = "CLEARANCE_CMP_METRICS_DIR"
	MetricsAddrEnv = "CLEARANCE_CMP_METRICS_ADDR"
)

// MetricsStoreFile is the aggregate's name under the metrics directory; MetricsLockFile serialises its writers.
const (
	MetricsStoreFile = "cmp-metrics.json"
	MetricsLockFile  = "cmp-metrics.lock"
	metricsTmpPrefix = ".cmp-metrics-"
	metricsFormat    = 1
)

// metricsLockWait bounds how long a run waits for the store's lock before it gives up and drops its numbers.
const metricsLockWait = time.Second

// metricsMaxVersions bounds the versions kept (one per image that has rendered into this volume since the pod started):
// a new one past it evicts the version updated longest ago.
const metricsMaxVersions = 8

// DurationBounds are the render duration histogram's upper bounds, in seconds. The plugin's whole run has 80 s.
var DurationBounds = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 45, 60, 80}

// Core call results.
const (
	CoreOK          = "ok"          // the core answered a decision
	CoreUnavailable = "unavailable" // the core could not be reached, or did not answer in time (client.ErrCoreUnavailable)
	CoreError       = "error"       // the core answered something else: a refusal of the request, a response the plugin cannot read
)

// RunStats is what one run counts while it works: its calls to the core. Nil is a valid RunStats that counts nothing.
type RunStats struct {
	mu   sync.Mutex
	core map[string]uint64
}

// NewRunStats is an empty RunStats.
func NewRunStats() *RunStats { return &RunStats{core: map[string]uint64{}} }

// coreCall counts one call to the core by its result.
func (s *RunStats) coreCall(err error) {
	if s == nil {
		return
	}
	r := CoreOK
	switch {
	case err == nil:
	case errors.Is(err, client.ErrCoreUnavailable):
		r = CoreUnavailable
	default:
		r = CoreError
	}
	s.mu.Lock()
	s.core[r]++
	s.mu.Unlock()
}

// metricsStore is the file's content.
type metricsStore struct {
	Format   int                      `json:"format"`
	Resets   uint64                   `json:"resets,omitempty"` // times the file did not parse and was started again
	Versions map[string]*versionStats `json:"versions"`
}

// versionStats are the counters of one plugin version.
type versionStats struct {
	Updated int64             `json:"updated"` // unix seconds of the last run recorded
	Renders map[string]uint64 `json:"renders"` // by outcome: cleared, held, error
	Errors  map[string]uint64 `json:"errors"`  // by "class/code"
	Core    map[string]uint64 `json:"core"`    // by result
	Bounds  []float64         `json:"bounds"`  // the histogram's upper bounds
	Buckets []uint64          `json:"buckets"` // per bound, not cumulative; len(Bounds)+1, the last is +Inf
	Sum     float64           `json:"sum"`     // seconds
	Count   uint64            `json:"count"`   // runs timed
}

func newVersionStats() *versionStats {
	return &versionStats{Renders: map[string]uint64{}, Errors: map[string]uint64{}, Core: map[string]uint64{},
		Bounds: append([]float64(nil), DurationBounds...), Buckets: make([]uint64, len(DurationBounds)+1)}
}

// Run is one run's record.
type Run struct {
	Version  string
	Outcome  Outcome // "" when Err is set
	Err      error
	Duration time.Duration
	Stats    *RunStats
}

var (
	labelValueRx = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	codeRx       = regexp.MustCompile(`^CMP-[A-Z0-9-]{1,60}$`)
	wordRx       = regexp.MustCompile(`^[a-z_]{1,32}$`)
)

// metricsVersion is the version label: the build's, or "unknown" for one that is not a plain label value.
func metricsVersion(v string) string {
	if !labelValueRx.MatchString(v) {
		return "unknown"
	}
	return v
}

// apply adds the run to the store.
func (st *metricsStore) apply(r Run, now time.Time) {
	if st.Versions == nil {
		st.Versions = map[string]*versionStats{}
	}
	ver := metricsVersion(r.Version)
	vs := st.Versions[ver]
	if vs == nil {
		if len(st.Versions) >= metricsMaxVersions {
			oldest, at := "", int64(0)
			for k, v := range st.Versions {
				if oldest == "" || v.Updated < at || (v.Updated == at && k < oldest) {
					oldest, at = k, v.Updated
				}
			}
			delete(st.Versions, oldest)
		}
		vs = newVersionStats()
		st.Versions[ver] = vs
	}
	vs.fill()
	vs.Updated = now.Unix()
	if r.Err != nil {
		vs.Renders["error"]++
		class, code := ClassFault, CodeFaultInternal
		if ce, ok := asCmp(r.Err); ok && codeRx.MatchString(ce.Code) && wordRx.MatchString(string(ce.Class)) {
			class, code = ce.Class, ce.Code
		}
		vs.Errors[string(class)+"/"+code]++
	} else {
		o := string(r.Outcome)
		if !wordRx.MatchString(o) {
			o = "unknown"
		}
		vs.Renders[o]++
	}
	if r.Stats != nil {
		r.Stats.mu.Lock()
		for k, n := range r.Stats.core {
			vs.Core[k] += n
		}
		r.Stats.mu.Unlock()
	}
	sec := r.Duration.Seconds()
	if sec < 0 {
		sec = 0
	}
	i := sort.SearchFloat64s(vs.Bounds, sec) // the first bound >= sec; len(Bounds) is +Inf
	vs.Buckets[i]++
	vs.Sum += sec
	vs.Count++
}

// fill makes a version read from the file usable: nil maps, and a histogram whose bounds are not this build's (another
// version wrote it with other bounds, or it is malformed) started again.
func (vs *versionStats) fill() {
	if vs.Renders == nil {
		vs.Renders = map[string]uint64{}
	}
	if vs.Errors == nil {
		vs.Errors = map[string]uint64{}
	}
	if vs.Core == nil {
		vs.Core = map[string]uint64{}
	}
	same := len(vs.Bounds) == len(DurationBounds) && len(vs.Buckets) == len(DurationBounds)+1
	for i := 0; same && i < len(DurationBounds); i++ {
		same = vs.Bounds[i] == DurationBounds[i]
	}
	if !same {
		vs.Bounds, vs.Buckets = append([]float64(nil), DurationBounds...), make([]uint64, len(DurationBounds)+1)
		vs.Sum, vs.Count = 0, 0
	}
}

// RecordRun adds one run to the store in dir: under the lock, read, add, write a temporary file, rename it over.
func RecordRun(dir string, r Run, now time.Time) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	lf, err := os.OpenFile(filepath.Join(dir, MetricsLockFile), os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		return err
	}
	defer lf.Close()
	deadline := time.Now().Add(metricsLockWait)
	for {
		ok, err := tryLock(lf)
		if err != nil {
			return fmt.Errorf("lock %s: %w", MetricsLockFile, err)
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the metrics store stayed locked for %s; this run is not counted", metricsLockWait)
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer unlock(lf)
	// Holding the lock, no other writer is between its CreateTemp and its rename: any temporary file is a dead run's.
	if stray, _ := filepath.Glob(filepath.Join(dir, metricsTmpPrefix+"*")); len(stray) > 0 {
		for _, p := range stray {
			os.Remove(p)
		}
	}
	st, err := readStore(dir)
	if err != nil {
		resets := st.Resets
		st = &metricsStore{Resets: resets + 1}
	}
	st.Format = metricsFormat
	st.apply(r, now)
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, metricsTmpPrefix+"*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o644); err != nil { // the metrics container may run as another user of the pod's fsGroup
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, MetricsStoreFile)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// maxStoreBytes bounds what is read: the store is a few KiB (at most metricsMaxVersions versions of closed label sets).
const maxStoreBytes = 1 << 20

// readStore reads the store. A missing file is an empty store and no error; a file that does not parse is an error,
// with the resets it recorded when those can be read.
func readStore(dir string) (*metricsStore, error) {
	f, err := os.Open(filepath.Join(dir, MetricsStoreFile))
	if errors.Is(err, os.ErrNotExist) {
		return &metricsStore{Format: metricsFormat, Versions: map[string]*versionStats{}}, nil
	}
	if err != nil {
		return &metricsStore{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxStoreBytes+1))
	if err != nil {
		return &metricsStore{}, err
	}
	if len(b) > maxStoreBytes {
		return &metricsStore{}, fmt.Errorf("%s is over %d bytes", MetricsStoreFile, maxStoreBytes)
	}
	var st metricsStore
	if err := json.Unmarshal(b, &st); err != nil {
		var partial struct {
			Resets uint64 `json:"resets"`
		}
		_ = json.Unmarshal(b, &partial)
		return &metricsStore{Resets: partial.Resets}, fmt.Errorf("%s does not parse: %w", MetricsStoreFile, err)
	}
	if st.Format != metricsFormat {
		return &metricsStore{Resets: st.Resets}, fmt.Errorf("%s has format %d, this build reads %d", MetricsStoreFile, st.Format, metricsFormat)
	}
	if st.Versions == nil {
		st.Versions = map[string]*versionStats{}
	}
	for v, vs := range st.Versions {
		if vs == nil { // "v": null decodes without an error; the store is not one this plugin wrote
			return &metricsStore{Resets: st.Resets}, fmt.Errorf("%s has an empty entry for version %q", MetricsStoreFile, v)
		}
	}
	return &st, nil
}

// recordRunFromEnv is main's: record when CLEARANCE_CMP_METRICS_DIR is set, and only warn when that fails.
func recordRunFromEnv(getenv func(string) string, r Run, stderr io.Writer) {
	dir := strings.TrimSpace(getenv(MetricsDirEnv))
	if dir == "" {
		return
	}
	if err := RecordRun(dir, r, time.Now()); err != nil {
		fmt.Fprintf(stderr, "clearance-cmp: WARNING the run's metrics were not recorded (%s=%s): %v\n", MetricsDirEnv, dir, err)
	}
}

// esc escapes a label value for the text exposition.
func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// WriteExposition writes the store as Prometheus text (version 0.0.4). up is whether the store could be read. Only
// label values that are plain identifiers are written: the file is the plugin's own, but it is read as untrusted.
//
//	clearance_cmp_renders_total{version,outcome}            counter: runs, by outcome (cleared, held, error)
//	clearance_cmp_render_errors_total{version,class,code}   counter: failed runs, by error class and stable code
//	clearance_cmp_render_duration_seconds{version}          histogram: a run's wall time
//	clearance_cmp_core_calls_total{version,result}          counter: calls to the core (ok, unavailable, error)
//	clearance_cmp_last_run_timestamp_seconds{version}       gauge: when a run of the version was last recorded
//	clearance_cmp_metrics_store_up                          1 when the store could be read (or does not exist yet)
//	clearance_cmp_metrics_store_resets_total                counter: times the store did not parse and was started again
func WriteExposition(w io.Writer, st *metricsStore, up bool) error {
	var b strings.Builder
	vers := make([]string, 0, len(st.Versions))
	for v, vs := range st.Versions {
		if labelValueRx.MatchString(v) && vs != nil {
			vers = append(vers, v)
		}
	}
	sort.Strings(vers)
	sorted := func(m map[string]uint64) []string {
		ks := make([]string, 0, len(m))
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}
	b.WriteString("# HELP clearance_cmp_renders_total Plugin runs (generate), by outcome: cleared, held or error.\n# TYPE clearance_cmp_renders_total counter\n")
	for _, v := range vers {
		for _, o := range sorted(st.Versions[v].Renders) {
			if wordRx.MatchString(o) {
				fmt.Fprintf(&b, "clearance_cmp_renders_total{version=\"%s\",outcome=\"%s\"} %d\n", esc(v), o, st.Versions[v].Renders[o])
			}
		}
	}
	b.WriteString("# HELP clearance_cmp_render_errors_total Failed plugin runs, by error class (fault, dependency, render, refusal) and stable code.\n# TYPE clearance_cmp_render_errors_total counter\n")
	for _, v := range vers {
		for _, k := range sorted(st.Versions[v].Errors) {
			class, code, ok := strings.Cut(k, "/")
			if ok && wordRx.MatchString(class) && codeRx.MatchString(code) {
				fmt.Fprintf(&b, "clearance_cmp_render_errors_total{version=\"%s\",class=\"%s\",code=\"%s\"} %d\n", esc(v), class, code, st.Versions[v].Errors[k])
			}
		}
	}
	b.WriteString("# HELP clearance_cmp_render_duration_seconds Wall time of a plugin run, from start to answer.\n# TYPE clearance_cmp_render_duration_seconds histogram\n")
	for _, v := range vers {
		vs := st.Versions[v]
		if len(vs.Buckets) != len(vs.Bounds)+1 {
			continue
		}
		var cum uint64
		for i, le := range vs.Bounds {
			cum += vs.Buckets[i]
			fmt.Fprintf(&b, "clearance_cmp_render_duration_seconds_bucket{version=\"%s\",le=\"%s\"} %d\n", esc(v), strconv.FormatFloat(le, 'g', -1, 64), cum)
		}
		cum += vs.Buckets[len(vs.Bounds)]
		fmt.Fprintf(&b, "clearance_cmp_render_duration_seconds_bucket{version=\"%s\",le=\"+Inf\"} %d\n", esc(v), cum)
		fmt.Fprintf(&b, "clearance_cmp_render_duration_seconds_sum{version=\"%s\"} %s\n", esc(v), strconv.FormatFloat(vs.Sum, 'g', -1, 64))
		fmt.Fprintf(&b, "clearance_cmp_render_duration_seconds_count{version=\"%s\"} %d\n", esc(v), cum)
	}
	b.WriteString("# HELP clearance_cmp_core_calls_total Calls the plugin made to the Clearance core, by result: ok, unavailable or error.\n# TYPE clearance_cmp_core_calls_total counter\n")
	for _, v := range vers {
		for _, r := range sorted(st.Versions[v].Core) {
			if wordRx.MatchString(r) {
				fmt.Fprintf(&b, "clearance_cmp_core_calls_total{version=\"%s\",result=\"%s\"} %d\n", esc(v), r, st.Versions[v].Core[r])
			}
		}
	}
	b.WriteString("# HELP clearance_cmp_last_run_timestamp_seconds When a run of this plugin version was last recorded.\n# TYPE clearance_cmp_last_run_timestamp_seconds gauge\n")
	for _, v := range vers {
		fmt.Fprintf(&b, "clearance_cmp_last_run_timestamp_seconds{version=\"%s\"} %d\n", esc(v), st.Versions[v].Updated)
	}
	upv := 0
	if up {
		upv = 1
	}
	b.WriteString("# HELP clearance_cmp_metrics_store_up 1 when the plugin's metrics store could be read (or has no run yet).\n# TYPE clearance_cmp_metrics_store_up gauge\n")
	fmt.Fprintf(&b, "clearance_cmp_metrics_store_up %d\n", upv)
	b.WriteString("# HELP clearance_cmp_metrics_store_resets_total Times the metrics store did not parse and was started again.\n# TYPE clearance_cmp_metrics_store_resets_total counter\n")
	fmt.Fprintf(&b, "clearance_cmp_metrics_store_resets_total %d\n", st.Resets)
	_, err := io.WriteString(w, b.String())
	return err
}

// MetricsHandler serves /metrics (the store, read on every scrape: it is small and renamed whole) and /healthz.
func MetricsHandler(dir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		st, err := readStore(dir)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = WriteExposition(w, st, err == nil)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	return mux
}

// metricsMain is `clearance-cmp metrics`: the long-lived server of the store. It reads only the two metrics settings,
// never the token or the core's address.
func metricsMain(args []string, getenv func(string) string, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintln(stderr, "usage: clearance-cmp metrics\n\n"+
			"Serves the plugin's metrics store ("+MetricsDirEnv+") as Prometheus text on "+MetricsAddrEnv+" (/metrics, /healthz).")
		return 2
	}
	addr, dir := strings.TrimSpace(getenv(MetricsAddrEnv)), strings.TrimSpace(getenv(MetricsDirEnv))
	if addr == "" {
		fmt.Fprintf(stderr, "clearance-cmp metrics: %s is not set: nothing listens (metrics are off)\n", MetricsAddrEnv)
		return 2
	}
	if dir == "" {
		fmt.Fprintf(stderr, "clearance-cmp metrics: %s is not set: there is no store to serve; set it to the directory the plugin sidecar records into\n", MetricsDirEnv)
		return 2
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		fmt.Fprintf(stderr, "clearance-cmp metrics: %s=%q is not host:port (%v)\n", MetricsAddrEnv, addr, err)
		return 2
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(stderr, "clearance-cmp metrics: listen %s: %v\n", addr, err)
		return 1
	}
	srv := &http.Server{Handler: MetricsHandler(dir), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	fmt.Fprintf(stderr, "clearance-cmp metrics: serving %s on %s\n", filepath.Join(dir, MetricsStoreFile), ln.Addr())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "clearance-cmp metrics: %v\n", err)
		return 1
	}
	return 0
}
