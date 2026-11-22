package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
)

var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func scrape(t *testing.T, dir string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	MetricsHandler(dir).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("scrape: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	return rec.Body.String()
}

// value is the sample of the exposition line that starts with series (its full name and labels), or -1.
func value(expo, series string) float64 {
	for _, l := range strings.Split(expo, "\n") {
		if rest, ok := strings.CutPrefix(l, series+" "); ok {
			v, err := strconv.ParseFloat(rest, 64)
			if err == nil {
				return v
			}
		}
	}
	return -1
}

func TestARunIsCountedByOutcomeClassCodeCoreAndDuration(t *testing.T) {
	dir := t.TempDir()
	s := NewRunStats()
	s.coreCall(nil)
	s.coreCall(&client.UnavailableError{Op: "registerChange", Reason: client.ReasonTimeout})
	s.coreCall(&client.APIError{Status: 403})
	runs := []Run{
		{Version: "v1.2.3", Outcome: Cleared, Duration: 300 * time.Millisecond, Stats: s},
		{Version: "v1.2.3", Outcome: Held, Duration: 2 * time.Second},
		{Version: "v1.2.3", Err: newErr(CodeFaultTimeout, "the render ran out of time", nil), Duration: 79 * time.Second},
		{Version: "v1.2.3", Err: newErr(CodeRefusedDenied, "denied", nil), Duration: 100 * time.Second}, // past the last bound: +Inf only
		{Version: "v1.2.3", Err: errors.New("not a CmpError")},                                          // counted as the internal fault
	}
	for _, r := range runs {
		if err := RecordRun(dir, r, t0); err != nil {
			t.Fatal(err)
		}
	}
	e := scrape(t, dir)
	want := map[string]float64{
		`clearance_cmp_renders_total{version="v1.2.3",outcome="cleared"}`:                               1,
		`clearance_cmp_renders_total{version="v1.2.3",outcome="held"}`:                                  1,
		`clearance_cmp_renders_total{version="v1.2.3",outcome="error"}`:                                 3,
		`clearance_cmp_render_errors_total{version="v1.2.3",class="fault",code="CMP-FAULT-TIMEOUT"}`:    1,
		`clearance_cmp_render_errors_total{version="v1.2.3",class="refusal",code="CMP-REFUSED-DENIED"}`: 1,
		`clearance_cmp_render_errors_total{version="v1.2.3",class="fault",code="CMP-FAULT-INTERNAL"}`:   1,
		`clearance_cmp_core_calls_total{version="v1.2.3",result="ok"}`:                                  1,
		`clearance_cmp_core_calls_total{version="v1.2.3",result="unavailable"}`:                         1,
		`clearance_cmp_core_calls_total{version="v1.2.3",result="error"}`:                               1,
		`clearance_cmp_render_duration_seconds_bucket{version="v1.2.3",le="0.25"}`:                      1, // the empty run
		`clearance_cmp_render_duration_seconds_bucket{version="v1.2.3",le="0.5"}`:                       2,
		`clearance_cmp_render_duration_seconds_bucket{version="v1.2.3",le="2.5"}`:                       3,
		`clearance_cmp_render_duration_seconds_bucket{version="v1.2.3",le="80"}`:                        4,
		`clearance_cmp_render_duration_seconds_bucket{version="v1.2.3",le="+Inf"}`:                      5,
		`clearance_cmp_render_duration_seconds_count{version="v1.2.3"}`:                                 5,
		`clearance_cmp_render_duration_seconds_sum{version="v1.2.3"}`:                                   181.3,
		`clearance_cmp_last_run_timestamp_seconds{version="v1.2.3"}`:                                    float64(t0.Unix()),
		`clearance_cmp_metrics_store_up`:                                                                1,
		`clearance_cmp_metrics_store_resets_total`:                                                      0,
	}
	for series, v := range want {
		if got := value(e, series); got != v {
			t.Errorf("%s = %v, want %v", series, got, v)
		}
	}
	// Every sample line is name{labels} value or name value, and every family has HELP and TYPE.
	line := regexp.MustCompile(`^[a-z_]+(\{[a-z_]+="[^"\\\n]*"(,[a-z_]+="[^"\\\n]*")*\})? [0-9.e+]+$`)
	for _, l := range strings.Split(strings.TrimSpace(e), "\n") {
		if !strings.HasPrefix(l, "# ") && !line.MatchString(l) {
			t.Errorf("not an exposition line: %q", l)
		}
	}
	for _, fam := range []string{"clearance_cmp_renders_total", "clearance_cmp_render_errors_total", "clearance_cmp_render_duration_seconds", "clearance_cmp_core_calls_total"} {
		if !strings.Contains(e, "# TYPE "+fam+" ") || !strings.Contains(e, "# HELP "+fam+" ") {
			t.Errorf("%s has no HELP or TYPE", fam)
		}
	}
}

// Renders run concurrently (CLEARANCE_CMP_MAX_RENDERS, and the canary sidecar on the same volume): no run is lost.
func TestConcurrentRunsAreAllCounted(t *testing.T) {
	dir := t.TempDir()
	const workers, each = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				s := NewRunStats()
				s.coreCall(nil)
				errs <- RecordRun(dir, Run{Version: "v1", Outcome: Cleared, Duration: time.Second, Stats: s}, t0)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	e := scrape(t, dir)
	if got := value(e, `clearance_cmp_renders_total{version="v1",outcome="cleared"}`); got != workers*each {
		t.Fatalf("renders %v, want %d", got, workers*each)
	}
	if got := value(e, `clearance_cmp_core_calls_total{version="v1",result="ok"}`); got != workers*each {
		t.Fatalf("core calls %v, want %d", got, workers*each)
	}
}

// The same across processes, as the cmp-server runs them: the test binary records (TestMain, CMP_TEST_METRICS_RECORD).
func TestConcurrentProcessesAreAllCounted(t *testing.T) {
	dir := t.TempDir()
	const procs = 4
	var cmds []*exec.Cmd
	for i := 0; i < procs; i++ {
		c := exec.Command(os.Args[0], "-test.run=^$")
		c.Env = append(os.Environ(), "CMP_TEST_METRICS_RECORD="+dir)
		var buf bytes.Buffer
		c.Stdout, c.Stderr = &buf, &buf
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, c)
	}
	for _, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatal(err, c.Stdout)
		}
	}
	if got := value(scrape(t, dir), `clearance_cmp_renders_total{version="v1",outcome="cleared"}`); got != procs*testRecordRuns {
		t.Fatalf("renders %v, want %d", got, procs*testRecordRuns)
	}
}

// testRecordRuns is how many runs one CMP_TEST_METRICS_RECORD process records.
const testRecordRuns = 40

func recordForTest(dir string) {
	for i := 0; i < testRecordRuns; i++ {
		if err := RecordRun(dir, Run{Version: "v1", Outcome: Cleared, Duration: time.Second}, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	os.Exit(0)
}

// A run killed mid-write leaves a temporary file and the store whole; a store that does not parse is started again and
// the reset counted. Neither breaks a scrape or a later run.
func TestAStrayTempFileOrABadStoreIsRecoveredFrom(t *testing.T) {
	dir := t.TempDir()
	if err := RecordRun(dir, Run{Version: "v1", Outcome: Cleared}, t0); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, metricsTmpPrefix+"123")
	os.WriteFile(stray, []byte(`{"format":1,"versions":{"v1":{"ren`), 0o644)
	if got := value(scrape(t, dir), `clearance_cmp_renders_total{version="v1",outcome="cleared"}`); got != 1 {
		t.Fatalf("a stray temp file changed the scrape: %v", got)
	}
	if err := RecordRun(dir, Run{Version: "v1", Outcome: Cleared}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stray); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the stray temp file was not removed under the lock")
	}
	if got := value(scrape(t, dir), `clearance_cmp_renders_total{version="v1",outcome="cleared"}`); got != 2 {
		t.Fatal(got)
	}
	// A store that does not parse: the scrape says so (store_up 0) and still answers.
	os.WriteFile(filepath.Join(dir, MetricsStoreFile), []byte(`{"format":1,"resets":2,"versions":`), 0o644)
	if e := scrape(t, dir); value(e, "clearance_cmp_metrics_store_up") != 0 || strings.Contains(e, "renders_total{") {
		t.Fatal(e)
	}
	if err := RecordRun(dir, Run{Version: "v1", Outcome: Held}, t0); err != nil {
		t.Fatal(err)
	}
	e := scrape(t, dir)
	if value(e, "clearance_cmp_metrics_store_up") != 1 || value(e, "clearance_cmp_metrics_store_resets_total") != 1 ||
		value(e, `clearance_cmp_renders_total{version="v1",outcome="held"}`) != 1 || value(e, `clearance_cmp_renders_total{version="v1",outcome="cleared"}`) != -1 {
		t.Fatal(e)
	}
	// Another format is also started again.
	os.WriteFile(filepath.Join(dir, MetricsStoreFile), []byte(`{"format":99,"resets":4,"versions":{}}`), 0o644)
	if err := RecordRun(dir, Run{Version: "v1", Outcome: Held}, t0); err != nil {
		t.Fatal(err)
	}
	if e := scrape(t, dir); value(e, "clearance_cmp_metrics_store_resets_total") != 5 {
		t.Fatal(e)
	}
	// No store yet: up, and no series.
	if e := scrape(t, t.TempDir()); value(e, "clearance_cmp_metrics_store_up") != 1 || strings.Contains(e, "{version=") {
		t.Fatal(e)
	}
}

// What is recorded is a closed set of labels: an error's message, the token and the core's address never reach the
// store or the endpoint.
func TestNoSecretOrMessageIsRecorded(t *testing.T) {
	dir := t.TempDir()
	secret := "tok-secret-value https://core.internal.example.test/v1?token=abc"
	err := newErr(CodeFaultToken, "the plugin's token could not be read; "+secret, errors.New(secret))
	if rerr := RecordRun(dir, Run{Version: "v1", Err: err}, t0); rerr != nil {
		t.Fatal(rerr)
	}
	b, _ := os.ReadFile(filepath.Join(dir, MetricsStoreFile))
	for _, s := range []string{string(b), scrape(t, dir)} {
		if strings.Contains(s, "tok-secret") || strings.Contains(s, "core.internal") || strings.Contains(s, "token=") {
			t.Fatalf("a secret or message was recorded:\n%s", s)
		}
	}
	if !strings.Contains(string(b), `"fault/CMP-FAULT-TOKEN":1`) {
		t.Fatal(string(b))
	}
}

// The store is the plugin's own, but it is read as untrusted: a label value that is not a plain identifier is dropped.
func TestTheEndpointWritesOnlyPlainLabelValues(t *testing.T) {
	dir := t.TempDir()
	st := &metricsStore{Format: metricsFormat, Versions: map[string]*versionStats{
		"v1":          {Renders: map[string]uint64{"cleared": 1, `x"} 1` + "\nevil": 9}, Errors: map[string]uint64{"fault/CMP-FAULT-TOOL": 1, "fault/not-a-code": 2, "x": 3}, Core: map[string]uint64{"ok": 1, "OK!": 4}},
		`bad"version`: {Renders: map[string]uint64{"cleared": 7}},
	}}
	b, _ := json.Marshal(st)
	os.WriteFile(filepath.Join(dir, MetricsStoreFile), b, 0o644)
	e := scrape(t, dir)
	if strings.Contains(e, "evil") || strings.Contains(e, "not-a-code") || strings.Contains(e, "bad") || strings.Contains(e, "OK!") || strings.Contains(e, "} 3\n") {
		t.Fatal(e)
	}
	if value(e, `clearance_cmp_renders_total{version="v1",outcome="cleared"}`) != 1 || value(e, `clearance_cmp_render_errors_total{version="v1",class="fault",code="CMP-FAULT-TOOL"}`) != 1 {
		t.Fatal(e)
	}
	// A version label from a build with an odd version string is "unknown", not dropped.
	if metricsVersion("dev build/1") != "unknown" || metricsVersion("v0.56.0-rc.1+abc") != "v0.56.0-rc.1+abc" {
		t.Fatal()
	}
}

func TestVersionsAreBoundedAndAChangedHistogramStartsAgain(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < metricsMaxVersions+2; i++ {
		if err := RecordRun(dir, Run{Version: fmt.Sprintf("v%d", i), Outcome: Cleared}, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	st, err := readStore(dir)
	if err != nil || len(st.Versions) != metricsMaxVersions || st.Versions["v0"] != nil || st.Versions["v1"] != nil || st.Versions["v9"] == nil {
		t.Fatal(err, len(st.Versions))
	}
	// A version whose histogram was written with other bounds keeps its counters and starts its histogram again.
	st.Versions["v9"].Bounds = []float64{1, 2}
	st.Versions["v9"].Buckets = []uint64{5, 5, 5}
	b, _ := json.Marshal(st)
	os.WriteFile(filepath.Join(dir, MetricsStoreFile), b, 0o644)
	if err := RecordRun(dir, Run{Version: "v9", Outcome: Cleared, Duration: time.Second}, t0); err != nil {
		t.Fatal(err)
	}
	e := scrape(t, dir)
	if value(e, `clearance_cmp_renders_total{version="v9",outcome="cleared"}`) != 2 || value(e, `clearance_cmp_render_duration_seconds_count{version="v9"}`) != 1 {
		t.Fatal(e)
	}
}

func TestRecordingIsOffWithoutTheDirAndOnlyWarnsWhenItFails(t *testing.T) {
	var stderr bytes.Buffer
	recordRunFromEnv(getter(map[string]string{}), Run{Version: "v1", Outcome: Cleared}, &stderr)
	if stderr.Len() != 0 {
		t.Fatal(stderr.String())
	}
	// A directory that cannot be one: a warning, nothing else.
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o644)
	recordRunFromEnv(getter(map[string]string{MetricsDirEnv: f}), Run{Version: "v1", Outcome: Cleared}, &stderr)
	if !strings.Contains(stderr.String(), "WARNING the run's metrics were not recorded") {
		t.Fatal(stderr.String())
	}
}

// A lock held past metricsLockWait drops the run with an error, and does not hang the render.
func TestAHeldLockDropsTheRunInBoundedTime(t *testing.T) {
	dir := t.TempDir()
	lf, err := os.OpenFile(filepath.Join(dir, MetricsLockFile), os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	if ok, err := tryLock(lf); !ok || err != nil {
		t.Skip("no file lock on this platform")
	}
	defer unlock(lf)
	start := time.Now()
	if err := RecordRun(dir, Run{Version: "v1", Outcome: Cleared}, t0); err == nil || !strings.Contains(err.Error(), "stayed locked") {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*metricsLockWait {
		t.Fatalf("waited %s", d)
	}
}

func TestMetricsServerIsOffByDefault(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{}, MetricsAddrEnv + " is not set: nothing listens"},
		{map[string]string{MetricsDirEnv: "/x"}, MetricsAddrEnv + " is not set: nothing listens"},
		{map[string]string{MetricsAddrEnv: ":9464"}, MetricsDirEnv + " is not set"},
		{map[string]string{MetricsAddrEnv: "9464", MetricsDirEnv: "/x"}, "is not host:port"},
	} {
		var stderr bytes.Buffer
		if code := metricsMain(nil, getter(c.env), &stderr); code != 2 || !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%v: exit %d, %q", c.env, code, stderr.String())
		}
	}
	if code := metricsMain([]string{"extra"}, getter(map[string]string{}), io.Discard); code != 2 {
		t.Fatal(code)
	}
}

// Generate counts its calls to the core, including the outage that the outage policy answers from the cache.
func TestGenerateCountsItsCoreCalls(t *testing.T) {
	e := newEnv(t)
	e.d.Stats = NewRunStats()
	e.core.answer = &client.Change{ID: "ch-c", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(48 * time.Hour).Format(time.RFC3339Nano)}
	if _, _, err := e.generate(t); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Hour)
	e.cfg.RenderCacheTTL = 0
	e.core.err = &client.UnavailableError{Op: "registerChange", Reason: client.ReasonTimeout}
	if _, _, err := e.generate(t); err != nil {
		t.Fatal(err)
	}
	if e.d.Stats.core[CoreOK] != 1 || e.d.Stats.core[CoreUnavailable] != 1 {
		t.Fatal(e.d.Stats.core)
	}
}

func TestDoctorReportsTheMetricsSettings(t *testing.T) {
	find := func(checks []Check) Check {
		for _, c := range checks {
			if c.Name == "metrics" {
				return c
			}
		}
		t.Fatal("no metrics check")
		return Check{}
	}
	f := newDoctorFixture(t)
	checks, _, _ := f.run(t)
	if c := find(checks); c.Level != levelOK || !strings.HasPrefix(c.Msg, "off:") {
		t.Fatal(c)
	}
	f = newDoctorFixture(t)
	f.env[MetricsDirEnv] = filepath.Join(f.dir, "metrics")
	f.env[MetricsAddrEnv] = ":9464"
	checks, _, _ = f.run(t)
	if c := find(checks); c.Level != levelOK || !strings.Contains(c.Msg, "serves it on :9464") {
		t.Fatal(c)
	}
	f = newDoctorFixture(t)
	f.env[MetricsAddrEnv] = ":9464"
	checks, _, _ = f.run(t)
	if c := find(checks); c.Level != levelFail {
		t.Fatal(c)
	}
	f = newDoctorFixture(t)
	f.env[MetricsDirEnv] = filepath.Join(f.dir, "metrics")
	os.MkdirAll(f.env[MetricsDirEnv], 0o750)
	os.WriteFile(filepath.Join(f.env[MetricsDirEnv], MetricsStoreFile), []byte("{"), 0o644)
	checks, _, _ = f.run(t)
	if c := find(checks); c.Level != levelWarn {
		t.Fatal(c)
	}
}
