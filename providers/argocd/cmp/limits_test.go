package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeTool puts an executable shell script called name first on PATH and returns its directory.
func fakeTool(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// withFS sets the filesystem sandbox mode (and the token path) for one test, captures the warning, and restores the
// defaults after it.
func withFS(t *testing.T, mode, token string) *bytes.Buffer {
	t.Helper()
	var w bytes.Buffer
	oldW, oldP := fsWarn, landlockProbe
	fsWarn = &w
	SetFSSandbox(mode, token)
	t.Cleanup(func() { fsWarn, landlockProbe = oldW, oldP; SetFSSandbox("", "") })
	return &w
}

// budgetCtx is a render's context: its limits, a scratch root and a source directory.
func budgetCtx(t *testing.T, lim Limits) (context.Context, *budget) {
	t.Helper()
	b := &budget{lim: lim, root: t.TempDir(), src: t.TempDir()}
	return withBudget(context.Background(), b), b
}

func asLimit(t *testing.T, err error, class string) *LimitError {
	t.Helper()
	var le *LimitError
	if !errors.As(err, &le) {
		t.Fatalf("want a %s LimitError, got %v", class, err)
	}
	if le.Limit != class || le.Code() == "" || le.Code() != limitCodes[class] {
		t.Fatalf("want class %s, got %s (%v)", class, le.Limit, le)
	}
	// and the plugin reports it as that code, in the right class, naming the setting on its first line
	ce := classifyRender(context.Background(), fmt.Errorf("helm template: %w", err), lookupNotAsked, false)
	if ce.Code != le.Code() || ce.Class != Codes[le.Code()] || !strings.Contains(ce.FirstLine(), le.Setting) {
		t.Fatalf("classified as %s (%s): %q", ce.Code, ce.Class, ce.FirstLine())
	}
	if want := class == LimitWallTime || class == LimitConcurrency; ce.FallsBack() != want {
		t.Fatalf("%s: falls back %v, want %v", class, ce.FallsBack(), want)
	}
	if !strings.Contains(le.Error(), le.Setting) || !strings.Contains(le.Error(), "nothing syncs") {
		t.Fatalf("the message does not name its setting %s: %v", le.Setting, le)
	}
	return le
}

func TestLimitSettings(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	l, errs := parseLimits(get(nil), 20*time.Second)
	if len(errs) != 0 || l != DefaultLimits() {
		t.Fatalf("defaults: %+v %v", l, errs)
	}
	// The default wall time leaves the core call its time inside the plugin's deadline, under Argo CD's 90 s.
	// ... including the chart lookup and every attempt of the core call, so an unreachable core is found out in time.
	if d := DefaultLimits(); ChartLookupTimeout+d.Timeout+coreBudget(20*time.Second) >= PluginDeadline || PluginDeadline >= 90*time.Second {
		t.Fatalf("the default wall time %s does not fit", d.Timeout)
	}
	if got := coreBudget(20 * time.Second); got != 40*time.Second+CoreBackoff {
		t.Fatalf("core budget %s", got)
	}
	if _, errs := parseLimits(get(map[string]string{EnvRenderTimeout: "34s"}), 20*time.Second); len(errs) != 0 {
		t.Fatalf("34s fits (5+34+40.25 < 80): %v", errs)
	}
	if _, errs := parseLimits(get(map[string]string{EnvRenderTimeout: "35s"}), 20*time.Second); len(errs) != 1 {
		t.Fatal("35s does not fit (5+35+40.25 >= 80) and was accepted")
	}
	l, errs = parseLimits(get(map[string]string{EnvRenderTimeout: "20s", EnvMaxCPU: "5s", EnvMaxMemory: "256Mi", EnvMaxOutput: "8Mi",
		EnvMaxTemp: "2Gi", EnvMaxRenders: "2"}), 20*time.Second)
	if len(errs) != 0 || l != (Limits{Timeout: 20 * time.Second, CPU: 5 * time.Second, Memory: 256 << 20, Output: 8 << 20, Temp: 2 << 30, Renders: 2}) {
		t.Fatalf("set: %+v %v", l, errs)
	}
	// every bad value is reported at once, each naming its setting
	_, errs = parseLimits(get(map[string]string{EnvRenderTimeout: "soon", EnvMaxCPU: "0s", EnvMaxMemory: "64Mi", EnvMaxOutput: "lots",
		EnvMaxTemp: "-1", EnvMaxRenders: "0"}), 20*time.Second)
	if len(errs) != 6 {
		t.Fatalf("want 6 errors, got %d: %v", len(errs), errs)
	}
	for i, name := range []string{EnvRenderTimeout, EnvMaxCPU, EnvMaxMemory, EnvMaxOutput, EnvMaxTemp, EnvMaxRenders} {
		if !strings.Contains(errs[i].Error(), name) {
			t.Errorf("error %d does not name %s: %v", i, name, errs[i])
		}
	}
	// the wall time and the call's time together must fit inside the plugin's deadline
	_, errs = parseLimits(get(map[string]string{EnvRenderTimeout: "70s"}), 20*time.Second)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "CLEARANCE_CMP_CALL_TIMEOUT") {
		t.Fatalf("70s + 20s accepted: %v", errs)
	}
	// and ParseConfig refuses them, naming the setting
	vars := map[string]string{"ARGOCD_APP_NAME": "a", "ARGOCD_APP_NAMESPACE": "n", "PARAM_APP": "a", "PARAM_ENV": "e", "PARAM_CLUSTER": "c",
		"CLEARANCE_URL": "http://x.test", EnvMaxMemory: "huge"}
	if _, err := ParseConfig(get(vars)); err == nil || !strings.Contains(err.Error(), EnvMaxMemory) {
		t.Fatalf("ParseConfig accepted a bad memory bound: %v", err)
	}
	for in, want := range map[string]int64{"0": 0, "1024": 1024, "1Ki": 1024, "3Mi": 3 << 20, "2Gi": 2 << 30} {
		if n, err := ParseSize(in); err != nil || n != want {
			t.Errorf("%s: %d %v", in, n, err)
		}
	}
	for _, in := range []string{"", "1MB", "1.5Gi", "-1", "Mi", "99999999999Gi"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// A step that writes more than the output bound to stdout is stopped and named.
func TestOutputBoundStopsAStep(t *testing.T) {
	withFS(t, NetnsTry, "")
	fakeTool(t, "helm", "head -c 3000000 /dev/zero")
	lim := DefaultLimits()
	lim.Output = 1 << 20
	ctx, _ := budgetCtx(t, lim)
	_, err := OSRun(ctx, t.TempDir(), nil, "helm", "template", "x", ".")
	le := asLimit(t, err, LimitOutput)
	if le.Step != "helm template" || le.Setting != EnvMaxOutput || le.Bound != "1Mi" {
		t.Fatalf("%+v", le)
	}
	// under the bound, the same step's output is returned whole
	lim.Output = 4 << 20
	ctx, _ = budgetCtx(t, lim)
	if out, err := OSRun(ctx, t.TempDir(), nil, "helm", "template", "x", "."); err != nil || len(out) != 3000000 {
		t.Fatalf("%d bytes, %v", len(out), err)
	}
}

// The rendered manifests as a whole are held to the output bound too.
func TestRenderedManifestsAreHeldToTheOutputBound(t *testing.T) {
	cfg := Config{CacheDir: t.TempDir(), Limits: DefaultLimits()}
	cfg.Limits.Output = 1 << 20
	_, err := renderBounded(context.Background(), cfg, t.TempDir(), new(bytes.Buffer), func(context.Context) (*Rendered, error) {
		return &Rendered{Manifests: bytes.Repeat([]byte("x"), 2<<20)}, nil
	})
	asLimit(t, err, LimitOutput)
}

// The render phase has one deadline: a step that hangs past it is stopped and the error names the wall-time bound.
func TestWallTimeBoundStopsTheRender(t *testing.T) {
	withFS(t, NetnsTry, "")
	fakeTool(t, "helm", "exec sleep 30")
	cfg := Config{CacheDir: t.TempDir(), Limits: DefaultLimits()}
	cfg.Limits.Timeout = time.Second
	start := time.Now()
	_, err := renderBounded(context.Background(), cfg, t.TempDir(), new(bytes.Buffer), func(ctx context.Context) (*Rendered, error) {
		_, err := OSRun(ctx, t.TempDir(), nil, "helm", "template", "x", ".")
		return nil, err
	})
	asLimit(t, err, LimitWallTime)
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("the hung step ran %s past a 1s bound", took)
	}
}

// Every temporary file of a render is under its scratch root, and the root is bounded: a step that leaves more there
// is stopped (by RLIMIT_FSIZE on Linux, by the measurement after the step elsewhere).
func TestTempBoundStopsAStep(t *testing.T) {
	withFS(t, NetnsTry, "")
	fakeTool(t, "helm", `exec head -c 20000000 /dev/zero > "$TMPDIR/big"`)
	lim := DefaultLimits()
	lim.Temp = 16 << 20
	ctx, b := budgetCtx(t, lim)
	_, err := OSRun(ctx, t.TempDir(), nil, "helm", "template", "x", ".")
	asLimit(t, err, LimitTemp)
	// the step's TMPDIR was under the render's root, and was removed with the step
	if ents, _ := os.ReadDir(b.root); len(ents) != 0 {
		t.Fatalf("the step left %d entries in the render's root", len(ents))
	}
}

// Renders beyond CLEARANCE_CMP_MAX_RENDERS wait for a slot; one that waits past its wall time is refused, naming the
// setting, and gets a slot as soon as one is free.
func TestConcurrencyBoundQueuesRenders(t *testing.T) {
	cfg := Config{CacheDir: t.TempDir(), Limits: DefaultLimits()}
	cfg.Limits.Renders, cfg.Limits.Timeout = 1, 300*time.Millisecond
	release, _, err := acquireSlot(context.Background(), filepath.Join(cfg.CacheDir, "slots"), 1)
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	render := func(context.Context) (*Rendered, error) { ran = true; return &Rendered{}, nil }
	_, err = renderBounded(context.Background(), cfg, t.TempDir(), new(bytes.Buffer), render)
	asLimit(t, err, LimitConcurrency)
	if ran {
		t.Fatal("a render ran without a slot")
	}
	release()
	if _, err := renderBounded(context.Background(), cfg, t.TempDir(), new(bytes.Buffer), render); err != nil || !ran {
		t.Fatalf("a free slot was not taken: %v", err)
	}
	// two slots: two renders at once, the third waits
	r1, _, err1 := acquireSlot(context.Background(), filepath.Join(cfg.CacheDir, "slots"), 2)
	r2, _, err2 := acquireSlot(context.Background(), filepath.Join(cfg.CacheDir, "slots"), 2)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, _, err := acquireSlot(ctx, filepath.Join(cfg.CacheDir, "slots"), 2); err == nil {
		t.Fatal("a third render got one of two slots")
	}
	r1()
	r2()
}

// A slot directory that cannot be created loses the bound, with a warning, and never fails the render.
func TestAnUnusableSlotDirectoryNeverFailsARender(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	var w bytes.Buffer
	cfg := Config{CacheDir: file} // a file, not a directory
	if _, err := renderBounded(context.Background(), cfg, t.TempDir(), &w, func(context.Context) (*Rendered, error) { return &Rendered{}, nil }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), "not bounded") || !strings.Contains(w.String(), EnvMaxRenders) {
		t.Fatalf("no warning: %q", w.String())
	}
}

// The render's own temporary directories (the chart checkout, the injected values) are under its scratch root, so the
// sandbox and the temp bound cover them.
func TestRenderUsesTheBudgetRoot(t *testing.T) {
	ctx, b := budgetCtx(t, DefaultLimits())
	if workDir(ctx) != b.root || workDir(context.Background()) != "" {
		t.Fatal(workDir(ctx))
	}
}

func TestFSSandboxSettingIsParsedStrictly(t *testing.T) {
	for v, want := range map[string]string{"": NetnsTry, "try": NetnsTry, "require": NetnsRequire, "off": NetnsOff} {
		if got, err := ParseFSSandbox(v); err != nil || got != want {
			t.Errorf("%q: %q, %v", v, got, err)
		}
	}
	for _, v := range []string{"on", "true", "Require", "landlock"} {
		if _, err := ParseFSSandbox(v); err == nil || !strings.Contains(err.Error(), FSSandboxEnv) {
			t.Errorf("%q accepted: %v", v, err)
		}
	}
}

// A token kept where every step may read (under /etc, HOME) cannot be protected: ParseConfig refuses it, naming the
// setting, unless the sandbox is off.
func TestATokenUnderAReadableRootIsRefused(t *testing.T) {
	vars := map[string]string{"ARGOCD_APP_NAME": "a", "ARGOCD_APP_NAMESPACE": "n", "PARAM_APP": "a", "PARAM_ENV": "e", "PARAM_CLUSTER": "c",
		"CLEARANCE_URL": "http://x.test", "CLEARANCE_TOKEN_FILE": "/etc/clearance/token"}
	get := func(k string) string { return vars[k] }
	_, err := ParseConfig(get)
	if err == nil || !strings.Contains(err.Error(), "CLEARANCE_TOKEN_FILE") || !strings.Contains(err.Error(), "/etc") || !strings.Contains(err.Error(), FSSandboxEnv) {
		t.Fatalf("a token under /etc was accepted: %v", err)
	}
	vars[FSSandboxEnv] = "off"
	if _, err := ParseConfig(get); err != nil {
		t.Fatal(err)
	}
	delete(vars, FSSandboxEnv)
	vars["CLEARANCE_TOKEN_FILE"] = "/var/run/secrets/tokens/clearance"
	if _, err := ParseConfig(get); err != nil {
		t.Fatal(err)
	}
}

// The spec never grants a root that holds the token, nor anything under /var or /run.
func TestTheSpecLeavesOutEveryRootHoldingTheToken(t *testing.T) {
	src, root := t.TempDir(), t.TempDir()
	token := filepath.Join(src, "token")
	withFS(t, NetnsTry, token)
	s := buildSpec(DefaultLimits(), true, "/usr/local/bin/helm", src, filepath.Join(root, "step"), &budget{lim: DefaultLimits(), root: root, src: src})
	for _, list := range [][]string{s.RX, s.RO, s.RW, s.Dev} {
		for _, p := range list {
			if tokenUnder(token, p) || p == "/var" || p == "/run" || p == "/var/run" || p == "/" {
				t.Fatalf("the spec grants %s", p)
			}
		}
	}
	if len(s.RW) == 0 || s.RW[len(s.RW)-1] != root {
		t.Fatalf("the render root is not writable: %v", s.RW)
	}
	if s.CPU != 30 || s.Data != 512<<20 || s.FSize != 512<<20 {
		t.Fatalf("limits %+v", s)
	}
	if s := buildSpec(DefaultLimits(), false, "/x/helm", src, root, nil); len(s.RX)+len(s.RO)+len(s.RW) != 0 || s.Landlock {
		t.Fatalf("no landlock, no rules: %+v", s)
	}
}

// require: Landlock missing means no step runs, and the refusal names the setting; try runs without it and warns
// once; off never asks the kernel.
func TestFSSandboxModes(t *testing.T) {
	m := marker(t)
	probes := 0
	noLandlock := func() (int, error) { probes++; return 0, errors.New("injected: no landlock") }

	w := withFS(t, NetnsRequire, "")
	landlockProbe = noLandlock
	withNetns(t, NetnsOff)
	SetFSSandbox(NetnsRequire, "")
	_, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", ".")
	if err == nil || !strings.Contains(err.Error(), FSSandboxEnv) || !strings.Contains(err.Error(), "Landlock") {
		t.Fatalf("require ran without the sandbox: %v", err)
	}
	if runs(m) != 0 || w.Len() != 0 {
		t.Fatalf("runs %d, warning %q", runs(m), w.String())
	}

	SetFSSandbox(NetnsTry, "")
	for i := 0; i < 3; i++ {
		if _, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", "."); err != nil {
			t.Fatal(err)
		}
	}
	if runs(m) != 3 || strings.Count(w.String(), "WITHOUT the filesystem sandbox") != 1 || !strings.Contains(w.String(), FSSandboxEnv+"=require") {
		t.Fatalf("runs %d, warning %q", runs(m), w.String())
	}
	if FSSandboxState() != "unavailable" {
		t.Fatal(FSSandboxState())
	}

	SetFSSandbox(NetnsOff, "")
	probes = 0
	if _, err := OSRun(context.Background(), t.TempDir(), nil, "kustomize", "build", "."); err != nil || probes != 0 || FSSandboxState() != "off" {
		t.Fatalf("off: %v, %d probes, state %s", err, probes, FSSandboxState())
	}
}

// The registration after the render always keeps its whole budget: a render that starts late (after a pre-render
// confirmation the core answered slowly) gets the run's deadline less every attempt of the core call and the wait
// between them, so the call that decides is never the one cut short.
func TestTheRenderLeavesTheCoreItsWholeBudget(t *testing.T) {
	var got time.Time
	d := Deps{Exec: func(ctx context.Context, _, _ string, _ ...string) ([]byte, error) {
		got, _ = ctx.Deadline()
		return nil, errors.New("stop here")
	}, Stderr: new(bytes.Buffer)}
	cfg := Config{AppName: "a", Destination: "n", RegisterWait: 20 * time.Second, CacheDir: t.TempDir(), Limits: DefaultLimits()}
	cfg.Limits.Timeout = time.Minute                                         // longer than what is left: the reservation is what bounds the render
	run, cancel := context.WithTimeout(context.Background(), 50*time.Second) // a run with 50 s left
	defer cancel()
	runEnd, _ := run.Deadline()
	if _, _, cerr := renderTree(run, d, cfg, t.TempDir()); cerr == nil {
		t.Fatal("the fake render succeeded")
	}
	if left := runEnd.Sub(got); left < coreBudget(cfg.RegisterWait)-time.Second || left > coreBudget(cfg.RegisterWait)+time.Second {
		t.Fatalf("the render ends %s before the run, want the core's budget %s", left, coreBudget(cfg.RegisterWait))
	}
}

// A duration too large to add is refused, not wrapped into a sum that fits.
func TestAHugeDeadlineSettingIsRefused(t *testing.T) {
	_, errs := parseLimits(func(k string) string {
		return map[string]string{EnvRenderTimeout: "2562047h47m16.854775807s"}[k]
	}, 20*time.Second)
	if len(errs) == 0 {
		t.Fatal("an overflowing render timeout was accepted")
	}
}

// A render that finishes after its deadline (a slow scan or cleanup) is not a result: it is the wall-time error.
func TestARenderPastItsDeadlineIsNotAResult(t *testing.T) {
	cfg := Config{CacheDir: t.TempDir(), Limits: DefaultLimits()}
	cfg.Limits.Timeout = time.Second
	_, err := renderBounded(context.Background(), cfg, t.TempDir(), new(bytes.Buffer), func(ctx context.Context) (*Rendered, error) {
		<-ctx.Done()
		return &Rendered{Manifests: []byte("kind: ConfigMap\n")}, nil
	})
	asLimit(t, err, LimitWallTime)
}

// No slot is taken once the render's time is over, even if one is free.
func TestNoSlotForAnExpiredRender(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if release, _, err := acquireSlot(ctx, filepath.Join(t.TempDir(), "slots"), 2); err == nil {
		release()
		t.Fatal("a slot was taken with an expired context")
	}
}

// What a stopped step printed never names the cause: the deadline does.
func TestStderrDoesNotMaskADeadline(t *testing.T) {
	if le := stepLimit(DefaultLimits(), "helm template", &capWriter{max: 1}, "write: file too large\nout of memory", nil, false, true); le != nil {
		t.Fatalf("a stopped step was classified %s", le.Limit)
	}
}

// The chart tag lookup runs under the configured limits, in a private scratch, never the shared temp directory.
func TestTheTagLookupHasAPrivateScratch(t *testing.T) {
	cfg := Config{Limits: DefaultLimits()}
	cfg.Limits.Output = 2 << 20
	ctx, done := lookupBudget(context.Background(), cfg)
	defer done()
	var dir string
	var lim Limits
	lookupChart(ctx, func(ctx context.Context, d, _ string, _ ...string) ([]byte, error) {
		dir = d
		if b := budgetFrom(ctx); b != nil {
			lim = b.lim
		}
		return nil, errors.New("no remote")
	}, "https://git.example.test/o/r.git", "v1")
	if dir == "" || dir == os.TempDir() || filepath.Dir(dir) != filepath.Clean(os.TempDir()) && !strings.Contains(dir, "clearance-lookup-") {
		t.Fatalf("the lookup ran in %q", dir)
	}
	if lim.Output != 2<<20 {
		t.Fatalf("the lookup's limits are %+v, not the configured ones", lim)
	}
}
