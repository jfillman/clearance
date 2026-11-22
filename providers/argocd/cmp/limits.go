package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The render limits (hardening W-34: S3, X7). Every render step (git, helm, kustomize) runs under bounds the kernel
// or the plugin enforces, and going over one stops the render with a LimitError that names the bound and the
// setting that raises it. Nothing syncs from a stopped render. Each bound has a default sized from measured renders
// (docs/install-argocd-plugin.md, "Render limits"); none is required, and a value that is not well formed stops the
// plugin at start with the setting named.
//
//	CLEARANCE_CMP_RENDER_TIMEOUT     wall time of the whole render phase (waiting for a slot, fetching, helm, kustomize)
//	CLEARANCE_CMP_RENDER_MAX_CPU     CPU time of one step (RLIMIT_CPU)
//	CLEARANCE_CMP_RENDER_MAX_MEMORY  memory (data segment) of one step (RLIMIT_DATA), and GOMEMLIMIT for the Go tools
//	CLEARANCE_CMP_RENDER_MAX_OUTPUT  bytes a step may write to stdout, and the size of the rendered manifests
//	CLEARANCE_CMP_RENDER_MAX_TEMP    the render's scratch directory, checked after every step; one file (RLIMIT_FSIZE)
//	CLEARANCE_CMP_MAX_RENDERS        renders running at once in this sidecar (a file-lock slot under the cache dir)
const (
	EnvRenderTimeout = "CLEARANCE_CMP_RENDER_TIMEOUT"
	EnvMaxCPU        = "CLEARANCE_CMP_RENDER_MAX_CPU"
	EnvMaxMemory     = "CLEARANCE_CMP_RENDER_MAX_MEMORY"
	EnvMaxOutput     = "CLEARANCE_CMP_RENDER_MAX_OUTPUT"
	EnvMaxTemp       = "CLEARANCE_CMP_RENDER_MAX_TEMP"
	EnvMaxRenders    = "CLEARANCE_CMP_MAX_RENDERS"
)

// PluginDeadline is how long one `generate` may take in all: Argo CD kills a plugin at 90 s (ARGOCD_EXEC_TIMEOUT),
// and the last 10 s are left for the error to reach it.
const PluginDeadline = 80 * time.Second

// ChartLookupTimeout bounds the chart tag lookup Generate makes before the render (for the pre-render cache's key). It
// is an optimisation: a lookup that times out is no answer, and the render fetches the chart itself.
const ChartLookupTimeout = 5 * time.Second

// The plugin's calls to the core: one retry after a jittered wait (newCore). coreBudget is the most one call can take,
// every attempt timing out: (CoreRetries+1) attempts and the waits between them. The startup check reserves all of it,
// so an unreachable core is ErrCoreUnavailable (and the outage policy's cache) before PluginDeadline, never a deadline.
const (
	CoreRetries    = 1
	CoreBackoff    = 250 * time.Millisecond
	CoreBackoffMax = 2 * time.Second
)

func coreBudget(callTimeout time.Duration) time.Duration {
	total, d := time.Duration(CoreRetries+1)*callTimeout, CoreBackoff
	for i := 0; i < CoreRetries; i++ {
		total += min(d, CoreBackoffMax)
		d *= 2
	}
	return total
}

// Limits are the render bounds.
type Limits struct {
	Timeout time.Duration // the render phase, slot wait included
	CPU     time.Duration // per step
	Memory  int64         // per step, bytes
	Output  int64         // per step stdout, and the rendered manifests, bytes
	Temp    int64         // the render's scratch directory, bytes; also the largest single file
	Renders int           // concurrent renders in this sidecar
}

// DefaultLimits are the bounds with nothing set, each sized from measurement (docs/install-argocd-plugin.md, "Render
// limits", has the table). The parity fixture's render (testdata/parity-gate-api, the gate-api Application on
// hangar-prod) is 5.7 KB of manifests; helm renders it in 0.06 s wall and 0.05 s CPU at 45 MB peak RSS, but needs a
// data segment of about 96 MiB to start at all (the Go runtime's heap arena map counts), kustomize about 48 MiB. Its
// chart repository checks out at about 50 MB. So: wall 30 s (500x the render; with the 5 s chart lookup and the core
// call's two 20 s attempts it fits the 80 s PluginDeadline, under Argo CD's 90 s), CPU 30 s per step, memory 512 MiB per step (5x helm's floor, and the
// container limit the install guide recommends), stdout 32 MiB (over 5000x the fixture, 4x the pre-render cache's
// 8 MiB stream cap), scratch 512 MiB per render (10x the checkout), 4 renders at once (Argo CD's repo-server
// reposerver.parallelism.limit is commonly 2 or unset).
func DefaultLimits() Limits {
	return Limits{Timeout: 30 * time.Second, CPU: 30 * time.Second, Memory: 512 << 20, Output: 32 << 20, Temp: 512 << 20, Renders: 4}
}

// parseLimits reads the settings, reporting every problem rather than the first.
func parseLimits(get func(string) string, callTimeout time.Duration) (Limits, []error) {
	l := DefaultLimits()
	var errs []error
	dur := func(name string, def, min time.Duration) time.Duration {
		v := strings.TrimSpace(get(name))
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d < min {
			errs = append(errs, fmt.Errorf("%s is a duration of at least %s (like %s), got %q", name, min, def, v))
			return def
		}
		return d
	}
	size := func(name string, def, min int64) int64 {
		v := strings.TrimSpace(get(name))
		if v == "" {
			return def
		}
		n, err := ParseSize(v)
		if err != nil || n < min {
			errs = append(errs, fmt.Errorf("%s is a size of at least %s (bytes, or with Ki, Mi or Gi, like %s), got %q", name, FormatSize(min), FormatSize(def), v))
			return def
		}
		return n
	}
	l.Timeout = dur(EnvRenderTimeout, l.Timeout, time.Second)
	l.CPU = dur(EnvMaxCPU, l.CPU, time.Second)
	l.Memory = size(EnvMaxMemory, l.Memory, 128<<20) // measured: below about 96 MiB helm's Go runtime cannot start
	l.Output = size(EnvMaxOutput, l.Output, 1<<20)
	l.Temp = size(EnvMaxTemp, l.Temp, 16<<20)
	if v := strings.TrimSpace(get(EnvMaxRenders)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 64 {
			errs = append(errs, fmt.Errorf("%s is a whole number from 1 to 64, got %q", EnvMaxRenders, v))
		} else {
			l.Renders = n
		}
	}
	if callTimeout > 0 {
		if need := ChartLookupTimeout + l.Timeout + coreBudget(callTimeout); need >= PluginDeadline {
			errs = append(errs, fmt.Errorf("%s (%s) plus the chart lookup (%s) plus %d attempts of CLEARANCE_CMP_CALL_TIMEOUT (%s) and the wait between them is %s, which must be under %s: Argo CD kills a plugin at 90 s, and an unreachable core must be found out in time for the outage policy",
				EnvRenderTimeout, l.Timeout, ChartLookupTimeout, CoreRetries+1, callTimeout, need, PluginDeadline))
		}
	}
	return l, errs
}

// ParseSize reads a byte count: digits, optionally followed by Ki, Mi or Gi (powers of 1024).
func ParseSize(v string) (int64, error) {
	mult := int64(1)
	for suf, m := range map[string]int64{"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30} {
		if strings.HasSuffix(v, suf) {
			v, mult = strings.TrimSuffix(v, suf), m
			break
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("not a size: %q", v)
	}
	return n * mult, nil
}

// FormatSize is ParseSize's inverse for whole units.
func FormatSize(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%dGi", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%dMi", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%dKi", n>>10)
	}
	return strconv.FormatInt(n, 10)
}

// The limit classes. F4's error codes had not landed when these were written; the codes below are this package's own
// (render.limit.<class>) and are meant to be folded into F4's catalogue when it lands.
const (
	LimitWallTime    = "wall-time"
	LimitCPU         = "cpu"
	LimitMemory      = "memory"
	LimitOutput      = "output"
	LimitTemp        = "temp"
	LimitConcurrency = "concurrency"
)

// LimitError is a render stopped by one of its bounds.
type LimitError struct {
	Limit   string // one of the Limit* classes
	Setting string // the environment variable that raises it
	Bound   string // the bound in force, as the setting would be written
	Step    string // the step that went over ("helm template"), or "" for the render as a whole
	Detail  string // what was seen
}

// Code is the error code of the limit: render.limit.<class>.
func (e *LimitError) Code() string { return "render.limit." + e.Limit }

func (e *LimitError) Error() string {
	what := "the render"
	if e.Step != "" {
		what = e.Step
	}
	return fmt.Sprintf("render limit exceeded [%s]: %s %s (bound %s=%s); the render was stopped and nothing syncs. "+
		"If this render is expected to be this large, raise %s on the clearance-cmp sidecar", e.Code(), what, e.Detail, e.Setting, e.Bound, e.Setting)
}

// budget is one render's bounds and scratch root, carried to every step through the context.
type budget struct {
	lim  Limits
	root string // the render's scratch directory: every temporary file of the render is under it
	src  string // the plugin's source directory (read only for the steps)
}

type budgetKey struct{}

func withBudget(ctx context.Context, b *budget) context.Context {
	return context.WithValue(ctx, budgetKey{}, b)
}

func budgetFrom(ctx context.Context) *budget {
	b, _ := ctx.Value(budgetKey{}).(*budget)
	return b
}

// workDir is where a render's temporary directories go: the render's scratch root, or the system's ("").
func workDir(ctx context.Context) string {
	if b := budgetFrom(ctx); b != nil {
		return b.root
	}
	return ""
}

// renderBounded runs render under cfg.Limits: a slot among CLEARANCE_CMP_MAX_RENDERS, one wall-time deadline for all of
// it, a scratch root of its own (removed after), and the size of what it rendered. A bound that stops it is a
// *LimitError.
func renderBounded(ctx context.Context, cfg Config, srcDir string, stderr io.Writer, render func(context.Context) (*Rendered, error)) (*Rendered, error) {
	lim := cfg.Limits
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	rctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()
	wall := func(err error) error {
		if errors.Is(rctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return &LimitError{Limit: LimitWallTime, Setting: EnvRenderTimeout, Bound: lim.Timeout.String(),
				Detail: fmt.Sprintf("did not finish in %s (%v)", lim.Timeout, err)}
		}
		return err
	}
	release, waited, err := acquireSlot(rctx, filepath.Join(cfg.CacheDir, "slots"), lim.Renders)
	if err != nil {
		if rctx.Err() != nil {
			if ctx.Err() == nil {
				return nil, &LimitError{Limit: LimitConcurrency, Setting: EnvMaxRenders, Bound: strconv.Itoa(lim.Renders),
					Detail: fmt.Sprintf("waited %s for one of %d render slots, all busy, and ran out of its %s (%s)", waited.Round(time.Millisecond), lim.Renders, EnvRenderTimeout, lim.Timeout)}
			}
			return nil, ctx.Err()
		}
		// A slot directory that cannot be used never fails a render: the bound is lost, and said so.
		fmt.Fprintf(stderr, "clearance: WARNING render concurrency is not bounded (%v): %s needs a writable CLEARANCE_CMP_CACHE_DIR\n", err, EnvMaxRenders)
		release = func() {}
	}
	defer release()
	root, err := os.MkdirTemp("", "clearance-render-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	r, err := render(withBudget(rctx, &budget{lim: lim, root: root, src: srcDir}))
	if err != nil {
		var le *LimitError
		if errors.As(err, &le) {
			return nil, le
		}
		return nil, wall(err)
	}
	if n := int64(len(r.Manifests)); n > lim.Output {
		return nil, &LimitError{Limit: LimitOutput, Setting: EnvMaxOutput, Bound: FormatSize(lim.Output),
			Detail: fmt.Sprintf("rendered %s of manifests", FormatSize(n))}
	}
	return r, nil
}

// acquireSlot takes one of n file locks under dir (shared by every plugin process in the sidecar, which the
// cmp-server starts one per request). It waits, with a jittered backoff, until one is free or ctx ends, and returns
// how long it waited.
func acquireSlot(ctx context.Context, dir string, n int) (func(), time.Duration, error) {
	start := time.Now()
	if dir == "" || dir == "slots" {
		return nil, 0, errors.New("no cache directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, 0, err
	}
	files := make([]*os.File, 0, n)
	defer func() {
		for _, f := range files {
			if f != nil {
				f.Close()
			}
		}
	}()
	for i := 0; i < n; i++ {
		f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("slot-%02d", i)), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, 0, err
		}
		files = append(files, f)
	}
	delay := 10 * time.Millisecond
	for {
		for i, f := range files {
			ok, err := tryLock(f)
			if err != nil {
				return nil, time.Since(start), err
			}
			if ok {
				files[i] = nil // kept open: the lock is held until release
				return func() { unlock(f); f.Close() }, time.Since(start), nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, time.Since(start), ctx.Err()
		case <-time.After(jitter(delay)):
		}
		if delay < 500*time.Millisecond {
			delay *= 2
		}
	}
}

// jitter is a "full jitter" wait: uniformly random in [d/2, d], so waiters that started together do not retry together.
func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	return d/2 + rand.N(d/2+1)
}

// dirSize is the total size of the regular files under dir (what a step left in the render's scratch).
func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// capWriter keeps at most max bytes. Past that it records the overflow, calls over once, and fails the write.
type capWriter struct {
	buf  []byte
	max  int64
	seen int64
	over func()
	full bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.seen += int64(len(p))
	if w.seen > w.max {
		if !w.full {
			w.full = true
			if w.over != nil {
				w.over()
			}
		}
		return 0, errOutputCap
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

var errOutputCap = errors.New("output limit reached")

// headWriter keeps the first max bytes of a stream and drops the rest without failing the writer (a step's stderr:
// the message is in its first lines, and a chatty tool must not be stopped for it).
type headWriter struct {
	buf []byte
	max int
}

func (w *headWriter) Write(p []byte) (int, error) {
	if room := w.max - len(w.buf); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		w.buf = append(w.buf, p[:room]...)
	}
	return len(p), nil
}

func (w *headWriter) String() string { return string(w.buf) }
