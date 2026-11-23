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

	"github.com/jfillman/clearance/client"
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
// so an unreachable core is ErrCoreUnavailable (and the outage policy's cache) before PluginDeadline, never a deadline;
// and renderTree ends every render coreBudget before the run's deadline, so a render that starts late (after a pre-render
// confirmation the core answered slowly) is the one cut short, never the call that decides.
const (
	CoreRetries    = 1
	CoreBackoff    = 250 * time.Millisecond
	CoreBackoffMax = 2 * time.Second
)

// coreMargin is kept between the end of a call to the core and the run's deadline, for the plugin to act on the answer.
const coreMargin = 250 * time.Millisecond

// registerInTime is RegisterChange held to the run: however long the work before it took (the 2 s PostRenderReserve is
// a margin, not a bound), a core that has not answered when the run is coreMargin from its end is an outage
// (client.ErrCoreUnavailable), and the outage policy decides, as it does for a core that times out. It never becomes
// the run's own deadline, which would skip that policy.
//
// Only a call that failed because this window ended is converted: the error must itself be a context error, and the
// window's own cause (errCoreWindow) must be what ended it, not the run's deadline or a cancellation. An answer the core
// gave (a refusal, a bad response) is never reclassified, even when the window closed just after it arrived.
func registerInTime(ctx context.Context, core Core, req *client.ChangeRequest) (*client.Change, error) {
	cctx := ctx
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		cctx, cancel = context.WithDeadlineCause(ctx, dl.Add(-coreMargin), errCoreWindow)
		defer cancel()
	}
	ch, err := core.RegisterChange(cctx, req)
	if err != nil && !errors.Is(err, client.ErrCoreUnavailable) &&
		(errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) &&
		errors.Is(context.Cause(cctx), errCoreWindow) {
		return nil, &client.UnavailableError{Op: "registerChange", Reason: client.ReasonTimeout,
			Err: fmt.Errorf("the core did not answer within the time left in the run: %w", err)}
	}
	return ch, err
}

// errCoreWindow is the cause of a core call's window closing coreMargin before the run's end.
var errCoreWindow = errors.New("the core call's window before the run's end closed")

// PostRenderReserve is the time kept after the render for the plugin's own work around the core call: removing the
// scratch, canonicalising and hashing the manifests, the caches, encoding the request and writing the stream. The
// measured fixture takes a few milliseconds for all of it; 2 s covers a render at the output bound on a slow node.
const PostRenderReserve = 2 * time.Second

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
	if l.Timeout >= PluginDeadline || callTimeout >= PluginDeadline {
		// Each term alone must fit before any is added: a huge duration would overflow the sum below.
		errs = append(errs, fmt.Errorf("%s (%s) and CLEARANCE_CMP_CALL_TIMEOUT (%s) must each be under %s", EnvRenderTimeout, l.Timeout, callTimeout, PluginDeadline))
	} else if callTimeout > 0 {
		if need := ChartLookupTimeout + l.Timeout + PostRenderReserve + coreBudget(callTimeout); need >= PluginDeadline {
			errs = append(errs, fmt.Errorf("%s (%s) plus the chart lookup (%s), the plugin's own work after the render (%s), and %d attempts of CLEARANCE_CMP_CALL_TIMEOUT (%s) with the wait between them is %s, which must be under %s: Argo CD kills a plugin at 90 s, and an unreachable core must be found out in time for the outage policy",
				EnvRenderTimeout, l.Timeout, ChartLookupTimeout, PostRenderReserve, CoreRetries+1, callTimeout, need, PluginDeadline))
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

// The limit classes. Each is one of F4's error codes (errors.go): the wall time and the slots are faults (a slow network
// or a busy sidecar can cause them, and last-known-good may answer them), the rest are render errors (the same inputs
// go over the same bound again).
const (
	LimitWallTime    = "wall-time"
	LimitCPU         = "cpu"
	LimitMemory      = "memory"
	LimitOutput      = "output"
	LimitTemp        = "temp"
	LimitConcurrency = "concurrency"
)

// limitCodes is each class's error code.
var limitCodes = map[string]string{
	LimitWallTime: CodeFaultTimeout, LimitConcurrency: CodeFaultBusy,
	LimitCPU: CodeRenderLimitCPU, LimitMemory: CodeRenderLimitMem, LimitOutput: CodeRenderLimitOut, LimitTemp: CodeRenderLimitTemp,
}

// LimitError is a render stopped by one of its bounds. classifyRender turns it into the *CmpError of its code.
type LimitError struct {
	Limit   string // one of the Limit* classes
	Setting string // the environment variable that raises it
	Bound   string // the bound in force, as the setting would be written
	Step    string // the step that went over ("helm template"), or "" for the render as a whole
	Detail  string // what was seen
}

// Code is the limit's error code (CMP-FAULT-TIMEOUT, CMP-FAULT-BUSY or CMP-RENDER-LIMIT-*).
func (e *LimitError) Code() string { return limitCodes[e.Limit] }

// Summary is the short first line: which bound, and the setting that raises it.
func (e *LimitError) Summary() string {
	what := "the render"
	if e.Step != "" {
		what = e.Step
	}
	return fmt.Sprintf("%s went over its %s bound (%s=%s)", what, e.Limit, e.Setting, e.Bound)
}

func (e *LimitError) Error() string {
	what := "the render"
	if e.Step != "" {
		what = e.Step
	}
	return fmt.Sprintf("render limit exceeded: %s %s (bound %s=%s); the render was stopped; nothing it rendered syncs. "+
		"If this render is expected to be this large, raise %s on the clearance-cmp sidecar", what, e.Detail, e.Setting, e.Bound, e.Setting)
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

// lookupBudget is the chart tag lookup's context: the configured step limits and a scratch root of its own (removed
// by done), no source directory and no slot. Without it the lookup would run under the default limits with the
// system temp directory, which holds every render's scratch and the caches, open to it.
func lookupBudget(ctx context.Context, cfg Config) (context.Context, func(), bool) {
	lim := cfg.Limits
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	root, err := os.MkdirTemp("", "clearance-lookup-")
	if err != nil {
		return ctx, func() {}, false // no private scratch: skip the lookup (an optimisation), never run it with the shared /tmp
	}
	return withBudget(ctx, &budget{lim: lim, root: root}), func() { os.RemoveAll(root) }, true
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
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, errAllBusy) { // every slot was held for the whole wait
				return nil, &LimitError{Limit: LimitConcurrency, Setting: EnvMaxRenders, Bound: strconv.Itoa(lim.Renders),
					Detail: fmt.Sprintf("waited %s for one of %d render slots, all busy, and ran out of its %s (%s)", waited.Round(time.Millisecond), lim.Renders, EnvRenderTimeout, lim.Timeout)}
			}
			return nil, wall(err) // the time ran out before a slot was even looked at: the wall time, not the slots
		}
		// A slot directory that cannot be used never fails a render: the bound is lost, and said so.
		fmt.Fprintf(stderr, "clearance: WARNING render concurrency is not bounded (%v): %s needs a writable CLEARANCE_CMP_CACHE_DIR\n", err, EnvMaxRenders)
		release = func() {}
	}
	defer release()
	sweepStaleScratch(os.TempDir(), time.Now())
	root, err := os.MkdirTemp("", "clearance-render-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			fmt.Fprintf(stderr, "clearance: WARNING the render's scratch %s could not be removed (%v): it counts against the volume until the pod restarts\n", root, err)
		}
	}()
	r, err := render(withBudget(rctx, &budget{lim: lim, root: root, src: srcDir}))
	if err == nil && rctx.Err() != nil {
		err = rctx.Err() // finished, but past the deadline (a slow scan or cleanup): not a result to register
	}
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

// staleScratchAge is how old a render's or a lookup's scratch directory must be before another run removes it. No run
// lives past PluginDeadline (80 s; Argo CD kills a plugin at 90 s), so a scratch this old belongs to a process that is
// gone: one killed with SIGKILL (Argo CD's own exec timeout, the container's OOM kill) never ran its cleanup, and the
// sidecar's /tmp emptyDir outlives the container. Without the sweep each such kill would keep its scratch (a chart
// checkout, rendered manifests) on the volume until the pod is replaced.
const staleScratchAge = 10 * time.Minute

// sweepStaleScratch removes the scratch directories (clearance-render-*, clearance-lookup-*) in dir older than
// staleScratchAge. Anything else in dir, and a scratch still in use, is left alone; a failure is not an error.
func sweepStaleScratch(dir string, now time.Time) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() || !(strings.HasPrefix(n, "clearance-render-") || strings.HasPrefix(n, "clearance-lookup-")) {
			continue
		}
		if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > staleScratchAge {
			os.RemoveAll(filepath.Join(dir, n))
		}
	}
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
	busy := false // a whole scan found every slot held: only then is running out of time "all busy"
	expired := func() error {
		if busy {
			return fmt.Errorf("%w: %w", errAllBusy, ctx.Err())
		}
		return ctx.Err()
	}
	for {
		if ctx.Err() != nil { // never a slot for a render whose time is over
			return nil, time.Since(start), expired()
		}
		for i, f := range files {
			ok, err := tryLock(f)
			if err != nil {
				return nil, time.Since(start), err
			}
			if ok {
				if ctx.Err() != nil { // the time ran out while the lock was being taken: give it back
					unlock(f)
					return nil, time.Since(start), expired()
				}
				files[i] = nil // kept open: the lock is held until release
				return func() { unlock(f); f.Close() }, time.Since(start), nil
			}
		}
		busy = true
		select {
		case <-ctx.Done():
			return nil, time.Since(start), expired()
		case <-time.After(jitter(delay)):
		}
		if delay < 500*time.Millisecond {
			delay *= 2
		}
	}
}

// errAllBusy marks a slot wait that ran out of time after finding every slot held.
var errAllBusy = errors.New("every render slot is busy")

// jitter is a "full jitter" wait: uniformly random in [d/2, d], so waiters that started together do not retry together.
func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	return d/2 + rand.N(d/2+1)
}

// dirSize is the total size of the regular files under dir (what a step left in the render's scratch). A part it cannot
// read (a directory the step made unreadable) is an error, never a smaller total.
func dirSize(dir string) (int64, error) {
	var n int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			n += fi.Size()
		}
		return nil
	})
	return n, err
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
