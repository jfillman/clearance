package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/argosrc"
)

// Core is the part of the Clearance client the plugin uses.
type Core interface {
	RegisterChange(ctx context.Context, req *client.ChangeRequest) (*client.Change, error)
}

// Deps are the plugin's collaborators; tests replace them.
type Deps struct {
	Exec   Exec
	Run    argosrc.Runner // the generic renderer's; nil is OSRun
	Core   Core
	Cache  Cache
	Now    func() time.Time
	Stderr io.Writer
	Stats  *RunStats // the run's metrics (metrics.go); nil counts nothing
}

// Outcome is what `generate` decided.
type Outcome string

const (
	Cleared Outcome = "cleared" // manifests stamped with the grant
	Held    Outcome = "held"    // manifests plus the PreSync wait Job
)

// Generate is the plugin's `generate` step: render, canonicalise, hash, find or register the change, and write the
// manifests to out. An error is a refusal: the caller exits non-zero, Argo CD shows ComparisonError and nothing
// syncs (a tier-3 denial, a denied or expired change, an outage hold, a render that fails). Every error is a *CmpError
// (errors.go): a fault, a render error or a refusal, with a stable code.
func Generate(ctx context.Context, d Deps, cfg Config, srcDir string, out io.Writer) (Outcome, error) {
	var err error
	// The plugin runs with srcDir "." (main below). Every containment check compares resolved paths, and a relative
	// path resolves to a relative one, which never has the absolute root as its prefix: on 0.52.0 that refused every
	// value file ("resolves outside the repository", hangar-prod 2026-11-18). Resolve it once, here.
	if srcDir, err = filepath.Abs(srcDir); err != nil {
		return "", newErr(CodeFaultInternal, "the source directory cannot be resolved", err)
	}
	// Before anything is fetched: the chart comes only from where the platform says, by the platform's own spelling.
	cfg, err = cfg.Canonical()
	if err != nil {
		if isKind(err, kindRefused) || isKind(err, kindNoRepos) {
			return "", classifyRender(ctx, err, lookupNotAsked, cfg.Sources != "")
		}
		return "", classifyConfig(err) // the sources parameter, or a list entry (a sidecar setting)
	}
	// The pre-render cache (rendercache.go) and the last-known-good store (lkg.go) need the commit the chart's tag
	// resolves to now, one lookup on the remote: an unchanged Application is answered before anything is rendered. The
	// lookup is bounded (ChartLookupTimeout, reserved by the startup check): no answer in time is no answer, and the
	// render fetches the chart itself.
	if (cfg.RenderCacheTTL > 0 || cfg.LKG) && cfg.Sources == "" && cfg.ChartRepo != "" {
		lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
		// The configured step limits, and a private scratch: never the shared /tmp. Without one the lookup is skipped (it
		// is an optimisation; the render resolves the tag in its own scratch).
		if lctx, done, ok := lookupBudget(lctx, cfg); ok {
			cfg.chartCommit, cfg.chartLookupErr = lookupChart(lctx, d.Exec, cfg.ChartRepo, cfg.ChartRev)
			cfg.chartLooked = true
			done()
		}
		cancel()
	}
	rkey, lkey := renderKey(cfg), lkgKey(cfg)
	if e, ok := d.Cache.GetRender(rkey, d.Now(), cfg.RenderCacheTTL); ok {
		if o, handled, err := serveRender(ctx, d, cfg, e, out, nil); handled {
			if err == nil { // these inputs at this chart commit are the last cleared: keep the fallback pointing at them
				d.Cache.touchLKG(lkey, d.Now())
				d.Cache.putLKGTag(cfg, lkey)
			}
			return o, err
		}
	}
	tree, r, cerr := renderTree(ctx, d, cfg, srcDir)
	if cerr != nil {
		if cerr.FallsBack() && cfg.LKG {
			// Only a fault or an unavailable dependency before the decision, only for the exact inputs, and only once
			// the core confirms (lkg.go).
			if lkey == "" && cfg.chartLookupErr != nil {
				// The chart host is unreachable: the commit this tag was last cleared at, for these exact inputs.
				var commit string
				if lkey, commit = d.Cache.lkgByTag(cfg); lkey != "" {
					fmt.Fprintf(d.Stderr, "clearance: the chart tag %s could not be resolved (%v); last-known-good uses the commit it was last cleared at, %s\n", cfg.ChartRev, cfg.chartLookupErr, shortRes(commit))
					cfg.chartCommit = commit
				}
			}
			if o, handled, err := serveLKG(ctx, d, cfg, lkey, cerr, out); handled {
				return o, err
			}
		}
		return "", cerr
	}
	fmt.Fprintf(d.Stderr, "clearance: %s/%s rendered %d objects, tree %s", cfg.App, cfg.Env, len(tree.Hashes), tree.Root[:12])
	for _, s := range r.Sources {
		what := s.Repo
		if s.Chart != "" {
			what += " chart " + s.Chart
		}
		fmt.Fprintf(d.Stderr, ", source %d %s %s@%s", s.Position, s.Type, what, shortRes(s.Resolved))
		if s.Checkout {
			fmt.Fprint(d.Stderr, " (Argo CD's checkout)")
		}
	}
	if r.ChartMerge != "" {
		fmt.Fprintf(d.Stderr, ", chart %s@%s (%s), chart-cache=%s", cfg.ChartRepo, cfg.ChartRev, r.ChartMerge[:12], r.ChartFetch)
	}
	fmt.Fprintf(d.Stderr, ", netns=%s, fs-sandbox=%s\n", NetnsState(), FSSandboxState())

	now := d.Now()
	started := time.Now() // wall clock, against the decisions DropRenders records
	// cleared emits the stamped stream and remembers it (rendercache.go, lkg.go) when the render is what the keys name.
	cleared := func(e CacheEntry) (Outcome, error) {
		var buf bytes.Buffer
		if _, err := emit(tree, &buf, Cleared, e.ID, cfg); err != nil {
			return "", newErr(CodeFaultInternal, "the stamped manifests could not be written", err)
		}
		if req, rerr := registration(cfg, tree); rerr == nil && (cfg.ChartRepo == "" || r.ChartMerge == cfg.chartCommit) {
			ent := renderEntry{Request: req, ID: e.ID, Tier: e.Tier, Outage: e.Outage, Tree: tree.Root, App: cfg.App, Env: cfg.Env, Cluster: cfg.Cluster, CachedAt: e.CachedAt, ExpiresAt: e.ExpiresAt, Stream: buf.Bytes()}
			if rkey != "" {
				ent.Key = rkey
				d.Cache.PutRender(ent, started)
			}
			if lkey != "" {
				ent.Key = lkey
				d.Cache.PutLKG(ent, started)
				d.Cache.putLKGTag(cfg, lkey)
			}
		}
		if _, err := out.Write(buf.Bytes()); err != nil {
			return "", newErr(CodeFaultInternal, "the manifests could not be written to Argo CD", err)
		}
		return Cleared, nil
	}
	if e, ok := d.Cache.Get(cfg.App, cfg.Env, cfg.Cluster, tree.Root, now); ok && now.Sub(e.CachedAt) < cfg.CacheTTL {
		return cleared(e)
	}
	req, err := registration(cfg, tree)
	if err != nil {
		return "", newErr(CodeRenderRevision, "the change cannot be registered for this revision", err)
	}
	ch, err := registerInTime(ctx, d.Core, req)
	d.Stats.coreCall(err)
	if err != nil {
		if errors.Is(err, client.ErrCoreUnavailable) {
			// The outage policy (docs/gate.md, C-6): a tree already cleared whose tier lets through while the core is
			// down is served from what was remembered; anything else holds, because an unknown tier is never allowed.
			// A fresh clock: the call can have taken most of the run, and an entry is never served past its ExpiresAt.
			if e, ok := d.Cache.Get(cfg.App, cfg.Env, cfg.Cluster, tree.Root, d.Now()); ok && e.Outage == "allow-and-record" {
				fmt.Fprintf(d.Stderr, "clearance: the core is unreachable (%v); serving %s from the cache (tier %d, allow-and-record)\n", err, e.ID, e.Tier)
				return emitted(emit(tree, out, Cleared, e.ID, cfg))
			}
			return "", outageHold(tree.Root, err)
		}
		return "", classifyCore(err)
	}
	switch ch.State {
	case "cleared":
		exp, _ := time.Parse(time.RFC3339Nano, ch.ExpiresAt)
		if exp.IsZero() {
			exp = now.Add(cfg.CacheTTL)
		}
		ce := CacheEntry{ID: ch.ID, Tier: ch.Tier, Outage: ch.Outage, Tree: tree.Root, CachedAt: now, ExpiresAt: exp}
		d.Cache.PutUndecided(cfg.App, cfg.Env, cfg.Cluster, ce, started)
		return cleared(ce)
	case "holding":
		d.Cache.DropRenders(cfg.App, cfg.Env, cfg.Cluster, tree.Root) // a hold is never served from the cache
		d.Cache.Drop(cfg.App, cfg.Env, cfg.Cluster, tree.Root)
		o, err := emit(tree, out, Held, ch.ID, cfg)
		if err != nil {
			if strings.Contains(err.Error(), "CLEARANCE_WAIT_IMAGE") {
				return "", refusal(cfg, CodeFaultWaitImage, fmt.Sprintf("change %s is held for people, but CLEARANCE_WAIT_IMAGE is not set", ch.ID), ch.ID, err)
			}
			return "", refusal(cfg, CodeFaultInternal, fmt.Sprintf("change %s is held, and its wait Job could not be written", ch.ID), ch.ID, err)
		}
		return o, nil
	default:
		d.Cache.DropRenders(cfg.App, cfg.Env, cfg.Cluster, tree.Root)
		d.Cache.Drop(cfg.App, cfg.Env, cfg.Cluster, tree.Root)
		why := ""
		if ch.DenyReason != nil {
			why = ": " + *ch.DenyReason
		}
		return "", refusal(cfg, stateCode(ch.State), fmt.Sprintf("change %s is %s (tier %d); nothing syncs", ch.ID, ch.State, ch.Tier), ch.ID,
			fmt.Errorf("change %s is %s (tier %d)%s; nothing syncs", ch.ID, ch.State, ch.Tier, why))
	}
}

// emitted classifies emit's error: the tree was already hashed, so a failure to write it is the plugin's.
func emitted(o Outcome, err error) (Outcome, error) {
	if err != nil {
		return "", newErr(CodeFaultInternal, "the manifests could not be written to Argo CD", err)
	}
	return o, nil
}

// renderTree is the render phase: render the sources, canonicalise and hash. Its error is classified (errors.go), and
// a panic in it is recovered as a fault, so the last-known-good fallback can tell the plugin's failure from the
// Application's. With last-known-good on, the render gets the run's deadline less one call to the core, so a slow
// render still leaves time to confirm the remembered change.
func renderTree(ctx context.Context, d Deps, cfg Config, srcDir string) (tree *Tree, r *Rendered, cerr *CmpError) {
	rctx := ctx
	// The registration after the render (or last-known-good's confirmation) always keeps its whole budget, every
	// attempt and the wait between them (coreBudget): a render that started late, after a pre-render confirmation the
	// core answered slowly, is cut short, never the call that decides. An unreachable core is then an outage
	// (ErrCoreUnavailable, the outage policy), not the run's deadline.
	if reserve := coreBudget(cfg.RegisterWait) + PostRenderReserve; cfg.RegisterWait > 0 {
		if dl, ok := ctx.Deadline(); ok {
			if left := time.Until(dl); left <= reserve {
				// Not enough time left to render and still ask the core (a slow pre-render confirmation came first):
				// fail now, as a timeout, rather than render into the time the decision needs.
				return nil, nil, newErr(CodeFaultTimeout, "the render ran out of time", fmt.Errorf("only %s of the run is left, less than the %s the core's call and the plugin's own work need after a render", left.Round(time.Millisecond), reserve))
			}
			var cancel context.CancelFunc
			rctx, cancel = context.WithDeadline(ctx, dl.Add(-reserve))
			defer cancel()
		}
	}
	defer func() {
		if p := recover(); p != nil {
			tree, r = nil, nil
			cerr = newErr(CodeFaultPanic, "the plugin panicked while rendering", fmt.Errorf("panic: %v", p))
		}
	}()
	// The render runs under its limits, in a slot and a scratch root of its own (limits.go).
	r, err := renderBounded(rctx, cfg, srcDir, d.Stderr, func(ctx context.Context) (*Rendered, error) {
		if cfg.Sources != "" {
			run := d.Run
			if run == nil {
				run = OSRun
			}
			return RenderSources(ctx, run, cfg, srcDir)
		}
		return Render(ctx, d.Exec, cfg, srcDir)
	})
	if err != nil {
		return nil, nil, classifyRender(rctx, err, chartLookup(cfg), cfg.Sources != "")
	}
	tree, err = Canonicalize(r.Manifests, cfg.Destination, cfg.ExtraCluster)
	if err != nil {
		return nil, nil, newErr(CodeRenderTree, "the render cannot be hashed", err)
	}
	if r.Generic {
		tree.SetRelease(r.Release)
	} else {
		tree.SetRelease(releaseFromValues(cfg, srcDir))
	}
	return tree, r, nil
}

func shortRes(r string) string {
	if len(r) > 19 {
		return r[:19]
	}
	return r
}

func emit(tree *Tree, out io.Writer, o Outcome, id string, cfg Config) (Outcome, error) {
	objs := tree.Emitted
	if o == Cleared {
		tree.Stamp(id)
	} else {
		tree.Stamp("")
		job, err := WaitJob(cfg, id)
		if err != nil {
			return "", err
		}
		objs = append(append([]map[string]any{}, objs...), job)
	}
	return o, WriteStream(out, objs)
}

// registration is the change request, the same object shape the clearance-gate Tekton task posts
// (glidepath's catalog task, the register step), for a pushed commit: pr 0, head the commit Argo syncs, every object
// "added" because there is no base render to diff (an uncovered tree is classified as wholly new). The core answers
// the cleared change for the same app, environment, cluster and tree when there is one (gate.Service.clearedByTree).
func registration(cfg Config, tree *Tree) (*client.ChangeRequest, error) {
	repo, err := cfg.RepoName()
	if err != nil {
		return nil, err
	}
	if !sha40.MatchString(cfg.Revision) {
		return nil, fmt.Errorf("ARGOCD_APP_REVISION %q is not a commit: the plugin registers the commit Argo CD syncs", cfg.Revision)
	}
	objs := make([]client.ObjectChange, 0, len(tree.Keys))
	for _, k := range tree.Keys {
		objs = append(objs, client.ObjectChange{APIVersion: k[0], Kind: k[1], Namespace: k[2], Name: k[3], Op: "added",
			Fields: []string{}, Images: []string{}, Digest: tree.Hashes[k]})
	}
	paths := []string{cfg.SourcePath}
	if cfg.SourcePath == "" {
		paths = []string{"."}
	}
	return &client.ChangeRequest{App: cfg.App, Env: cfg.Env, Cluster: cfg.Cluster, Repo: repo, PR: 0, Head: cfg.Revision,
		Proposer: "system:argocd-cmp", ProposerKind: "person", Protected: true, TreeDigest: tree.Root, Paths: paths,
		LinesChanged: 0, Objects: objs,
		// A pushed commit has no CI run and no provenance check of its own: only the render is known. A tree that
		// no earlier change cleared therefore cannot clear by policy at tier 1 (checks:ci,provenance...), it holds.
		Checks: map[string]string{"ci": "unknown", "provenance": "unknown", "render": "ok", "admission": "unknown"}}, nil
}

func newCore(cfg Config) (Core, error) {
	return client.New(client.Options{BaseURL: cfg.CoreURL, Token: client.FileToken(cfg.TokenFile),
		Timeout: cfg.RegisterWait, UserAgent: "clearance-argocd-cmp", CAFile: cfg.CAFile,
		// One retry after a jittered wait (125-250 ms): the sidecar's renders that found the core down together do not
		// come back at the same instant. ParseConfig checks that every attempt fits inside PluginDeadline (coreBudget).
		Retries: CoreRetries, RetryBackoff: CoreBackoff, RetryBackoffMax: CoreBackoffMax})
}

func main() {
	maybeShim()                                     // a render step's sandbox shim (fssandbox.go): applies its limits and execs the tool, never returns
	if len(os.Args) > 1 && os.Args[1] == "parity" { // the parity suite (parity.go), not the plugin
		os.Exit(parityMain(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "doctor" { // the install preflight (doctor.go), not the plugin
		os.Exit(doctorMain(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "metrics" { // the metrics server (metrics.go), not the plugin
		os.Exit(metricsMain(os.Args[2:], os.Getenv, os.Stderr))
	}
	start, stats := time.Now(), NewRunStats()
	// The plugin's stderr is held while the run is short: a failure puts its "clearance-cmp: <code>: ..." line first, so
	// the first line of Argo CD's ComparisonError from the plugin is the code, and the warnings and the summary follow
	// it. The hold is bounded (stderrHoldFor, stderrHoldMax) and a SIGTERM or SIGINT writes what is held before the
	// process exits, so a run that is killed still leaves its warnings and progress on stderr.
	ps := newPluginStderr(os.Stderr, stderrHoldFor, stderrHoldMax)
	defer ps.Flush() // a panic still shows what was held
	stopSignals := flushOnSignal(ps, os.Stderr, start)
	defer stopSignals()
	netnsWarn, fsWarn = ps, ps
	// fail ends a run that failed before or after Generate: it is counted (CLEARANCE_CMP_METRICS_DIR is read on its own,
	// so a sidecar setting that stops the plugin at start still shows as a fault) and the process exits.
	fail := func(ce error, code int) {
		ps.Fail(ce)
		recordRunFromEnv(os.Getenv, Run{Version: pluginVersion, Err: ce, Duration: time.Since(start), Stats: stats}, os.Stderr)
		os.Exit(code)
	}
	cfg, err := ParseConfig(os.Getenv)
	if err != nil {
		fail(classifyConfig(err), 2)
	}
	SetNetns(cfg.Netns)
	SetFSSandbox(cfg.FSSandbox, cfg.TokenFile)
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(256 << 20) // the plugin itself: a soft bound, so the GC works before the container's limit does
	}
	core, err := newCore(cfg)
	if err != nil {
		fail(newErr(CodeFaultConfig, "the core client cannot be set up from the sidecar's settings", err), 2)
	}
	if err := EnableReaping(); err != nil { // a descendant of a render step never outlives it, setsid or not (proc_linux.go)
		fail(newErr(CodeFaultSandbox, "the render steps' processes cannot be contained", err), 2)
	}
	d := Deps{Exec: OSExec, Run: OSRun, Core: core, Cache: Cache{Dir: cfg.CacheDir}, Now: time.Now, Stderr: ps, Stats: stats}
	ctx, cancel := context.WithTimeout(context.Background(), PluginDeadline) // Argo CD kills a plugin at 90 s (ARGOCD_EXEC_TIMEOUT)
	defer cancel()
	o, err := generateCounted(ctx, d, cfg, start)
	if rerr := reapAll(); rerr != nil { // nothing a render step started outlives the plugin (proc_linux.go)
		fmt.Fprintln(ps, "clearance-cmp: WARNING", rerr)
	}
	if err != nil { // a *CmpError: its code and short line come first
		cancel()
		fail(err, 1)
	}
	ps.Flush()
	recordRunFromEnv(os.Getenv, Run{Version: pluginVersion, Outcome: o, Duration: time.Since(start), Stats: stats}, os.Stderr)
}

// generateCounted is Generate for main: a panic outside the render phase (which renderTree already recovers as
// CMP-FAULT-PANIC) is counted as that fault before the process dies of it, so the fault rate sees it.
func generateCounted(ctx context.Context, d Deps, cfg Config, start time.Time) (Outcome, error) {
	defer func() {
		if p := recover(); p != nil {
			recordRunFromEnv(os.Getenv, Run{Version: pluginVersion, Duration: time.Since(start), Stats: d.Stats,
				Err: newErr(CodeFaultPanic, "the plugin panicked", fmt.Errorf("panic: %v", p))}, os.Stderr)
			panic(p)
		}
	}()
	return Generate(ctx, d, cfg, ".", os.Stdout)
}

// The bounds of the stderr hold. A run that lasts longer than stderrHoldFor, or holds more than stderrHoldMax bytes,
// writes what it held and streams from then on: a run that is then killed with SIGKILL (the kernel's OOM killer, or
// Argo CD's exec timeout after its SIGTERM) has already shown its warnings and progress. Such a late failure's code line
// comes after the lines streamed before it. The failures that end in a few seconds (a refusal, a render error, a
// fault found before or at the first core call) keep their code line first. 20 s is well under the plugin's own 80 s
// deadline and Argo CD's 90 s exec timeout, and far above a normal render; 64 KiB is far above a run's warnings and
// summary (a few hundred bytes), and bounds what a run keeps in memory for its stderr.
const (
	stderrHoldFor = 20 * time.Second
	stderrHoldMax = 64 << 10
)

// pluginStderr holds the plugin's stderr while the run is short. On success Flush writes it as it was; on a failure
// Fail writes the "clearance-cmp: <code>: <summary>" line first and the held lines (warnings, the summary) after it.
// Past its bounds (holdFor after it is made, or more than maxHeld bytes held) it writes what it held and streams: a
// failure's code line then follows the lines already written. The zero value (no out aside) holds without bound.
type pluginStderr struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	out       io.Writer
	maxHeld   int  // 0: no size bound
	streaming bool // the hold ended: writes go straight to out
	timer     *time.Timer
}

// newPluginStderr holds what is written to it for at most holdFor (0: no time bound) and maxHeld bytes (0: no size
// bound).
func newPluginStderr(out io.Writer, holdFor time.Duration, maxHeld int) *pluginStderr {
	p := &pluginStderr{out: out, maxHeld: maxHeld}
	if holdFor > 0 {
		p.timer = time.AfterFunc(holdFor, p.Release)
	}
	return p
}

func (p *pluginStderr) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.streaming {
		return p.out.Write(b)
	}
	n, err := p.buf.Write(b)
	if p.maxHeld > 0 && p.buf.Len() > p.maxHeld {
		p.releaseLocked()
	}
	return n, err
}

// Release ends the hold: what is held is written, and later writes go straight through.
func (p *pluginStderr) Release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseLocked()
}

func (p *pluginStderr) releaseLocked() {
	p.streaming = true
	p.out.Write(p.buf.Bytes())
	p.buf.Reset()
}

// Flush writes what is held and ends the hold; it is safe to call again.
func (p *pluginStderr) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timer != nil {
		p.timer.Stop()
	}
	p.releaseLocked()
}

// Fail writes the failure's code line, then what is held. Past the hold's bounds the lines already streamed come
// before the code line.
func (p *pluginStderr) Fail(ce error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.timer != nil {
		p.timer.Stop()
	}
	fmt.Fprintln(p.out, "clearance-cmp:", ce)
	p.releaseLocked()
}

// flushOnSignal makes a SIGTERM or SIGINT (Argo CD's exec timeout, a pod being stopped) write what ps holds, then a line
// naming the signal, before the process exits with 128 + the signal's number. A SIGKILL cannot be caught: the hold's
// bounds cover it. The returned func stops the handler.
func flushOnSignal(ps *pluginStderr, stderr io.Writer, start time.Time) (stop func()) {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-sigc:
			ps.Flush()
			fmt.Fprintf(stderr, "clearance-cmp: WARNING stopped by %v after %s: the run did not finish\n", sig,
				time.Since(start).Round(time.Millisecond))
			code := 1
			if s, ok := sig.(syscall.Signal); ok {
				code = 128 + int(s)
			}
			os.Exit(code)
		case <-done:
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(sigc)
			close(done)
		})
	}
}
