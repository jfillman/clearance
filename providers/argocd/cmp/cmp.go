package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
		if strings.HasPrefix(err.Error(), "refused:") {
			return "", classifyRender(ctx, err, lookupNotAsked, cfg.Sources != "")
		}
		return "", classifyConfig(err) // the sources parameter, or a list entry (a sidecar setting)
	}
	// The pre-render cache (rendercache.go) and the last-known-good store (lkg.go) need the commit the chart's tag
	// resolves to now, one lookup on the remote: an unchanged Application is answered before anything is rendered.
	if (cfg.RenderCacheTTL > 0 || cfg.LKG) && cfg.Sources == "" && cfg.ChartRepo != "" {
		lctx, cancel := ctx, context.CancelFunc(func() {})
		if cfg.LKG {
			lctx, cancel = context.WithTimeout(ctx, lookupTimeout) // an unreachable host must leave time to confirm
		}
		cfg.chartCommit, cfg.chartLookupErr = lookupChart(lctx, d.Exec, cfg.ChartRepo, cfg.ChartRev)
		cfg.chartLooked = true
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
	}
	if r.ChartMerge != "" {
		fmt.Fprintf(d.Stderr, ", chart %s@%s (%s), chart-cache=%s", cfg.ChartRepo, cfg.ChartRev, r.ChartMerge[:12], r.ChartFetch)
	}
	fmt.Fprintf(d.Stderr, ", netns=%s\n", NetnsState())

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
	ch, err := d.Core.RegisterChange(ctx, req)
	if err != nil {
		if errors.Is(err, client.ErrCoreUnavailable) {
			// The outage policy (docs/gate.md, C-6): a tree already cleared whose tier lets through while the core is
			// down is served from what was remembered; anything else holds, because an unknown tier is never allowed.
			if e, ok := d.Cache.Get(cfg.App, cfg.Env, cfg.Cluster, tree.Root, now); ok && e.Outage == "allow-and-record" {
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
	if dl, ok := ctx.Deadline(); ok && cfg.LKG && cfg.RegisterWait > 0 && time.Until(dl) > cfg.RegisterWait {
		var cancel context.CancelFunc
		rctx, cancel = context.WithDeadline(ctx, dl.Add(-cfg.RegisterWait))
		defer cancel()
	}
	defer func() {
		if p := recover(); p != nil {
			tree, r = nil, nil
			cerr = newErr(CodeFaultPanic, "the plugin panicked while rendering", fmt.Errorf("panic: %v", p))
		}
	}()
	var err error
	if cfg.Sources != "" {
		run := d.Run
		if run == nil {
			run = OSRun
		}
		r, err = RenderSources(rctx, run, cfg)
	} else {
		r, err = Render(rctx, d.Exec, cfg, srcDir)
	}
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
		Timeout: cfg.RegisterWait, Retries: 1, UserAgent: "clearance-argocd-cmp", CAFile: cfg.CAFile})
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "parity" { // the parity suite (parity.go), not the plugin
		os.Exit(parityMain(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "doctor" { // the install preflight (doctor.go), not the plugin
		os.Exit(doctorMain(os.Args[2:], os.Stdout, os.Stderr))
	}
	cfg, err := ParseConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "clearance-cmp:", classifyConfig(err))
		os.Exit(2)
	}
	SetNetns(cfg.Netns)
	core, err := newCore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "clearance-cmp:", newErr(CodeFaultConfig, "the core client cannot be set up from the sidecar's settings", err))
		os.Exit(2)
	}
	d := Deps{Exec: OSExec, Run: OSRun, Core: core, Cache: Cache{Dir: cfg.CacheDir}, Now: time.Now, Stderr: os.Stderr}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second) // Argo CD kills a plugin at 90 s (ARGOCD_EXEC_TIMEOUT)
	defer cancel()
	if _, err := Generate(ctx, d, cfg, ".", os.Stdout); err != nil { // a *CmpError: its code and short line come first
		fmt.Fprintln(os.Stderr, "clearance-cmp:", err)
		os.Exit(1)
	}
}
