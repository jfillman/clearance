package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
// syncs (a tier-3 denial, a denied or expired change, an outage hold, a render that fails).
func Generate(ctx context.Context, d Deps, cfg Config, srcDir string, out io.Writer) (Outcome, error) {
	var r *Rendered
	var err error
	if cfg.Sources != "" {
		run := d.Run
		if run == nil {
			run = OSRun
		}
		r, err = RenderSources(ctx, run, cfg)
	} else {
		r, err = Render(ctx, d.Exec, cfg, srcDir)
	}
	if err != nil {
		return "", err
	}
	tree, err := Canonicalize(r.Manifests, cfg.Destination, cfg.ExtraCluster)
	if err != nil {
		return "", err
	}
	if r.Generic {
		tree.SetRelease(r.Release)
	} else {
		tree.SetRelease(releaseFromValues(cfg, srcDir))
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
		fmt.Fprintf(d.Stderr, ", chart %s@%s (%s)", cfg.ChartRepo, cfg.ChartRev, r.ChartMerge[:12])
	}
	fmt.Fprintln(d.Stderr)

	now := d.Now()
	if e, ok := d.Cache.Get(cfg.App, cfg.Env, cfg.Cluster, tree.Root, now); ok && now.Sub(e.CachedAt) < cfg.CacheTTL {
		return emit(tree, out, Cleared, e.ID, cfg)
	}
	req, err := registration(cfg, tree)
	if err != nil {
		return "", err
	}
	ch, err := d.Core.RegisterChange(ctx, req)
	if err != nil {
		if errors.Is(err, client.ErrCoreUnavailable) {
			// The outage policy (docs/gate.md, C-6): a tree already cleared whose tier lets through while the core is
			// down is served from what was remembered; anything else holds, because an unknown tier is never allowed.
			if e, ok := d.Cache.Get(cfg.App, cfg.Env, cfg.Cluster, tree.Root, now); ok && e.Outage == "allow-and-record" {
				fmt.Fprintf(d.Stderr, "clearance: the core is unreachable (%v); serving %s from the cache (tier %d, allow-and-record)\n", err, e.ID, e.Tier)
				return emit(tree, out, Cleared, e.ID, cfg)
			}
			return "", fmt.Errorf("clearance outage hold: the core is unreachable and tree %s has no cleared, allow-and-record entry: %w", tree.Root[:12], err)
		}
		return "", fmt.Errorf("clearance refused the change: %w", err)
	}
	switch ch.State {
	case "cleared":
		exp, _ := time.Parse(time.RFC3339Nano, ch.ExpiresAt)
		if exp.IsZero() {
			exp = now.Add(cfg.CacheTTL)
		}
		d.Cache.Put(cfg.App, cfg.Env, cfg.Cluster, CacheEntry{ID: ch.ID, Tier: ch.Tier, Outage: ch.Outage, Tree: tree.Root, CachedAt: now, ExpiresAt: exp})
		return emit(tree, out, Cleared, ch.ID, cfg)
	case "holding":
		d.Cache.Drop(cfg.App, cfg.Env, cfg.Cluster, tree.Root)
		return emit(tree, out, Held, ch.ID, cfg)
	default:
		d.Cache.Drop(cfg.App, cfg.Env, cfg.Cluster, tree.Root)
		why := ""
		if ch.DenyReason != nil {
			why = ": " + *ch.DenyReason
		}
		return "", fmt.Errorf("change %s is %s (tier %d)%s; nothing syncs", ch.ID, ch.State, ch.Tier, why)
	}
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
		Timeout: cfg.RegisterWait, Retries: 1, UserAgent: "clearance-argocd-cmp"})
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "parity" { // the parity suite (parity.go), not the plugin
		os.Exit(parityMain(os.Args[2:], os.Stdout, os.Stderr))
	}
	cfg, err := ParseConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "clearance-cmp:", err)
		os.Exit(2)
	}
	core, err := newCore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "clearance-cmp:", err)
		os.Exit(2)
	}
	d := Deps{Exec: OSExec, Run: OSRun, Core: core, Cache: Cache{Dir: cfg.CacheDir}, Now: time.Now, Stderr: os.Stderr}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second) // Argo CD kills a plugin at 90 s (ARGOCD_EXEC_TIMEOUT)
	defer cancel()
	if _, err := Generate(ctx, d, cfg, ".", os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "clearance-cmp:", err)
		os.Exit(1)
	}
}
