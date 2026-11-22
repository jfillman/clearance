package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
)

// The pre-render cache (hardening S2): an unchanged Application skips the render and the core call.
//
// The key is a hash of everything that determines the output: the Application (name, destination, project, app, env,
// cluster), the gitops revision Argo CD checked out (ARGOCD_APP_REVISION, a full commit: it fixes every value file and
// the kustomize directory), the commit the chart's tag resolves to now (a lookup on the remote, never the tag), every
// plugin parameter, the destination's Kubernetes and API versions, the core's URL and the plugin's version (the
// image, and with it Helm's and kustomize's). The value is the stream the plugin emitted, already stamped, and the
// cleared change's id.
//
// Only a cleared outcome is stored, with the registration request the render sent. The cache skips the clone, Helm and
// kustomize, never the decision: serveRender asks the core as often as without the cache (not at all inside the tree
// cache's CLEARANCE_CMP_CACHE_TTL, otherwise with the stored request) and serves the stored stream only for the same
// cleared change. A hold, a denial or another change drops the entry and renders in full. CLEARANCE_CMP_RENDER_CACHE_TTL
// bounds how long rendered bytes are reused, never past the clearance's ExpiresAt.
//
// Generic mode (PARAM_SOURCES) is not cached here: its sources have no commit to key on without fetching them.

// pluginVersion is the image's version, set at build (-ldflags -X main.pluginVersion=...).
var pluginVersion = "dev"

const (
	renderCacheMaxEntries = 256
	renderCacheMaxStream  = 8 << 20
	renderKeyVersion      = 1
)

// renderEntry is one cached render.
type renderEntry struct {
	Key     string `json:"key"`
	App     string `json:"app"`
	Env     string `json:"env"`
	Cluster string `json:"cluster"`
	ID      string `json:"id"`
	// Request is the registration a fresh render of these inputs sends (registration(cfg, tree)): a hit past the tree
	// cache's lifetime asks the core with it instead of rendering, and serves the stream only for the same change.
	Request   *client.ChangeRequest `json:"request"`
	Tier      int                   `json:"tier"`
	Outage    string                `json:"outage"`
	Tree      string                `json:"tree"`
	CachedAt  time.Time             `json:"cachedAt"`  // when the core last said cleared
	ExpiresAt time.Time             `json:"expiresAt"` // the clearance's own expiry
	StreamSum string                `json:"streamSha256"`
	Stream    []byte                `json:"stream"`
}

// renderKey is the key of a run, or "" when the run may not use the cache: generic mode, a revision that is not a
// full commit (a branch name says nothing of the files), or a chart repository whose tag did not resolve.
func renderKey(cfg Config) string {
	if cfg.RenderCacheTTL <= 0 || cfg.Sources != "" || !sha40.MatchString(cfg.Revision) || (cfg.ChartRepo != "" && cfg.chartCommit == "") {
		return ""
	}
	build := pluginVersion
	if bi, ok := debug.ReadBuildInfo(); ok {
		build += "|" + bi.GoVersion + "|" + bi.Main.Version
	}
	api := append([]string{}, cfg.APIVersions...)
	sort.Strings(api)
	b, _ := json.Marshal(struct {
		V                                           int
		Plugin                                      string
		AppName, Destination, Revision, SourceRepo  string
		SourcePath, Project, App, Env, Cluster      string
		ChartRepo, ChartRev, ChartPath, ChartCommit string
		ValueFiles                                  []string
		ValuesJSON, KustomizeDir                    string
		ExtraCluster                                []string
		KubeVersion                                 string
		APIVersions                                 []string
		CoreURL, Netns                              string
	}{renderKeyVersion, build, cfg.AppName, cfg.Destination, cfg.Revision, cfg.SourceRepo,
		cfg.SourcePath, cfg.Project, cfg.App, cfg.Env, cfg.Cluster,
		cfg.ChartRepo, cfg.ChartRev, cfg.ChartPath, cfg.chartCommit,
		cfg.ValueFiles, cfg.ValuesJSON, cfg.KustomizeDir, cfg.ExtraCluster, cfg.KubeVersion, api, cfg.CoreURL, cfg.Netns})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (c Cache) renderPath(key string) string { return c.entryPath(rendersDir, key) }

// The two stores of renderEntry files under the cache directory: the pre-render cache and the last-known-good store
// (lkg.go). Same format, different keys and lifetimes.
const (
	rendersDir = "renders"
	lkgDir     = "lkg"
)

func (c Cache) entryPath(sub, key string) string { return filepath.Join(c.Dir, sub, key+".json") }

// GetRender is the cached render for key, if it is still within its clearance and lifetime and is whole.
func (c Cache) GetRender(key string, now time.Time, ttl time.Duration) (renderEntry, bool) {
	e, ok := c.getEntry(rendersDir, key, now)
	if !ok || !now.Before(e.ExpiresAt) || now.Sub(e.CachedAt) >= ttl {
		return renderEntry{}, false
	}
	return e, true
}

// getEntry reads the entry for key in sub if it is whole (it names its key, has a change and a stream whose SHA-256 is
// the recorded one), and marks it used. Lifetimes are the caller's.
func (c Cache) getEntry(sub, key string, now time.Time) (renderEntry, bool) {
	if key == "" || c.Dir == "" {
		return renderEntry{}, false
	}
	p := c.entryPath(sub, key)
	b, err := os.ReadFile(p)
	if err != nil {
		return renderEntry{}, false
	}
	var e renderEntry
	// A miss never removes the file: another render may have replaced it since it was read. A bad or expired entry is
	// overwritten by the next full render of the key, or pruned.
	if json.Unmarshal(b, &e) != nil || e.Key != key || e.ID == "" || len(e.Stream) == 0 || e.StreamSum != sumHex(e.Stream) {
		return renderEntry{}, false
	}
	os.Chtimes(p, now, now) // last used
	return e, true
}

// PutRender stores a cleared render atomically. started is when this run began asking the core: if a hold or a
// denial for the same tree was recorded since (DropRenders), the cleared answer is older than that decision and is
// not stored. A failure only costs the next render its work.
func (c Cache) PutRender(e renderEntry, started time.Time) { c.putEntry(rendersDir, e, started) }

func (c Cache) putEntry(sub string, e renderEntry, started time.Time) {
	if c.Dir == "" || e.Key == "" || e.ID == "" || len(e.Stream) == 0 || len(e.Stream) > renderCacheMaxStream {
		return
	}
	dir := filepath.Join(c.Dir, sub)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	if c.decidedSince(e.App, e.Env, e.Cluster, e.Tree, started) {
		return
	}
	e.StreamSum = sumHex(e.Stream)
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".entry-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), c.entryPath(sub, e.Key)) != nil {
		os.Remove(tmp.Name())
		return
	}
	if c.decidedSince(e.App, e.Env, e.Cluster, e.Tree, started) { // a decision landed while this was written
		os.Remove(c.entryPath(sub, e.Key))
		return
	}
	if sub == lkgDir {
		c.pruneRenders(dir, lkgMaxEntries, lkgMaxBytes)
	} else {
		c.pruneRenders(dir, renderCacheMaxEntries, 0)
	}
}

// decidedSince is whether a hold or denial of the tree was recorded (DropRenders) at or after t.
func (c Cache) decidedSince(app, env, cluster, tree string, t time.Time) bool {
	st, err := os.Stat(c.tombstone(app, env, cluster, tree))
	return err == nil && !st.ModTime().Before(t)
}

// PutUndecided is Put for a tree cache entry, refused (and undone) if a hold or denial of the tree was recorded since
// started, when this run began asking the core: the cleared answer is older than that decision.
func (c Cache) PutUndecided(app, env, cluster string, e CacheEntry, started time.Time) {
	if c.decidedSince(app, env, cluster, e.Tree, started) {
		return
	}
	c.Put(app, env, cluster, e)
	if c.decidedSince(app, env, cluster, e.Tree, started) {
		c.Drop(app, env, cluster, e.Tree)
	}
}

// tombstone is the file whose time says when a hold or denial of the tree was last recorded.
func (c Cache) tombstone(app, env, cluster, tree string) string {
	return filepath.Join(c.Dir, rendersDir, ".dropped-"+sumHex([]byte(app+"\x00"+env+"\x00"+cluster+"\x00"+tree)))
}

// DropRenders forgets every render of this app, environment, cluster and tree, whatever its key (the key also has
// parameters that do not change the tree, and the core's answer is about the tree), in the pre-render cache and the
// last-known-good store, and records the decision so a cleared answer that was already in flight is not stored after
// it. Called when the core says hold or denied.
func (c Cache) DropRenders(app, env, cluster, tree string) {
	if c.Dir == "" || tree == "" {
		return
	}
	dir := filepath.Join(c.Dir, rendersDir)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	ts := c.tombstone(app, env, cluster, tree)
	os.WriteFile(ts, nil, 0o600)
	now := time.Now()
	os.Chtimes(ts, now, now)
	for _, sub := range []string{rendersDir, lkgDir} {
		c.dropTree(filepath.Join(c.Dir, sub), app, env, cluster, tree)
	}
}

func (c Cache) dropTree(dir, app, env, cluster, tree string) {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		var x renderEntry
		if err == nil && json.Unmarshal(b, &x) == nil && x.Tree != tree {
			continue // not this tree; a file that does not parse is removed below
		}
		if err == nil && (x.App != app || x.Env != env || x.Cluster != cluster) {
			continue
		}
		os.Remove(filepath.Join(dir, e.Name()))
	}
}

// pruneRenders keeps the newest-used maxEntries entries (and, when maxBytes > 0, at most maxBytes of them) and clears
// temporary files an interrupted write left. Each store has its own bounds: the last-known-good store is not evicted
// by the pre-render cache's traffic.
func (c Cache) pruneRenders(dir string, maxEntries int, maxBytes int64) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type f struct {
		name string
		mod  time.Time
		size int64
	}
	var files, tags []f
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(e.Name(), ".entry-"), strings.HasPrefix(e.Name(), ".dropped-"):
			if time.Since(info.ModTime()) > time.Hour {
				os.Remove(filepath.Join(dir, e.Name()))
			}
		case strings.HasSuffix(e.Name(), ".json"):
			files = append(files, f{e.Name(), info.ModTime(), info.Size()})
		case strings.HasSuffix(e.Name(), ".tag"): // last-known-good tag pointers (lkg.go), a few bytes each
			tags = append(tags, f{e.Name(), info.ModTime(), info.Size()})
		}
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].mod.After(tags[j].mod) })
	for i, x := range tags {
		if i >= maxEntries {
			os.Remove(filepath.Join(dir, x.name))
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) }) // newest first
	var total int64
	for i, x := range files {
		total += x.size
		if i >= maxEntries || (maxBytes > 0 && total > maxBytes && i > 0) {
			os.Remove(filepath.Join(dir, x.name))
		}
	}
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// DropRender forgets one render by key (its stamp no longer matches the tree cache's change).
func (c Cache) DropRender(key string) {
	if key != "" && c.Dir != "" {
		os.Remove(c.renderPath(key))
	}
}

// serveRender answers a pre-render hit, or a last-known-good lookup (fault non-nil: the plugin's fault this run, lkg.go).
// The cache skips the clone, Helm and kustomize; it never decides. The core is asked exactly as often as without the
// cache:
//
//	the tree cache says cleared within CLEARANCE_CMP_CACHE_TTL, same change  -> serve, no core call (as before)
//	otherwise                                                                -> RegisterChange(stored request)
//	  cleared, the change the stream is stamped with                         -> refresh the tree cache, serve
//	  cleared as another change, holding, denied, anything else              -> drop the entries, render in full
//	  the core is unreachable                                                -> the outage policy, allow-and-record only
//
// handled is false when the caller must render in full (for a last-known-good lookup: fail with the fault).
func serveRender(ctx context.Context, d Deps, cfg Config, e renderEntry, out io.Writer, fault *CmpError) (o Outcome, handled bool, err error) {
	now := d.Now()
	sub := rendersDir
	if fault != nil {
		sub = lkgDir
	}
	serve := func(how string) (Outcome, bool, error) {
		if fault != nil {
			n := d.Cache.countLKGServe()
			fmt.Fprintf(d.Stderr, "clearance: LAST-KNOWN-GOOD served: %s/%s hit %s (%s); %s; serving the render last cleared for this exact gitops revision %s, chart %s@%s and parameters, change %s, tree %s; lkg-serves=%d\n",
				cfg.App, cfg.Env, fault.Code, fault.Summary, how, shortRes(cfg.Revision), cfg.ChartRev, shortRes(cfg.chartCommit), e.ID, shortRes(e.Tree), n)
		} else {
			fmt.Fprintf(d.Stderr, "clearance: %s/%s is unchanged (chart %s@%s, gitops %s): %s; serving the cleared render %s from the cache without a clone, helm or kustomize, tree %s\n",
				cfg.App, cfg.Env, cfg.ChartRev, shortRes(cfg.chartCommit), shortRes(cfg.Revision), how, e.ID, shortRes(e.Tree))
		}
		if _, werr := out.Write(e.Stream); werr != nil {
			return "", true, newErr(CodeFaultInternal, "the manifests could not be written to Argo CD", werr)
		}
		return Cleared, true, nil
	}
	te, tok := d.Cache.Get(cfg.App, cfg.Env, cfg.Cluster, e.Tree, now)
	if tok && te.ID != e.ID || e.Request == nil {
		os.Remove(d.Cache.entryPath(sub, e.Key)) // stamped with a change the tree cache no longer names: render and ask
		return "", false, nil
	}
	if tok && now.Sub(te.CachedAt) < cfg.CacheTTL {
		return serve("the tree cache confirmed it within " + cfg.CacheTTL.String())
	}
	started := time.Now()
	ch, err := registerInTime(ctx, d.Core, e.Request)
	d.Stats.coreCall(err)
	if err != nil {
		if errors.Is(err, client.ErrCoreUnavailable) {
			// Read the tree cache again, as the uncached path does after the failure: a hold another render met while
			// this call was pending has removed the clearance.
			te, tok = d.Cache.Get(cfg.App, cfg.Env, cfg.Cluster, e.Tree, d.Now())
			if tok && te.ID == e.ID && te.Outage == "allow-and-record" {
				fmt.Fprintf(d.Stderr, "clearance: the core is unreachable (%v); serving %s from the cache (tier %d, allow-and-record)\n", err, te.ID, te.Tier)
				return serve("outage policy")
			}
			return "", true, outageHold(e.Tree, err)
		}
		return "", true, classifyCore(err)
	}
	if ch.State == "cleared" && ch.ID == e.ID {
		exp, _ := time.Parse(time.RFC3339Nano, ch.ExpiresAt)
		if exp.IsZero() {
			exp = now.Add(cfg.CacheTTL)
		}
		d.Cache.PutUndecided(cfg.App, cfg.Env, cfg.Cluster, CacheEntry{ID: ch.ID, Tier: ch.Tier, Outage: ch.Outage, Tree: e.Tree, CachedAt: now, ExpiresAt: exp}, started)
		if d.Cache.decidedSince(cfg.App, cfg.Env, cfg.Cluster, e.Tree, started) {
			// A hold or denial of this tree was recorded while the call was pending: the answer is older than it.
			os.Remove(d.Cache.entryPath(sub, e.Key))
			return "", false, nil
		}
		return serve("the core confirmed the same change")
	}
	// Another change, a hold, a denial: nothing of this entry is served. The full render decides and emits (a hold
	// gets its wait Job exactly as without the cache).
	d.Cache.DropRenders(cfg.App, cfg.Env, cfg.Cluster, e.Tree)
	d.Cache.Drop(cfg.App, cfg.Env, cfg.Cluster, e.Tree)
	return "", false, nil
}

// outageHold is the refusal while the core cannot be reached and nothing cleared is remembered for the tree.
func outageHold(tree string, err error) *CmpError {
	return newErr(CodeRefusedOutageHold, "the core is unreachable and this tree has no cleared, allow-and-record entry",
		fmt.Errorf("clearance outage hold: the core is unreachable and tree %s has no cleared, allow-and-record entry: %w", shortRes(tree), err))
}
