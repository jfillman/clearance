package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"
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
// Only a cleared outcome is stored. A hold or a denial is never served from here: it goes to the core every time,
// and one that comes back drops the entry. An entry is served while the clearance is (its ExpiresAt) and for at most
// the cache's own lifetime (CLEARANCE_CMP_RENDER_CACHE_TTL), which bounds how long a clearance withdrawn since stays
// served by the plugin (admission and the grant feed decide at the cluster either way). The outage policy is not
// involved: a served entry asks nothing of the core, and a render that has to ask and finds the core unreachable
// goes through Generate's outage path unchanged.
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
	Key       string    `json:"key"`
	App       string    `json:"app"`
	Env       string    `json:"env"`
	Cluster   string    `json:"cluster"`
	ID        string    `json:"id"`
	Tier      int       `json:"tier"`
	Outage    string    `json:"outage"`
	Tree      string    `json:"tree"`
	CachedAt  time.Time `json:"cachedAt"`  // when the core last said cleared
	ExpiresAt time.Time `json:"expiresAt"` // the clearance's own expiry
	StreamSum string    `json:"streamSha256"`
	Stream    []byte    `json:"stream"`
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
		CoreURL                                     string
	}{renderKeyVersion, build, cfg.AppName, cfg.Destination, cfg.Revision, cfg.SourceRepo,
		cfg.SourcePath, cfg.Project, cfg.App, cfg.Env, cfg.Cluster,
		cfg.ChartRepo, cfg.ChartRev, cfg.ChartPath, cfg.chartCommit,
		cfg.ValueFiles, cfg.ValuesJSON, cfg.KustomizeDir, cfg.ExtraCluster, cfg.KubeVersion, api, cfg.CoreURL})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (c Cache) renderPath(key string) string { return filepath.Join(c.Dir, "renders", key+".json") }

// GetRender is the cached render for key, if it is still within its clearance and lifetime and is whole. An entry
// that is not (a file that does not parse, a stream that does not match its sum, a key that is not its own) is removed.
func (c Cache) GetRender(key string, now time.Time, ttl time.Duration) (renderEntry, bool) {
	if key == "" || c.Dir == "" {
		return renderEntry{}, false
	}
	p := c.renderPath(key)
	b, err := os.ReadFile(p)
	if err != nil {
		return renderEntry{}, false
	}
	var e renderEntry
	if json.Unmarshal(b, &e) != nil || e.Key != key || e.ID == "" || len(e.Stream) == 0 || e.StreamSum != sumHex(e.Stream) {
		os.Remove(p)
		return renderEntry{}, false
	}
	if !now.Before(e.ExpiresAt) || now.Sub(e.CachedAt) >= ttl {
		os.Remove(p)
		return renderEntry{}, false
	}
	os.Chtimes(p, now, now) // last used
	return e, true
}

// PutRender stores a cleared render atomically. started is when this run began asking the core: if a hold or a
// denial for the same tree was recorded since (DropRenders), the cleared answer is older than that decision and is
// not stored. A failure only costs the next render its work.
func (c Cache) PutRender(e renderEntry, started time.Time) {
	if c.Dir == "" || e.Key == "" || e.ID == "" || len(e.Stream) == 0 || len(e.Stream) > renderCacheMaxStream {
		return
	}
	dir := filepath.Join(c.Dir, "renders")
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	if st, err := os.Stat(c.tombstone(e.App, e.Env, e.Cluster, e.Tree)); err == nil && !st.ModTime().Before(started) {
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
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), c.renderPath(e.Key)) != nil {
		os.Remove(tmp.Name())
		return
	}
	c.pruneRenders(dir)
}

// tombstone is the file whose time says when a hold or denial of the tree was last recorded.
func (c Cache) tombstone(app, env, cluster, tree string) string {
	return filepath.Join(c.Dir, "renders", ".dropped-"+sumHex([]byte(app+"\x00"+env+"\x00"+cluster+"\x00"+tree)))
}

// DropRenders forgets every render of this app, environment, cluster and tree, whatever its key (the key also has
// parameters that do not change the tree, and the core's answer is about the tree), and records the decision so a
// cleared answer that was already in flight is not stored after it. Called when the core says hold or denied.
func (c Cache) DropRenders(app, env, cluster, tree string) {
	if c.Dir == "" || tree == "" {
		return
	}
	dir := filepath.Join(c.Dir, "renders")
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	ts := c.tombstone(app, env, cluster, tree)
	os.WriteFile(ts, nil, 0o600)
	now := time.Now()
	os.Chtimes(ts, now, now)
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

// pruneRenders keeps the newest-used renderCacheMaxEntries entries and clears temporary files an interrupted write left.
func (c Cache) pruneRenders(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type f struct {
		name string
		mod  time.Time
	}
	var files []f
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
			files = append(files, f{e.Name(), info.ModTime()})
		}
	}
	if len(files) <= renderCacheMaxEntries {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	for _, x := range files[:len(files)-renderCacheMaxEntries] {
		os.Remove(filepath.Join(dir, x.name))
	}
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
