package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Last-known-good (hardening F5). When the plugin itself faults before the decision (a panic, a tool that cannot start
// or is killed, its own I/O, a timeout: ClassFault in errors.go), or a dependency is unavailable (git or the chart's
// host cannot be reached: ClassDep), an Application whose inputs did not change since a
// render was cleared is served that render instead of turning Unknown. Never for anything else:
//
//   - only a fault: a render error (the inputs do not render) or a refusal (Clearance said no) never falls back;
//   - only the exact inputs: the key is every input of the output, as the pre-render cache's (the gitops revision, a
//     full commit; the commit the chart's tag resolves to now, looked up this run; every parameter; the Application;
//     the cluster's versions; the core), less the plugin's own version and sandbox mode, which do not change what was
//     cleared. A new revision, a moved tag, a changed parameter, a tag the remote says it does not have, generic mode:
//     no key, fail closed. When the remote cannot be reached at all, the commit is the one this tag last resolved to
//     when these inputs were cleared (lkgByTag): the render that is running now, so a tag moved during the outage is
//     seen when the host is back, not before;
//   - only what was cleared: only a cleared outcome is stored, a hold or denial of the tree drops it (DropRenders);
//   - never without a decision: the core confirms the same change exactly as for a pre-render hit (serveRender): the
//     tree cache within CLEARANCE_CMP_CACHE_TTL, else one call with the stored request; an unreachable core follows the
//     outage policy (allow-and-record only). Anything else fails with the fault.
//
// Every serve is logged on stderr ("LAST-KNOWN-GOOD served", with the fault's code) and counted in lkg/served under the
// cache directory (doctor reports the count). Off by default: CLEARANCE_CMP_LAST_KNOWN_GOOD=on turns it on.

// LKGEnv is the setting.
const LKGEnv = "CLEARANCE_CMP_LAST_KNOWN_GOOD"

// lkgKeyVersion changes when the key's inputs do. The store has its own bounds, separate from the pre-render cache's
// (256 entries, 15 minutes): lkgMaxEntries entries and lkgMaxBytes in all, the entry used longest ago going first, and
// no lifetime of its own (the core's confirmation is the lifetime). Every cleared full render rewrites its entry, and
// a pre-render hit marks it used, so an app served from the pre-render cache keeps its last-known-good.
const (
	lkgKeyVersion = 1
	lkgMaxEntries = 1024
	lkgMaxBytes   = 256 << 20
	// lookupTimeout bounds the tag lookup (with or without last-known-good): an unreachable chart host must leave the
	// run time to render and to confirm with the core. It is ChartLookupTimeout, which the startup check reserves.
	lookupTimeout = ChartLookupTimeout
)

// ParseLKG reads CLEARANCE_CMP_LAST_KNOWN_GOOD: "off" (the default, also unset) or "on"; anything else stops the plugin.
func ParseLKG(v string) (bool, error) {
	switch strings.TrimSpace(v) {
	case "", "off":
		return false, nil
	case "on":
		return true, nil
	}
	return false, fmt.Errorf("%s is %q or %q, got %q", LKGEnv, "off", "on", v)
}

// lkgKey is the last-known-good key of a run, or "" when the run has none (see above).
func lkgKey(cfg Config) string {
	if !cfg.LKG || cfg.Sources != "" || !sha40.MatchString(cfg.Revision) || (cfg.ChartRepo != "" && cfg.chartCommit == "") {
		return ""
	}
	return lkgHash(cfg, cfg.chartCommit)
}

// lkgTagKey names the pointer to the last-known-good of these inputs at whatever commit the chart's tag last
// resolved to when it was cleared: everything of lkgKey but the commit.
func lkgTagKey(cfg Config) string {
	if !cfg.LKG || cfg.Sources != "" || cfg.ChartRepo == "" || !sha40.MatchString(cfg.Revision) {
		return ""
	}
	return lkgHash(cfg, "tag-pointer")
}

func lkgHash(cfg Config, commit string) string {
	api := append([]string{}, cfg.APIVersions...)
	sort.Strings(api)
	b, _ := json.Marshal(struct {
		V                                           int
		AppName, Destination, Revision, SourceRepo  string
		SourcePath, Project, App, Env, Cluster      string
		ChartRepo, ChartRev, ChartPath, ChartCommit string
		ValueFiles                                  []string
		ValuesJSON, KustomizeDir                    string
		ExtraCluster                                []string
		KubeVersion                                 string
		APIVersions                                 []string
		CoreURL                                     string
	}{lkgKeyVersion, cfg.AppName, cfg.Destination, cfg.Revision, cfg.SourceRepo,
		cfg.SourcePath, cfg.Project, cfg.App, cfg.Env, cfg.Cluster,
		cfg.ChartRepo, cfg.ChartRev, cfg.ChartPath, commit,
		cfg.ValueFiles, cfg.ValuesJSON, cfg.KustomizeDir, cfg.ExtraCluster, cfg.KubeVersion, api, cfg.CoreURL})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// PutLKG stores a cleared render as the last-known-good of its key (the rules of PutRender: atomic, refused after a
// decision on the tree, bounded to renderCacheMaxEntries by last use).
func (c Cache) PutLKG(e renderEntry, started time.Time) { c.putEntry(lkgDir, e, started) }

// putLKGTag records that key is the last-known-good of cfg's inputs at the chart commit cfg resolved, for a run that
// cannot resolve the tag (lkgByTag). Written atomically; a failure only loses that fallback.
func (c Cache) putLKGTag(cfg Config, key string) {
	tk := lkgTagKey(cfg)
	if tk == "" || key == "" || !sha40.MatchString(cfg.chartCommit) || c.Dir == "" {
		return
	}
	dir := filepath.Join(c.Dir, lkgDir)
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".entry-*")
	if err != nil {
		return
	}
	_, werr := tmp.WriteString(key + " " + cfg.chartCommit + "\n")
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), filepath.Join(dir, tk+".tag")) != nil {
		os.Remove(tmp.Name())
	}
}

// lkgByTag is the last-known-good key, and the chart commit it was cleared at, of cfg's inputs when the chart's tag
// could not be resolved this run (git or the chart host unreachable). The entry it names is still checked whole and
// confirmed by the core like any other; "" when there is none.
func (c Cache) lkgByTag(cfg Config) (key, commit string) {
	tk := lkgTagKey(cfg)
	if tk == "" || c.Dir == "" {
		return "", ""
	}
	b, err := os.ReadFile(filepath.Join(c.Dir, lkgDir, tk+".tag"))
	if err != nil {
		return "", ""
	}
	f := strings.Fields(string(b))
	if len(f) != 2 || len(f[0]) != 64 || !sha40.MatchString(f[1]) {
		return "", ""
	}
	// The pointer is only a hint: the key must be what these inputs hash to at that commit.
	if lkgHash(cfg, f[1]) != f[0] {
		return "", ""
	}
	return f[0], f[1]
}

// touchLKG marks the last-known-good of key used (a pre-render hit served these inputs without a full render).
func (c Cache) touchLKG(key string, now time.Time) {
	if key != "" && c.Dir != "" {
		os.Chtimes(c.entryPath(lkgDir, key), now, now)
	}
}

// serveLKG answers a fault with the last-known-good render, or says why not. handled is false when nothing was served
// and the caller fails with the fault.
func serveLKG(ctx context.Context, d Deps, cfg Config, key string, fault *CmpError, out io.Writer) (Outcome, bool, error) {
	miss := func(why string) (Outcome, bool, error) {
		fmt.Fprintf(d.Stderr, "clearance: last-known-good not served for %s/%s after %s: %s; failing closed\n", cfg.App, cfg.Env, fault.Code, why)
		return "", false, nil
	}
	if !fault.FallsBack() {
		return miss("only a plugin fault or an unavailable dependency falls back") // never reached: Generate asks only for those
	}
	if key == "" {
		return miss("no key: generic mode, a revision that is not a commit, a chart tag the remote does not have, or no commit ever cleared for this tag")
	}
	e, ok := d.Cache.getEntry(lkgDir, key, d.Now())
	if !ok {
		return miss("nothing was cleared for this exact gitops revision, chart commit and parameters")
	}
	o, handled, err := serveRender(ctx, d, cfg, e, out, fault)
	if !handled {
		return miss("the core did not confirm the remembered change")
	}
	if err != nil {
		// The confirmation itself was refused (an outage hold, the core refusing the request): that is the answer, and
		// the fault stays in the detail.
		if ce, ok := asCmp(err); ok {
			ce.Err = fmt.Errorf("%w (last-known-good was tried after %s: %s)", ce.Err, fault.Code, fault.Summary)
		}
		return "", true, err
	}
	return o, true, nil
}

// lkgCountPath is the file holding the number of last-known-good serves.
func (c Cache) lkgCountPath() string { return filepath.Join(c.Dir, lkgDir, "served") }

// countLKGServe adds one to the serve count and returns it (0 when it cannot be kept: the serve is still logged).
func (c Cache) countLKGServe() int64 {
	if c.Dir == "" || os.MkdirAll(filepath.Join(c.Dir, lkgDir), 0o700) != nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	unlock, err := lockFile(ctx, filepath.Join(c.Dir, lkgDir, "served.lock"))
	if err != nil {
		return 0
	}
	defer unlock()
	n := c.LKGServes() + 1
	tmp, err := os.CreateTemp(filepath.Join(c.Dir, lkgDir), ".entry-*")
	if err != nil {
		return 0
	}
	_, werr := tmp.WriteString(strconv.FormatInt(n, 10) + "\n")
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), c.lkgCountPath()) != nil {
		os.Remove(tmp.Name())
		return 0
	}
	return n
}

// LKGServes is how many last-known-good renders this cache directory has served.
func (c Cache) LKGServes() int64 {
	b, err := os.ReadFile(c.lkgCountPath())
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}
