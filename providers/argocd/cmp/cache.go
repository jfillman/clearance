package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CacheEntry is what the plugin remembers of a cleared tree, so a render that did not change is not asked again.
type CacheEntry struct {
	ID        string    `json:"id"`
	Tier      int       `json:"tier"`
	Outage    string    `json:"outage"` // allow-and-record or hold: what to do with this tree while the core is unreachable
	Tree      string    `json:"tree"`
	CachedAt  time.Time `json:"cachedAt"`
	ExpiresAt time.Time `json:"expiresAt"` // the clearance's own expiry: never served after it
}

// Cache is a directory of entries, one file per (app, env, cluster, tree). Only a cleared change is cached.
type Cache struct{ Dir string }

// treeCacheMaxEntries bounds the cleared-tree entries (W-34 F7): every new tree a sidecar clears adds one small file
// (about 250 bytes), so without a bound a long-lived pod's cache directory grows with every commit it ever rendered.
// Past it the entry written longest ago goes first. Losing one costs at most a call to the core (within
// CLEARANCE_CMP_CACHE_TTL), or, while the core is unreachable, an outage hold for a tree last cleared thousands of trees ago.
const treeCacheMaxEntries = 4096

func (c Cache) path(app, env, cluster, tree string) string {
	sum := sha256.Sum256([]byte(app + "\x00" + env + "\x00" + cluster + "\x00" + tree))
	return filepath.Join(c.Dir, hex.EncodeToString(sum[:])+".json")
}

// Get returns the entry, if there is one that is still within its clearance.
func (c Cache) Get(app, env, cluster, tree string, now time.Time) (CacheEntry, bool) {
	b, err := os.ReadFile(c.path(app, env, cluster, tree))
	if err != nil {
		return CacheEntry{}, false
	}
	var e CacheEntry
	if json.Unmarshal(b, &e) != nil || e.ID == "" || e.Tree != tree || !now.Before(e.ExpiresAt) {
		return CacheEntry{}, false
	}
	return e, true
}

// Put writes the entry atomically; a failure only costs a later call to the core, so it is not an error.
func (c Cache) Put(app, env, cluster string, e CacheEntry) {
	if c.Dir == "" {
		return
	}
	if os.MkdirAll(c.Dir, 0o700) != nil {
		return
	}
	b, _ := json.Marshal(e)
	tmp, err := os.CreateTemp(c.Dir, ".entry-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), c.path(app, env, cluster, e.Tree)) != nil {
		os.Remove(tmp.Name())
		return
	}
	c.pruneTrees(treeCacheMaxEntries)
}

// pruneTrees keeps the newest maxEntries tree entries and clears temporary files an interrupted Put left (older than an
// hour: a Put in flight is never older than the plugin's own deadline). Only the tree entries (64 hex characters and
// .json) and Put's own temporary files are looked at; the other caches' directories under Dir are not touched.
func (c Cache) pruneTrees(maxEntries int) {
	ents, err := os.ReadDir(c.Dir)
	if err != nil {
		return
	}
	type f struct {
		name string
		mod  time.Time
	}
	var files []f
	for _, e := range ents {
		name := e.Name()
		isEntry := len(name) == 64+len(".json") && strings.HasSuffix(name, ".json") && isHex(name[:64])
		if e.IsDir() || !(isEntry || strings.HasPrefix(name, ".entry-")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if !isEntry {
			if time.Since(info.ModTime()) > time.Hour {
				os.Remove(filepath.Join(c.Dir, name))
			}
			continue
		}
		files = append(files, f{name, info.ModTime()})
	}
	if len(files) <= maxEntries {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) }) // newest first
	for _, x := range files[maxEntries:] {
		os.Remove(filepath.Join(c.Dir, x.name))
	}
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// Drop forgets a tree (the core said it is no longer cleared).
func (c Cache) Drop(app, env, cluster, tree string) { os.Remove(c.path(app, env, cluster, tree)) }
