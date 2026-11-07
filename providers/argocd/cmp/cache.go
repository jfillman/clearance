package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
	}
}

// Drop forgets a tree (the core said it is no longer cleared).
func (c Cache) Drop(app, env, cluster, tree string) { os.Remove(c.path(app, env, cluster, tree)) }
