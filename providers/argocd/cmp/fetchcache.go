package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// The chart fetch cache (hardening S1). A render used to `git clone` the chart on every call: about nine tenths of
// its time. The cache keeps the checked-out tree of a chart repository by what it resolved to, so a render fetches
// nothing when it has seen that commit.
//
//   - Key: the platform's spelling of the repository (Canonical) and the RESOLVED commit, never the tag. Each render
//     asks the remote what the tag points at (`git ls-remote`, one round trip), so a tag that moved misses.
//   - Entry: <dir>/<key>/tree (the checkout, without .git) and <dir>/<key>/meta.json (repository, commit, a digest of
//     every file, mode and link in the tree, its size). An entry is written once, in a temporary directory beside it,
//     and renamed into place; a rename onto an entry that exists loses and the existing entry is used. It is never
//     edited afterwards.
//   - Use: a render never reads the entry in place. restore copies the tree into the render's own scratch directory
//     and hashes the bytes it copies in the same pass; a digest that differs from meta.json, a meta that is not the
//     key's repository and commit, or any read error discards the entry and the render fetches again. What Helm reads
//     is therefore exactly the bytes the digest covers, and neither Helm nor an eviction can change the entry under it.
//   - The symlink and containment checks still run on what Helm reads (render.go), on every render.
//   - Bounds: at most MaxBytes and MaxEntries; the entry used longest ago goes first.
//   - Concurrency: a file lock per key makes renders of the same commit fetch it once.
type ChartCache struct {
	Dir        string // the directory of entries; empty disables the cache
	MaxBytes   int64  // total size of the entries' trees (0: no byte bound)
	MaxEntries int    // number of entries (0: no bound)
	Now        func() time.Time
}

const chartMetaVersion = 1

type chartMeta struct {
	Version int       `json:"version"`
	Repo    string    `json:"repo"`
	Commit  string    `json:"commit"`
	Digest  string    `json:"digest"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
}

func (c ChartCache) enabled() bool { return c.Dir != "" }

func (c ChartCache) key(repo, commit string) string {
	sum := sha256.Sum256([]byte("chart\x00" + repo + "\x00" + commit))
	return hex.EncodeToString(sum[:])
}

func (c ChartCache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// resolveChart asks the remote what the revision is now: a branch head, else a tag (peeled when annotated), in the
// order `git clone --branch` reads them. It returns "" when the remote does not say (the caller fetches and sees the
// real answer): the lookup is an optimisation and a wrong or missing answer only costs a clone.
func resolveChart(ctx context.Context, run Exec, repo, rev string) string {
	out, err := run(ctx, os.TempDir(), "git", "ls-remote", "--", repo, "refs/heads/"+rev, "refs/tags/"+rev, "refs/tags/"+rev+"^{}")
	if err != nil {
		return ""
	}
	refs := map[string]string{}
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) == 2 && sha40.MatchString(f[0]) {
			refs[f[1]] = f[0]
		}
	}
	for _, r := range []string{"refs/heads/" + rev, "refs/tags/" + rev + "^{}", "refs/tags/" + rev} {
		if s := refs[r]; s != "" {
			return s
		}
	}
	return ""
}

// Fetch puts the chart repository's tree at rev into dest (which must not exist) and returns the commit it is, and how:
// "hit" (restored from the cache), "miss" (fetched, and kept) or "off" (fetched, not kept: no cache, a cache that cannot
// be written, a checkout above the byte bound). hint is what resolveChart said ("" when unknown). Without a cache it is
// the plain shallow clone, as before. The clone always goes to dest, the render's own scratch: a failure of the cache
// (a directory that cannot be written, a full disk) never fails the render, only a failure of git, or the render's own
// deadline, does. The checkout is then copied into the cache.
func (c ChartCache) Fetch(ctx context.Context, run Exec, repo, rev, hint, dest string) (commit, how string, err error) {
	clone := func() (string, string, error) {
		commit, err := cloneChart(ctx, run, repo, rev, dest)
		if err != nil {
			return "", "", err
		}
		os.RemoveAll(filepath.Join(dest, ".git")) // Helm reads files; the cache keeps files
		if c.enabled() && c.publish(ctx, repo, commit, dest) {
			return commit, "miss", nil
		}
		return commit, "off", nil
	}
	if !c.enabled() || os.MkdirAll(c.Dir, 0o700) != nil {
		commit, err := cloneChart(ctx, run, repo, rev, dest)
		return commit, "off", err
	}
	if hint != "" {
		if err := c.restore(repo, hint, dest); err == nil {
			return hint, "hit", nil
		}
		unlock, err := lockFile(ctx, c.lockPath(repo, hint))
		if err != nil {
			if ctx.Err() != nil {
				return "", "", err
			}
			return clone()
		}
		defer unlock()
		// Another render may have fetched it while this one waited for the lock.
		err = c.restore(repo, hint, dest)
		if err == nil {
			return hint, "hit", nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			c.discardIfBad(ctx, repo, hint)
		}
	}
	return clone()
}

// lockPath is the lock file of a key. There are 256 of them, named by the key's first byte and never removed: a lock
// that an eviction unlinked would let one waiter hold the old file and a later render lock a new one for the same commit.
func (c ChartCache) lockPath(repo, commit string) string {
	return filepath.Join(c.Dir, "lock-"+c.key(repo, commit)[:2])
}

// cloneChart is the uncached fetch: a shallow clone at the pinned tag, and the commit it peels to.
func cloneChart(ctx context.Context, run Exec, repo, rev, dest string) (string, error) {
	if _, err := run(ctx, filepath.Dir(dest), "git", "clone", "--quiet", "--depth", "1", "--branch", rev, "--", repo, dest); err != nil {
		return "", fmt.Errorf("fetch the chart at %s: %w", rev, err)
	}
	sha, err := run(ctx, dest, "git", "rev-parse", "HEAD^{commit}")
	if err != nil {
		return "", fmt.Errorf("peel the chart tag: %w", err)
	}
	commit := strings.TrimSpace(string(sha))
	if !sha40.MatchString(commit) {
		return "", fmt.Errorf("the chart tag %s peeled to %q, not a commit", rev, commit)
	}
	return commit, nil
}

// publish copies the checkout in dest into the cache as the entry for (repo, commit): into a temporary directory, with
// its digest, then renamed into place under the directory lock (which also orders it against another render's eviction
// and discard). A checkout above the byte bound is not kept. It reports whether the entry is there; the render does not
// depend on it.
func (c ChartCache) publish(ctx context.Context, repo, commit, dest string) bool {
	tmp, err := os.MkdirTemp(c.Dir, ".tmp-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(tmp)
	digest, size, err := copyTree(dest, filepath.Join(tmp, "tree"))
	if err != nil || (c.MaxBytes > 0 && size > c.MaxBytes) {
		return false
	}
	b, _ := json.Marshal(chartMeta{Version: chartMetaVersion, Repo: repo, Commit: commit, Digest: digest, Size: size, Created: c.now().UTC()})
	meta := filepath.Join(tmp, "meta.json")
	if os.WriteFile(meta, b, 0o600) != nil {
		return false
	}
	now := c.now()
	os.Chtimes(meta, now, now) // last used, for the eviction order, from the start
	unlock, err := lockFile(ctx, filepath.Join(c.Dir, "lock-dir"))
	if err != nil {
		return false
	}
	defer unlock()
	key := c.key(repo, commit)
	final := filepath.Join(c.Dir, key)
	if _, err := os.Stat(final); err == nil {
		if c.verify(repo, commit) == nil {
			return true // another render's entry stands
		}
		c.discard(final)
	}
	if os.Rename(tmp, final) != nil {
		return false
	}
	c.evict(key)
	return true
}

// discardIfBad removes the entry for (repo, commit) if, under the directory lock, it still does not verify: an entry
// that another render replaced since is not removed.
func (c ChartCache) discardIfBad(ctx context.Context, repo, commit string) {
	unlock, err := lockFile(ctx, filepath.Join(c.Dir, "lock-dir"))
	if err != nil {
		return
	}
	defer unlock()
	dir := filepath.Join(c.Dir, c.key(repo, commit))
	if _, err := os.Stat(dir); err == nil && c.verify(repo, commit) != nil {
		c.discard(dir)
	}
}

// verify is whether the entry for (repo, commit) is there and is what it claims, without copying it.
func (c ChartCache) verify(repo, commit string) error {
	dir := filepath.Join(c.Dir, c.key(repo, commit))
	m, err := c.meta(dir, repo, commit)
	if err != nil {
		return err
	}
	digest, _, err := copyTree(filepath.Join(dir, "tree"), "")
	if err != nil {
		return err
	}
	if digest != m.Digest {
		return errors.New("the tree does not match its digest")
	}
	return nil
}

func (c ChartCache) meta(dir, repo, commit string) (chartMeta, error) {
	var m chartMeta
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if m.Version != chartMetaVersion || m.Repo != repo || m.Commit != commit || m.Digest == "" {
		return m, errors.New("the entry is not the one its key names")
	}
	return m, nil
}

// restore copies the entry for (repo, commit) to dest, verifying it while it copies. An entry that is absent
// (fs.ErrNotExist) or bad is an error; removing a bad one is discardIfBad's, under the lock.
func (c ChartCache) restore(repo, commit, dest string) error {
	dir := filepath.Join(c.Dir, c.key(repo, commit))
	m, err := c.meta(dir, repo, commit)
	if err != nil {
		return err
	}
	digest, _, err := copyTree(filepath.Join(dir, "tree"), dest)
	if err == nil && digest != m.Digest {
		err = errors.New("the tree does not match its digest")
	}
	if err != nil {
		os.RemoveAll(dest)
		return err
	}
	now := c.now()
	os.Chtimes(filepath.Join(dir, "meta.json"), now, now) // last used, for the eviction order
	return nil
}

// discard removes an entry so that no reader sees it half deleted: renamed away first, then removed.
func (c ChartCache) discard(dir string) {
	trash, err := os.MkdirTemp(c.Dir, ".trash-")
	if err != nil {
		return
	}
	if os.Rename(dir, filepath.Join(trash, "e")) != nil {
		os.Remove(trash)
		return
	}
	os.RemoveAll(trash)
}

// evict (called under the directory lock) brings the cache within its bounds, least recently used first, never the entry named keep, and clears what
// an interrupted populate left (temporary directories older than ten minutes).
func (c ChartCache) evict(keep string) {
	ents, err := os.ReadDir(c.Dir)
	if err != nil {
		return
	}
	type entry struct {
		name string
		used time.Time
		size int64
	}
	var all []entry
	var total int64
	now := c.now()
	for _, e := range ents {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, ".tmp-") || strings.HasPrefix(name, ".trash-"):
			if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > 10*time.Minute {
				os.RemoveAll(filepath.Join(c.Dir, name))
			}
		case e.IsDir() && len(name) == 64:
			dir := filepath.Join(c.Dir, name)
			b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
			var m chartMeta
			st, serr := os.Stat(filepath.Join(dir, "meta.json"))
			if err != nil || serr != nil || json.Unmarshal(b, &m) != nil {
				c.discard(dir) // not an entry: nothing writes a directory here without a meta
				continue
			}
			all = append(all, entry{name, st.ModTime(), m.Size})
			total += m.Size
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].used.Before(all[j].used) })
	count := len(all)
	for _, e := range all {
		over := (c.MaxBytes > 0 && total > c.MaxBytes) || (c.MaxEntries > 0 && count > c.MaxEntries)
		if !over {
			break
		}
		if e.name == keep {
			continue
		}
		c.discard(filepath.Join(c.Dir, e.name))
		total -= e.size
		count--
	}
}

// copyTree walks src in a fixed order and returns a digest of every directory, file (its bytes and whether it is
// executable) and link (its target) in it, and the bytes of the files. With dst set it also writes the tree there as
// it reads it. A file that is neither (a device, a socket) is refused: git does not make one.
func copyTree(src, dst string) (string, int64, error) {
	h := sha256.New()
	var size int64
	if dst != "" {
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return "", 0, err
		}
	}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		target := filepath.Join(dst, filepath.FromSlash(rel))
		switch {
		case d.IsDir():
			fmt.Fprintf(h, "d\x00%s\x00", rel)
			if dst != "" && rel != "." {
				return os.MkdirAll(target, 0o755)
			}
			return nil
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "l\x00%s\x00%s\x00", rel, link)
			if dst != "" {
				return os.Symlink(link, target)
			}
			return nil
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			mode := fs.FileMode(0o644)
			if info.Mode()&0o111 != 0 {
				mode = 0o755
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			fh := sha256.New()
			var w io.Writer = fh
			var out *os.File
			if dst != "" {
				if out, err = os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode); err != nil {
					return err
				}
				w = io.MultiWriter(fh, out)
			}
			n, err := io.Copy(w, f)
			if out != nil {
				if cerr := out.Close(); err == nil {
					err = cerr
				}
				if err == nil {
					err = os.Chmod(target, mode) // umask must not decide the executable bit
				}
			}
			if err != nil {
				return err
			}
			size += n
			fmt.Fprintf(h, "f\x00%s\x00%o\x00%d\x00%x\x00", rel, mode, n, fh.Sum(nil))
			return nil
		}
		return fmt.Errorf("%s is neither a file, a directory nor a link", rel)
	})
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// lockFile takes an exclusive lock on path (created when missing) and returns its release. It waits for the
// holder, giving up when ctx ends.
func lockFile(ctx context.Context, path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		ok, err := tryLock(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if ok {
			var once sync.Once
			return func() { once.Do(func() { unlock(f); f.Close() }) }, nil
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
