// Command webui puts the pinned clearance-ui web bundle into internal/web/static, where `clearance web` embeds it.
//
//	go run ./tools/webui                 # download (or reuse the cache), verify the pin, extract into the static dir
//	go run ./tools/webui -verify         # download and verify the pin only (CI: does the pin resolve and match?)
//
// The pin is web-ui.lock: repo, version and the sha256 of the release tarball. The tarball is fetched over https
// from that repository's GitHub release and refused unless its sha256 is the pinned one (the .sha256 asset beside it
// is never consulted: an attacker who can swap the tarball can swap that too). The archive is extracted only when it
// holds nothing but regular files and directories under the root (no absolute or ".." names, no links, devices or
// duplicates), stays inside the size caps, and has an index.html; it replaces the static dir's contents whole.
package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	maxFileBytes  = 16 << 20
	maxTotalBytes = 64 << 20
	maxEntries    = 1024
	maxTarball    = 64 << 20
)

// Lock is web-ui.lock.
type Lock struct{ Repo, Version, SHA256 string }

var (
	repoRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$`)
	versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	shaRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ParseLock reads key=value lines (blank lines and # comments skipped) and validates all three keys.
func ParseLock(r io.Reader) (Lock, error) {
	kv := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Lock{}, fmt.Errorf("lock: %q is not key=value", line)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, dup := kv[k]; dup {
			return Lock{}, fmt.Errorf("lock: %s set twice", k)
		}
		kv[k] = v
	}
	if err := sc.Err(); err != nil {
		return Lock{}, err
	}
	for k := range kv {
		if k != "repo" && k != "version" && k != "sha256" {
			return Lock{}, fmt.Errorf("lock: unknown key %q", k)
		}
	}
	l := Lock{Repo: kv["repo"], Version: kv["version"], SHA256: kv["sha256"]}
	switch {
	case !repoRE.MatchString(l.Repo):
		return Lock{}, fmt.Errorf("lock: repo %q is not owner/name", l.Repo)
	case !versionRE.MatchString(l.Version):
		return Lock{}, fmt.Errorf("lock: version %q is not X.Y.Z", l.Version)
	case !shaRE.MatchString(l.SHA256):
		return Lock{}, fmt.Errorf("lock: sha256 %q is not 64 lowercase hex characters", l.SHA256)
	}
	return l, nil
}

// TarballURL is the release asset's https URL.
func (l Lock) TarballURL(base string) string {
	if base == "" {
		base = "https://github.com"
	}
	return fmt.Sprintf("%s/%s/releases/download/v%s/clearance-ui-web-%s.tar.gz", base, l.Repo, l.Version, l.Version)
}

// Fetch returns the tarball's bytes, from the cache directory when it holds a file named for the pinned sha256 that
// still hashes to it, otherwise downloaded (https only, redirects included) and checked against the pin before it
// is cached. allowHTTP is for tests against a local server.
func Fetch(l Lock, base, cacheDir string, allowHTTP bool) ([]byte, error) {
	cached := ""
	if cacheDir != "" {
		cached = filepath.Join(cacheDir, l.SHA256+".tar.gz")
		if b, err := os.ReadFile(cached); err == nil && sum(b) == l.SHA256 {
			return b, nil
		}
	}
	u := l.TarballURL(base)
	if pu, err := url.Parse(u); err != nil || (pu.Scheme != "https" && !allowHTTP) {
		return nil, fmt.Errorf("refusing to download %q: not https", u)
	}
	client := &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" && !allowHTTP {
				return fmt.Errorf("refusing redirect to %s: not https", req.URL.Redacted())
			}
			if len(via) > 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxTarball+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxTarball {
		return nil, fmt.Errorf("tarball is over %d bytes", maxTarball)
	}
	if got := sum(b); got != l.SHA256 {
		return nil, fmt.Errorf("sha256 mismatch for %s: pinned %s, downloaded %s", u, l.SHA256, got)
	}
	if cached != "" {
		if err := os.MkdirAll(cacheDir, 0o755); err == nil {
			_ = os.WriteFile(cached, b, 0o644) // best effort: the cache only saves a download
		}
	}
	return b, nil
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Extract unpacks the gzipped tar into a staging directory beside dest, validates it, and swaps it in for dest's
// contents. Nothing in dest changes if the archive is refused.
func Extract(tgz []byte, dest string) error {
	parent := filepath.Dir(dest)
	stage, err := os.MkdirTemp(parent, ".webui-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := unpack(tgz, stage); err != nil {
		return err
	}
	if st, err := os.Stat(filepath.Join(stage, "index.html")); err != nil || !st.Mode().IsRegular() {
		return errors.New("archive has no index.html at its root")
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	old, err := os.ReadDir(dest)
	if err != nil {
		return err
	}
	for _, e := range old {
		if err := os.RemoveAll(filepath.Join(dest, e.Name())); err != nil {
			return err
		}
	}
	news, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	for _, e := range news {
		if err := os.Rename(filepath.Join(stage, e.Name()), filepath.Join(dest, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func unpack(tgz []byte, stage string) error {
	zr, err := gzip.NewReader(strings.NewReader(string(tgz)))
	if err != nil {
		return fmt.Errorf("not a gzip archive: %w", err)
	}
	tr := tar.NewReader(zr)
	seen := map[string]bool{}
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if n >= maxEntries {
			return fmt.Errorf("archive has more than %d entries", maxEntries)
		}
		name := strings.TrimPrefix(h.Name, "./")
		if name == "" || name == "." { // the root directory entry
			if h.Typeflag != tar.TypeDir {
				return fmt.Errorf("entry %q is not a directory", h.Name)
			}
			continue
		}
		clean := path.Clean(strings.TrimSuffix(name, "/"))
		if strings.HasPrefix(name, "/") || strings.Contains(name, `\`) || strings.ContainsRune(name, 0) ||
			clean == ".." || strings.HasPrefix(clean, "../") || clean != strings.TrimSuffix(name, "/") {
			return fmt.Errorf("refusing entry %q: unsafe path", h.Name)
		}
		if seen[clean] {
			return fmt.Errorf("refusing entry %q: duplicate", h.Name)
		}
		seen[clean] = true
		target := filepath.Join(stage, filepath.FromSlash(clean))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if h.Size > maxFileBytes {
				return fmt.Errorf("refusing entry %q: over %d bytes", h.Name, maxFileBytes)
			}
			total += h.Size
			if total > maxTotalBytes {
				return fmt.Errorf("archive is over %d bytes extracted", maxTotalBytes)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			// O_EXCL: never write through anything already there (a symlink cannot exist: they are refused).
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(f, io.LimitReader(tr, h.Size))
			if err := f.Close(); cerr == nil {
				cerr = err
			}
			if cerr != nil {
				return cerr
			}
		default:
			return fmt.Errorf("refusing entry %q: type %q is not a regular file or directory (links are refused)", h.Name, string(h.Typeflag))
		}
	}
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("webui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	lockPath := fs.String("lock", "web-ui.lock", "the pin")
	dest := fs.String("dest", "internal/web/static", "the directory `clearance web` embeds")
	verify := fs.Bool("verify", false, "download and check the pin only; extract nothing")
	cache := fs.String("cache", "", "download cache directory (default: the user cache dir, or $WEBUI_CACHE)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := os.Open(*lockPath)
	if err != nil {
		fmt.Fprintln(stderr, "webui:", err)
		return 1
	}
	l, err := ParseLock(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(stderr, "webui:", err)
		return 1
	}
	cd := *cache
	if cd == "" {
		cd = os.Getenv("WEBUI_CACHE")
	}
	if cd == "" {
		if u, err := os.UserCacheDir(); err == nil {
			cd = filepath.Join(u, "clearance-web-ui")
		}
	}
	b, err := Fetch(l, "", cd, false)
	if err != nil {
		fmt.Fprintln(stderr, "webui:", err)
		return 1
	}
	if *verify {
		fmt.Fprintf(stdout, "clearance-ui %s: sha256 %s matches the pin\n", l.Version, l.SHA256)
		return 0
	}
	if err := Extract(b, *dest); err != nil {
		fmt.Fprintln(stderr, "webui:", err)
		return 1
	}
	fmt.Fprintf(stdout, "clearance-ui %s extracted into %s (sha256 %s)\n", l.Version, *dest, l.SHA256)
	return 0
}
