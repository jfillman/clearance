package argosrc

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Runner runs a program in dir with extra environment (added to the runner's own bare one) and returns its stdout;
// a failure carries the program's stderr. No shell is involved.
type Runner func(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error)

var (
	sha40Rx    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	scpLikeRx  = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^/].*$`)
	versionRx  = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	chartNmRx  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	revisionRx = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+@-]{0,200}$`)
)

// checkGitURL admits the transports Argo CD's repo-server uses (https, http, ssh, git, scp-like) and refuses
// everything else: a `file://`, `ext::` or local path is a read of the sidecar's own disk.
func (o Options) checkGitURL(i int, repo string) error {
	if repo == "" || strings.HasPrefix(repo, "-") {
		return fmt.Errorf("source %d: the repository URL %q is not valid", i, repo)
	}
	if scpLikeRx.MatchString(repo) {
		return nil
	}
	if u, err := url.Parse(repo); err == nil && u.Host != "" {
		switch u.Scheme {
		case "https", "http", "ssh", "git":
			return nil
		}
		return fmt.Errorf("source %d: the repository URL scheme %q is not allowed (https, http, ssh, git)", i, u.Scheme)
	}
	if o.AllowLocalRepos {
		return nil
	}
	return fmt.Errorf("source %d: the repository URL %q is not a remote URL", i, repo)
}

// fetchGit checks out the source's repository at its target revision into a new directory (HEAD when none is given)
// and returns the directory and the peeled commit. The .git directory is removed: the plugin renders files.
// A semver constraint or a tag prefix (which Argo CD resolves against the tag list) is not an exact revision and is
// refused; so is a repository with submodules.
func (o Options) fetchGit(ctx context.Context, i int, repo, rev string) (dir, commit string, err error) {
	if err := o.checkGitURL(i, repo); err != nil {
		return "", "", err
	}
	if rev == "" {
		rev = "HEAD"
	}
	if !revisionRx.MatchString(rev) && rev != "HEAD" {
		return "", "", fmt.Errorf("source %d: targetRevision %q is not a branch, tag or commit", i, rev)
	}
	dir, err = os.MkdirTemp(o.Work, "git-")
	if err != nil {
		return "", "", err
	}
	if dir, err = filepath.EvalSymlinks(dir); err != nil { // one spelling of the root, for the containment checks
		return "", "", err
	}
	env := []string{"GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=https:http:ssh:git" + o.extraProtocols()}
	steps := [][]string{
		{"init", "--quiet", "."},
		{"-c", "advice.detachedHead=false", "fetch", "--quiet", "--depth", "1", "--no-tags", "--", repo, rev},
		{"-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", "FETCH_HEAD"},
	}
	for _, a := range steps {
		if _, err := o.Run(ctx, dir, env, "git", a...); err != nil {
			hint := ""
			if a[len(a)-1] == rev && (strings.ContainsAny(rev, "*^~<>=| ") || strings.Contains(rev, ".x")) {
				hint = " (a semver constraint is not an exact revision; the plugin pins a branch, a tag or a commit)"
			}
			return "", "", fmt.Errorf("source %d: fetch %s at %s: %w%s", i, redactURL(repo), rev, err, hint)
		}
	}
	out, err := o.Run(ctx, dir, env, "git", "rev-parse", "HEAD^{commit}")
	if err != nil {
		return "", "", fmt.Errorf("source %d: peel %s: %w", i, rev, err)
	}
	commit = strings.TrimSpace(string(out))
	if !sha40Rx.MatchString(commit) {
		return "", "", fmt.Errorf("source %d: %s peeled to %q, not a commit", i, rev, commit)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitmodules")); err == nil {
		return "", "", unsupported(i, "git submodules", "the repository has a .gitmodules file")
	}
	if err := os.RemoveAll(filepath.Join(dir, ".git")); err != nil {
		return "", "", err
	}
	if err := checkSymlinks(dir); err != nil {
		return "", "", fmt.Errorf("source %d: %w", i, err)
	}
	return dir, commit, nil
}

func (o Options) extraProtocols() string {
	if o.AllowLocalRepos {
		return ":file"
	}
	return ""
}

// redactURL drops a userinfo from a URL before it is shown.
func redactURL(s string) string {
	if u, err := url.Parse(s); err == nil && u.User != nil {
		u.User = url.User("***")
		return u.String()
	}
	return s
}

// helmEnv confines Helm's cache, config and data to the render's own scratch directory.
func (o Options) helmEnv() []string {
	return []string{"HELM_CACHE_HOME=" + filepath.Join(o.Work, "helm-cache"), "HELM_CONFIG_HOME=" + filepath.Join(o.Work, "helm-config"),
		"HELM_DATA_HOME=" + filepath.Join(o.Work, "helm-data")}
}

// isOCIChartRepo is helm.IsHelmOciRepo: a chart repository URL with no host in it ("ghcr.io/org/charts") is an OCI
// registry; with a scheme and a host it is an HTTP(S) chart repository.
func isOCIChartRepo(repo string) bool {
	if repo == "" {
		return false
	}
	u, err := url.Parse(repo)
	return err == nil && u.Host == ""
}

// fetchChart pulls a chart (helm pull, as Argo CD's Fetch and PullOCI do) and unpacks it. It returns the chart's
// directory and the sha256 of the packaged chart, which is what a version names only by convention.
func (o Options) fetchChart(ctx context.Context, i int, repo, chart, version string) (dir, digest string, err error) {
	if !chartNmRx.MatchString(chart) || strings.Contains(chart, "..") {
		return "", "", fmt.Errorf("source %d: chart name %q is not valid", i, chart)
	}
	if version != "" && !versionRx.MatchString(version) {
		return "", "", unsupported(i, "a chart version constraint", fmt.Sprintf("targetRevision %q is not an exact chart version", version))
	}
	oci := isOCIChartRepo(repo)
	if oci && version == "" {
		return "", "", unsupported(i, "an OCI chart without a version", "Argo CD resolves the latest tag; the plugin needs an exact one")
	}
	pull, err := os.MkdirTemp(o.Work, "pull-")
	if err != nil {
		return "", "", err
	}
	args := []string{"pull", "--destination", pull}
	if version != "" {
		args = append(args, "--version", version)
	}
	if oci {
		if strings.HasPrefix(repo, "-") || strings.ContainsAny(repo, " \t\n") {
			return "", "", fmt.Errorf("source %d: the registry %q is not valid", i, repo)
		}
		args = append(args, "oci://"+strings.TrimSuffix(repo, "/")+"/"+chart)
	} else {
		u, uerr := url.Parse(repo)
		if uerr != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", "", fmt.Errorf("source %d: the chart repository %q is not an http(s) URL or an OCI registry", i, repo)
		}
		args = append(args, "--repo", repo, chart)
	}
	if _, err := o.Run(ctx, pull, o.helmEnv(), "helm", args...); err != nil {
		return "", "", fmt.Errorf("source %d: pull chart %s %s from %s: %w", i, chart, version, redactURL(repo), err)
	}
	ents, err := os.ReadDir(pull)
	if err != nil || len(ents) != 1 {
		return "", "", fmt.Errorf("source %d: helm pull left %d files, expected the one package", i, len(ents))
	}
	tgz := filepath.Join(pull, ents[0].Name())
	b, err := os.ReadFile(tgz)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(b)
	digest = "sha256:" + hex.EncodeToString(sum[:])
	dir, err = os.MkdirTemp(o.Work, "chart-")
	if err != nil {
		return "", "", err
	}
	if err := untar(b, dir); err != nil {
		return "", "", fmt.Errorf("source %d: unpack the chart: %w", i, err)
	}
	subs, err := os.ReadDir(dir)
	if err != nil || len(subs) != 1 || !subs[0].IsDir() {
		return "", "", fmt.Errorf("source %d: the chart package does not hold exactly one directory", i)
	}
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		return "", "", err
	}
	root := filepath.Join(dir, subs[0].Name())
	if err := checkSymlinks(root); err != nil {
		return "", "", fmt.Errorf("source %d: %w", i, err)
	}
	return root, digest, nil
}

const (
	maxUnpackBytes = 256 << 20
	maxUnpackFiles = 20000
)

// untar unpacks a .tgz into dest, refusing absolute and parent-relative names and links that leave dest.
func untar(data []byte, dest string) error {
	zr, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	absDest, _ := filepath.Abs(dest)
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if n >= maxUnpackFiles {
			return errors.New("the package holds too many files")
		}
		name := filepath.Clean(filepath.FromSlash(h.Name))
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("illegal path %q in the package", h.Name)
		}
		target := filepath.Join(absDest, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if total > maxUnpackBytes {
				return errors.New("the package is too large")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, h.Size)); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			lt := h.Linkname
			resolved := lt
			if !filepath.IsAbs(lt) {
				resolved = filepath.Join(filepath.Dir(target), lt)
			}
			if !strings.HasPrefix(filepath.Clean(resolved)+string(os.PathSeparator), absDest+string(os.PathSeparator)) {
				return fmt.Errorf("symlink %q in the package points outside it", h.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(lt, target); err != nil {
				return err
			}
		case tar.TypeXGlobalHeader:
		default:
			return fmt.Errorf("the package holds an entry of type %q (%s), which is refused", string(h.Typeflag), h.Name)
		}
	}
}
