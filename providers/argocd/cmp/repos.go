package main

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/jfillman/clearance/internal/argosrc"
)

// The chart allow list. For an Application behind the gate Argo CD no longer fetches the chart: this plugin does, with
// `git clone` of the chartRepo parameter. Argo CD's per-app allowed sources (the AppProject's sourceRepos) therefore do
// not reach it, so the plugin applies the same rule itself. The list comes from CLEARANCE_CHART_REPOS, an environment
// variable of the sidecar container that the platform sets per cluster: a plugin parameter would not do, because the
// parameters are built from tenant-written values (identity.yaml) and are the thing being checked. No wildcard and no
// default: a sidecar given no list fetches no chart (fail closed), because "any repository" is the gap itself.

var (
	scpRepoRx   = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):([^/].*)$`)
	listSplitRx = regexp.MustCompile(`[\s,]+`)
)

// ParseRepoList reads CLEARANCE_CHART_REPOS: repository URLs separated by commas or white space.
func ParseRepoList(s string) []string {
	var out []string
	for _, f := range listSplitRx.Split(s, -1) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// NormalizeRepo is the one spelling two URLs of the same repository share: scheme and host lowercased, user and
// default port dropped, scp-like `git@host:o/r` read as ssh, one trailing "/" and ".git" dropped. The path keeps its
// case (a server may tell them apart). The result is "scheme://host/path". Anything that is not a remote repository
// URL is an error: a local path, file://, ext:: and the like (a read of the sidecar's own disk), an option, a query
// or fragment, and a path with an empty, "." or ".." segment (two readers could resolve it differently).
// oci is an OCI chart registry, written with no scheme ("ghcr.io/org/charts") or as oci://.
func NormalizeRepo(raw string, oci bool) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "-") || strings.ContainsAny(s, " \t\r\n\x00\\?#") {
		return "", fmt.Errorf("%q is not a repository URL", redact(raw))
	}
	var scheme, host, path string
	switch {
	case strings.Contains(s, "://"):
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return "", fmt.Errorf("%q is not a repository URL", redact(raw))
		}
		scheme, host, path = strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Path
		switch scheme {
		case "https", "http", "ssh", "git", "oci":
		default:
			return "", fmt.Errorf("%q: the scheme %q is not allowed (https, http, ssh, git, oci)", redact(raw), scheme)
		}
		if p := u.Port(); p != "" && !(scheme == "https" && p == "443" || scheme == "http" && p == "80" || scheme == "ssh" && p == "22") {
			host += ":" + p
		}
	case oci:
		scheme = "oci"
		h, p, _ := strings.Cut(s, "/")
		host, path = strings.ToLower(h), "/"+p
	default:
		m := scpRepoRx.FindStringSubmatch(s)
		if m == nil {
			return "", fmt.Errorf("%q is not a remote repository URL", redact(raw))
		}
		scheme, host, path = "ssh", strings.ToLower(m[1]), "/"+m[2]
	}
	path = strings.TrimSuffix(path, "/")
	path = strings.TrimSuffix(path, ".git")
	if host == "" || path == "" || path == "/" {
		return "", fmt.Errorf("%q has no host or no repository path", redact(raw))
	}
	for _, seg := range strings.Split(path[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("%q has an empty, \".\" or \"..\" path segment", redact(raw))
		}
	}
	return scheme + "://" + host + path, nil
}

// redact drops a userinfo before a URL is shown.
func redact(s string) string {
	if u, err := url.Parse(s); err == nil && u.User != nil {
		u.User = url.User("***")
		return u.String()
	}
	return s
}

// repoSet is the normalised allow list plus the repositories the Application itself is already checked for
// (ARGOCD_APP_SOURCE_REPO_URL, which Argo CD matches against the AppProject before it runs the plugin).
func (c Config) repoSet() (map[string]bool, error) {
	set := map[string]bool{}
	var errs []error
	for _, r := range c.AllowedRepos {
		k, err := NormalizeRepo(r, strings.HasPrefix(r, "oci://"))
		if err != nil {
			errs = append(errs, fmt.Errorf("CLEARANCE_CHART_REPOS entry %w", err))
			continue
		}
		set[k] = true
	}
	if c.SourceRepo != "" {
		if k, err := NormalizeRepo(c.SourceRepo, false); err == nil {
			set[k] = true
		}
	}
	return set, errors.Join(errs...)
}

// fetched lists every repository this run would fetch from: the chartRepo parameter, or each source of the generic
// mode (a Helm or OCI chart source has a registry, which is the same kind of fetch).
func (c Config) fetched() ([]fetch, error) {
	if c.Sources == "" {
		if c.ChartRepo == "" {
			return nil, nil
		}
		return []fetch{{repo: c.ChartRepo, what: "chart repository"}}, nil
	}
	srcs, err := argosrc.ParseSources(c.Sources)
	if err != nil {
		return nil, err
	}
	var out []fetch
	for i, s := range srcs {
		out = append(out, fetch{repo: s.RepoURL, oci: s.Chart != "" && !strings.Contains(s.RepoURL, "://"), what: fmt.Sprintf("source %d repository", i+1)})
	}
	return out, nil
}

type fetch struct {
	repo string
	oci  bool
	what string
}

// CheckRepos refuses a run that would fetch from a repository the platform did not list. It runs before anything is
// fetched. The message is what Argo CD shows as the Application's comparison error.
func (c Config) CheckRepos() error {
	want, err := c.fetched()
	if err != nil || len(want) == 0 {
		return err
	}
	set, err := c.repoSet()
	if err != nil {
		return err
	}
	for _, w := range want {
		k, err := NormalizeRepo(w.repo, w.oci)
		if err != nil {
			return fmt.Errorf("refused: the %s %w; the plugin fetches only remote git repositories and chart registries the platform allows", w.what, err)
		}
		if len(c.AllowedRepos) == 0 {
			return fmt.Errorf("refused: CLEARANCE_CHART_REPOS is not set on the plugin sidecar, so no %s may be fetched (%s); the platform must list the repositories charts may come from", w.what, redact(w.repo))
		}
		if !set[k] {
			return fmt.Errorf("refused: the %s %s is not one of the repositories this cluster's platform allows (CLEARANCE_CHART_REPOS); an app's chart must come from the platform's chart repository", w.what, redact(w.repo))
		}
	}
	return nil
}
