package provenance

import (
	"errors"
	"path"
	"regexp"
	"strings"
	"sync"
)

// The three scope.py functions provenance uses: normalize, path_violations and repo_allowed. R-1a ports scope.py
// whole for the decision engine; when both land, these call that package instead.

var errBadPath = errors.New("bad path")

// normalize is scope.normalize: no NUL or backslash, relative, inside the repository, posix-normalised.
func normalize(p string) (string, error) {
	if p == "" || strings.ContainsAny(p, "\x00\\") || strings.HasPrefix(p, "/") {
		return "", errBadPath
	}
	n := path.Clean(p)
	if n == ".." || strings.HasPrefix(n, "../") || n == "." {
		return "", errBadPath
	}
	return n, nil
}

// normal is provenance.normal: the normalised path, or the path itself when it cannot be.
func normal(p string) string {
	if n, err := normalize(p); err == nil {
		return n
	}
	return p
}

var globRx sync.Map

// globToRegex is scope.glob_to_regex: `**/` any directories, `**` anything, `*` and `?` within one segment.
func globToRegex(glob string) *regexp.Regexp {
	if re, ok := globRx.Load(glob); ok {
		return re.(*regexp.Regexp)
	}
	var b strings.Builder
	b.WriteString(`^`)
	for i := 0; i < len(glob); {
		switch {
		case strings.HasPrefix(glob[i:], "**/"):
			b.WriteString(`(?:.*/)?`)
			i += 3
		case strings.HasPrefix(glob[i:], "**"):
			b.WriteString(`.*`)
			i += 2
		case glob[i] == '*':
			b.WriteString(`[^/]*`)
			i++
		case glob[i] == '?':
			b.WriteString(`[^/]`)
			i++
		default:
			j := i + 1
			for j < len(glob) && glob[j] != '*' && glob[j] != '?' {
				j++
			}
			b.WriteString(regexp.QuoteMeta(glob[i:j]))
			i = j
		}
	}
	b.WriteString(`\n?\z`) // Python `$`: the end, or before a final newline
	re := regexp.MustCompile(b.String())
	globRx.Store(glob, re)
	return re
}

// pathViolations is scope.path_violations: the changed paths a deny glob matches; unsafe paths count too.
func pathViolations(paths, deny []string) []string {
	var bad []string
	for _, p := range paths {
		n, err := normalize(p)
		if err != nil {
			bad = append(bad, p)
			continue
		}
		for _, g := range deny {
			if globToRegex(g).MatchString(n) {
				bad = append(bad, p)
				break
			}
		}
	}
	return bad
}

// repoAllowed is scope.repo_allowed: owner/name against globs; no allowlist allows nothing.
func repoAllowed(repo string, allow []string) bool {
	if strings.Count(repo, "/") != 1 || strings.HasPrefix(repo, "/") || strings.HasSuffix(repo, "/") {
		return false
	}
	for _, a := range allow {
		if globToRegex(a).MatchString(repo) {
			return true
		}
	}
	return false
}
