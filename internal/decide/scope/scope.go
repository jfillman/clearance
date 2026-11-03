// Package scope is scope.py: path and repo scope, and AF-9a's field scope over JSON pointers.
//
// Globs are compiled to the regular expressions the Python builds and matched with Python's `re.match`
// semantics, where `$` also matches just before a final newline.
package scope

import (
	"errors"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/decide/pyval"
)

// ErrBadPath is scope.BadPath.
var ErrBadPath = errors.New("bad path")

// Normalize is scope.normalize: a repo-relative path, normalised, or ErrBadPath.
func Normalize(p string) (string, error) {
	if p == "" || strings.ContainsAny(p, "\x00\\") || strings.HasPrefix(p, "/") {
		return "", ErrBadPath
	}
	n := path.Clean(p) // equals posixpath.normpath for a relative path
	if n == ".." || strings.HasPrefix(n, "../") || n == "." {
		return "", ErrBadPath
	}
	return n, nil
}

// NormalizeAny is Normalize on a value that may not be a string (which is a bad path).
func NormalizeAny(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", ErrBadPath
	}
	return Normalize(s)
}

// Normal is provenance.normal: the normalised path, or the path itself when it is not a safe one.
func Normal(p string) string {
	if n, err := Normalize(p); err == nil {
		return n
	}
	return p
}

func globBody(g string) string {
	var b strings.Builder
	for i := 0; i < len(g); {
		switch {
		case strings.HasPrefix(g[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 3
		case strings.HasPrefix(g[i:], "**"):
			b.WriteString(".*")
			i += 2
		case g[i] == '*':
			b.WriteString("[^/]*")
			i++
		case g[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			_, size := utf8.DecodeRuneInString(g[i:])
			b.WriteString(regexp.QuoteMeta(g[i : i+size]))
			i += size
		}
	}
	return b.String()
}

// pyEnd is Python's `$` under re.match: the end, or just before a final newline.
const pyEnd = `\n?\z`

// Globs caches compiled globs. The zero value is ready; it is safe for concurrent use and bounded.
type Globs struct {
	mu   sync.RWMutex
	path map[string]*regexp.Regexp
	ptr  map[string]*regexp.Regexp
	fn   map[string]*regexp.Regexp
}

const maxCached = 4096

var neverMatch = regexp.MustCompile(`[^\x00-\x{10FFFF}]`)

func (c *Globs) get(m *map[string]*regexp.Regexp, key string, build func() string) *regexp.Regexp {
	c.mu.RLock()
	re, ok := (*m)[key]
	c.mu.RUnlock()
	if ok {
		return re
	}
	re, err := regexp.Compile(build())
	if err != nil {
		re = neverMatch // an fnmatch class Go cannot compile (a reversed range): it matches nothing
	}
	c.mu.Lock()
	if *m == nil || len(*m) >= maxCached {
		*m = make(map[string]*regexp.Regexp)
	}
	(*m)[key] = re
	c.mu.Unlock()
	return re
}

// Path is scope.glob_to_regex.
func (c *Globs) Path(g string) *regexp.Regexp {
	return c.get(&c.path, g, func() string { return `\A` + globBody(g) + pyEnd })
}

// Pointer is scope.pointer_glob_to_regex.
func (c *Globs) Pointer(g string) *regexp.Regexp {
	return c.get(&c.ptr, g, func() string { return `\A` + globBody(g) + `(?:/.*)?` + pyEnd })
}

// PathViolations is len(scope.path_violations(paths, deny)): unsafe paths count too.
func (c *Globs) PathViolations(paths []any, deny []string) int {
	bad := 0
	for _, p := range paths {
		n, err := NormalizeAny(p)
		if err != nil {
			bad++
			continue
		}
		for _, g := range deny {
			if c.Path(g).MatchString(n) {
				bad++
				break
			}
		}
	}
	return bad
}

// RepoAllowed is scope.repo_allowed.
func (c *Globs) RepoAllowed(repo string, allow []string) bool {
	if strings.Count(repo, "/") != 1 || strings.HasPrefix(repo, "/") || strings.HasSuffix(repo, "/") {
		return false
	}
	for _, g := range allow {
		if c.Path(g).MatchString(repo) {
			return true
		}
	}
	return false
}

func ptrEscape(k any) string {
	return strings.ReplaceAll(strings.ReplaceAll(pyval.Str(k), "~", "~0"), "/", "~1")
}

// DiffPointers is scope.diff_pointers.
func DiffPointers(before, after any) map[string]struct{} {
	out := map[string]struct{}{}
	diffPointers(before, after, "", out)
	return out
}

func diffPointers(before, after any, prefix string, out map[string]struct{}) {
	if pyval.Eq(before, after) {
		return
	}
	bm, bIsMap := before.(*pyval.Map)
	am, aIsMap := after.(*pyval.Map)
	if bIsMap && aIsMap {
		keys := pyval.NewMap(bm.Len() + am.Len())
		for _, k := range bm.Keys() {
			keys.Set(k, nil)
		}
		for _, k := range am.Keys() {
			keys.Set(k, nil)
		}
		ks := append([]any(nil), keys.Keys()...)
		sort.SliceStable(ks, func(i, j int) bool { return pyval.Str(ks[i]) < pyval.Str(ks[j]) })
		for _, k := range ks {
			ptr := prefix + "/" + ptrEscape(k)
			bv, inB := bm.Get(k)
			av, inA := am.Get(k)
			if !inB || !inA {
				out[ptr] = struct{}{}
			} else if !pyval.Eq(bv, av) {
				diffPointers(bv, av, ptr, out)
			}
		}
		return
	}
	bl, bIsList := before.([]any)
	al, aIsList := after.([]any)
	if bIsList && aIsList && len(bl) == len(al) {
		for i := range bl {
			if !pyval.Eq(bl[i], al[i]) {
				diffPointers(bl[i], al[i], prefix+"/"+itoa(i), out)
			}
		}
		return
	}
	if prefix == "" {
		prefix = "/"
	}
	out[prefix] = struct{}{}
}

// FieldViolations is len(scope.field_violations(pointers, deny)).
func (c *Globs) FieldViolations(pointers map[string]struct{}, deny []string) int {
	n := 0
	for p := range pointers {
		for _, g := range deny {
			if c.Pointer(g).MatchString(p) {
				n++
				break
			}
		}
	}
	return n
}

// FieldOutsideAllow is len(scope.field_outside_allow(pointers, allow)).
func (c *Globs) FieldOutsideAllow(pointers map[string]struct{}, allow []string) int {
	if len(allow) == 0 {
		return 0
	}
	n := 0
	for p := range pointers {
		ok := false
		for _, g := range allow {
			if c.Pointer(g).MatchString(p) {
				ok = true
				break
			}
		}
		if !ok {
			n++
		}
	}
	return n
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}
