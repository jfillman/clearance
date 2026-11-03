package pycompat

import (
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

// Match is fnmatch.fnmatchcase(name, pattern): `*` matches anything (slashes and newlines included), `?` one
// character, `[seq]` and `[!seq]` a set with ranges; the whole name must match. Compiled patterns are cached
// (bounded); scope.Globs keeps its own cache over FnmatchTranslate.
func Match(name, pattern string) bool { return fnCache.get(pattern).MatchString(name) }

// MatchAny is any(fnmatchcase(name, g) for g in globs).
func MatchAny(name string, globs []string) bool {
	for _, g := range globs {
		if Match(name, g) {
			return true
		}
	}
	return false
}

// NeverMatch is a regexp that matches nothing (Python's `(?!)`).
var NeverMatch = regexp.MustCompile(`[^\x00-\x{10FFFF}]`)

// FnmatchRegexp compiles FnmatchTranslate(pat). Translation always yields a valid expression; should compiling
// fail anyway, the pattern matches nothing (fail closed).
func FnmatchRegexp(pat string) *regexp.Regexp {
	re, err := regexp.Compile(FnmatchTranslate(pat))
	if err != nil {
		return NeverMatch
	}
	return re
}

type regexCache struct {
	mu sync.RWMutex
	m  map[string]*regexp.Regexp
}

const maxCachedPatterns = 4096

// fnCache is a cache, not state: a pattern's regexp is a pure function of it, and the cache is bounded.
var fnCache regexCache

func (c *regexCache) get(pat string) *regexp.Regexp {
	c.mu.RLock()
	re, ok := c.m[pat]
	c.mu.RUnlock()
	if ok {
		return re
	}
	re = FnmatchRegexp(pat)
	c.mu.Lock()
	if c.m == nil || len(c.m) >= maxCachedPatterns {
		c.m = make(map[string]*regexp.Regexp)
	}
	c.m[pat] = re
	c.mu.Unlock()
	return re
}

// FnmatchTranslate is fnmatch.translate (CPython 3.14) as a Go regular expression anchored at both ends. Sets keep
// Python's range rules: a reversed range (`z-a`) is dropped, so `[z-a]` matches nothing and `[!z-a]` any one
// character; a `-` first or last is literal.
func FnmatchTranslate(pat string) string {
	rs := []rune(pat)
	n := len(rs)
	var b strings.Builder
	b.WriteString(`\A(?s:`)
	for i := 0; i < n; {
		c := rs[i]
		i++
		switch c {
		case '*':
			for i < n && rs[i] == '*' {
				i++
			}
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			j := i
			if j < n && rs[j] == '!' {
				j++
			}
			if j < n && rs[j] == ']' {
				j++
			}
			for j < n && rs[j] != ']' {
				j++
			}
			if j >= n {
				b.WriteString(`\[`)
				continue
			}
			b.WriteString(fnSet(rs, i, j))
			i = j + 1
		default:
			var buf [utf8.UTFMax]byte
			b.WriteString(regexp.QuoteMeta(string(buf[:utf8.EncodeRune(buf[:], c)])))
		}
	}
	b.WriteString(`)\z`)
	return b.String()
}

// fnSet translates the set pat[i:j] (between '[' and ']') the way fnmatch._translate does.
func fnSet(pat []rune, i, j int) string {
	var chunks [][]rune
	if !containsRune(pat[i:j], '-') {
		chunks = [][]rune{pat[i:j]}
	} else {
		k := i + 1
		if pat[i] == '!' {
			k = i + 2
		}
		for {
			k = indexRune(pat, '-', k, j)
			if k < 0 {
				break
			}
			chunks = append(chunks, pat[i:k])
			i = k + 1
			k += 3
		}
		if chunk := pat[i:j]; len(chunk) > 0 {
			chunks = append(chunks, chunk)
		} else {
			last := len(chunks) - 1
			chunks[last] = append(append([]rune(nil), chunks[last]...), '-')
		}
		// Remove empty ranges: a chunk ending above where the next begins.
		for k := len(chunks) - 1; k > 0; k-- {
			prev, cur := chunks[k-1], chunks[k]
			if len(prev) > 0 && len(cur) > 0 && prev[len(prev)-1] > cur[0] {
				chunks[k-1] = append(append([]rune(nil), prev[:len(prev)-1]...), cur[1:]...)
				chunks = append(chunks[:k], chunks[k+1:]...)
			}
		}
	}
	// Join the chunks with range hyphens, every character inside them escaped where Go's set syntax would read it.
	var body []rune
	for ci, ch := range chunks {
		if ci > 0 {
			body = append(body, '-')
		}
		body = append(body, ch...)
	}
	switch {
	case len(body) == 0:
		return `[^\x00-\x{10FFFF}]` // an empty set never matches
	case len(body) == 1 && body[0] == '!':
		return "." // a negated empty set is any one character
	}
	var s strings.Builder
	s.WriteByte('[')
	start := 0
	if body[0] == '!' {
		s.WriteByte('^')
		start = 1
	}
	// Positions of the joining hyphens, which stay range operators.
	joins := map[int]bool{}
	pos := 0
	for ci, ch := range chunks {
		if ci > 0 {
			joins[pos] = true
			pos++
		}
		pos += len(ch)
	}
	for p := start; p < len(body); p++ {
		r := body[p]
		if r == '-' && joins[p] {
			s.WriteByte('-')
			continue
		}
		switch r {
		case '\\', ']', '[', '^', '-', '&', '~', '|':
			s.WriteByte('\\')
		}
		s.WriteRune(r)
	}
	s.WriteByte(']')
	return s.String()
}

func containsRune(rs []rune, r rune) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

func indexRune(rs []rune, r rune, from, to int) int {
	for k := from; k < to && k < len(rs); k++ {
		if rs[k] == r {
			return k
		}
	}
	return -1
}
