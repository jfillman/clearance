package pycompat

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Str is Python's str() of a JSON value: a string itself, None, True/False, an int's digits, a float's repr, and
// repr() for a list or dict (a dict's keys in sorted order: Go maps keep no insertion order).
func Str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return Repr(v)
}

// Repr is Python's repr() of a JSON value.
func Repr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return quote(x)
	case json.Number:
		s, err := NumberString(x)
		if err != nil {
			return string(x)
		}
		return s
	case float64:
		return FloatRepr(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case *big.Int:
		return x.String()
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = Repr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []string:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = quote(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = quote(k) + ": " + Repr(x[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(v)
}

// quote is repr(str): single quotes unless the text holds a single quote and no double one.
func quote(s string) string {
	q := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, r := range s {
		switch {
		case r == rune(q) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r > 0x7f && !unicode.IsPrint(r):
			if r > 0xffff {
				fmt.Fprintf(&b, `\U%08x`, r)
			} else if r > 0xff {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				fmt.Fprintf(&b, `\x%02x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(q)
	return b.String()
}

// Number is a JSON number's value as Python compares it: an int (exact) or a float.
func Number(v any) (*big.Float, bool) {
	switch x := v.(type) {
	case json.Number:
		if IsInt(x) {
			z, ok := new(big.Int).SetString(string(x), 10)
			if !ok {
				return nil, false
			}
			return new(big.Float).SetInt(z), true
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return nil, false
		}
		return big.NewFloat(f), true
	case float64:
		if x != x {
			return nil, false
		}
		return big.NewFloat(x), true
	case int:
		return new(big.Float).SetInt64(int64(x)), true
	case int64:
		return new(big.Float).SetInt64(x), true
	case *big.Int:
		return new(big.Float).SetInt(x), true
	case bool: // Python: True == 1
		if x {
			return big.NewFloat(1), true
		}
		return big.NewFloat(0), true
	}
	return nil, false
}

// Equal is Python's == over JSON values: numbers by value (1 == 1.0, True == 1), lists in order, dicts by key.
func Equal(a, b any) bool {
	if na, ok := Number(a); ok {
		if nb, ok := Number(b); ok {
			return na.Cmp(nb) == 0
		}
		return false
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !Equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !Equal(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// AsInt is isinstance(v, int) and not isinstance(v, bool) for a JSON value, with its value when it fits int64.
func AsInt(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		if !IsInt(x) {
			return 0, false
		}
		n, err := strconv.ParseInt(string(x), 10, 64)
		return n, err == nil
	case int:
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}

// -- fnmatch.fnmatchcase ------------------------------------------------------------------------------------------

var globCache sync.Map // pattern -> *regexp.Regexp

// Match is fnmatch.fnmatchcase(name, pattern): `*` matches anything (slashes included), `?` one character,
// `[seq]` and `[!seq]` a set; the whole name must match.
func Match(name, pattern string) bool {
	if re, ok := globCache.Load(pattern); ok {
		return re.(*regexp.Regexp).MatchString(name)
	}
	re := regexp.MustCompile(translate(pattern))
	globCache.Store(pattern, re)
	return re.MatchString(name)
}

// MatchAny is any(fnmatchcase(name, g) for g in globs).
func MatchAny(name string, globs []string) bool {
	for _, g := range globs {
		if Match(name, g) {
			return true
		}
	}
	return false
}

// translate is fnmatch.translate.
func translate(pat string) string {
	var b strings.Builder
	b.WriteString(`(?s)\A`)
	rs := []rune(pat)
	for i := 0; i < len(rs); {
		c := rs[i]
		i++
		switch c {
		case '*':
			for i < len(rs) && rs[i] == '*' {
				i++
			}
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			j := i
			if j < len(rs) && rs[j] == '!' {
				j++
			}
			if j < len(rs) && rs[j] == ']' {
				j++
			}
			for j < len(rs) && rs[j] != ']' {
				j++
			}
			if j >= len(rs) {
				b.WriteString(`\[`)
				continue
			}
			stuff := string(rs[i:j])
			i = j + 1
			if stuff == "" {
				b.WriteString(`[^\s\S]`) // Python: an empty set never matches
				continue
			}
			if stuff == "!" {
				b.WriteString(".")
				continue
			}
			neg := strings.HasPrefix(stuff, "!")
			if neg {
				stuff = stuff[1:]
			}
			var set strings.Builder
			for _, r := range stuff {
				if r == '\\' || r == ']' || r == '[' || r == '^' {
					set.WriteByte('\\')
				}
				set.WriteRune(r)
			}
			if neg {
				b.WriteString("[^" + set.String() + "]")
			} else {
				b.WriteString("[" + set.String() + "]")
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`\z`)
	return b.String()
}

// -- time ------------------------------------------------------------------------------------------------------------

// ISO is audit.iso: UTC, whole seconds, "Z".
func ISO(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// Isoformat is datetime.isoformat() of an aware datetime: microseconds only when non-zero, "+HH:MM".
func Isoformat(t time.Time) string {
	if t.Nanosecond()/1000 != 0 {
		return t.Format("2006-01-02T15:04:05.000000-07:00")
	}
	return t.Format("2006-01-02T15:04:05-07:00")
}

// ParseIsoformat is datetime.fromisoformat for the forms Isoformat and ISO write.
func ParseIsoformat(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-07:00", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("not an ISO timestamp: %q", s)
}

// Truncate cuts s to n characters (code points), as Python's s[:n].
func Truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// Len is Python's len(str): code points.
func Len(s string) int { return len([]rune(s)) }
