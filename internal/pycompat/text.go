package pycompat

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/canon"
)

// Str is Python str(v): a string itself, a date or datetime as Python prints it, repr() for everything else.
func Str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case Date:
		return fmt.Sprintf("%04d-%02d-%02d", x.Y, x.M, x.D)
	case DateTime:
		s := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", x.Y, x.M, x.D, x.H, x.Min, x.S)
		if x.Micro != 0 {
			s += fmt.Sprintf(".%06d", x.Micro)
		}
		if x.Aware {
			s += offsetText(x.Offset)
		}
		return s
	}
	return Repr(v)
}

func offsetText(off int) string {
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	s := fmt.Sprintf("%s%02d:%02d", sign, off/3600, off%3600/60)
	if off%60 != 0 {
		s += fmt.Sprintf(":%02d", off%60)
	}
	return s
}

// Repr is Python repr(v), over either value model. A *Map prints in insertion order; a map[string]any prints its
// keys sorted (a Go map keeps no insertion order). A json.Number prints as the int or float json.loads makes of it.
func Repr(v any) string {
	var b strings.Builder
	repr(&b, v)
	return b.String()
}

func repr(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("None")
	case bool:
		if x {
			b.WriteString("True")
		} else {
			b.WriteString("False")
		}
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case int:
		b.WriteString(strconv.Itoa(x))
	case *big.Int:
		b.WriteString(x.String())
	case float64:
		b.WriteString(FloatRepr(x))
	case json.Number:
		n, err := NumberString(x)
		if err != nil {
			n = string(x)
		}
		b.WriteString(n)
	case string:
		b.WriteString(StrRepr(x))
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(StrRepr(e))
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(StrRepr(k))
			b.WriteString(": ")
			repr(b, x[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			repr(b, e)
		}
		b.WriteByte(']')
	case *Map:
		b.WriteByte('{')
		for i := range x.Len() {
			if i > 0 {
				b.WriteString(", ")
			}
			k, e := x.At(i)
			repr(b, k)
			b.WriteString(": ")
			repr(b, e)
		}
		b.WriteByte('}')
	case Date:
		fmt.Fprintf(b, "datetime.date(%d, %d, %d)", x.Y, x.M, x.D)
	case DateTime:
		fmt.Fprintf(b, "datetime.datetime(%d, %d, %d, %d, %d", x.Y, x.M, x.D, x.H, x.Min)
		if x.S != 0 || x.Micro != 0 {
			fmt.Fprintf(b, ", %d", x.S)
		}
		if x.Micro != 0 {
			fmt.Fprintf(b, ", %d", x.Micro)
		}
		if x.Aware {
			b.WriteString(", tzinfo=")
			b.WriteString(tzRepr(x.Offset))
		}
		b.WriteByte(')')
	default:
		fmt.Fprintf(b, "%v", x)
	}
}

func tzRepr(off int) string {
	if off == 0 {
		return "datetime.timezone.utc"
	}
	// datetime.timedelta's repr normalises to days (possibly negative) and non-negative seconds.
	days, secs := off/86400, off%86400
	if secs < 0 {
		days--
		secs += 86400
	}
	if days != 0 {
		return fmt.Sprintf("datetime.timezone(datetime.timedelta(days=%d, seconds=%d))", days, secs)
	}
	return fmt.Sprintf("datetime.timezone(datetime.timedelta(seconds=%d))", secs)
}

// StrRepr is Python repr(str): single quotes unless the text holds a ' and no ", the escapes Python uses, and
// every character str.isprintable() refuses written as \x, \u or \U.
func StrRepr(s string) string {
	quote := byte('\'')
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		quote = '"'
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case !Printable(r):
			switch {
			case r < 0x100:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r < 0x10000:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// Printable is Python str.isprintable() for one character: not Cc, Cf, Cs, Co, Cn, Zl, Zp or Zs, except space.
func Printable(r rune) bool {
	if r == ' ' {
		return true
	}
	return unicode.IsPrint(r)
}

// IsSpace is Python str.isspace() for one character (which, unlike unicode.IsSpace, includes \x1c-\x1f).
func IsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', 0x1c, 0x1d, 0x1e, 0x1f, ' ', 0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// Strip is Python str.strip().
func Strip(s string) string { return strings.TrimFunc(s, IsSpace) }

// Len is Python len(str): code points.
func Len(s string) int { return utf8.RuneCountInString(s) }

// Lower is Python str.lower(): the full Unicode lowercase mapping, including U+0130's two-character one and the
// final-sigma rule, which strings.ToLower does not apply.
func Lower(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToLower(s)
	}
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		switch r {
		case 0x130:
			b.WriteString("i̇")
		case 0x3a3:
			if finalSigma(rs, i) {
				b.WriteRune(0x3c2)
			} else {
				b.WriteRune(0x3c3)
			}
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// finalSigma is Unicode's Final_Sigma condition, as CPython applies it: a cased letter before (skipping
// case-ignorable ones) and none after.
func finalSigma(rs []rune, i int) bool {
	before := false
	for j := i - 1; j >= 0; j-- {
		if caseIgnorable(rs[j]) {
			continue
		}
		before = cased(rs[j])
		break
	}
	if !before {
		return false
	}
	for j := i + 1; j < len(rs); j++ {
		if caseIgnorable(rs[j]) {
			continue
		}
		return !cased(rs[j])
	}
	return true
}

func cased(r rune) bool {
	return unicode.IsUpper(r) || unicode.IsLower(r) || unicode.IsTitle(r)
}

func caseIgnorable(r rune) bool {
	return unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf, unicode.Lm, unicode.Sk) ||
		r == '\'' || r == '.' || r == ':' || r == '^' || r == '`' || r == 0xb7 || r == 0x2019
}

// Truncate is Python s[:n] for n >= 0, on code points.
func Truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// FloatRepr is Python repr(float): the shortest round-tripping digits, fixed notation when the decimal exponent is
// in (-4, 16], scientific otherwise ("1.0", "1e-05", "1e+16", "-0.0"), and "inf", "-inf" or "nan". The digits are
// canon.PyFloat's, the one implementation; only the three non-finite spellings differ (canon writes JSON's).
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	return canon.PyFloat(f)
}
