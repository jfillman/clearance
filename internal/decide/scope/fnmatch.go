package scope

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// FnmatchCase is Python's fnmatch.fnmatchcase(name, pat): `*` matches anything (including `/` and newlines), `?`
// one character, `[...]` a class (`[!...]` negated). A pattern whose class Go cannot compile matches nothing.
func (c *Globs) FnmatchCase(name, pat string) bool {
	re := c.get(&c.fn, pat, func() string { return translate(pat) })
	return re.MatchString(name)
}

// translate is fnmatch.translate for the patterns allowlists use.
func translate(pat string) string {
	var b strings.Builder
	b.WriteString(`\A(?s:`)
	lastStar := false
	for i := 0; i < len(pat); {
		ch := pat[i]
		switch ch {
		case '*':
			if !lastStar {
				b.WriteString(".*")
			}
			lastStar = true
			i++
			continue
		case '?':
			b.WriteString(".")
			i++
		case '[':
			j := i + 1
			if j < len(pat) && pat[j] == '!' {
				j++
			}
			if j < len(pat) && pat[j] == ']' {
				j++
			}
			for j < len(pat) && pat[j] != ']' {
				j++
			}
			if j >= len(pat) {
				b.WriteString(`\[`)
				i++
				break
			}
			stuff := pat[i+1 : j]
			i = j + 1
			switch {
			case stuff == "":
				b.WriteString(`[^\x00-\x{10FFFF}]`) // never matches
			case stuff == "!":
				b.WriteString(".")
			default:
				neg := false
				if stuff[0] == '!' {
					neg, stuff = true, stuff[1:]
				}
				var cls strings.Builder
				for _, r := range stuff {
					if r == '-' {
						cls.WriteRune(r)
						continue
					}
					cls.WriteString(regexp.QuoteMeta(string(r)))
				}
				b.WriteByte('[')
				if neg {
					b.WriteByte('^')
				}
				b.WriteString(cls.String())
				b.WriteByte(']')
			}
		default:
			_, size := utf8.DecodeRuneInString(pat[i:])
			b.WriteString(regexp.QuoteMeta(pat[i : i+size]))
			i += size
		}
		lastStar = false
	}
	b.WriteString(`)\z`)
	return b.String()
}
