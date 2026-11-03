package canon

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"
)

// Parse decodes one JSON value the way Python's json.loads does for everything the chain can hold, into the
// values Canonical takes: nil, bool, string, json.Number (the literal, unchanged), []any, map[string]any. A
// duplicate key keeps its last value, as in Python.
//
// It is stricter than json.loads where json.loads would accept something the chain cannot hold or that
// Canonical could not reproduce: NaN/Infinity tokens, a lone surrogate escape (json.loads accepts it, then
// canonical's .encode() raises), invalid UTF-8, an integer literal over MaxIntDigits digits (json.loads raises
// too), or nesting deeper than MaxDepth. encoding/json is not used because it replaces invalid UTF-8 and lone
// surrogates with U+FFFD, which would hash a different string than the one stored.
func Parse(data []byte) (any, error) {
	p := parser{s: data}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, p.errf("extra data")
	}
	return v, nil
}

type parser struct {
	s []byte
	i int
}

func (p *parser) errf(format string, a ...any) error {
	return fmt.Errorf("canon: parse at byte %d: %s", p.i, fmt.Sprintf(format, a...))
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) lit(word string, v any) (any, error) {
	if len(p.s)-p.i >= len(word) && string(p.s[p.i:p.i+len(word)]) == word {
		p.i += len(word)
		return v, nil
	}
	return nil, p.errf("invalid literal")
}

func (p *parser) value(depth int) (any, error) {
	if depth > MaxDepth {
		return nil, p.errf("nesting deeper than %d", MaxDepth)
	}
	if p.i >= len(p.s) {
		return nil, p.errf("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.str()
	case c == 't':
		return p.lit("true", true)
	case c == 'f':
		return p.lit("false", false)
	case c == 'n':
		return p.lit("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		end, ok := scanNumber(p.s[p.i:], 0)
		if !ok {
			return nil, p.errf("invalid number")
		}
		lit := string(p.s[p.i : p.i+end])
		if !IsFloatLiteral(lit) {
			d := len(lit)
			if lit[0] == '-' {
				d--
			}
			if d > MaxIntDigits {
				return nil, p.errf("integer literal of %d digits exceeds Python's limit of %d", d, MaxIntDigits)
			}
		}
		p.i += end
		return json.Number(lit), nil
	default:
		return nil, p.errf("unexpected character %q", c)
	}
}

func (p *parser) object(depth int) (any, error) {
	p.i++ // {
	m := map[string]any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return m, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.errf("expected a key")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.errf("expected ':'")
		}
		p.i++
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		m[k.(string)] = v
		p.ws()
		if p.i >= len(p.s) {
			return nil, p.errf("unterminated object")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return m, nil
		default:
			return nil, p.errf("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (any, error) {
	p.i++ // [
	a := []any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return a, nil
	}
	for {
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		a = append(a, v)
		p.ws()
		if p.i >= len(p.s) {
			return nil, p.errf("unterminated array")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return a, nil
		default:
			return nil, p.errf("expected ',' or ']'")
		}
	}
}

var errLoneSurrogate = errors.New("lone surrogate escape (Python's canonical cannot encode it)")

func (p *parser) hex4() (rune, bool) {
	if len(p.s)-p.i < 4 {
		return 0, false
	}
	n, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	p.i += 4
	return rune(n), true
}

func (p *parser) str() (any, error) {
	p.i++ // "
	var out []byte
	start := p.i
	for {
		if p.i >= len(p.s) {
			return nil, p.errf("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			out = append(out, p.s[start:p.i]...)
			p.i++
			return string(out), nil
		case c < 0x20:
			return nil, p.errf("invalid control character in string")
		case c == '\\':
			out = append(out, p.s[start:p.i]...)
			p.i++
			if p.i >= len(p.s) {
				return nil, p.errf("unterminated escape")
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, ok := p.hex4()
				if !ok {
					return nil, p.errf("invalid \\u escape")
				}
				if r >= 0xdc00 && r <= 0xdfff {
					return nil, p.errf("%v", errLoneSurrogate)
				}
				if r >= 0xd800 && r <= 0xdbff {
					// Python pairs a high surrogate only with an immediately following \uDC00-\uDFFF.
					if len(p.s)-p.i < 6 || p.s[p.i] != '\\' || p.s[p.i+1] != 'u' {
						return nil, p.errf("%v", errLoneSurrogate)
					}
					save := p.i
					p.i += 2
					lo, ok := p.hex4()
					if !ok {
						p.i = save
						return nil, p.errf("invalid \\u escape")
					}
					if lo < 0xdc00 || lo > 0xdfff {
						return nil, p.errf("%v", errLoneSurrogate)
					}
					r = 0x10000 + (r-0xd800)<<10 + (lo - 0xdc00)
				}
				out = utf8.AppendRune(out, r)
			default:
				return nil, p.errf("invalid escape \\%c", e)
			}
			start = p.i
		case c < utf8.RuneSelf:
			p.i++
		default:
			r, size := utf8.DecodeRune(p.s[p.i:])
			if r == utf8.RuneError && size <= 1 {
				return nil, p.errf("invalid UTF-8")
			}
			p.i += size
		}
	}
}
