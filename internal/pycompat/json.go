package pycompat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/canon"
)

// Options select json.dumps' arguments.
type Options struct {
	// ASCII is ensure_ascii=True: every character outside space..~ is escaped as \uXXXX.
	ASCII bool
	// Spaced is the default separators (", ", ": "); false is separators=(",", ":").
	Spaced bool
	// KeepOrder is sort_keys=False: a *Map's keys in insertion order. The default is sort_keys=True. A
	// map[string]any is always written sorted (a Go map keeps no order).
	KeepOrder bool
}

// Dumps is json.dumps(v, ...) with the given options, over either value model. A *Map with a non-string key writes
// it as json.dumps does (its JSON text, quoted); sorting such a map is Python's TypeError. A Date or DateTime is not
// JSON serializable (json.dumps without default=). Any other Go value is normalised through encoding/json first.
//
// The evidence chain's canonical form is not this: it is canon.Canonical, which also refuses what Python's
// .encode() refuses (invalid UTF-8) and checks number literals; this is for the gate's other digests and messages.
func Dumps(v any, o Options) ([]byte, error) {
	var b bytes.Buffer
	if err := encode(&b, v, o); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// DumpsLen is len(json.dumps(v)) with Python's defaults (ensure_ascii, ", " and ": ", no sort), in characters.
func DumpsLen(v any) (int, error) {
	b, err := Dumps(v, Options{ASCII: true, Spaced: true, KeepOrder: true})
	if err != nil {
		return 0, err
	}
	return len(b), nil // ensure_ascii output is all ASCII: bytes are characters
}

// ArgsDigest is audit.args_digest: the sha256 of the canonical JSON of v. v may be any Go value encoding/json
// can marshal; it is normalised through JSON first, so a struct digests as its JSON object. It is "" when v has
// no JSON form (canon.ArgsDigest, which this wraps, returns the error instead).
func ArgsDigest(v any) string {
	n, err := Normalize(v)
	if err != nil {
		return ""
	}
	d, err := canon.ArgsDigest(n)
	if err != nil {
		return ""
	}
	return d
}

// Normalize turns any marshalable Go value into the generic JSON value encoding/json decodes (with UseNumber).
func Normalize(v any) (any, error) {
	switch v.(type) {
	case nil, string, bool, json.Number, float64, map[string]any, []any:
		return v, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canon.Parse(raw)
}

// Decode reads exactly one JSON value the way json.loads does, into the JSON model (canon.Parse: map[string]any,
// numbers as json.Number, trailing data refused). DecodeJSON is the same for the dict model.
func Decode(r io.Reader) (any, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return canon.Parse(raw)
}

func encode(b *bytes.Buffer, v any, o Options) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, x, o.ASCII)
	case json.Number:
		s, err := NumberString(x)
		if err != nil {
			return err
		}
		switch s {
		case "inf":
			b.WriteString("Infinity")
		case "-inf":
			b.WriteString("-Infinity")
		case "nan":
			b.WriteString("NaN")
		default:
			b.WriteString(s)
		}
	case float64:
		b.WriteString(canon.PyFloat(x)) // NaN, Infinity, -Infinity as json.dumps writes them
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case *big.Int:
		b.WriteString(x.String())
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				sep(b, o, ',')
			}
			if err := encode(b, e, o); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				sep(b, o, ',')
			}
			writeString(b, e, o.ASCII)
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
				sep(b, o, ',')
			}
			writeString(b, k, o.ASCII)
			sep(b, o, ':')
			if err := encode(b, x[k], o); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case *Map:
		return encodeMap(b, x, o)
	case Date, DateTime:
		return fmt.Errorf("pycompat: %s is not JSON serializable", TypeName(v))
	default:
		n, err := Normalize(v)
		if err != nil {
			return err
		}
		if _, same := n.(map[string]any); !same {
			if _, same = n.([]any); !same {
				return fmt.Errorf("pycompat: cannot encode %T", v)
			}
		}
		return encode(b, n, o)
	}
	return nil
}

func encodeMap(b *bytes.Buffer, x *Map, o Options) error {
	idx := make([]int, x.Len())
	for i := range idx {
		idx[i] = i
	}
	if !o.KeepOrder {
		for _, k := range x.keys {
			if _, ok := k.(string); !ok {
				return errors.New("pycompat: sort_keys over a non-string key")
			}
		}
		sort.SliceStable(idx, func(a, c int) bool { return x.keys[idx[a]].(string) < x.keys[idx[c]].(string) })
	}
	b.WriteByte('{')
	for n, i := range idx {
		if n > 0 {
			sep(b, o, ',')
		}
		k := x.keys[i]
		ks, ok := k.(string)
		if !ok {
			// json.dumps writes a bool, None or number key as its JSON text in quotes.
			var kb bytes.Buffer
			if err := encode(&kb, k, o); err != nil {
				return err
			}
			ks = kb.String()
		}
		writeString(b, ks, o.ASCII)
		sep(b, o, ':')
		if err := encode(b, x.vals[i], o); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

func sep(b *bytes.Buffer, o Options, c byte) {
	b.WriteByte(c)
	if o.Spaced {
		b.WriteByte(' ')
	}
}

const hexDigits = "0123456789abcdef"

// writeString is json.dumps' string encoder: '"', '\\' and the short escapes, other controls as \u00XX, and with
// ascii every character past '~' (DEL included) as \uXXXX, a surrogate pair beyond the BMP. Invalid UTF-8 is
// written as U+FFFD (a Python str cannot hold it).
func writeString(b *bytes.Buffer, s string, ascii bool) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || (ascii && r > 0x7e):
				if r >= 0x10000 {
					r -= 0x10000
					u4(b, 0xd800|(r>>10))
					u4(b, 0xdc00|(r&0x3ff))
				} else {
					u4(b, r)
				}
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func u4(b *bytes.Buffer, r rune) {
	b.WriteString(`\u`)
	b.WriteByte(hexDigits[r>>12&0xf])
	b.WriteByte(hexDigits[r>>8&0xf])
	b.WriteByte(hexDigits[r>>4&0xf])
	b.WriteByte(hexDigits[r&0xf])
}

// ASCIIEscape rewrites every non-ASCII character in JSON text as \uXXXX (what ensure_ascii=True adds to output
// encoding/json produced with SetEscapeHTML(false)). Only string contents can hold them, so a byte-level pass is safe.
func ASCIIEscape(in []byte) []byte {
	var b bytes.Buffer
	for len(in) > 0 {
		r, n := utf8.DecodeRune(in)
		switch {
		case r == 0x7f:
			b.WriteString(`\u007f`)
		case r < 0x80:
			b.WriteByte(byte(r))
		case r > 0xffff:
			r -= 0x10000
			u4(&b, 0xd800+(r>>10))
			u4(&b, 0xdc00+(r&0x3ff))
		default:
			u4(&b, r)
		}
		in = in[n:]
	}
	return b.Bytes()
}

// NumberString is Python's str() of the number json.loads would make of n: an int's decimal, a float's repr
// ("inf", "-inf" or "nan" for the out-of-range ones).
func NumberString(n json.Number) (string, error) {
	if isIntLiteral(string(n)) {
		z, ok := new(big.Int).SetString(string(n), 10)
		if !ok {
			return "", fmt.Errorf("pycompat: bad number %q", n)
		}
		return z.String(), nil
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return "", err
	}
	return FloatRepr(f), nil
}
