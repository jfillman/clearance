package pyval

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxDepth bounds how deeply nested a decoded JSON value may be.
const MaxDepth = 64

// ErrDepth is returned for JSON nested deeper than MaxDepth.
var ErrDepth = errors.New("pyval: JSON nested too deeply")

// DecodeJSON decodes one JSON value as Python's json.loads would: objects into *Map in document order (a key set
// twice keeps its first position and its last value), integers exactly (int64, or *big.Int beyond it), other
// numbers as float64 (one too large for a float is ±inf, as in Python). Trailing data is an error.
func DecodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("pyval: trailing data after JSON value")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, ErrDepth
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := NewMap(4)
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("pyval: object key is not a string")
				}
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				m.Set(k, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return m, nil
		case '[':
			l := []any{}
			for dec.More() {
				v, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return l, nil
		}
		return nil, fmt.Errorf("pyval: unexpected %v", t)
	case json.Number:
		return Number(string(t))
	case string, bool, nil:
		return t, nil
	}
	return nil, fmt.Errorf("pyval: unexpected token %T", tok)
}

// Number converts a JSON number literal the way Python's json module does.
func Number(s string) (any, error) {
	if !strings.ContainsAny(s, ".eE") {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i, nil
		}
		b, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("pyval: bad integer %q", s)
		}
		return b, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, err
	}
	return f, nil
}

// DumpsLen is len(json.dumps(v)) with Python's defaults (ensure_ascii, ", " and ": "), in characters.
func DumpsLen(v any) (int, error) {
	var b bytes.Buffer
	if err := dump(&b, v, dumpOpts{ascii: true, item: ", ", kv: ": "}); err != nil {
		return 0, err
	}
	return b.Len(), nil // ensure_ascii output is all ASCII: bytes are characters
}

type dumpOpts struct {
	sortKeys, ascii bool
	item, kv        string
}

func dump(b *bytes.Buffer, v any, o dumpOpts) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case *big.Int:
		b.WriteString(x.String())
	case float64:
		switch {
		case math.IsNaN(x):
			b.WriteString("NaN")
		case math.IsInf(x, 1):
			b.WriteString("Infinity")
		case math.IsInf(x, -1):
			b.WriteString("-Infinity")
		default:
			b.WriteString(FloatRepr(x))
		}
	case string:
		dumpString(b, x, o.ascii)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(o.item)
			}
			if err := dump(b, e, o); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *Map:
		idx := make([]int, x.Len())
		for i := range idx {
			idx[i] = i
		}
		if o.sortKeys {
			for _, k := range x.keys {
				if _, ok := k.(string); !ok {
					return errors.New("pyval: sort_keys over a non-string key")
				}
			}
			sort.SliceStable(idx, func(a, c int) bool { return x.keys[idx[a]].(string) < x.keys[idx[c]].(string) })
		}
		b.WriteByte('{')
		for n, i := range idx {
			if n > 0 {
				b.WriteString(o.item)
			}
			k := x.keys[i]
			ks, ok := k.(string)
			if !ok {
				// json.dumps writes a bool, None or number key as its JSON text in quotes.
				var kb bytes.Buffer
				if err := dump(&kb, k, o); err != nil {
					return err
				}
				ks = kb.String()
			}
			dumpString(b, ks, o.ascii)
			b.WriteString(o.kv)
			if err := dump(b, x.vals[i], o); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("pyval: %s is not JSON serializable", TypeName(v))
	}
	return nil
}

const hexDigits = "0123456789abcdef"

func dumpString(b *bytes.Buffer, s string, ascii bool) {
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
			case r == utf8.RuneError:
				b.WriteRune(r)
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

// ToJSON converts a value to what encoding/json produces when decoding with UseNumber (map[string]any, []any,
// json.Number, string, bool, nil), for a store.Event. A non-string key is written as Python's json.dumps writes it.
func ToJSON(v any) any {
	switch x := v.(type) {
	case int64:
		return json.Number(strconv.FormatInt(x, 10))
	case *big.Int:
		return json.Number(x.String())
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return x
		}
		return json.Number(FloatRepr(x))
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = ToJSON(e)
		}
		return out
	case *Map:
		out := make(map[string]any, x.Len())
		for i := range x.Len() {
			k, e := x.At(i)
			ks, ok := k.(string)
			if !ok {
				ks = Repr(k)
			}
			out[ks] = ToJSON(e)
		}
		return out
	}
	return v
}
