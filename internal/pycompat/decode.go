package pycompat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/jfillman/clearance/internal/canon"
)

// MaxDepth bounds how deeply nested a decoded JSON value may be.
const MaxDepth = 64

// ErrDepth is returned for JSON nested deeper than MaxDepth.
var ErrDepth = errors.New("pycompat: JSON nested too deeply")

// DecodeJSON decodes one JSON value into the dict model (*Map) as Python's json.loads would: objects into *Map in document order (a key set
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
		return nil, errors.New("pycompat: trailing data after JSON value")
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
					return nil, errors.New("pycompat: object key is not a string")
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
		return nil, fmt.Errorf("pycompat: unexpected %v", t)
	case json.Number:
		return parseNumber(string(t))
	case string, bool, nil:
		return t, nil
	}
	return nil, fmt.Errorf("pycompat: unexpected token %T", tok)
}

// isIntLiteral says whether a JSON number literal is an int to json.loads.
func isIntLiteral(lit string) bool { return !canon.IsFloatLiteral(lit) }

// parseNumber converts a JSON number literal the way Python's json module does: an int exactly (int64, or *big.Int
// beyond it; longer than canon.MaxIntDigits digits is refused, as json.loads refuses it), any other literal a float
// (one too large is ±inf).
func parseNumber(s string) (any, error) {
	if isIntLiteral(s) {
		if len(strings.TrimPrefix(s, "-")) > canon.MaxIntDigits {
			return nil, fmt.Errorf("pycompat: integer literal exceeds Python's limit of %d digits", canon.MaxIntDigits)
		}
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i, nil
		}
		b, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("pycompat: bad integer %q", s)
		}
		return b, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, err
	}
	return f, nil
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
