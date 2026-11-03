package pycompat

import (
	"encoding/json"
	"math"
	"math/big"
	"strconv"
)

// numeric is v as the Python number it is, in the dict model's types (bool, int64, *big.Int, float64), and
// whether it is one. A json.Number becomes an int or a float by its literal, as json.loads decides (a float literal
// too large for a float64 is ±inf, as in Python); a Go int becomes an int64.
func numeric(v any) (any, bool) {
	switch x := v.(type) {
	case bool, int64, *big.Int, float64:
		return v, true
	case int:
		return int64(x), true
	case json.Number:
		n, err := parseNumber(string(x))
		if err != nil {
			return nil, false
		}
		return n, true
	}
	return nil, false
}

// IsInt reports whether v is a Python int that is not a bool: an int64, *big.Int or Go int, or a json.Number
// whose literal json.loads makes an int (no '.', 'e' or 'E').
func IsInt(v any) bool {
	switch x := v.(type) {
	case int64, *big.Int, int:
		return true
	case json.Number:
		return isIntLiteral(string(x))
	}
	return false
}

// Number is a number's value as Python compares it, exactly: an int, a float (not NaN), or a bool (True == 1).
// A float literal too large for a float64 is ±Inf, as Python's float() makes it.
func Number(v any) (*big.Float, bool) {
	n, ok := numeric(v)
	if !ok {
		return nil, false
	}
	switch x := n.(type) {
	case bool:
		if x {
			return big.NewFloat(1), true
		}
		return big.NewFloat(0), true
	case int64:
		return new(big.Float).SetInt64(x), true
	case *big.Int:
		return new(big.Float).SetInt(x), true
	case float64:
		if math.IsNaN(x) {
			return nil, false
		}
		return big.NewFloat(x), true // ±Inf is a big.Float too
	}
	return nil, false
}

// AsInt is isinstance(v, int) and not isinstance(v, bool), with v's value when it fits an int64.
func AsInt(v any) (int64, bool) {
	if !IsInt(v) {
		return 0, false
	}
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func toRat(v any) (*big.Rat, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return big.NewRat(1, 1), true
		}
		return new(big.Rat), true
	case int64:
		return new(big.Rat).SetInt64(x), true
	case *big.Int:
		return new(big.Rat).SetInt(x), true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, false
		}
		return new(big.Rat).SetFloat64(x), true
	}
	return nil, false
}

// NumCmp compares two numbers exactly, as Python does (an int and a float are compared without rounding).
// ok is false when either is not a number or is NaN.
func NumCmp(a, b any) (int, bool) {
	a, aok := numeric(a)
	b, bok := numeric(b)
	if !aok || !bok {
		return 0, false
	}
	if fa, isF := a.(float64); isF && math.IsNaN(fa) {
		return 0, false
	}
	if fb, isF := b.(float64); isF && math.IsNaN(fb) {
		return 0, false
	}
	if ia, ok := smallInt(a); ok {
		if ib, ok := smallInt(b); ok {
			switch {
			case ia < ib:
				return -1, true
			case ia > ib:
				return 1, true
			}
			return 0, true
		}
	}
	fa, aInf := infSign(a)
	fb, bInf := infSign(b)
	if aInf || bInf {
		switch {
		case fa < fb:
			return -1, true
		case fa > fb:
			return 1, true
		}
		return 0, true
	}
	ra, _ := toRat(a)
	rb, _ := toRat(b)
	return ra.Cmp(rb), true
}

func smallInt(v any) (int64, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case int64:
		return x, true
	}
	return 0, false
}

func infSign(v any) (float64, bool) {
	if f, ok := v.(float64); ok && math.IsInf(f, 0) {
		return f, true
	}
	return 0, false
}

// Equal is Python `a == b` at the top level, over either value model: numbers by value (True == 1 == 1.0, an int
// and a float exactly), lists in order, dicts (a *Map or a map[string]any) by key whatever their order. NaN is never
// equal to anything at the top level.
func Equal(a, b any) bool { return eq(a, b, true) }

// EqualIn is Python's comparison of two container elements (`x is y or x == y`): PyYAML's one shared NaN object
// equals itself there.
func EqualIn(a, b any) bool { return eq(a, b, false) }

func eq(a, b any, direct bool) bool {
	if na, ok := numeric(a); ok {
		nb, ok := numeric(b)
		if !ok {
			return false
		}
		fa, aF := na.(float64)
		fb, bF := nb.(float64)
		if aF && bF && math.IsNaN(fa) && math.IsNaN(fb) {
			return !direct
		}
		c, ok := NumCmp(na, nb)
		return ok && c == 0
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
			if !eq(x[i], y[i], false) {
				return false
			}
		}
		return true
	case *Map:
		y, ok := b.(*Map)
		if !ok || x.Len() != y.Len() {
			return false
		}
		for i := range x.Len() {
			k, v := x.At(i)
			w, found := y.Get(k)
			if !found || !eq(v, w, false) {
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
			w, found := y[k]
			if !found || !eq(v, w, false) {
				return false
			}
		}
		return true
	case Date:
		y, ok := b.(Date)
		return ok && x == y
	case DateTime:
		y, ok := b.(DateTime)
		if !ok || x.Aware != y.Aware {
			return false
		}
		return x.instant() == y.instant()
	}
	return false
}

// Truthy is Python bool(v), over either value model.
func Truthy(v any) bool {
	if n, ok := numeric(v); ok {
		v = n
	}
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case *big.Int:
		return x.Sign() != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case []string:
		return len(x) > 0
	case *Map:
		return x.Len() > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// TypeName is Python type(v).__name__.
func TypeName(v any) string {
	if n, ok := numeric(v); ok {
		v = n
	}
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int64, *big.Int:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []any, []string:
		return "list"
	case *Map, map[string]any:
		return "dict"
	case Date:
		return "date"
	case DateTime:
		return "datetime"
	}
	return "object"
}
