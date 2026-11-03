// Package pyval holds JSON and YAML values the way the Python engine sees them, so the Go engine's decisions,
// messages and hashes are the Python ones byte for byte.
//
// A value is one of: nil (None), bool, int64, *big.Int (an integer outside int64, which Python holds exactly),
// float64, string, []any (list), *Map (dict, insertion-ordered), Date or DateTime (PyYAML timestamps).
//
// Equality follows Python's: True == 1 == 1.0, a dict equals another with the same keys whatever their order,
// and NaN equals NaN only inside a container, where Python compares PyYAML's one shared NaN object by identity.
package pyval

import (
	"math"
	"math/big"
	"strconv"
)

// Map is a Python dict: keys in insertion order, a key set twice keeps its first position and its last value.
type Map struct {
	keys []any
	vals []any
	idx  map[hkey]int
}

// NewMap returns an empty Map with room for n entries.
func NewMap(n int) *Map {
	return &Map{keys: make([]any, 0, n), vals: make([]any, 0, n), idx: make(map[hkey]int, n)}
}

// Len is the number of keys.
func (m *Map) Len() int {
	if m == nil {
		return 0
	}
	return len(m.keys)
}

// Keys are the keys in insertion order. The slice is the Map's own; do not modify it.
func (m *Map) Keys() []any {
	if m == nil {
		return nil
	}
	return m.keys
}

// At is the i-th key and value in insertion order.
func (m *Map) At(i int) (any, any) { return m.keys[i], m.vals[i] }

// Set sets key to v (Python d[key] = v). It reports false when key is unhashable (a list or dict).
func (m *Map) Set(key, v any) bool {
	h, ok := hashKey(key)
	if !ok {
		return false
	}
	if i, dup := m.idx[h]; dup {
		m.vals[i] = v
		return true
	}
	m.idx[h] = len(m.keys)
	m.keys = append(m.keys, key)
	m.vals = append(m.vals, v)
	return true
}

// Get is Python d.get(key): the value and whether the key is present.
func (m *Map) Get(key any) (any, bool) {
	if m == nil {
		return nil, false
	}
	h, ok := hashKey(key)
	if !ok {
		return nil, false
	}
	i, found := m.idx[h]
	if !found {
		return nil, false
	}
	return m.vals[i], true
}

// GetStr is Get for a string key.
func (m *Map) GetStr(key string) (any, bool) { return m.Get(key) }

// Has reports whether key is present.
func (m *Map) Has(key any) bool {
	_, ok := m.Get(key)
	return ok
}

// Delete removes key (Python d.pop(key, None)).
func (m *Map) Delete(key any) {
	h, ok := hashKey(key)
	if !ok {
		return
	}
	i, found := m.idx[h]
	if !found {
		return
	}
	delete(m.idx, h)
	m.keys = append(m.keys[:i], m.keys[i+1:]...)
	m.vals = append(m.vals[:i], m.vals[i+1:]...)
	for j := i; j < len(m.keys); j++ {
		hj, _ := hashKey(m.keys[j])
		m.idx[hj] = j
	}
}

// Copy is a shallow copy.
func (m *Map) Copy() *Map {
	out := NewMap(m.Len())
	for i := range m.Len() {
		out.Set(m.keys[i], m.vals[i])
	}
	return out
}

// Date is a PyYAML date (datetime.date).
type Date struct{ Y, M, D int }

// DateTime is a PyYAML timestamp (datetime.datetime). Aware is false for a naive one; Offset is in seconds east.
type DateTime struct {
	Y, M, D, H, Min, S, Micro int
	Aware                     bool
	Offset                    int
}

func (t DateTime) instant() int64 {
	days := daysFromCivil(t.Y, t.M, t.D)
	return ((days*86400+int64(t.H*3600+t.Min*60+t.S))-int64(t.Offset))*1_000_000 + int64(t.Micro)
}

func daysFromCivil(y, m, d int) int64 {
	if m <= 2 {
		y--
	}
	era := y / 400
	if y < 0 && y%400 != 0 {
		era--
	}
	yoe := y - era*400
	mp := (m + 9) % 12
	doy := (153*mp+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return int64(era)*146097 + int64(doe) - 719468
}

// hkey is a Python hash-equality class: values that compare equal (True, 1, 1.0) share one.
type hkey struct {
	kind byte
	i    int64
	s    string
	f    float64
}

func hashKey(v any) (hkey, bool) {
	switch x := v.(type) {
	case nil:
		return hkey{kind: 0}, true
	case bool:
		if x {
			return hkey{kind: 1, i: 1}, true
		}
		return hkey{kind: 1}, true
	case int64:
		return hkey{kind: 1, i: x}, true
	case *big.Int:
		return hkey{kind: 2, s: x.String()}, true
	case float64:
		if math.IsNaN(x) {
			return hkey{kind: 4}, true // PyYAML's one NaN object: equal to itself by identity
		}
		if x == math.Trunc(x) && !math.IsInf(x, 0) {
			if x >= -9.223372036854775808e18 && x < 9.223372036854775808e18 {
				return hkey{kind: 1, i: int64(x)}, true
			}
			b, _ := new(big.Float).SetFloat64(x).Int(nil)
			return hkey{kind: 2, s: b.String()}, true
		}
		return hkey{kind: 3, f: x}, true
	case string:
		return hkey{kind: 5, s: x}, true
	case Date:
		return hkey{kind: 6, s: Str(x)}, true
	case DateTime:
		if x.Aware {
			return hkey{kind: 7, i: x.instant()}, true
		}
		return hkey{kind: 8, i: x.instant()}, true
	}
	return hkey{}, false
}

// IsInt reports whether v is a Python int that is not a bool.
func IsInt(v any) bool {
	switch v.(type) {
	case int64, *big.Int:
		return true
	}
	return false
}

func numeric(v any) bool {
	switch v.(type) {
	case bool, int64, *big.Int, float64:
		return true
	}
	return false
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
// ok is false when either is NaN.
func NumCmp(a, b any) (int, bool) {
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

// Eq is Python `a == b` at the top level: NaN is never equal to anything.
func Eq(a, b any) bool { return eq(a, b, true) }

// EqIn is Python's comparison of two container elements (`x is y or x == y`): PyYAML's NaN equals itself.
func EqIn(a, b any) bool { return eq(a, b, false) }

func eq(a, b any, direct bool) bool {
	if numeric(a) && numeric(b) {
		fa, aF := a.(float64)
		fb, bF := b.(float64)
		if aF && bF && math.IsNaN(fa) && math.IsNaN(fb) {
			return !direct
		}
		c, ok := NumCmp(a, b)
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

// Truthy is Python bool(v).
func Truthy(v any) bool {
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
	case *Map:
		return x.Len() > 0
	}
	return true
}

// TypeName is Python type(v).__name__.
func TypeName(v any) string {
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
	case []any:
		return "list"
	case *Map:
		return "dict"
	case Date:
		return "date"
	case DateTime:
		return "datetime"
	}
	return "object"
}

// FloatRepr is Python repr(float).
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	a := math.Abs(f)
	if a != 0 && (a < 1e-4 || a >= 1e16) {
		return strconv.FormatFloat(f, 'e', -1, 64)
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s
		}
	}
	return s + ".0"
}
