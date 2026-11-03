package pycompat

import (
	"math"
	"math/big"
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
	if n, ok := numeric(v); ok {
		v = n // a json.Number or a Go int hashes as the Python number it is
	}
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
