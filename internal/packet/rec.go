package packet

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Record is a stored chain record as read (numbers are json.Number).
type Record = map[string]any

func str(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

func obj(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	return v
}

func num(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), n == float64(int64(n))
	}
	return 0, false
}

func seqOf(r Record) int64 { n, _ := num(r["seq"]); return n }

func boolp(v any) *bool {
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

func i64p(v any) *int64 {
	if n, ok := num(v); ok {
		return &n
	}
	return nil
}

// verifiedField says whether the writer established field itself (the record's own `verified` list).
func verifiedField(r Record, field string) bool {
	vs, _ := r["verified"].([]any)
	for _, v := range vs {
		if v == field {
			return true
		}
	}
	return false
}

func strs(v any) []string {
	l, _ := v.([]any)
	var out []string
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// short is a compact one-line JSON form of v, cut at max runes.
func short(v any, max int) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return cut(s, max)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return cut(string(b), max)
}

func cut(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}

func ptr[T any](v T) *T { return &v }

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func addUnique(l []string, s string) []string {
	if s == "" {
		return l
	}
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}

func joinSeqs(l []int64) string {
	ss := make([]string, len(l))
	for i, n := range l {
		ss[i] = fmt.Sprint(n)
	}
	return strings.Join(ss, " ")
}

// opClass is the I-1 operational class of a record, only when the record carries it.
func opClass(r Record) []string { return strs(r["operational_class"]) }
