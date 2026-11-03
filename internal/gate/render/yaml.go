package render

import (
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/pyyaml"
)

// The documents of a rendered manifest file, read the way register.py reads them: yaml.safe_load_all, PyYAML's
// YAML 1.1 SafeLoader, which is internal/pyyaml (the core's one YAML loader: `yes` is True, `1e3` a string, `0755`
// octal, `1:30` sexagesimal, a timestamp a date, `<<` merges). This file only turns its dicts into the form the
// walks here use: each mapping keeps its key order (for images), with its keys as json.dumps writes them, and a
// date or datetime becomes str() of it (register.canonical's default=str).

// maxNodes bounds what one document may expand to through aliases (a "billion laughs" document).
const maxNodes = 1 << 20

// loadAll is yaml.safe_load_all: every document of the stream, ordered.
func loadAll(data []byte) ([]any, error) {
	docs, err := pyyaml.SafeLoadAll(string(data), maxNodes)
	if err != nil {
		return nil, err
	}
	for i, d := range docs {
		docs[i] = stringKeys(d)
	}
	return docs, nil
}

// stringKeys is v with every mapping's keys as json.dumps writes them (two keys that write the same keep the
// first's position and the last's value) and every date or datetime as its str().
func stringKeys(v any) any {
	switch x := v.(type) {
	case *pycompat.Map:
		m := pycompat.NewMap(x.Len())
		for i := range x.Len() {
			k, e := x.At(i)
			m.Set(keyString(k), stringKeys(e))
		}
		return m
	case []any:
		for i, e := range x {
			x[i] = stringKeys(e)
		}
		return x
	case pycompat.Date, pycompat.DateTime:
		return pycompat.Str(x)
	}
	return v
}

// keyString is a mapping key as json.dumps writes it: a string itself, else its JSON form (1, true, null), a date
// its str().
func keyString(k any) string {
	switch x := k.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	}
	b, err := pycompat.Dumps(k, pycompat.Options{})
	if err != nil {
		return pycompat.Str(k)
	}
	return string(b)
}

// get is m[key] for a mapping (nil for anything else).
func get(v any, key string) any {
	m, ok := v.(*pycompat.Map)
	if !ok {
		return nil
	}
	e, _ := m.Get(key)
	return e
}

// plain is the value with every mapping turned into a map[string]any.
func plain(v any) any {
	switch x := v.(type) {
	case *pycompat.Map:
		m := make(map[string]any, x.Len())
		for i := range x.Len() {
			k, e := x.At(i)
			m[k.(string)] = plain(e)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = plain(e)
		}
		return out
	}
	return v
}
