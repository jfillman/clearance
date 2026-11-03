package client_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/server"
)

// The client's wire types are the core's, field for field: same JSON names, same omitempty, same shapes. The
// deliberate narrowings are listed in `equivalent`.
func TestWireTypesMirrorTheCore(t *testing.T) {
	pairs := []struct {
		client, core any
	}{
		{client.EvaluationRequest{}, decide.EvaluationRequest{}},
		{client.EvaluationResult{}, server.EvaluationResult{}},
		{client.OutcomeRequest{}, server.OutcomeRequest{}},
		{client.RecordRequest{}, server.RecordRequest{}},
		{client.DefinitionsRequest{}, server.DefinitionsRequest{}},
		{client.DefinitionsResult{}, server.DefinitionsResult{}},
		{client.RecordRef{}, server.RecordRef{}},
		{client.Change{}, gate.Change{}},
		{client.Decided{}, gate.Decided{}},
		{client.ObjectChange{}, gate.ObjectChange{}},
		{client.Verdict{}, provenance.Verdict{}},
		{client.Health{}, server.Health{}},
		{client.Ready{}, server.Ready{}},
	}
	for _, p := range pairs {
		ct, st := reflect.TypeOf(p.client), reflect.TypeOf(p.core)
		var diffs []string
		compare(ct, st, ct.Name(), &diffs, map[[2]reflect.Type]bool{})
		for _, d := range diffs {
			t.Errorf("%s vs %s: %s", ct, st, d)
		}
	}
	if !slices.Equal(client.RecordKinds, server.RecordKinds) {
		t.Errorf("RecordKinds %v, the core's %v", client.RecordKinds, server.RecordKinds)
	}
}

var (
	tTime   = reflect.TypeOf(time.Time{})
	tInt    = reflect.TypeOf(decide.Int{})
	tPyTime = reflect.TypeOf(gate.PyTime{})
	tRaw    = reflect.TypeOf(json.RawMessage(nil))
	tAny    = reflect.TypeOf((*any)(nil)).Elem()
)

// equivalent are the type pairs that differ on purpose (types.go's header).
func equivalent(c, s reflect.Type, path string) bool {
	switch {
	case s == tInt && c.Kind() == reflect.Int64:
		return true
	case s == tPyTime && c.Kind() == reflect.String:
		return true
	case s == tAny && path == "Verdict.audit_seq" && c == reflect.TypeOf((*int64)(nil)):
		return true // provenance's audit_seq is a seq or absent
	case s == tAny && path == "Decided.audit_seq" && c.Kind() == reflect.Int64:
		return true // the gate's audit_seq is the record's seq
	}
	return false
}

type field struct {
	name string
	omit bool
	typ  reflect.Type
}

// jsonFields are t's JSON fields, embedded structs flattened as encoding/json does.
func jsonFields(t reflect.Type) []field {
	var out []field
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if tag == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			et := f.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			out = append(out, jsonFields(et)...)
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, field{name, strings.Contains(opts, "omitempty"), f.Type})
	}
	return out
}

func compare(c, s reflect.Type, path string, diffs *[]string, seen map[[2]reflect.Type]bool) {
	if equivalent(c, s, path) || c == s {
		return
	}
	if s == tTime || s == tRaw || c == tTime || c == tRaw {
		*diffs = append(*diffs, fmt.Sprintf("%s: %s vs %s", path, c, s))
		return
	}
	if c.Kind() != s.Kind() {
		*diffs = append(*diffs, fmt.Sprintf("%s: %s vs %s", path, c, s))
		return
	}
	key := [2]reflect.Type{c, s}
	if seen[key] {
		return
	}
	seen[key] = true
	switch c.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		compare(c.Elem(), s.Elem(), path+"[]", diffs, seen)
	case reflect.Map:
		compare(c.Key(), s.Key(), path+"{key}", diffs, seen)
		compare(c.Elem(), s.Elem(), path+"{}", diffs, seen)
	case reflect.Struct:
		cf, sf := jsonFields(c), jsonFields(s)
		byName := map[string]field{}
		for _, f := range sf {
			byName[f.name] = f
		}
		for _, f := range cf {
			g, ok := byName[f.name]
			if !ok {
				*diffs = append(*diffs, fmt.Sprintf("%s.%s: not a field of the core's type", path, f.name))
				continue
			}
			delete(byName, f.name)
			if f.omit != g.omit {
				*diffs = append(*diffs, fmt.Sprintf("%s.%s: omitempty %v, the core's %v", path, f.name, f.omit, g.omit))
			}
			compare(f.typ, g.typ, path+"."+f.name, diffs, seen)
		}
		for name := range byName {
			*diffs = append(*diffs, fmt.Sprintf("%s.%s: missing from the client's type", path, name))
		}
	}
}

// A drift the test must catch: a sanity check that compare is not vacuous.
func TestTheMirrorCheckCatchesADifference(t *testing.T) {
	type a struct {
		X string `json:"x"`
		Y int    `json:"y,omitempty"`
	}
	type b struct {
		X string `json:"x,omitempty"`
		Z int    `json:"z"`
	}
	var diffs []string
	compare(reflect.TypeOf(a{}), reflect.TypeOf(b{}), "a", &diffs, map[[2]reflect.Type]bool{})
	if len(diffs) != 3 {
		t.Fatalf("want 3 differences (omitempty, extra, missing), got %v", diffs)
	}
}
