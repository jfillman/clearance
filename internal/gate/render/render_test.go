package render

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// golden is register.py's own output over testdata/manifests (testdata/tricky.python.json, written by PyYAML 6.0.3
// and register.load_dir/canonical/images/tree_digest/objects): YAML 1.1 booleans, octal and sexagesimal ints,
// "1e3" as a string, timestamps as str(datetime), merges, big ints, non-ASCII escapes and a List's items.
type golden struct {
	Keys      [][]string          `json:"keys"`
	Canonical map[string]string   `json:"canonical"`
	Images    map[string][]string `json:"images"`
	Tree      string              `json:"tree"`
	Objects   []Object            `json:"objects"`
}

func TestLoadDirMatchesRegisterPy(t *testing.T) {
	raw, err := os.ReadFile("testdata/tricky.python.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	set, err := LoadDir("testdata/manifests")
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != len(g.Keys) || len(set) == 0 {
		t.Fatalf("%d objects, Python found %d", len(set), len(g.Keys))
	}
	for k, d := range set {
		id := strings.Join(k[:], "|")
		if got := canonical(d.Value); got != g.Canonical[id] {
			t.Errorf("%s:\n go %s\n py %s", id, got, g.Canonical[id])
		}
		if got := Images(d); !reflect.DeepEqual(got, g.Images[id]) && !(len(got) == 0 && len(g.Images[id]) == 0) {
			t.Errorf("%s images: %v, Python %v", id, got, g.Images[id])
		}
	}
	if got := TreeDigest(set); got != g.Tree {
		t.Errorf("tree %s, Python %s", got, g.Tree)
	}
	objs, err := Objects(Set{}, set)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(objs, g.Objects) {
		t.Errorf("objects:\n go %+v\n py %+v", objs, g.Objects)
	}
}

func TestSafeLoaderRefusals(t *testing.T) {
	for _, doc := range []string{"a: =\n", "a: !!python/object:os.system x\n", "a: !custom x\n", "a: 2026-02-31\n", "a: !!bool foo\n"} {
		if err := Add(Set{}, []byte(doc)); err == nil {
			t.Errorf("%q loaded; PyYAML's SafeLoader refuses it", doc)
		}
	}
}

func TestDiffPointers(t *testing.T) {
	a := map[string]any{"a": map[string]any{"b/c": int64(1), "x~": []any{int64(1), int64(2)}}, "same": true}
	b := map[string]any{"a": map[string]any{"b/c": 1.0, "x~": []any{int64(1)}, "new": "n"}, "same": true}
	if got := DiffPointers(a, b, ""); !reflect.DeepEqual(got, []string{"/a/new", "/a/x~0/1"}) {
		t.Fatal(got) // 1 == 1.0, as in Python
	}
	if got := DiffPointers("x", "y", ""); !reflect.DeepEqual(got, []string{"/"}) {
		t.Fatal(got)
	}
}

func FuzzRegisterDiff(f *testing.F) {
	seed, _ := os.ReadFile("testdata/manifests/tricky.yaml")
	f.Add(seed, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: tricky, namespace: ns}\ndata: {a: 1}\n"))
	f.Add([]byte("a: &x [*x]\n"), []byte("---\n---\n"))
	f.Add([]byte("apiVersion: v1\nkind: XList\nitems: [{apiVersion: v1, kind: K, metadata: {name: n}, spec: {<<: [{a: 1}, {b: 2}]}}]\n"), []byte{})
	f.Fuzz(func(t *testing.T, before, after []byte) {
		if len(before)+len(after) > 1<<16 {
			return
		}
		b, a := Set{}, Set{}
		if Add(b, before) != nil || Add(a, after) != nil {
			return
		}
		objs, err := Objects(b, a)
		if err != nil {
			return
		}
		again, _ := Objects(b, a)
		if !reflect.DeepEqual(objs, again) {
			t.Fatal("Objects is not deterministic")
		}
		_ = TreeDigest(a)
		if same, _ := Objects(a, a); len(same) != 0 {
			t.Fatal("a set differs from itself", same)
		}
	})
}

func TestAnAliasBombIsRefused(t *testing.T) {
	bomb := "a: &a [x,x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n" +
		"d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]\ne: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d,*d]\nf: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e,*e]\n" +
		"g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f,*f]\nh: [*g,*g,*g,*g,*g,*g,*g,*g,*g,*g]\n"
	if err := Add(Set{}, []byte(bomb)); err == nil {
		t.Fatal("a billion laughs loaded")
	}
}
