package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"sort"
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
	// The tree is the manifest-tree digest (not register.py's, which hashed the canonical documents themselves):
	// recomputed here from Python's canonical forms, so the definition is checked independently of TreeDigest.
	var lines []string
	for _, k := range g.Keys {
		sum := sha256.Sum256([]byte(g.Canonical[strings.Join(k, "|")]))
		lines = append(lines, strings.Join(k, "/")+":"+hex.EncodeToString(sum[:]))
	}
	sort.Strings(lines)
	want := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	if got := TreeDigest(set); got != hex.EncodeToString(want[:]) {
		t.Errorf("tree %s, want %x", got, want)
	}
	objs, err := Objects(Set{}, set)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(objs, g.Objects) {
		t.Errorf("objects:\n go %+v\n py %+v", objs, g.Objects)
	}
}

// TestTreeDigestIsGlidepaths: the manifest-tree digest of testdata/parity is the tree Glidepath's clearance-gate check
// computes for the same render (its Python, run over app.yaml with PyYAML 6.0.3 on 2026-11-03:
// sha256("\n".join(sorted(f"{apiVersion}/{kind}/{namespace}/{name}:{sha256(canonical json)}")))), so `clearance
// register`, the Tekton check and the Argo CD plugin bind a change to the same digest.
func TestTreeDigestIsGlidepaths(t *testing.T) {
	set, err := LoadDir("testdata/parity")
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string]string{
		"apps/v1/Deployment/app-shop-prod/shop":                 "6bf2a416cc8bf2abebca0dda6c0f4793e284dfc3b04964e4178b98c5e3916a7a",
		"rbac.authorization.k8s.io/v1/ClusterRole//shop-reader": "2f8966b1556655c957622a418fd2aa4b1680078ed800bf2d4260f7ab67deab24",
		"v1/Service/app-shop-prod/shop":                         "d677c244ccd9ce9bdeaa0f00ae94da8e3620bf88b64e6a249a36662fd29f01bb",
	}
	if len(set) != len(objects) {
		t.Fatalf("%d objects, want %d", len(set), len(objects))
	}
	for k, d := range set {
		if got, want := ObjectDigest(d), objects[strings.Join(k[:], "/")]; got != want {
			t.Errorf("%v: %s, Glidepath %s", k, got, want)
		}
	}
	if got := TreeDigest(set); got != "27cbba8e2f2c096b28ffba850f594304e273c79145fd8f8e7ed3ee1337ec1238" {
		t.Errorf("tree %s", got)
	}
	// The order objects are read in does not matter; an empty render is sha256 of nothing.
	if got := TreeDigest(Set{}); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty tree %s", got)
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
