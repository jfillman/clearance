package describe

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/schemas"
)

func body(t *testing.T, over func(m map[string]any)) map[string]any {
	t.Helper()
	d := vectorDescription(vectorItems(3), map[string]any{"engine": "postgres"})
	d.Subject.Root, _ = Merkle1(d.Items, d.Subject.Facts)
	raw, _ := json.Marshal(d)
	v, err := pycompat.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if over != nil {
		over(m)
	}
	return m
}

func sub(m map[string]any, k string) map[string]any { return m[k].(map[string]any) }
func item0(m map[string]any) map[string]any         { return m["items"].([]any)[0].(map[string]any) }

// The parser and schemas/change-description.schema.json agree on what is a description: what one accepts the other
// does (the checks only the parser makes, unique items and canonical values, are tested apart).
func TestTheDescriptionSchemaMatchesTheParser(t *testing.T) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemas.ChangeDescriptionV1))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	url := schemas.SchemaID("change-description", 1)
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string]map[string]any{
		"valid":                  body(t, nil),
		"no items":               body(t, func(m map[string]any) { m["items"] = []any{} }),
		"no facts":               body(t, func(m map[string]any) { delete(sub(m, "subject"), "facts") }),
		"a built-in kind":        body(t, func(m map[string]any) { sub(m, "subject")["kind"] = "terraform-plan" }),
		"no scope":               body(t, func(m map[string]any) { delete(sub(m, "target"), "scope") }),
		"an app":                 body(t, func(m map[string]any) { sub(m, "target")["app"] = "gate-api" }),
		"a pushed commit":        body(t, func(m map[string]any) { delete(sub(m, "source"), "pr") }),
		"a hash":                 body(t, func(m map[string]any) { item0(m)["hash"] = strings.Repeat("a", 64) }),
		"attrs":                  body(t, func(m map[string]any) { item0(m)["attrs"] = map[string]any{"rows": json.Number("3")} }),
		"unknown top field":      body(t, func(m map[string]any) { m["summary"] = map[string]any{} }),
		"unknown subject field":  body(t, func(m map[string]any) { sub(m, "subject")["digests"] = map[string]any{} }),
		"unknown item field":     body(t, func(m map[string]any) { item0(m)["value"] = "x" }),
		"no describedBy":         body(t, func(m map[string]any) { delete(m, "describedBy") }),
		"an unknown op":          body(t, func(m map[string]any) { item0(m)["op"] = "unchanged" }),
		"a destroy op":           body(t, func(m map[string]any) { item0(m)["op"] = "destroy" }),
		"version 0":              body(t, func(m map[string]any) { sub(m, "subject")["version"] = json.Number("0") }),
		"a version string":       body(t, func(m map[string]any) { sub(m, "subject")["version"] = "1" }),
		"an upper-case kind":     body(t, func(m map[string]any) { sub(m, "subject")["kind"] = "IO.Acme.X" }),
		"a bad rootFn":           body(t, func(m map[string]any) { sub(m, "subject")["rootFn"] = "merkle" }),
		"a prefixed root":        body(t, func(m map[string]any) { sub(m, "subject")["root"] = "sha256:" + strings.Repeat("a", 64) }),
		"an upper-case hash":     body(t, func(m map[string]any) { item0(m)["hash"] = strings.Repeat("A", 64) }),
		"a value in fields":      body(t, func(m map[string]any) { item0(m)["fields"] = []any{"password=x"} }),
		"a bad attr name":        body(t, func(m map[string]any) { item0(m)["attrs"] = map[string]any{"1x": true} }),
		"a control char in id":   body(t, func(m map[string]any) { item0(m)["id"] = "a\nb" }),
		"no environment":         body(t, func(m map[string]any) { delete(sub(m, "target"), "environment") }),
		"a short commit":         body(t, func(m map[string]any) { sub(m, "source")["commit"] = "abc" }),
		"a negative pr":          body(t, func(m map[string]any) { sub(m, "source")["pr"] = json.Number("-1") }),
		"no provider":            body(t, func(m map[string]any) { sub(m, "describedBy")["provider"] = "" }),
		"items not a list":       body(t, func(m map[string]any) { m["items"] = map[string]any{} }),
		"facts not an object":    body(t, func(m map[string]any) { sub(m, "subject")["facts"] = []any{} }),
		"an empty type":          body(t, func(m map[string]any) { item0(m)["type"] = "" }),
		"a repo without a slash": body(t, func(m map[string]any) { sub(m, "source")["repo"] = "repo" }),
		"a null app":             body(t, func(m map[string]any) { sub(m, "target")["app"] = nil }),
		"an empty app":           body(t, func(m map[string]any) { sub(m, "target")["app"] = "" }),
		"null facts":             body(t, func(m map[string]any) { sub(m, "subject")["facts"] = nil }),
		"null attrs":             body(t, func(m map[string]any) { item0(m)["attrs"] = nil }),
		"null fields":            body(t, func(m map[string]any) { item0(m)["fields"] = nil }),
		"a null pr":              body(t, func(m map[string]any) { sub(m, "source")["pr"] = nil }),
		"a null scope":           body(t, func(m map[string]any) { sub(m, "target")["scope"] = nil }),
		"an empty version":       body(t, func(m map[string]any) { sub(m, "describedBy")["version"] = "" }),
		"a bad pointer escape":   body(t, func(m map[string]any) { item0(m)["fields"] = []any{"/metadata/a~2b"} }),
		"a good pointer escape":  body(t, func(m map[string]any) { item0(m)["fields"] = []any{"/metadata/labels/app.kubernetes.io~1name~0x"} }),
		"the largest version":    body(t, func(m map[string]any) { sub(m, "subject")["version"] = json.Number("1048576") }),
		"one past it":            body(t, func(m map[string]any) { sub(m, "subject")["version"] = json.Number("1048577") }),
	}
	accepted := 0
	for name, b := range bodies {
		_, perr := Parse(b)
		verr := sch.Validate(any(b))
		if (perr == nil) != (verr == nil) {
			t.Errorf("%s: parser %v, schema %v", name, perr, verr)
		}
		if perr == nil {
			accepted++
		}
	}
	if accepted != 11 {
		t.Errorf("%d of %d accepted, want 11 (the comparison would be vacuous)", accepted, len(bodies))
	}
	// What only the parser checks: an item twice.
	twice := body(t, func(m map[string]any) { m["items"] = append(m["items"].([]any), item0(m)) })
	if _, err := Parse(twice); err == nil || sch.Validate(any(twice)) != nil {
		t.Fatalf("an item twice: parser %v", err)
	}
}

func TestSummariesAreDerivedFromItems(t *testing.T) {
	d := vectorDescription([]Item{{Type: "t", ID: "a", Op: OpCreate}, {Type: "t", ID: "b", Op: OpDelete}, {Type: "t", ID: "c", Op: OpDelete},
		{Type: "t", ID: "d", Op: OpReplace}, {Type: "t", ID: "e", Op: OpUpdate}}, nil)
	s := d.Summarize()
	if s.Create != 1 || s.Update != 1 || s.Delete != 2 || s.Replace != 1 || strings.Join(s.Deleted, ",") != "b,c" {
		t.Fatalf("%+v", s)
	}
	if s := vectorDescription(nil, nil).Summarize(); s.Deleted == nil || s.Create+s.Update+s.Delete+s.Replace != 0 {
		t.Fatalf("%+v", s)
	}
}

// merkle/1: the order items are listed in does not change the root; every member of every item, and every fact, does.
func TestMerkle1BindsEveryMemberAndNoOrder(t *testing.T) {
	items := []Item{{Type: "table", ID: "a", Op: OpUpdate, Fields: []string{"/c"}, Attrs: map[string]any{"rows": json.Number("1")}, Hash: strings.Repeat("1", 64)},
		{Type: "table", ID: "b", Op: OpCreate}, {Type: "index", ID: "a", Op: OpDelete}}
	facts := map[string]any{"engine": "postgres"}
	root, err := Merkle1(items, facts)
	if err != nil {
		t.Fatal(err)
	}
	rev := []Item{items[2], items[0], items[1]}
	if r, _ := Merkle1(rev, facts); r != root {
		t.Fatal("the root depends on item order")
	}
	mut := []func(*Item){
		func(i *Item) { i.Type = "view" }, func(i *Item) { i.ID = "z" }, func(i *Item) { i.Op = OpReplace },
		func(i *Item) { i.Fields = []string{"/d"} }, func(i *Item) { i.Attrs = map[string]any{"rows": json.Number("2")} },
		func(i *Item) { i.Hash = strings.Repeat("2", 64) },
	}
	for n, m := range mut {
		cp := append([]Item(nil), items...)
		m(&cp[0])
		if r, err := Merkle1(cp, facts); err != nil || r == root {
			t.Errorf("mutation %d does not change the root (%v)", n, err)
		}
	}
	if r, err := Merkle1(items, map[string]any{"engine": "mysql"}); err != nil || r == root {
		t.Errorf("the facts do not enter the root (%v)", err)
	}
	// No facts is {}: absent and empty facts are one root.
	a, _ := Merkle1(items, nil)
	b, _ := Merkle1(items, map[string]any{})
	if a != b || a == root {
		t.Fatal("absent and empty facts differ, or facts are ignored")
	}
	// An absent and an empty member hash the same.
	x, _ := ItemDigest(Item{Type: "t", ID: "i", Op: OpCreate})
	y, _ := ItemDigest(Item{Type: "t", ID: "i", Op: OpCreate, Fields: []string{}, Attrs: map[string]any{}})
	if !bytes.Equal(x, y) {
		t.Fatal("absent and empty members hash differently")
	}
	if _, err := Merkle1([]Item{items[1], items[1]}, nil); err == nil {
		t.Fatal("an item twice gives a root")
	}
}

// M is RFC 6962's: the same root the transparency-dev compact range (the ledger's) gives, for every size to 33, and
// every item's inclusion proof verifies, and fails for another item or another root.
func TestMerkle1IsRFC6962AndProvesEveryItem(t *testing.T) {
	for n := 0; n <= 33; n++ {
		items := make([]Item, n)
		for i := range items {
			items[i] = Item{Type: "t", ID: strings.Repeat("x", i+1), Op: OpCreate}
		}
		m, err := ItemsRoot(items)
		if err != nil {
			t.Fatal(err)
		}
		ds, _ := sortedDigests(items)
		rf := compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
		rng := rf.NewEmptyRange(0)
		for _, d := range ds {
			if err := rng.Append(rfc6962.DefaultHasher.HashLeaf(d), nil); err != nil {
				t.Fatal(err)
			}
		}
		want := rfc6962.DefaultHasher.EmptyRoot()
		if n > 0 {
			want, _ = rng.GetRootHash(nil)
		}
		if !bytes.Equal(m, want) {
			t.Fatalf("n=%d: M %x, RFC 6962 %x", n, m, want)
		}
		d := vectorDescription(items, map[string]any{"n": json.Number("1")})
		d.Subject.Root, _ = Merkle1(items, d.Subject.Facts)
		for i := range items {
			p, err := d.ProveItem(i)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyItem(d.Subject.Root, items[i], p); err != nil {
				t.Fatalf("n=%d item %d: %v", n, i, err)
			}
			other := Item{Type: "t", ID: "not-there", Op: OpCreate}
			if err := VerifyItem(d.Subject.Root, other, p); err == nil {
				t.Fatalf("n=%d: an item not in the change verifies", n)
			}
			if err := VerifyItem(strings.Repeat("0", 64), items[i], p); !errors.Is(err, ErrRootMismatch) {
				t.Fatalf("n=%d: another root verifies: %v", n, err)
			}
		}
	}
}

func TestVerifyRoot(t *testing.T) {
	d := vectorDescription(vectorItems(4), nil)
	d.Subject.Root, _ = Merkle1(d.Items, nil)
	if c, err := d.VerifyRoot(); !c || err != nil {
		t.Fatal(c, err)
	}
	d.Items[0].Op = OpDelete
	if _, err := d.VerifyRoot(); !errors.Is(err, ErrRootMismatch) {
		t.Fatal("a changed item keeps its root")
	}
	d.Subject.RootFn = RootPlan1
	if c, err := d.VerifyRoot(); c || err != nil {
		t.Fatal("plan/1 is carried, not computed", c, err)
	}
	d.Subject.RootFn = "merkle/2"
	if _, err := d.VerifyRoot(); err == nil {
		t.Fatal("an unknown root function verifies")
	}
}

// tree/1 is the manifest-tree digest as docs/gate.md defines it.
func TestTree1IsTheManifestTreeDigest(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	got := Tree1([]TreeEntry{{"v1", "Service", "ns", "web", b}, {"apps/v1", "Deployment", "ns", "web", a}, {"v1", "Namespace", "", "ns", a}})
	lines := "apps/v1/Deployment/ns/web:" + a + "\nv1/Namespace//ns:" + a + "\nv1/Service/ns/web:" + b
	if got != Plan1([]byte(lines)) {
		t.Fatal(got)
	}
	if Tree1(nil) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("the empty tree")
	}
	if _, err := hex.DecodeString(got); err != nil || len(got) != 64 {
		t.Fatal(got)
	}
}

func FuzzParseDescription(f *testing.F) {
	seed := vectorDescription(vectorItems(2), map[string]any{"a": true})
	seed.Subject.Root, _ = Merkle1(seed.Items, seed.Subject.Facts)
	raw, _ := json.Marshal(seed)
	if _, err := Parse(mustDecode(f, raw)); err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"subject":{},"items":[{"op":"create"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := pycompat.Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		d, err := Parse(v)
		if err != nil {
			return
		}
		if err := d.Validate(); err != nil {
			t.Fatalf("Parse accepted what Validate refuses: %v", err)
		}
		if _, err := Merkle1(d.Items, d.Subject.Facts); err != nil {
			t.Fatalf("a parsed description has no merkle/1 root: %v", err)
		}
		_ = d.Summarize()
	})
}

func mustDecode(tb testing.TB, raw []byte) any {
	v, err := pycompat.Decode(bytes.NewReader(raw))
	if err != nil {
		tb.Fatal(err)
	}
	return v
}

// A root is the same whether a Go caller hashes float64(1) or a reader hashes the 1 it was written as; a number with
// no finite form is refused; a nil Items is written as []; and no proof is made against a stale root.
func TestHashesUseTheSerializedForm(t *testing.T) {
	d := vectorDescription([]Item{{Type: "t", ID: "a", Op: OpCreate, Attrs: map[string]any{"n": float64(1)}}}, map[string]any{"ratio": float64(2)})
	d.Subject.Root, _ = Merkle1(d.Items, d.Subject.Facts)
	raw, err := d.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(mustDecode(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := back.VerifyRoot(); !c || err != nil {
		t.Fatalf("the reader's root differs from the producer's: %v", err)
	}
	big := body(t, func(m map[string]any) { sub(m, "subject")["facts"] = map[string]any{"ratio": json.Number("1e400")} })
	if _, err := Parse(big); err == nil {
		t.Fatal("a non-finite number is accepted")
	}
	empty := vectorDescription(nil, nil)
	empty.Subject.Root, _ = Merkle1(nil, nil)
	if c, err := empty.MarshalCanonical(); err != nil || !bytes.Contains(c, []byte(`"items":[]`)) {
		t.Fatalf("%s %v", c, err)
	}
	stale := vectorDescription(vectorItems(3), map[string]any{"a": true})
	stale.Subject.Root, _ = Merkle1(stale.Items, stale.Subject.Facts)
	stale.Subject.Facts["a"] = false
	if _, err := stale.ProveItem(0); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("a proof against a stale root: %v", err)
	}
	for v, ok := range map[int]bool{1: true, MaxVersion: true, MaxVersion + 1: false, 0: false} {
		dv := vectorDescription(nil, nil)
		dv.Subject.Version = v
		dv.Subject.Root, _ = Merkle1(nil, nil)
		if err := dv.Validate(); (err == nil) != ok {
			t.Errorf("version %d: %v", v, err)
		}
	}
	deep := any("x")
	for i := 0; i < canon.MaxDepth-1; i++ {
		deep = []any{deep}
	}
	dd := vectorDescription([]Item{{Type: "t", ID: "a", Op: OpCreate, Attrs: map[string]any{"deep": deep}}}, nil)
	dd.Subject.Root = strings.Repeat("0", 64)
	if err := dd.Validate(); err == nil {
		t.Fatal("attrs too deep to serialize in the description are accepted")
	}
}
