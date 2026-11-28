package describe

// The golden vectors (refinement 7): schemas/vectors/canon-v1.json and merkle-v1.json, which every SDK in any
// language reproduces byte for byte. internal/canon is the reference; this test holds the files equal to what it
// and the root functions give. `go test ./internal/describe -run TestGoldenVectors -update` rewrites them, for a new
// case only: a changed value in an existing case is a break in every SDK.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/jfillman/clearance/internal/canon"
)

var update = flag.Bool("update", false, "rewrite schemas/vectors from the vector cases")

const vectorsDir = "../../schemas/vectors/"

type canonVector struct {
	Name      string `json:"name"`
	Input     string `json:"input"`     // JSON text: number literals are part of the case
	Canonical string `json:"canonical"` // the canonical JSON, as text (UTF-8)
	SHA256    string `json:"sha256"`    // of the canonical bytes
}

var canonInputs = []struct{ name, in string }{
	{"empty object", `{}`},
	{"empty list", `[]`},
	{"scalars", `[null,true,false,0,-1,"s"]`},
	{"keys sort by code point", `{"b":1,"a":2,"B":3,"aa":4,"":5,"\u00e9":6,"e\u0301":7}`},
	{"keys beyond the BMP sort after U+FFFF", `{"￿":1,"𐀀":2,"":3}`},
	{"nesting keeps list order", `{"z":[3,1,2],"a":{"y":null,"x":[{"b":1,"a":0}]}}`},
	{"whitespace is dropped", "{ \"a\" : [ 1 , 2 ] ,\n\t\"b\" : { } }"},
	{"escapes: only quote, backslash and controls", `"q\" b\\ nl\n cr\r tab\t bs\b ff\f nul\u0000 us\u001f del` + "\u007f" + ` <>&"`},
	{"non-ASCII is written raw", `"é ü ✓ 😀   "`},
	{"solidus is not escaped", `"a\/b"`},
	{"integers keep their digits", `[0,-0,7,-42,12345678901234567890123456789]`},
	{"floats are Python's repr", `[1.0,1.5,-0.0,0.1,1e-05,0.0001,1e16,1e+16,1.5e300,123456789012345678.0,1E2]`},
	{"an integer-valued float stays a float", `[2.0,100.0,1e2]`},
	{"duplicate keys keep the last", `{"a":1,"a":2}`},
	{"an item, as merkle/1 hashes it", `{"type":"v1/ConfigMap","id":"ns/cm","op":"update","fields":["/data/x"],"attrs":{},"hash":""}`},
}

type merkleVector struct {
	Name        string       `json:"name"`
	Description *Description `json:"description"`
	ItemDigests []string     `json:"itemDigests"` // in item order
	ItemsRoot   string       `json:"itemsRoot"`   // M
	FactsDigest string       `json:"factsDigest"` // F
	Root        string       `json:"root"`        // sha256("clearance.subject/v1" ‖ M ‖ F)
	Proofs      []Inclusion  `json:"proofs"`      // one per item, in item order
}

func vectorDescription(items []Item, facts map[string]any) *Description {
	return &Description{
		Subject:     Subject{Kind: "io.example.db-migration", Version: 1, RootFn: RootMerkle1, Facts: facts},
		Target:      Target{Scope: "db-main", Environment: "prod"},
		Items:       items,
		Source:      Source{Repo: "example/migrations", Commit: "0123456789abcdef0123456789abcdef01234567", PR: 3},
		DescribedBy: DescribedBy{Provider: "example-gate", Version: "1.0.0"},
	}
}

func vectorItems(n int) []Item {
	out := make([]Item, n)
	for i := range out {
		out[i] = Item{Type: "table", ID: "public.t" + string(rune('a'+i)), Op: Ops[i%4], Fields: []string{"/columns/" + string(rune('a'+i))}}
	}
	return out
}

func merkleCases() []merkleVector {
	digest := Plan1([]byte("example content"))
	cases := []struct {
		name  string
		items []Item
		facts map[string]any
	}{
		{"no items, no facts", nil, nil},
		{"no items, facts", nil, map[string]any{"targeted": true, "schemaVersion": json.Number("42")}},
		{"one item", []Item{{Type: "table", ID: "public.users", Op: OpDelete}}, nil},
		{"one item with every member", []Item{{Type: "table", ID: "public.users", Op: OpUpdate, Fields: []string{"/columns/email", "/columns/name"},
			Attrs: map[string]any{"rows": json.Number("1200"), "locks": "exclusive", "online": false}, Hash: digest}}, map[string]any{"engine": "postgres"}},
		{"two items", vectorItems(2), nil},
		{"three items (an unbalanced tree)", vectorItems(3), nil},
		{"five items", vectorItems(5), map[string]any{"tool": map[string]any{"name": "flyway", "version": "10.0.0"}}},
		{"eight items (a full tree)", vectorItems(8), nil},
	}
	out := make([]merkleVector, 0, len(cases))
	for _, c := range cases {
		d := vectorDescription(c.items, c.facts)
		if d.Items == nil {
			d.Items = []Item{}
		}
		root, err := Merkle1(d.Items, d.Subject.Facts)
		if err != nil {
			panic(err)
		}
		d.Subject.Root = root
		v := merkleVector{Name: c.name, Description: d, Root: root, ItemDigests: []string{}, Proofs: []Inclusion{}}
		m, _ := ItemsRoot(d.Items)
		f, _ := FactsDigest(d.Subject.Facts)
		v.ItemsRoot, v.FactsDigest = hex.EncodeToString(m), hex.EncodeToString(f)
		for i, it := range d.Items {
			dg, _ := ItemDigest(it)
			v.ItemDigests = append(v.ItemDigests, hex.EncodeToString(dg))
			p, err := d.ProveItem(i)
			if err != nil {
				panic(err)
			}
			v.Proofs = append(v.Proofs, p)
		}
		out = append(out, v)
	}
	return out
}

func canonCases(t *testing.T) []canonVector {
	out := make([]canonVector, 0, len(canonInputs))
	for _, c := range canonInputs {
		v, err := canon.Parse([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		b, err := canon.Canonical(v)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		out = append(out, canonVector{c.name, c.in, string(b), canon.SHA256Hex(b)})
	}
	return out
}

func encodeVectors(t *testing.T, suite string, cases any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"suite": suite, "cases": cases}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestGoldenVectors(t *testing.T) {
	files := map[string][]byte{
		"canon-v1.json":  encodeVectors(t, "clearance.canon/v1", canonCases(t)),
		"merkle-v1.json": encodeVectors(t, RootMerkle1, merkleCases()),
	}
	for name, want := range files {
		if *update {
			if err := os.WriteFile(vectorsDir+name, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(vectorsDir + name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("schemas/vectors/%s is not what internal/canon and the root functions give (run with -update for a new case only)", name)
		}
	}
	// The committed vectors check themselves, read back as another SDK reads them: every proof verifies against the
	// root, and every description's root is recomputed from its items and facts.
	raw, err := os.ReadFile(vectorsDir + "merkle-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var mv struct{ Cases []merkleVector }
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&mv); err != nil {
		t.Fatal(err)
	}
	if len(mv.Cases) < 8 {
		t.Fatalf("%d merkle cases", len(mv.Cases))
	}
	proofs := 0
	for _, c := range mv.Cases {
		if computed, err := c.Description.VerifyRoot(); !computed || err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
		for i, p := range c.Proofs {
			if err := VerifyItem(c.Root, c.Description.Items[i], p); err != nil {
				t.Errorf("%s item %d: %v", c.Name, i, err)
			}
			proofs++
		}
	}
	if proofs < 20 {
		t.Fatalf("%d proofs checked", proofs)
	}
}
