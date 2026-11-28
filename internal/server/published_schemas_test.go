package server

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestPublishedSchemasMatchTheContract: a published schema the contract carries as components (PublishedSchemas)
// has, object by object, the same members, the same required members and the same strictness as the schema file
// in schemas/, so the two cannot drift. The schema file says more (patterns, enums, limits), which the parser
// enforces; the contract carries the shape.
func TestPublishedSchemasMatchTheContract(t *testing.T) {
	raw, err := os.ReadFile("../../" + ContractPath)
	if err != nil {
		t.Fatal(err)
	}
	var contract map[string]any
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	comps := contract["components"].(map[string]any)["schemas"].(map[string]any)
	published, _ := contract["x-clearance-published-schemas"].(map[string]any)
	files := map[string][]byte{}
	for _, p := range PublishedSchemas {
		id, err := p.ID()
		if err != nil {
			t.Fatal(err)
		}
		files[id] = p.Schema
	}
	if len(published) != len(PublishedSchemas) || len(published) == 0 {
		t.Fatalf("x-clearance-published-schemas %v, PublishedSchemas %d", published, len(PublishedSchemas))
	}
	for comp, id := range published {
		var file map[string]any
		if err := json.Unmarshal(files[id.(string)], &file); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if file["$id"] != id {
			t.Fatalf("%s: the file's $id is %v", comp, file["$id"])
		}
		c := &schemaCompare{t: t, contract: comps, file: file}
		c.compare(map[string]any{"$ref": "#/components/schemas/" + comp}, file, comp)
		if c.objects < 6 {
			t.Fatalf("%s: %d objects compared: the comparison would be vacuous", comp, c.objects)
		}
	}
}

type schemaCompare struct {
	t              *testing.T
	contract, file map[string]any
	objects        int
}

func (c *schemaCompare) resolve(n map[string]any, doc map[string]any) map[string]any {
	for {
		ref, ok := n["$ref"].(string)
		if !ok {
			return n
		}
		var next any = doc
		if strings.HasPrefix(ref, "#/components/schemas/") {
			next = doc[strings.TrimPrefix(ref, "#/components/schemas/")]
		} else {
			for _, p := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
				next = next.(map[string]any)[p]
			}
		}
		n = next.(map[string]any)
	}
}

func keysOf(m any) []string {
	mm, _ := m.(map[string]any)
	out := make([]string, 0, len(mm))
	for k := range mm {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func strsOf(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(string))
	}
	sort.Strings(out)
	return out
}

func (c *schemaCompare) compare(cn, fn map[string]any, path string) {
	cn, fn = c.resolve(cn, c.contract), c.resolve(fn, c.file)
	if props, ok := fn["properties"].(map[string]any); ok {
		c.objects++
		if got, want := keysOf(cn["properties"]), keysOf(props); !reflect.DeepEqual(got, want) {
			c.t.Errorf("%s: contract members %v, schema %v", path, got, want)
		}
		if got, want := strsOf(cn["required"]), strsOf(fn["required"]); !reflect.DeepEqual(got, want) {
			c.t.Errorf("%s: contract requires %v, schema %v", path, got, want)
		}
		if cn["additionalProperties"] != fn["additionalProperties"] {
			c.t.Errorf("%s: contract additionalProperties %v, schema %v", path, cn["additionalProperties"], fn["additionalProperties"])
		}
		cprops, _ := cn["properties"].(map[string]any)
		for k, v := range props {
			if cv, ok := cprops[k].(map[string]any); ok {
				c.compare(cv, v.(map[string]any), path+"."+k)
			}
		}
	}
	if items, ok := fn["items"].(map[string]any); ok {
		ci, _ := cn["items"].(map[string]any)
		if ci == nil {
			c.t.Errorf("%s: the contract has no items", path)
			return
		}
		c.compare(ci, items, path+"[]")
	}
	if ft, ok := fn["type"].(string); ok {
		if ct, _ := cn["type"].(string); ct != ft {
			c.t.Errorf("%s: contract type %v, schema %s", path, cn["type"], ft)
		}
	}
}
