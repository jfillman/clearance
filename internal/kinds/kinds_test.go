package kinds

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/jfillman/clearance/internal/describe"
	"github.com/jfillman/clearance/schemas"
)

// pack is a third party's kind, written as the worked database-migration example: item types with a glob, facts,
// item rules, a change rule that raises with a floor, consistency and a fixture test.
func pack() map[string]any {
	return map[string]any{
		"apiVersion": APIVersion, "name": "io.example.db-migration", "version": 1, "root": "merkle/1", "defaultTier": 1,
		"itemTypes": []any{
			map[string]any{"type": "table", "attrs": map[string]any{"type": "object", "additionalProperties": false,
				"properties": map[string]any{"rows": map[string]any{"type": "integer", "minimum": 0}}}},
			map[string]any{"type": "index", "ops": []any{"create", "delete"}},
			map[string]any{"type": "grant.*"},
		},
		"subjectSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []any{"engine"},
			"properties": map[string]any{"engine": map[string]any{"enum": []any{"postgres", "mysql"}}, "targeted": map[string]any{"type": "boolean"}}},
		"itemRules": []any{
			map[string]any{"name": "db:drop", "types": []any{"table"}, "when": "item.op == 'delete'", "tier": 3, "class": []any{"data-integrity"}},
			map[string]any{"name": "db:index", "types": []any{"index"}, "when": "true", "tier": 2},
			map[string]any{"name": "db:grant", "types": []any{"grant.*"}, "when": "true", "tier": 3, "class": []any{"privilege"}},
		},
		"changeRules": []any{
			map[string]any{"name": "db:targeted", "when": "change.subject.facts.targeted", "raise": 1, "floor": 2},
			map[string]any{"name": "db:many", "when": "size(change.items) > 50", "tier": 2},
		},
		"consistency": []any{map[string]any{"name": "db:engine", "expr": "has(change.subject.facts.engine)", "message": "the engine is named"}},
		"tests":       []any{map[string]any{"name": "a drop is tier 3", "description": map[string]any{}, "expect": map[string]any{"tier": 3, "rules": []any{"db:drop"}}}},
	}
}

func with(f func(m map[string]any)) map[string]any {
	m := pack()
	f(m)
	return m
}

func at(m map[string]any, k string, i int) map[string]any { return m[k].([]any)[i].(map[string]any) }

func kindSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemas.KindV1))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	const url = "https://clearance.hangarplatform.dev/schemas/kind/v1.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// schemas/kind.schema.json and Parse agree on what is a kind, over the refinements' rules.
func TestTheKindSchemaMatchesTheParser(t *testing.T) {
	sch := kindSchema(t)
	builtin := func(name string, f func(m map[string]any)) map[string]any {
		raw, _ := builtinFS.ReadFile("builtin/" + name + ".json")
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if f != nil {
			f(m)
		}
		return m
	}
	docs := map[string]map[string]any{
		"the example pack":              pack(),
		"manifest-tree":                 builtin(ManifestTree, nil),
		"terraform-plan":                builtin(TerraformPlan, nil),
		"a first-party name":            with(func(m map[string]any) { m["name"] = "dev.clearance.db-migration" }),
		"a star with defaultTier 2":     with(func(m map[string]any) { m["defaultTier"] = 2; m["itemTypes"] = []any{map[string]any{"type": "*"}} }),
		"terraform-plan v2 on merkle/1": builtin(TerraformPlan, func(m map[string]any) { m["version"] = 2; m["root"] = "merkle/1" }),
		"no rules":                      with(func(m map[string]any) { delete(m, "itemRules"); delete(m, "changeRules"); delete(m, "consistency") }),
		"another apiVersion":            with(func(m map[string]any) { m["apiVersion"] = "clearance.kind/v2" }),
		"a name without a dot":          with(func(m map[string]any) { m["name"] = "db-migration" }),
		"defaultTier 0":                 with(func(m map[string]any) { m["defaultTier"] = 0 }),
		"defaultTier 4":                 with(func(m map[string]any) { m["defaultTier"] = 4 }),
		"a star with defaultTier 1":     with(func(m map[string]any) { m["itemTypes"] = []any{map[string]any{"type": "*"}} }),
		"a third party on tree/1":       with(func(m map[string]any) { m["root"] = "tree/1" }),
		"manifest-tree v1 on merkle/1":  builtin(ManifestTree, func(m map[string]any) { m["root"] = "merkle/1" }),
		"terraform-plan v1 on tree/1":   builtin(TerraformPlan, func(m map[string]any) { m["root"] = "tree/1" }),
		"an unknown root":               with(func(m map[string]any) { m["root"] = "merkle/2" }),
		"a third party says builtin": with(func(m map[string]any) {
			m["builtin"] = true
			delete(m, "itemRules")
			delete(m, "changeRules")
			delete(m, "consistency")
		}),
		"a builtin kind with rules": builtin(TerraformPlan, func(m map[string]any) { m["itemRules"] = pack()["itemRules"] }),
		"no item types":             with(func(m map[string]any) { m["itemTypes"] = []any{} }),
		"an unknown field":          with(func(m map[string]any) { m["plugin"] = "x.so" }),
		"an unknown op":             with(func(m map[string]any) { at(m, "itemTypes", 1)["ops"] = []any{"unchanged"} }),
		"open attrs": with(func(m map[string]any) {
			delete(at(m, "itemTypes", 0)["attrs"].(map[string]any), "additionalProperties")
		}),
		"facts that are not an object": with(func(m map[string]any) {
			m["subjectSchema"] = map[string]any{"type": "array", "additionalProperties": false}
		}),
		"an item rule at tier 4":            with(func(m map[string]any) { at(m, "itemRules", 0)["tier"] = 4 }),
		"an item rule without when":         with(func(m map[string]any) { delete(at(m, "itemRules", 0), "when") }),
		"a blank when":                      with(func(m map[string]any) { at(m, "itemRules", 0)["when"] = "  " }),
		"a bad rule name":                   with(func(m map[string]any) { at(m, "itemRules", 0)["name"] = "Drop Table" }),
		"a bad class":                       with(func(m map[string]any) { at(m, "itemRules", 0)["class"] = []any{"Data Integrity"} }),
		"a change rule with tier and raise": with(func(m map[string]any) { at(m, "changeRules", 0)["tier"] = 2 }),
		"a change rule with neither":        with(func(m map[string]any) { delete(at(m, "changeRules", 0), "raise") }),
		"a floor with a tier":               with(func(m map[string]any) { at(m, "changeRules", 1)["floor"] = 2 }),
		"a change rule that sets tier 0":    with(func(m map[string]any) { at(m, "changeRules", 1)["tier"] = 0 }),
		"a raise of 0":                      with(func(m map[string]any) { at(m, "changeRules", 0)["raise"] = 0 }),
		"a check without a message":         with(func(m map[string]any) { at(m, "consistency", 0)["message"] = "" }),
		"a test with a tier and a refusal":  with(func(m map[string]any) { at(m, "tests", 0)["expect"].(map[string]any)["refused"] = "DG-UNBOUND" }),
		"a test expecting nothing":          with(func(m map[string]any) { at(m, "tests", 0)["expect"] = map[string]any{} }),
		"a test refusing with no code":      with(func(m map[string]any) { at(m, "tests", 0)["expect"] = map[string]any{"refused": "nope"} }),
		"a type with a space":               with(func(m map[string]any) { at(m, "itemTypes", 0)["type"] = "a table" }),
	}
	accepted := 0
	for name, doc := range docs {
		raw, _ := json.Marshal(doc)
		_, perr := Parse(raw)
		inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		verr := sch.Validate(inst)
		if (perr == nil) != (verr == nil) {
			t.Errorf("%s: parser %v, schema %v", name, perr, verr)
		}
		if perr == nil {
			accepted++
		}
	}
	if accepted != 7 {
		t.Errorf("%d of %d accepted, want 7 (the comparison would be vacuous)", accepted, len(docs))
	}
	// What only the parser checks.
	for name, doc := range map[string]map[string]any{
		"a rule name twice": with(func(m map[string]any) { at(m, "itemRules", 1)["name"] = "db:drop" }),
		"a type twice": with(func(m map[string]any) {
			m["itemTypes"] = append(m["itemTypes"].([]any), map[string]any{"type": "table"})
		}),
		"a schema that does not compile": with(func(m map[string]any) {
			at(m, "itemTypes", 0)["attrs"].(map[string]any)["properties"] = map[string]any{"rows": map[string]any{"type": 7}}
		}),
		"a remote $ref": with(func(m map[string]any) {
			m["subjectSchema"].(map[string]any)["properties"] = map[string]any{"engine": map[string]any{"$ref": "https://example.com/s.json"}}
		}),
	} {
		raw, _ := json.Marshal(doc)
		var e *Error
		if _, err := Parse(raw); !errors.As(err, &e) || e.Code != "DG-KIND" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTheBuiltinKindsLoadAndDeclareTheirRoots(t *testing.T) {
	for name, root := range BuiltinNames {
		k, err := Builtin(name)
		if err != nil {
			t.Fatal(name, err)
		}
		if k.Root != root || !k.Builtin || k.Version != 1 || !IsFirstParty(name) {
			t.Fatalf("%s: %+v", name, k.Kind)
		}
	}
	if _, err := Builtin("definition"); err == nil {
		t.Fatal("definition is not a built-in kind on the description")
	}
	if !IsFirstParty(FirstPartyPrefix+"db-migration") || IsFirstParty("io.acme.db-migration") {
		t.Fatal("first-party prefix")
	}
}

func desc(items ...describe.Item) *describe.Description {
	d := &describe.Description{
		Subject:     describe.Subject{Kind: "io.example.db-migration", Version: 1, RootFn: describe.RootMerkle1, Facts: map[string]any{"engine": "postgres"}},
		Target:      describe.Target{Environment: "prod"},
		Items:       items,
		Source:      describe.Source{Repo: "example/migrations", Commit: "0123456789abcdef0123456789abcdef01234567"},
		DescribedBy: describe.DescribedBy{Provider: "example-gate"},
	}
	d.Subject.Root, _ = describe.Merkle1(d.Items, d.Subject.Facts)
	return d
}

// Refinement 3: an item the kind does not know is refused DG-UNBOUND, never given the default tier; so is an op the
// type does not allow, an attr the schema does not declare, and facts the subject schema does not.
func TestBindRefusesWhatTheKindDoesNotDeclare(t *testing.T) {
	raw, _ := json.Marshal(pack())
	k, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ok := desc(describe.Item{Type: "table", ID: "public.users", Op: describe.OpDelete, Attrs: map[string]any{"rows": json.Number("3")}},
		describe.Item{Type: "index", ID: "users_email", Op: describe.OpCreate}, describe.Item{Type: "grant.select", ID: "reader", Op: describe.OpCreate})
	if err := k.Bind(ok); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]*describe.Description{
		"an unknown item type":   desc(describe.Item{Type: "sequence", ID: "s", Op: describe.OpCreate}),
		"an unknown op":          desc(describe.Item{Type: "table", ID: "t", Op: "unchanged"}),
		"an op the type refuses": desc(describe.Item{Type: "index", ID: "i", Op: describe.OpUpdate}),
		"an undeclared attr":     desc(describe.Item{Type: "table", ID: "t", Op: describe.OpCreate, Attrs: map[string]any{"sql": "DROP TABLE x"}}),
		"a wrong attr type":      desc(describe.Item{Type: "table", ID: "t", Op: describe.OpCreate, Attrs: map[string]any{"rows": "many"}}),
		"attrs on a bare type":   desc(describe.Item{Type: "index", ID: "i", Op: describe.OpCreate, Attrs: map[string]any{"rows": json.Number("1")}}),
		"another kind": func() *describe.Description {
			d := desc()
			d.Subject.Kind = "io.example.other"
			return d
		}(),
		"another version": func() *describe.Description {
			d := desc()
			d.Subject.Version = 2
			return d
		}(),
		"another root function": func() *describe.Description {
			d := desc()
			d.Subject.RootFn = describe.RootPlan1
			return d
		}(),
		"an undeclared fact": func() *describe.Description {
			d := desc()
			d.Subject.Facts = map[string]any{"engine": "postgres", "secret": "x"}
			return d
		}(),
		"a missing fact": func() *describe.Description {
			d := desc()
			d.Subject.Facts = nil
			return d
		}(),
	} {
		var e *Error
		if err := k.Bind(d); !errors.As(err, &e) || e.Code != "DG-UNBOUND" {
			t.Errorf("%s: %v", name, err)
		}
	}
}
