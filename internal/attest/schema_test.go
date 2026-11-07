package attest_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/schemas"
)

// schemas/change-attestation.schema.json and the statement the signer writes agree: what BuildStatement makes
// validates, and what the schema closes (unknown fields, a not-applied outcome, no limitations) it refuses.
func TestTheChangeAttestationSchemaMatchesTheStatement(t *testing.T) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemas.ChangeAttestationV1))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	const url = "https://clearance.hangarplatform.dev/schemas/change-attestation/v1.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	valid := func(v any) error {
		raw, _ := json.Marshal(v)
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		return sch.Validate(inst)
	}
	for name, rec := range map[string]map[string]any{"digest": map[string]any(outcomeRec(true, treeRoot)), "no digest": map[string]any(outcomeRec(true, ""))} {
		st, err := attest.BuildStatement(manifestChange(), rec, "clearance")
		if err != nil {
			t.Fatal(name, err)
		}
		if err := valid(st); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := valid(testStatement()); err != nil {
		t.Errorf("the test statement: %v", err)
	}
	raw, _ := json.Marshal(testStatement())
	for name, mod := range map[string]func(map[string]any){
		"unknown field":     func(m map[string]any) { m["predicate"].(map[string]any)["extra"] = 1 },
		"not applied":       func(m map[string]any) { m["predicate"].(map[string]any)["outcome"].(map[string]any)["applied"] = false },
		"no limitations":    func(m map[string]any) { m["predicate"].(map[string]any)["limitations"] = []any{} },
		"another predicate": func(m map[string]any) { m["predicateType"] = "https://example.test/x" },
		"no subject":        func(m map[string]any) { m["subject"] = []any{} },
	} {
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		mod(c)
		if valid(c) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
