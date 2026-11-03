package schemas

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/jfillman/clearance/internal/evidence"
)

// TestEvidenceSchemaMatchesTheWriter: the published schema names the version Seal writes and the enumerations it
// enforces, so the two cannot drift.
func TestEvidenceSchemaMatchesTheWriter(t *testing.T) {
	var s struct {
		Title    string `json:"title"`
		Required []string
		Props    map[string]struct {
			Enum  []any `json:"enum"`
			OneOf []struct {
				Properties map[string]struct {
					Enum []any `json:"enum"`
				} `json:"properties"`
			} `json:"oneOf"`
		} `json:"properties"`
		Else struct {
			Properties map[string]struct {
				Enum []any `json:"enum"`
			} `json:"properties"`
		} `json:"else"`
	}
	if err := json.Unmarshal(EvidenceV1, &s); err != nil {
		t.Fatal(err)
	}
	if s.Title != evidence.Schema {
		t.Fatalf("schema title %q, writer %q", s.Title, evidence.Schema)
	}
	strs := func(v []any) []string {
		var out []string
		for _, x := range v {
			out = append(out, x.(string))
		}
		return out
	}
	for name, c := range map[string]struct{ got, want []string }{
		"boundary":  {strs(s.Props["boundary"].Enum), evidence.Boundaries},
		"coverage":  {strs(s.Else.Properties["coverage"].Enum), evidence.Coverage},
		"assurance": {strs(s.Props["assurance"].Enum), evidence.Assurance},
		"schema":    {strs(s.Props["schema"].Enum), []string{evidence.Schema, evidence.SchemaV0}},
		"subject":   {strs(s.Props["subject"].OneOf[1].Properties["kind"].Enum), evidence.SubjectKinds},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s: schema %v, writer %v", name, c.got, c.want)
		}
	}
}
