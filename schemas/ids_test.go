package schemas

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the SDK-1 schemas' $id from schemas/naming.go")

// TestTheSchemaIDsComeFromTheBase: each SDK-1 schema's $id is SchemaID, so the product domain is one edit
// (schemas/naming.go, then this test with -update and go generate ./internal/server).
func TestTheSchemaIDsComeFromTheBase(t *testing.T) {
	for _, s := range SDK1Schemas {
		raw, err := os.ReadFile(s.File)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		want := SchemaID(s.Name, s.Version)
		if doc["$id"] == want {
			continue
		}
		if !*update {
			t.Errorf("%s: $id %v, want %s (run go test ./schemas -update)", s.File, doc["$id"], want)
			continue
		}
		// Rewrite the one $id string in place, so the file keeps its layout.
		old, _ := json.Marshal(doc["$id"])
		next, _ := json.Marshal(want)
		if n := bytes.Count(raw, append([]byte(`"$id": `), old...)); n != 1 {
			t.Fatalf("%s: %d $id lines", s.File, n)
		}
		raw = bytes.Replace(raw, append([]byte(`"$id": `), old...), append([]byte(`"$id": `), next...), 1)
		if err := os.WriteFile(s.File, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
