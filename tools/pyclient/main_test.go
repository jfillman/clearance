package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The committed Python models and version are what the contract and pyproject.toml generate now.
func TestTheGeneratedPythonClientIsCurrent(t *testing.T) {
	files, err := GenerateFrom("../..")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("generated %d files", len(files))
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join("../..", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale: run `go run ./tools/pyclient` from the module root", name)
		}
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	a, err := GenerateFrom("../..")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		b, _ := GenerateFrom("../..")
		for k := range a {
			if !bytes.Equal(a[k], b[k]) {
				t.Fatalf("%s differs between runs", k)
			}
		}
	}
	m := string(a[ModelsPath])
	for _, want := range []string{"class EvaluationRequest(Model):", "class GateChangeWithAuditSeq(Model):",
		`"evaluate": Operation("POST", "/access/v1/evaluation"`, `Field("decision_id", "decision_id", ("nullable", ("str",)), True)`} {
		if !strings.Contains(m, want) {
			t.Errorf("the models do not have %s", want)
		}
	}
}

func TestReleaseVersion(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"[project]\nname = \"x\"\nversion = \"0.26.1\"\n", "0.26.1", true},
		{"[tool.x]\nversion = \"9.9.9\"\n[project]\nversion = \"1.2.3\"\n", "1.2.3", true},
		{"[project]\nversion = \"latest\"\n", "", false},
		{"[project]\nname = \"x\"\n", "", false},
	}
	for _, tc := range cases {
		got, err := ReleaseVersion([]byte(tc.in))
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("%q: %q %v", tc.in, got, err)
		}
	}
}

func TestBadContractsFail(t *testing.T) {
	for name, c := range map[string]string{
		"not json":     "{",
		"bad ref":      `{"paths": {}, "components": {"schemas": {"A": {"type": "object", "properties": {"x": {"$ref": "#/components/schemas/Nope"}}}}}}`,
		"keyword-free": `{"paths": {}, "components": {"schemas": {"A": {"type": "object", "properties": {"a-b": {"type": "string"}}}}}}`,
		"clash":        `{"paths": {}, "components": {"schemas": {"DecideA": {"type": "object"}, "A": {"type": "object"}}}}`,
		"odd type":     `{"paths": {}, "components": {"schemas": {"A": {"type": "object", "properties": {"x": {"type": "tuple"}}}}}}`,
	} {
		if _, err := Models([]byte(c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
