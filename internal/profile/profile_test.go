package profile_test

// Ported from tests/test_profile.py (names mirrored), plus the schema drift test, the placeholder digest and
// runs_in, and the Parser adapter.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/profile"
)

const agents = "../../tests/fixtures/agents"

func defs(t *testing.T) map[string]profile.AgentDefinition {
	t.Helper()
	d, err := profile.LoadDir(agents)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(agents, name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := profile.DecodeYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func doc(t *testing.T) map[string]any { return load(t, "coding-agent") }

func prof(d map[string]any) map[string]any { return d["profile"].(map[string]any) }

func has(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func write(t *testing.T, dir, name string, d map[string]any) {
	t.Helper()
	b, err := json.Marshal(d) // JSON is YAML; yaml.Marshal would quote a json.Number
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaIsByteIdenticalToThePythonCopy(t *testing.T) {
	py, err := os.ReadFile("../../src/clearance/schemas/agent-definition.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(py) == 0 || !bytes.Equal(py, profile.SchemaJSON()) {
		t.Fatal("internal/profile/agent-definition.schema.json drifted from src/clearance/schemas; copy it again")
	}
}

func TestAllShippedDefinitionsLoad(t *testing.T) {
	d := defs(t)
	want := []string{"coding-agent", "researcher", "orchestrator", "triage-agent", "nightly-reviewer"}
	if len(d) != len(want) {
		t.Fatalf("loaded %d definitions", len(d))
	}
	for _, n := range want {
		if _, ok := d[n]; !ok {
			t.Fatalf("%s missing", n)
		}
	}
	if d["coding-agent"].Limits.TierCeiling != 1 || d["coding-agent"].Limits.Network != profile.NetworkClearanceModel {
		t.Fatalf("coding-agent limits %+v", d["coding-agent"].Limits)
	}
}

func TestEveryKindIsRepresented(t *testing.T) {
	kinds := map[string]bool{}
	for _, d := range defs(t) {
		kinds[d.Kind] = true
	}
	for _, k := range []string{"task", "team", "event", "scheduled"} {
		if !kinds[k] {
			t.Fatalf("no %s agent", k)
		}
	}
}

func TestBaselineDenyPathsAlwaysPresentAndCannotBeRemoved(t *testing.T) {
	d := doc(t)
	prof(d)["repos"] = map[string]any{"allow": []any{"jfillman/*"}, "denyPaths": []any{"extra/**"}}
	out, err := profile.Parse(d)
	if err != nil {
		t.Fatal(err)
	}
	if !has(out.DenyPaths, ".tekton/**") || !has(out.DenyPaths, "extra/**") {
		t.Fatal(out.DenyPaths)
	}
	// Repeating a baseline entry neither removes nor duplicates it.
	prof(d)["repos"] = map[string]any{"allow": []any{"jfillman/*"}, "denyPaths": []any{".tekton/**"}, "fieldDeny": []any{"/release"}}
	out, _ = profile.Parse(d)
	if len(out.DenyPaths) != len(profile.BaselineDenyPaths()) || len(out.FieldDeny) != len(profile.BaselineDenyFields()) {
		t.Fatal(out.DenyPaths, out.FieldDeny)
	}
}

func TestCicdYamlIsNotPathDeniedItIsFieldScoped(t *testing.T) {
	d := doc(t)
	prof(d)["repos"] = map[string]any{"allow": []any{"jfillman/*"}}
	out, err := profile.Parse(d)
	if err != nil {
		t.Fatal(err)
	}
	if has(out.DenyPaths, "cicd.yaml") || has(out.DenyPaths, "**/cicd.yaml") {
		t.Fatal(out.DenyPaths)
	}
	prof(d)["repos"].(map[string]any)["denyPaths"] = []any{"cicd.yaml"}
	out, _ = profile.Parse(d)
	if !has(out.DenyPaths, "cicd.yaml") {
		t.Fatal(out.DenyPaths)
	}
}

func TestBaselineDenyPathsCoverReleaseFiles(t *testing.T) {
	d := doc(t)
	prof(d)["repos"] = map[string]any{"allow": []any{"jfillman/*"}}
	out, _ := profile.Parse(d)
	for _, p := range []string{"release.yaml", "**/release.yaml", "**/*.release.yaml"} {
		if !has(out.DenyPaths, p) {
			t.Fatalf("%s not denied", p)
		}
	}
	for _, f := range profile.BaselineDenyFields() {
		if !has(out.FieldDeny, f) {
			t.Fatalf("%s not field-denied", f)
		}
	}
}

// The expected messages are what profile.parse (python-jsonschema 4.26) says for the same documents.
func TestSchemaRejects(t *testing.T) {
	for name, c := range map[string]struct {
		mutate func(map[string]any)
		want   string
	}{
		"bogus":       {func(d map[string]any) { d["bogus"] = 1 }, "coding-agent: <root>: Additional properties are not allowed ('bogus' was unexpected)"},
		"T3":          {func(d map[string]any) { prof(d)["tierCeiling"] = "T3" }, "coding-agent: profile/tierCeiling: 'T3' is not one of ['T0', 'T1', 'T2']"},
		"openPrs":     {func(d map[string]any) { delete(prof(d)["limits"].(map[string]any), "openPrs") }, "coding-agent: profile/limits: 'openPrs' is a required property"},
		"tag":         {func(d map[string]any) { d["runtime"].(map[string]any)["image"] = "ghcr.io/x/y:latest" }, `coding-agent: runtime/image: 'ghcr.io/x/y:latest' does not match '^[^\\s@]+@sha256:[a-f0-9]{64}$'`},
		"name":        {func(d map[string]any) { d["name"] = "Bad Name" }, "Bad Name: name: 'Bad Name' does not match '^[a-z][a-z0-9-]{1,40}$'"},
		"workload":    {func(d map[string]any) { d["identity"].(map[string]any)["type"] = "workload" }, "coding-agent: identity: 'serviceAccount' is a required property"},
		"network":     {func(d map[string]any) { prof(d)["network"] = "everything" }, "coding-agent: profile/network: 'everything' is not one of ['none', 'clearance', 'clearance+model', 'allowlist']"},
		"ttl":         {func(d map[string]any) { prof(d)["limits"].(map[string]any)["ttlMinutes"] = 99999 }, "coding-agent: profile/limits/ttlMinutes: 99999 is greater than the maximum of 1440"},
		"repo":        {func(d map[string]any) { prof(d)["repos"].(map[string]any)["allow"] = []any{"not-a-repo"} }, "coding-agent: profile/repos/allow/0: 'not-a-repo' does not match '^[A-Za-z0-9_.*-]+/[A-Za-z0-9_.*-]+$'"},
		"string ttl":  {func(d map[string]any) { prof(d)["limits"].(map[string]any)["ttlMinutes"] = "30" }, "coding-agent: profile/limits/ttlMinutes: '30' is not of type 'integer'"},
		"dup tool":    {func(d map[string]any) { prof(d)["tools"] = []any{"a", "a"} }, "coding-agent: profile/tools: ['a', 'a'] has non-unique elements"},
		"description": {func(d map[string]any) { d["description"] = "" }, "coding-agent: description: '' should be non-empty"},
		"trigger": {func(d map[string]any) {
			d["triggers"] = []any{map[string]any{"type": "event", "source": "glidepath", "bindingKey": "Bad Key"}}
		}, "coding-agent: triggers/0/bindingKey: 'Bad Key' does not match '^[a-z0-9*#][a-z0-9*#.-]*$'"},
		"trigger type": {func(d map[string]any) { d["triggers"] = []any{map[string]any{"type": "bogus"}} },
			"coding-agent: triggers/0: {'type': 'bogus'} is not valid under any of the given schemas"},
	} {
		t.Run(name, func(t *testing.T) {
			d := doc(t)
			prof(d)["repos"] = map[string]any{"allow": []any{"jfillman/*"}}
			c.mutate(d)
			_, err := profile.Parse(d)
			if _, ok := err.(*profile.DefinitionError); !ok {
				t.Fatalf("got %v, want a DefinitionError", err)
			}
			if err.Error() != c.want {
				t.Fatalf("\n got %s\nwant %s", err, c.want)
			}
		})
	}
}

func TestFileNameMustMatchAgentName(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "other.yaml", doc(t))
	if _, err := profile.LoadDir(dir); err == nil || !strings.Contains(err.Error(), "file name must match") {
		t.Fatalf("got %v", err)
	}
}

func TestAGlidepathEventTriggerValidates(t *testing.T) {
	dir := t.TempDir()
	base := load(t, "nightly-reviewer")
	base["kind"] = "event"
	trig := func(over map[string]any) []any {
		t := map[string]any{"type": "event", "source": "glidepath", "bindingKey": "*.pipelinerun.finished",
			"match": map[string]any{"subject.content.outcome": "failure"}, "maxPerHour": 6}
		for k, v := range over {
			t[k] = v
		}
		return []any{t}
	}
	base["triggers"] = trig(nil)
	write(t, dir, "nightly-reviewer.yaml", base)
	d, err := profile.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := json.Marshal(d[base["name"].(string)].Triggers[0]["match"])
	if string(m) != `{"subject.content.outcome":"failure"}` {
		t.Fatal(string(m))
	}
	for _, bad := range []map[string]any{
		{"bindingKey": "Bad Key"}, {"match": map[string]any{"a b": "x"}}, {"exchange": "x"}, {"match": map[string]any{"a": 1}},
	} {
		base["triggers"] = trig(bad)
		write(t, dir, "nightly-reviewer.yaml", base)
		if _, err := profile.LoadDir(dir); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}

func TestRuntimeInstructions(t *testing.T) {
	dir := t.TempDir()
	base := load(t, "nightly-reviewer")
	base["runtime"].(map[string]any)["instructions"] = "Review every app nightly."
	write(t, dir, "nightly-reviewer.yaml", base)
	d, err := profile.LoadDir(dir)
	if err != nil || d["nightly-reviewer"].Instructions != "Review every app nightly." {
		t.Fatalf("%+v %v", d["nightly-reviewer"], err)
	}
	base["runtime"].(map[string]any)["instructions"] = strings.Repeat("x", 1501)
	write(t, dir, "nightly-reviewer.yaml", base)
	if _, err := profile.LoadDir(dir); err == nil {
		t.Fatal("1501 characters accepted")
	} else if _, ok := err.(*profile.DefinitionError); !ok {
		t.Fatalf("%T", err)
	}
}

// -- beyond test_profile.py --------------------------------------------------------------------------------------

func TestAPlaceholderDigestIsRefusedAndRunsIn(t *testing.T) {
	d := doc(t)
	out, err := profile.Parse(d)
	if err != nil || out.RunsIn() != "cluster" || out.Framework != "claude-agent-sdk" {
		t.Fatalf("%+v %v", out, err)
	}
	d["runtime"].(map[string]any)["image"] = "ghcr.io/x/y@sha256:" + strings.Repeat("0", 64)
	if _, err := profile.Parse(d); err == nil || !strings.Contains(err.Error(), "placeholder digest") {
		t.Fatalf("got %v", err)
	}
	delete(d, "runtime")
	delete(d, "triggers")
	out, err = profile.Parse(d)
	if err != nil || out.RunsIn() != "client" || out.Framework != "generic" || out.Sandbox != "standard" {
		t.Fatalf("%+v %v", out, err)
	}
	if len(out.Triggers) != 1 || out.Triggers[0]["type"] != "manual" {
		t.Fatal(out.Triggers)
	}
}

func TestTheParserFillsADefinition(t *testing.T) {
	d := load(t, "triage-agent")
	got, err := profile.Parser()(d)
	if err != nil {
		t.Fatal(err)
	}
	full, _ := profile.Parse(d)
	if got.Name != "triage-agent" || got.Description == "" || got.Kind != full.Kind || got.TierCeiling != full.Limits.TierCeiling ||
		got.IdentityType != full.IdentityType || got.ServiceAccount != full.ServiceAccount || got.Image != full.Image ||
		len(got.DenyPaths) < len(profile.BaselineDenyPaths()) || got.Raw == nil {
		t.Fatalf("%+v", got)
	}
	tools := prof(d)["tools"].([]any)
	hr := false
	for _, x := range tools {
		hr = hr || x == "human.request"
	}
	if hr != has(got.Tools, "human.request.get") {
		t.Fatal("human.request brings human.request.get")
	}
	if _, err := profile.Parser()(map[string]any{"name": "x"}); err == nil {
		t.Fatal("accepted a bare document")
	}
}

func FuzzParse(f *testing.F) {
	raw, _ := os.ReadFile(filepath.Join(agents, "coding-agent.yaml"))
	f.Add(raw)
	f.Add([]byte("name: x\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := profile.DecodeYAML(b)
		if err != nil {
			return
		}
		_, _ = profile.Parse(d)
	})
}

// The provenance and githubapp tests build definitions from deftest's baseline; it must be this one.
func TestDeftestsBaselineIsTheRealOne(t *testing.T) {
	if strings.Join(deftest.BaselineDenyPaths, "|") != strings.Join(profile.BaselineDenyPaths(), "|") {
		t.Fatal("deftest.BaselineDenyPaths drifted from profile.BaselineDenyPaths()")
	}
}

// DecodeYAML is yaml.safe_load (PyYAML's YAML 1.1), as profile.load_dir reads a definition.
func TestDecodeYAMLIsSafeLoad(t *testing.T) {
	m, err := profile.DecodeYAML([]byte("a: no\na: on\nb: 1e3\nc: 0o17\nd: 010\ne: 1.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"a": true, "b": "1e3", "c": "0o17", "d": json.Number("8"), "e": json.Number("1.0")}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("got %#v, want %#v", m, want)
	}
	for _, doc := range []string{"1: x\n", "a: 2026-01-02\n", "a: .nan\n", "- a\n", "a: 2026-02-31\n"} {
		if _, err := profile.DecodeYAML([]byte(doc)); err == nil {
			t.Errorf("%q: decoded; it has no JSON form or is not a mapping", doc)
		}
	}
}
