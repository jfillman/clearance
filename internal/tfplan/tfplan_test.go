package tfplan

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
)

var ws = gate.Workspace{Backend: "s3", Key: "network/lab/terraform.tfstate", Name: "default"}

// The secrets the fixtures hold: a sensitive variable and a sensitive attribute value.
var secrets = []string{"hunter2-SECRET", "attr-SECRET-value"}

func load(t *testing.T, name string, o Options) (*Subject, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	o.Workspace = ws
	s, err := Compute([]byte("the saved plan "+name), raw, o)
	if err != nil {
		t.Fatal(err)
	}
	return s, raw
}

// The subject the core's own parser accepts, so the summary and resources agree with its checks.
func accepted(t *testing.T, s *Subject) {
	t.Helper()
	sub, _ := json.Marshal(s)
	raw := `{"app": "network", "env": "lab", "repo": "jfillman/hangar-infra", "pr": 0, "head": "` + strings.Repeat("a", 40) +
		`", "proposer": "user:dana", "proposerKind": "person", "paths": [], "checks": {}, "subject": ` + string(sub) + `}`
	req, err := pycompat.Decode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.ParseRequest(req); err != nil {
		b := sub
		t.Fatalf("the core refuses the subject: %v\n%s", err, b)
	}
}

func TestSubjectsPerFixture(t *testing.T) {
	cases := []struct {
		name                         string
		o                            Options
		create, update, replace, des int64
		destroyed                    []string
		fields                       map[string][]string
	}{
		{name: "create", create: 1},
		{name: "update", update: 1, fields: map[string][]string{"aws_instance.web": {"/instance_type"}}},
		{name: "destroy", des: 1, destroyed: []string{"aws_instance.bastion"}},
		{name: "replace", replace: 1},
		{name: "tag-only", update: 1, fields: map[string][]string{"aws_vpc.lab": {"/tags/Owner", "/tags_all"}}},
		{name: "create", o: Options{Targeted: true}, create: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, raw := load(t, c.name, c.o)
			sum := s.Summary
			if sum.Create != c.create || sum.Update != c.update || sum.Replace != c.replace || sum.Destroy != c.des ||
				!reflect.DeepEqual(sum.DestroyedAddresses, c.destroyed) {
				t.Fatalf("summary %+v", sum)
			}
			for _, r := range s.Resources {
				if want, ok := c.fields[r.Address]; ok && !reflect.DeepEqual(r.Fields, want) {
					t.Errorf("%s fields %v, want %v", r.Address, r.Fields, want)
				} else if !ok && len(r.Fields) > 0 {
					t.Errorf("%s fields %v", r.Address, r.Fields)
				}
			}
			if s.Targeted != c.o.Targeted || s.Versions.Terraform != "1.9.8" {
				t.Fatalf("%+v", s)
			}
			if s.PlanDigest != Digest([]byte("the saved plan "+c.name)) || Hex(s.PlanJSONDigest) == "" || Hex(s.VariableSetDigest) == "" {
				t.Fatalf("digests %+v", s)
			}
			accepted(t, s)
			// Secret values are in nothing that leaves: not the subject, not the redacted JSON it digests.
			out, _ := json.Marshal(s)
			red, err := Redacted(raw)
			if err != nil {
				t.Fatal(err)
			}
			if Digest(red) != s.PlanJSONDigest {
				t.Fatal("the plan JSON digest is not the redacted JSON's")
			}
			for _, sec := range secrets {
				if strings.Contains(string(out), sec) || strings.Contains(string(red), sec) {
					t.Fatalf("%q leaked", sec)
				}
			}
			if strings.Contains(string(red), "us-east-1") {
				t.Fatal("the redacted JSON keeps a value")
			}
		})
	}
}

func TestReplaceKeepsItsActionsAndTheDigestsFollowThePlan(t *testing.T) {
	s, _ := load(t, "replace", Options{})
	if !reflect.DeepEqual(s.Resources[0].Actions, []string{"delete", "create"}) || s.Resources[0].ActionReason != "replace_because_cannot_update" {
		t.Fatalf("%+v", s.Resources[0])
	}
	a, _ := load(t, "update", Options{})
	b, _ := load(t, "update", Options{})
	c, _ := load(t, "create", Options{})
	if a.PlanJSONDigest != b.PlanJSONDigest || a.PlanJSONDigest == c.PlanJSONDigest || a.VariableSetDigest != b.VariableSetDigest {
		t.Fatal("the digests are not deterministic")
	}
}

// A sensitive variable's value is not even hashed into the set digest: changing it changes nothing here.
func TestSensitiveVariableValuesAreNotHashed(t *testing.T) {
	raw, _ := os.ReadFile("testdata/create.json")
	changed := []byte(strings.Replace(string(raw), "hunter2-SECRET", "another-secret", 1))
	a, _ := Compute([]byte("p"), raw, Options{Workspace: ws})
	b, _ := Compute([]byte("p"), changed, Options{Workspace: ws})
	if a.VariableSetDigest != b.VariableSetDigest {
		t.Fatal("a sensitive variable's value changed the digest")
	}
	plain := []byte(strings.Replace(string(raw), "us-east-1", "eu-west-1", 1))
	if c, _ := Compute([]byte("p"), plain, Options{Workspace: ws}); c.VariableSetDigest == a.VariableSetDigest {
		t.Fatal("a plain variable's value did not change the digest")
	}
}

func TestNotAPlan(t *testing.T) {
	if _, err := Compute(nil, []byte(`[1]`), Options{}); err == nil {
		t.Fatal("accepted")
	}
	if _, err := Compute(nil, []byte(`{"x": 1}`), Options{}); err == nil {
		t.Fatal("accepted")
	}
}

func TestProvidersFromLock(t *testing.T) {
	raw, _ := os.ReadFile("testdata/tf.lock.hcl")
	if got := ProvidersFromLock(raw); !reflect.DeepEqual(got, map[string]string{"registry.terraform.io/hashicorp/aws": "5.70.0"}) {
		t.Fatal(got)
	}
}
