package gate_test

// SDK-1: the built-in kinds on the generic change description. Every corpus request maps onto a description that is
// valid, matches schemas/change-description.schema.json, binds to its embedded built-in kind and maps back to what
// tiering reads; its root is the digest the request carried. The replay over an exported chain is
// TestReplayStoredChanges.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/describe"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/kinds"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/schemas"
)

func corpusRequests(t *testing.T) []gate.ChangeRequest {
	t.Helper()
	var out []gate.ChangeRequest
	for _, cc := range corpusCases() {
		req, err := gate.ParseRequest(cc.Request)
		if err != nil {
			t.Fatalf("%s: %v", cc.Name, err)
		}
		out = append(out, req)
	}
	return out
}

func TestTheBuiltinKindsMapOntoTheDescription(t *testing.T) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemas.ChangeDescriptionV1))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	const url = "https://clearance.hangarplatform.dev/schemas/change-description/v1.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	items := 0
	for _, req := range corpusRequests(t) {
		d, err := gate.Describe(req)
		if err != nil || d == nil {
			t.Fatalf("%s: %v", req.ID(), err)
		}
		if err := d.Validate(); err != nil {
			t.Errorf("%s: %v", req.ID(), err)
		}
		raw, _ := json.Marshal(d)
		v, _ := pycompat.Decode(bytes.NewReader(raw))
		if err := sch.Validate(v); err != nil {
			t.Errorf("%s: the schema refuses the core's description: %v", req.ID(), err)
		}
		// What another provider would send is what the core maps: the parsed JSON is the same description.
		back, err := describe.Parse(v)
		if err != nil {
			t.Fatalf("%s: %v", req.ID(), err)
		}
		if again, _ := json.Marshal(back); !bytes.Equal(again, raw) {
			t.Errorf("%s: the description does not survive JSON:\n%s\n%s", req.ID(), raw, again)
		}
		k, err := kinds.Builtin(d.Subject.Kind)
		if err != nil {
			t.Fatal(err)
		}
		if err := k.Bind(back); err != nil {
			t.Errorf("%s: the built-in kind refuses its own mapping: %v", req.ID(), err)
		}
		if computed, err := d.VerifyRoot(); computed || err != nil {
			t.Errorf("%s: a built-in root is carried, not computed: %v", req.ID(), err)
		}
		switch req.Kind() {
		case gate.KindManifestTree:
			want := slices.DeleteFunc(slices.Clone(req.Objects), func(o gate.ObjectChange) bool { return o.Op == "unchanged" })
			var got []gate.ObjectChange
			for _, it := range back.Items {
				got = append(got, gate.ItemObject(it))
			}
			if len(want) == 0 && len(got) == 0 {
				break
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s: objects do not map back:\n%+v\n%+v", req.ID(), got, want)
			}
			if d.Subject.Root != bareHex(req.TreeDigest) || d.Subject.RootFn != describe.RootTree1 || len(d.Subject.Facts) != 0 {
				t.Errorf("%s: %+v", req.ID(), d.Subject)
			}
		case gate.KindTerraformPlan:
			want := slices.DeleteFunc(slices.Clone(req.Subject.Resources), func(r gate.Resource) bool { return !r.Changes() })
			var got []gate.Resource
			for _, it := range back.Items {
				got = append(got, gate.ItemResource(it))
			}
			for i := range want {
				if want[i].Fields == nil {
					want[i].Fields = []string{}
				}
			}
			for i := range got {
				if got[i].Fields == nil {
					got[i].Fields = []string{}
				}
			}
			if len(want) != len(got) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
				t.Errorf("%s: resources do not map back:\n%+v\n%+v", req.ID(), got, want)
			}
			if d.Subject.Root != req.Subject.PlanDigest || d.Subject.RootFn != describe.RootPlan1 {
				t.Errorf("%s: %+v", req.ID(), d.Subject)
			}
			s := d.Summarize()
			if sum := req.Subject.Summary; sum.Create != s.Create || sum.Update != s.Update || sum.Replace != s.Replace ||
				sum.Destroy != s.Delete || !slices.Equal(sum.DestroyedAddresses, s.Deleted) {
				t.Errorf("%s: the recorded summary %+v is not the derived %+v", req.ID(), *sum, s)
			}
		}
		items += len(d.Items)
	}
	if items < 50 {
		t.Fatalf("%d items over the corpus: the mapping test would be vacuous", items)
	}
}

func bareHex(s string) string {
	if len(s) > 7 && s[:7] == "sha256:" {
		return s[7:]
	}
	return s
}

// The core keeps the summary it derives: a caller's destroyedAddresses in another order is accepted, and the change
// holds the derived order; a caller's summary that is not the resources' is still refused.
func TestTheCoreKeepsTheDerivedSummary(t *testing.T) {
	s := plan(nil, res("aws_instance.a", "aws_instance", destroy), res("aws_instance.b", "aws_instance", destroy))
	sum := s["summary"].(map[string]any)
	sum["destroyedAddresses"] = []any{"aws_instance.b", "aws_instance.a"}
	req, err := gate.ParseRequest(tfChange(s, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Subject.Summary.DestroyedAddresses; !slices.Equal(got, []string{"aws_instance.a", "aws_instance.b"}) {
		t.Fatalf("the caller's order was kept: %v", got)
	}
	sum["destroyedAddresses"] = []any{"aws_instance.a"}
	if _, err := gate.ParseRequest(tfChange(s, nil)); err == nil {
		t.Fatal("a summary that hides a destroy is accepted")
	}
	sum["destroyedAddresses"] = []any{"aws_instance.b", "aws_instance.a"}
	sum["destroy"] = 1
	if _, err := gate.ParseRequest(tfChange(s, nil)); err == nil {
		t.Fatal("a summary that miscounts is accepted")
	}
}

// A definition release is not a subject kind on the description.
func TestADefinitionReleaseHasNoDescription(t *testing.T) {
	req, err := gate.ParseRequest(release(nil, defDoc(t), nil))
	if err != nil {
		t.Fatal(err)
	}
	if d, err := gate.Describe(req); d != nil || err != nil {
		t.Fatal(d, err)
	}
}

// TestReplayStoredChanges is SDK-1's replay over a live chain's recorded changes: CLEARANCE_SUBJECT_REPLAY names a
// file of the changes table's records, one JSON object per line, exported with
//
//	psql "$DSN" -Atc "select record from changes" > changes.jsonl
//
// Every manifest-tree and terraform-plan change is re-described from what it stores and re-tiered under the
// lab baseline. The root must be the stored digest, and the tier and reasons must be the stored ones. A change
// registered with a clearance.yaml or a provenance reason (neither is stored in full) is counted as skipped, not
// compared. Unset, the test skips: the lab clusters are not reachable from CI.
func TestReplayStoredChanges(t *testing.T) {
	file := os.Getenv("CLEARANCE_SUBJECT_REPLAY")
	if file == "" {
		t.Skip("CLEARANCE_SUBJECT_REPLAY not set (docs/change-description.md, Replaying a chain)")
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	same, skipped, other := 0, 0, 0
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		c, err := gate.FromRecord(sc.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		c.View()
		if c.Subject.Kind != gate.KindManifestTree && c.Subject.Kind != gate.KindTerraformPlan {
			other++
			continue
		}
		if c.RepoPolicyDigest != nil || c.ProposerKind == "unknown" {
			skipped++
			continue
		}
		req := gate.ReplayRequest(c)
		d, err := gate.Describe(req)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		want := c.TreeDigest
		if c.Subject.Kind == gate.KindTerraformPlan {
			want = c.Subject.PlanDigest
		}
		if d.Subject.Root != bareHex(want) {
			t.Errorf("%s: root %s, stored %s", c.ID, d.Subject.Root, want)
		}
		cl, err := gate.Classify(req, baseline, deftest.Tools(), nil)
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		if cl.Tier != c.Tier || !reflect.DeepEqual(cl.Reasons, c.Reasons) {
			t.Errorf("%s (%s, policy %s): tier %d %v, stored %d %v", c.ID, c.Subject.Kind, c.PolicyVersion, cl.Tier, cl.Reasons, c.Tier, c.Reasons)
			continue
		}
		same++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("replayed %d changes identically; %d skipped (clearance.yaml or provenance reason); %d of other kinds", same, skipped, other)
	if same == 0 {
		t.Fatal("no change replayed: the replay would be vacuous")
	}
}
