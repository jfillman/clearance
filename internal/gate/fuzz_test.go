package gate_test

import (
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
)

// FuzzChangeRequest: any JSON body is parsed or refused (BadChange), never a panic; a parsed one classifies
// (or is refused DG-POLICY) and its id is stable.
func FuzzChangeRequest(f *testing.F) {
	f.Add(`{"app":"gate-api","env":"prod","cluster":"c","repo":"a/b","pr":7,"head":"` + head + `","proposer":"user:d","treeDigest":"` + strings.Repeat("c", 64) + `","objects":[{"apiVersion":"v1","kind":"Secret","name":"s","fields":["/data/x"]}],"policy":{"tiers":{"3":{"kinds":["X"]}},"approvers":{"2":{"owner":3}},"ttlDays":1}}`)
	f.Add(`{"app":"a","env":"e","cluster":"c","repo":"a/b","pr":0,"head":"` + head + `","proposer":"p","treeDigest":"` + strings.Repeat("c", 64) + `","definition":{"name":"x","new":{"name":"x"}}}`)
	f.Add(`{"app":"network","env":"lab","repo":"a/b","pr":1,"head":"` + head + `","proposer":"user:d","subject":{"kind":"terraform-plan","planDigest":"` + strings.Repeat("ab", 32) + `","planJsonDigest":"` + strings.Repeat("cd", 32) + `","variableSetDigest":"` + strings.Repeat("ef", 32) + `","workspace":{"backend":"s3","key":"k","name":"default"},"versions":{"terraform":"1.9.8","providers":{"p":"1.0"}},"summary":{"create":0,"update":1,"replace":0,"destroy":1,"destroyedAddresses":["aws_vpc.b"]},"targeted":true,"resources":[{"address":"aws_vpc.a","type":"aws_vpc","actions":["update"],"fields":["/tags/x"]},{"address":"aws_vpc.b","type":"aws_vpc","actions":["delete"],"actionReason":"replace_by_request"}]},"policy":{"workspaces":{"protected":["k"],"tiers":{"3":{"types":["aws_vpc"]}}}}}`)
	f.Add(`{"app":"a","env":"e","cluster":"c","repo":"a/b","pr":1,"head":"` + head + `","proposer":"p","treeDigest":"` + strings.Repeat("c", 64) + `","checks":{"admission":"pass"},"policy":{"ttlDays":1},"policyCommit":"` + head + `","admission":{"engine":"kyverno/1.19.0","verdict":"pass","bundle":"https://x//30-policy@` + head + `","deny":0,"warn":2}}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, body string) {
		v, err := pycompat.Decode(strings.NewReader(body))
		if err != nil {
			return
		}
		req, err := gate.ParseRequest(v)
		if err != nil {
			return
		}
		if req.ID() != req.ID() || !strings.HasPrefix(req.ID(), "ch-") {
			t.Fatal("unstable id")
		}
		c, err := gate.Classify(req, gate.DefaultPolicy(), deftest.Tools(), nil)
		if err != nil {
			return
		}
		if c.Tier < 0 || c.Tier > 3 || (c.Decision == "hold") != (c.Requirement != nil) {
			t.Fatalf("bad classification %+v", c)
		}
		if req.Admission != nil && req.Checks["admission"] != req.Admission.Verdict {
			t.Fatal("checks.admission is not the admission verdict")
		}
	})
}
