package provenance_test

import (
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/pycompat"
)

// FuzzProvenanceRequest: any JSON body is parsed or refused, and a parsed one verifies against no receipts.
func FuzzProvenanceRequest(f *testing.F) {
	f.Add(`{"repo":"a/b","pr":1,"head":"` + commit + `","paths":["../x","a/./b",".tekton/x"],"trailers":{"Task":"t"}}`)
	f.Add(`{"repo":"a/b","pr":1,"head":"` + commit + `","paths":[],"author":"x[bot]"}`)
	f.Add(`{"repo":"a/b","pr":1,"head":"` + commit + `","paths":[],"coauthors":[{"commit":"` + commit + `","trailer":"Co-Authored-By: Claude <noreply@anthropic.com>"}]}`)
	f.Fuzz(func(t *testing.T, body string) {
		v, err := pycompat.Decode(strings.NewReader(body))
		if err != nil {
			return
		}
		req, err := provenance.ParseRequest(v)
		if err != nil {
			return
		}
		out := provenance.Verify(req, nil, nil, []string{"x[bot]"})
		unattested := out.Identity.Status == provenance.Unattested
		if out.AgentPR != (!out.Identity.OK || unattested) {
			t.Fatal("agent_pr must be the identity's failure, or an unattested verdict, when there is no record")
		}
		if unattested && (!out.Identity.OK || !out.Scope.OK || out.Identity.Rule != nil || out.Identity.Coauthor == nil) {
			t.Fatal("an unattested verdict is a warning: ok, no rule, and it names its trailer")
		}
	})
}
