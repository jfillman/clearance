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
		if out.AgentPR == out.Identity.OK {
			t.Fatal("agent_pr must be the identity's failure when there is no record")
		}
	})
}
