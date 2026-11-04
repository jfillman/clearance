package gate_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
)

// FuzzChangeRequest: any JSON body is parsed or refused (BadChange), never a panic; a parsed one classifies
// (or is refused DG-POLICY) and its id is stable.
func FuzzChangeRequest(f *testing.F) {
	f.Add(`{"app":"gate-api","env":"prod","cluster":"c","repo":"a/b","pr":7,"head":"` + head + `","proposer":"user:d","treeDigest":"` + strings.Repeat("c", 64) + `","objects":[{"apiVersion":"v1","kind":"Secret","name":"s","fields":["/data/x"]}],"policy":{"tiers":{"3":{"kinds":["X"]}},"approvers":{"2":{"owner":3}},"ttlDays":1}}`)
	f.Add(`{"app":"a","env":"e","cluster":"c","repo":"a/b","pr":0,"head":"` + head + `","proposer":"p","treeDigest":"` + strings.Repeat("c", 64) + `","definition":{"name":"x","new":{"name":"x"}}}`)
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

// FuzzProviderReport: any JSON object posted as a deploy.exception or deploy.degraded record is accepted or refused
// (BadReport), never a panic; an accepted exception always has the core's coverage for its kind.
func FuzzProviderReport(f *testing.F) {
	f.Add(`{"tool":"deploy.exception","destination":{"cluster":"c","environment":"e"},"exception":{"kind":"out-of-band","objects":[{"kind":"Deployment","name":"x"}]}}`)
	f.Add(`{"tool":"deploy.exception","destination":{"cluster":"c","environment":"e"},"change":{"id":"ch-0123456789abcdef"},"exception":{"kind":"digest-mismatch","expected":"a","observed":"b"}}`)
	f.Add(`{"tool":"deploy.degraded","destination":{"cluster":"c","environment":"e"},"decision":"allow","coverage":"coverage-unavailable","outage":{"from":"2026-01-01T00:00:00Z","to":"2026-01-01T01:00:00Z"}}`)
	f.Add(`{"tool":"deploy.exception","exception":[]}`)
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, body string) {
		v, err := pycompat.Decode(strings.NewReader(body))
		if err != nil {
			return
		}
		ev, ok := v.(map[string]any)
		if !ok {
			return
		}
		err = gate.CheckReport(ev, now)
		var br *gate.BadReport
		if err != nil && !errors.As(err, &br) {
			t.Fatalf("not a BadReport: %v", err)
		}
		if err == nil && ev["tool"] == gate.KindException {
			kind := ev["exception"].(map[string]any)["kind"].(string)
			if ev["coverage"] != gate.ExceptionCoverage[kind] {
				t.Fatalf("coverage %v for %s", ev["coverage"], kind)
			}
		}
	})
}
