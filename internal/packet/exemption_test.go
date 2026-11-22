package packet_test

import (
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/packet"
)

// A gate exemption (W-42) is its own class, listed only when the packet has one, and is not counted as an unresolved
// out-of-band finding.
func TestAGateExemptionIsItsOwnClass(t *testing.T) {
	const scope = "hangar-prod"
	st := miniChain(t, healthFor("2026-10-09T00:00:00Z", scope))
	lb := &labber{t: t, st: st}
	lb.add(argoW, gate("2026-11-02T10:00:50Z", "deploy.exception", "web", "staging", map[string]any{"coverage": "coverage-unavailable",
		"destination": map[string]any{"cluster": scope, "environment": "staging"},
		"exception": map[string]any{"kind": "gate-exemption", "exemption": map[string]any{"state": "requested", "application": "argocd/web-staging",
			"entry": "argocd/web-*", "rule": "tenants", "rule_digest": strings.Repeat("a", 64), "reason": "a migration to the new chart",
			"expires": "2026-12-01T00:00:00Z"}}}))
	rows := exceptionRows(t, st)
	if len(rows) != 1 || rows[0].Class != packet.ClassGateExemption || rows[0].Resolution != "exemption requested" ||
		!strings.Contains(rows[0].Diff, "argocd/web-staging exempt from rule tenants until 2026-12-01") {
		t.Fatalf("%+v", rows)
	}
}
