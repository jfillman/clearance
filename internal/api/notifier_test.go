package api

import (
	"net/http"
	"strings"
	"testing"
)

// G5: a notifier reads every change of the gate (the list, the counts, the stream's clearance events) and nothing else:
// not a change by id (it carries the clearance token), not the evidence, not a grant feed's tokens.
func TestANotifierReadsEveryChangeAndNothingElse(t *testing.T) {
	each(t, world{changes: fixtureChanges()}, func(t *testing.T, h *harness) {
		if n := len(items(h.ok("/v1/clearances", "tower"))); n != 2 {
			t.Errorf("the notifier sees every change: %d", n)
		}
		if n := len(items(h.ok("/v1/clearances?state=holding", "tower"))); n != 1 {
			t.Errorf("filters apply: %d", n)
		}
		if c := h.ok("/v1/clearances/counts?by=state", "tower"); num(c["total"]) != 2 {
			t.Errorf("counts: %v", c)
		}
		for _, p := range []string{"/v1/clearances/c-1", "/v1/clearances/c-1/attestation", "/v1/clearances/c-1/records",
			"/v1/evidence", "/v1/attestations", "/v1/clearance-policy"} {
			h.status(t, 403, "GET", p, "tower", "")
		}
		// the cluster+cleared filter is a filter for a notifier, never a grant feed with tokens
		for _, it := range items(h.ok("/v1/clearances?cluster=hangar-prod&state=cleared", "tower")) {
			if _, has := it["token"]; has {
				t.Errorf("a notifier read a token: %v", it)
			}
		}
		// awaiting=me is a person's question
		h.status(t, 400, "GET", "/v1/clearances?awaiting=me", "tower", "")
		// the stream: clearance events only
		r := h.do("GET", "/v1/stream?types=records", "tower", "")
		if r.status != http.StatusForbidden || !strings.Contains(string(r.body), "clearance events only") {
			t.Errorf("the notifier's stream of records: %d %s", r.status, r.body)
		}
	})
}
