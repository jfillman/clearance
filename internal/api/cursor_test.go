package api

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/jfillman/clearance/internal/store"
)

// The change list pages by (updated_at, id): many changes sharing one second are all returned, none twice, on both
// stores (the memory store and Postgres).
func TestChangeListPagesThroughChangesSharingOneSecond(t *testing.T) {
	var cs []store.Change
	for i := 0; i < 25; i++ { // all in one second
		cs = append(cs, change(fmt.Sprintf("s-%02d", i), "gate-api", "cleared", "group:default/team-gate", 0, "2026-11-01T12:00:00Z", nil))
	}
	for i := 0; i < 6; i++ { // and a few in the seconds around it
		cs = append(cs, change(fmt.Sprintf("a-%02d", i), "gate-api", "cleared", "group:default/team-gate", 0, "2026-11-01T11:59:59Z", nil),
			change(fmt.Sprintf("z-%02d", i), "gate-api", "cleared", "group:default/team-gate", 0, "2026-11-01T12:00:01Z", nil))
	}
	each(t, world{changes: cs}, func(t *testing.T, h *harness) {
		for _, limit := range []int{1, 4, 7, 25, 100} {
			seen := map[string]int{}
			after := ""
			for pages := 0; pages < 200; pages++ {
				path := fmt.Sprintf("/v1/clearances?limit=%d", limit)
				if after != "" {
					path += "&after=" + url.QueryEscape(after)
				}
				p := h.ok(path, "audit")
				for _, it := range items(p) {
					seen[it["id"].(string)]++
				}
				next, _ := p["next"].(string)
				if next == "" {
					break
				}
				after = next
			}
			if len(seen) != len(cs) {
				t.Errorf("limit %d: %d of %d changes paged through", limit, len(seen), len(cs))
			}
			for id, n := range seen {
				if n != 1 {
					t.Errorf("limit %d: %s returned %d times", limit, id, n)
				}
			}
		}
		// An older client's cursor (a bare time) keeps working: everything strictly older.
		p := h.ok("/v1/clearances?after="+url.QueryEscape("2026-11-01T12:00:00+00:00"), "audit")
		if len(items(p)) != 6 {
			t.Errorf("a bare-time cursor: %d changes, want the 6 older ones", len(items(p)))
		}
	})
}
