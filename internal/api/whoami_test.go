package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
)

// held is a holding change with a real requirement (1 from the owner group, 1 from outside).
func held(id, app, state, proposer string, approvals []gate.Approval, updated string) store.Change {
	tm, _ := time.Parse(time.RFC3339, updated)
	ts := gate.PyTime{Time: tm}
	c := &gate.Change{ID: id, App: app, Env: "prod", Repo: "jfillman/gitops-" + app, PR: 7, Head: strings.Repeat("1", 40),
		Owner: "group:default/team-gate", Tier: 3, State: state, Proposer: proposer, CreatedAt: ts, UpdatedAt: ts,
		ExpiresAt: gate.PyTime{Time: tm.AddDate(0, 0, 7)}, Reasons: []gate.Reason{{Rule: "kind:Rollout"}},
		Approvals:   approvals,
		Requirement: &gate.Requirement{Owner: 1, Outside: 1, OwnerGroup: "group:default/team-gate", OutsideGroups: []string{platform}}}
	raw, _ := json.Marshal(c.View())
	return store.Change{ID: id, App: app, Env: "prod", State: state, Repo: c.Repo, PR: 7, Head: c.Head,
		ExpiresAt: c.ExpiresAt.Time, Record: raw}
}

func awaitingWorld() world {
	return world{changes: []store.Change{
		held("w-1", "gate-api", "holding", "user:alice", nil, "2026-11-01T10:00:00Z"),
		// erin already cleared as owner: only an outside person may now
		held("w-2", "gate-api", "holding", "user:alice", []gate.Approval{{Person: "user:erin", Role: "owner"}}, "2026-11-01T11:00:00Z"),
		// erin proposed it
		held("w-3", "gate-api", "holding", "user:erin", nil, "2026-11-01T12:00:00Z"),
		held("w-4", "gate-api", "cleared", "user:alice", nil, "2026-11-01T13:00:00Z"),
	}}
}

func ids(m map[string]any) []string {
	out := []string{}
	for _, it := range items(m) {
		out = append(out, it["id"].(string))
	}
	return out
}

func TestAwaitingMeUsesTheGatesQualification(t *testing.T) {
	each(t, awaitingWorld(), func(t *testing.T, h *harness) {
		// erin (owner group): w-1 yes; w-2 she already cleared; w-3 she proposed; w-4 is not holding.
		if got := ids(h.ok("/v1/clearances?awaiting=me", "erin")); strings.Join(got, ",") != "w-1" {
			t.Errorf("erin: %v", got)
		}
		// bob (outside group): w-2 (owner filled, outside open), w-1 (outside open), w-3 (outside open), newest first.
		if got := ids(h.ok("/v1/clearances?awaiting=me", "bob")); strings.Join(got, ",") != "w-3,w-2,w-1" {
			t.Errorf("bob: %v", got)
		}
		// a delegate naming bob sees his.
		if got := ids(mustJSON200(t, h, "/v1/clearances?awaiting=me", "tower", "user:bob")); len(got) != 3 {
			t.Errorf("delegate for bob: %v", got)
		}
		// filters compose; limit pages with next.
		page := h.ok("/v1/clearances?awaiting=me&limit=1", "bob")
		if got := ids(page); len(got) != 1 || got[0] != "w-3" || page["next"] == nil {
			t.Errorf("page 1: %v next=%v", got, page["next"])
		}
		p2 := h.ok("/v1/clearances?awaiting=me&limit=1&after="+strings.ReplaceAll(page["next"].(string), "+", "%2B"), "bob")
		if got := ids(p2); len(got) != 1 || got[0] != "w-2" {
			t.Errorf("page 2: %v", got)
		}
		// sam is in no group: nothing; carol owns an app, not a group: nothing.
		for _, who := range []string{"sam", "carol"} {
			if got := ids(h.ok("/v1/clearances?awaiting=me", who)); len(got) != 0 {
				t.Errorf("%s: %v", who, got)
			}
		}
		// without the filter erin still sees what she sees
		if got := ids(h.ok("/v1/clearances", "erin")); len(got) != 4 {
			t.Errorf("unfiltered: %v", got)
		}
		h.status(t, 400, "GET", "/v1/clearances?awaiting=you", "erin", "")
		h.status(t, 400, "GET", "/v1/clearances?awaiting=me&state=cleared", "erin", "")
		h.status(t, 400, "GET", "/v1/clearances?awaiting=me", "audit", "") // an auditor has no clearing role
		h.status(t, 200, "GET", "/v1/clearances?awaiting=me&state=holding&app=gate-api", "erin", "")
	})
}

func TestWhoAmI(t *testing.T) {
	each(t, world{}, func(t *testing.T, h *harness) {
		h.status(t, 401, "GET", "/v1/whoami", "", "")
		h.status(t, 401, "GET", "/v1/whoami", "nobody", "")
		bob := h.ok("/v1/whoami", "bob")
		if bob["principal"] != "user:bob" || bob["person"] != "user:bob" || bob["role"] != "person" || bob["kind"] != "person" ||
			bob["via"] != nil || bob["admin"] != false || bob["auditor"] != false {
			t.Errorf("bob: %v", bob)
		}
		if g := bob["groups"].([]any); len(g) != 1 || g[0] != platform {
			t.Errorf("bob groups: %v", g)
		}
		if r := bob["roles"].([]any); len(r) != 1 || r[0] != "person" {
			t.Errorf("bob roles: %v", r)
		}
		carol := h.ok("/v1/whoami", "carol")
		if a := carol["apps"].([]any); len(a) != 1 || a[0] != "flight-api" {
			t.Errorf("carol apps: %v", carol)
		}
		sam := h.ok("/v1/whoami", "sam") // no groups, no apps: empty arrays, not null
		for _, k := range []string{"groups", "apps", "agents"} {
			if a, ok := sam[k].([]any); !ok || len(a) != 0 {
				t.Errorf("sam %s: %v", k, sam[k])
			}
		}
		au := h.ok("/v1/whoami", "audit")
		if au["auditor"] != true || au["role"] != "auditor" {
			t.Errorf("auditor: %v", au)
		}
		// a delegate naming bob: the principal is the delegate, the reads are bob's
		d := mustJSON200(t, h, "/v1/whoami", "tower", "user:bob")
		if d["principal"] != tower || d["person"] != "user:bob" || d["via"] != tower {
			t.Errorf("delegate: %v", d)
		}
		// a machine is let ask too; a feed reader is a feed
		if f := h.ok("/v1/whoami", "sync"); f["role"] != "feed" {
			t.Errorf("feed: %v", f)
		}
		// no secret leaves: only the documented keys
		for k := range bob {
			switch k {
			case "principal", "kind", "roles", "role", "person", "via", "admin", "auditor", "groups", "apps", "agents", "issuer", "expires_at":
			default:
				t.Errorf("unexpected key %q", k)
			}
		}
	})
	each(t, world{}, func(t *testing.T, h *harness) {
		h.srv.opt.Access.Admins = []string{"user:erin"}
		if e := h.ok("/v1/whoami", "erin"); e["admin"] != true {
			t.Errorf("erin: %v", e)
		}
		if e := h.ok("/v1/whoami", "bob"); e["admin"] != false {
			t.Errorf("bob: %v", e)
		}
	})
}
