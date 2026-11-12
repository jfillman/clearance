package api

// C-6: the packet's exceptions (GET /v1/exceptions), on records the gate itself wrote from a provider's reports:
// a degraded-mode report, an exception, a break-glass window, an outage read; and nothing else.

import (
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
	"github.com/jfillman/clearance/internal/store/pg"
)

var exceptionsNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// writeExceptions has the gate write, on st: seq 0 an ordinary decision (noise), seq 1 a break-glass window
// opened by an admin, seq 2 an out-of-band exception inside it, seq 3 a provider's degraded-mode report, seq 4 a
// runtime read allowed during an outage, seq 5 an ordinary deploy.outcome (noise).
func writeExceptions(t *testing.T, st store.Store) {
	t.Helper()
	argo := evidence.Writer{Provider: evidence.Provider{Name: "argo-gate", Version: "0.1.0"},
		Verified: map[string]bool{"provider": true, "ts": true}}
	gw := evidence.Writer{Provider: evidence.Provider{Name: "autopilot-gateway", Version: "0.4.1"},
		Verified: map[string]bool{"provider": true, "ts": true}}
	svc := gate.NewService(gate.Config{Admins: []string{"user:alice"}}, st, func() time.Time { return exceptionsNow })
	seed(t, st, []store.Event{ev(map[string]any{"principal": "user:carol", "tool": "repo.read", "app": "flight-api"})})
	if _, err := svc.OpenBreakglass(bg, authn.Principal{ID: "user:alice", Kind: authn.KindPerson},
		gate.BreakglassRequest{Reason: "rollback by hand", TTL: "1h", Cluster: "hangar-prod", Env: "prod",
			App: strPtr("flight-api")}, ""); err != nil {
		t.Fatal(err)
	}
	dest := map[string]any{"cluster": "hangar-prod", "environment": "prod"}
	base := func(tool string) store.Event {
		return store.Event{"ts": evidence.ISO(exceptionsNow), "tool": tool, "boundary": "deployment",
			"principal": "hangar-prod/argocd/clearance-sync", "target": "flight-api-prod", "result": "reported",
			"app": "flight-api", "destination": dest}
	}
	ex := base(gate.KindException)
	ex["exception"] = map[string]any{"kind": "out-of-band", "objects": []any{map[string]any{"kind": "Deployment",
		"name": "flight-api"}}}
	if _, err := svc.Report(bg, ex, argo); err != nil {
		t.Fatal(err)
	}
	dg := base(gate.KindDegraded)
	dg["decision"], dg["coverage"], dg["tier"] = "allow", "coverage-unavailable", 1
	dg["outage"] = map[string]any{"from": "2026-10-30T11:00:00Z", "to": "2026-10-30T11:20:00Z"}
	if _, err := svc.Report(bg, dg, argo); err != nil {
		t.Fatal(err)
	}
	err := st.Atomic(bg, func(tx store.Tx) error {
		if _, err := tx.Append(bg, ev(map[string]any{"principal": "autopilot-runs/x", "agent": "coding-agent",
			"tool": "repo.read", "tier": 0, "coverage": "coverage-unavailable", "app": "flight-api", "session": "s-9",
			"task_id": "t-9"}), gw); err != nil {
			return err
		}
		out := base("deploy.outcome")
		out["outcome"] = map[string]any{"applied": true}
		_, err := tx.Append(bg, out, argo)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func strPtr(s string) *string { return &s }

var exceptionBackends = []backend{
	{"memory", func(t *testing.T, _ world) (Store, string) {
		st := memory.New()
		writeExceptions(t, st)
		m, err := fromReader(bg, st)
		if err != nil {
			t.Fatal(err)
		}
		return m, ""
	}},
	{"postgres", func(t *testing.T, _ world) (Store, string) {
		dsn := newDB(t)
		st, err := pg.Open(bg, dsn, pg.Options{Logger: quiet})
		if err != nil {
			t.Fatal(err)
		}
		writeExceptions(t, st)
		st.Close()
		return openReader(t, dsn), dsn
	}},
}

func TestTheExceptionsListIsWhatThePacketReads(t *testing.T) {
	for _, b := range exceptionBackends {
		t.Run(b.name, func(t *testing.T) {
			h := newHarness(t, b, world{})
			all := h.ok("/v1/exceptions", "audit")
			eqSeqs(t, "auditor", seqs(all), 4, 3, 2, 1)
			got := items(all)
			deg := got[1]
			if deg["tool"] != gate.KindDegraded || deg["coverage"] != "coverage-unavailable" {
				t.Fatalf("the degraded-mode report is not in the exceptions: %v", deg)
			}
			if op := deg["outage_policy"].(map[string]any); op["source"] != "baseline" || op["conforms"] != true {
				t.Fatal(op)
			}
			if got[2]["breakglass"] == nil || !strings.HasPrefix(got[2]["breakglass"].(string), "bg-") {
				t.Fatalf("the exception inside the window does not name it: %v", got[2])
			}
			eqSeqs(t, "tool", seqs(h.ok("/v1/exceptions?tool=deploy.degraded", "audit")), 3)
			eqSeqs(t, "kind", seqs(h.ok("/v1/exceptions?kind=out-of-band", "audit")), 2)
			eqSeqs(t, "kind none", seqs(h.ok("/v1/exceptions?kind=drift", "audit")))
			eqSeqs(t, "page", seqs(h.ok("/v1/exceptions?limit=2", "audit")), 4, 3)
			eqSeqs(t, "after", seqs(h.ok("/v1/exceptions?after=3", "audit")), 2, 1)
			// O-5: every person reads every exception, the owner and the stranger alike; a machine principal does not
			eqSeqs(t, "owner", seqs(h.ok("/v1/exceptions", "carol")), 4, 3, 2, 1)
			eqSeqs(t, "stranger", seqs(h.ok("/v1/exceptions", "bob")), 4, 3, 2, 1)
			eqSeqs(t, "delegate for a stranger", seqs(h.do("GET", "/v1/exceptions", "tower", "user:alice").json(t)), 4, 3, 2, 1)
			h.status(t, 403, "GET", "/v1/exceptions", "svc", "")
			h.status(t, 400, "GET", "/v1/exceptions?kind=sideways", "audit", "")
			h.status(t, 400, "GET", "/v1/exceptions?tool=repo.read", "audit", "")
			h.status(t, 400, "GET", "/v1/exceptions?decision=allow", "audit", "")
			h.status(t, 401, "GET", "/v1/exceptions", "", "")
		})
	}
}
