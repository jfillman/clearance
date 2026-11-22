package agent_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/token"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// I-44, option 0: with a status heartbeat the agent refreshes status.checkedAt of every valid grant once it is that old,
// feed or no feed (the expiry pass runs either way), so the age of checkedAt says whether the pass still runs. Without
// one (the default) status is written only when valid changes, exactly as before.
func TestTheStatusHeartbeatRefreshesCheckedAt(t *testing.T) {
	for _, hb := range []time.Duration{0, 5 * time.Minute} {
		w := newWorld(t)
		a, err := agent.New(agent.Config{Cluster: "hangar-prod", Environment: "prod", Version: "0.0.0-test",
			ArgoNamespace: "argocd-apps", Projects: []string{"tenants"}, StateNS: "clearance-system", StatusHeartbeat: hb},
			w.kube, w.feeds, w.core, w.clock.now, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Load(context.Background()); err != nil {
			t.Fatal(err)
		}
		w.a = a
		w.kube.protect("app-a", nil)
		w.feeds.claims = []token.Claims{claim(w.feeds, ch2, "app-a", t0, deploy("web", hex("c")))}
		w.feeds.publish()
		if err := w.sync(); err != nil {
			t.Fatal(err)
		}
		first := w.grant("app-a", ch2).CheckedAt
		if first != t0.UTC().Format(time.RFC3339) {
			t.Fatalf("hb %v: checkedAt %q after the first write", hb, first)
		}
		valids := w.kube.verbs["valid"]
		w.clock.add(2 * time.Minute) // under the heartbeat: no write
		_ = w.sync()
		if w.kube.verbs["valid"] != valids {
			t.Fatalf("hb %v: a status write before the heartbeat is due", hb)
		}
		w.feeds.down = true // the expiry pass runs without a feed: so does the heartbeat
		w.clock.add(4 * time.Minute)
		_ = w.sync()
		g := w.grant("app-a", ch2)
		if hb == 0 {
			if w.kube.verbs["valid"] != valids || g.CheckedAt != first {
				t.Fatalf("no heartbeat: status is not rewritten (%d writes, checkedAt %q)", w.kube.verbs["valid"]-valids, g.CheckedAt)
			}
			continue
		}
		if w.kube.verbs["valid"] != valids+1 || g.CheckedAt != t0.Add(6*time.Minute).UTC().Format(time.RFC3339) || g.Valid == nil || !*g.Valid {
			t.Fatalf("heartbeat due: one status write, checkedAt now, still valid (%d writes, %+v)", w.kube.verbs["valid"]-valids, g)
		}
		w.clock.add(20 * time.Minute) // expired: marked invalid, and no heartbeat keeps it looking alive
		_ = w.sync()
		if g := w.grant("app-a", ch2); g.Valid == nil || *g.Valid {
			t.Fatalf("an expired grant is marked invalid, not refreshed: %+v", g)
		}
	}
}
