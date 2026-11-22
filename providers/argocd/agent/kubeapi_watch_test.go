package agent_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

func standIn(t *testing.T, h http.HandlerFunc) *agent.API {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("sa-token\n"), 0o600)
	return &agent.API{Base: srv.URL, TokenFile: tok, Client: srv.Client(), Grants: agent.DefaultGrantAPI}
}

// The grant-expiry webhook's list and watch: the policy's selector (active=true, not the agent's managed-by), every
// namespace, status.checkedAt decoded, and the watch's events with their resourceVersions.
func TestActiveGrantsListAndWatch(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	k := standIn(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		if r.URL.Path != "/apis/clearance.hangar.io/v1/clearancegrants" || r.URL.Query().Get("labelSelector") != agent.LabelActive+"=true" {
			t.Errorf("unexpected %s", r.URL.RequestURI())
		}
		if r.URL.Query().Get("watch") != "true" {
			_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"100"},"items":[{"metadata":{"namespace":"app-a","name":"g1",` +
				`"labels":{"clearance.hangar.io/active":"true"}},"spec":{"expiresAt":"2026-11-20T12:15:00Z","objects":{"/ConfigMap/c":{"rendered":"h"}}},` +
				`"status":{"valid":true,"checkedAt":"2026-11-20T12:00:00Z"}}]}`))
			return
		}
		if r.URL.Query().Get("resourceVersion") != "100" || r.URL.Query().Get("allowWatchBookmarks") != "true" {
			t.Errorf("watch from %s", r.URL.RequestURI())
		}
		_, _ = w.Write([]byte(`{"type":"ADDED","object":{"metadata":{"namespace":"app-b","name":"g2","resourceVersion":"101","labels":{"clearance.hangar.io/active":"true"}},"spec":{}}}` + "\n" +
			`{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"102"}}}` + "\n" +
			`{"type":"DELETED","object":{"metadata":{"namespace":"app-a","name":"g1","resourceVersion":"103"},"spec":{}}}` + "\n" +
			`{"type":"ERROR","object":{"code":410}}` + "\n"))
	})
	gs, rv, err := k.ListActiveGrants(context.Background())
	if err != nil || rv != "100" || len(gs) != 1 {
		t.Fatalf("list: %v %q %v", gs, rv, err)
	}
	g := gs[0]
	if g.Namespace != "app-a" || g.Name != "g1" || !g.Active() || g.Valid == nil || !*g.Valid || g.CheckedAt != "2026-11-20T12:00:00Z" ||
		g.Spec.ExpiresAt != "2026-11-20T12:15:00Z" || g.Spec.Objects["/ConfigMap/c"].Rendered != "h" {
		t.Fatalf("decoded %+v", g)
	}
	var evs []agent.GrantEvent
	err = k.WatchActiveGrants(context.Background(), rv, func(ev agent.GrantEvent) { evs = append(evs, ev) })
	if !errors.Is(err, agent.ErrWatchGone) {
		t.Fatalf("a 410 in the stream is ErrWatchGone: %v", err)
	}
	if len(evs) != 3 || evs[0].Type != "ADDED" || evs[0].Grant.Name != "g2" || evs[0].RV != "101" ||
		evs[1].Type != "BOOKMARK" || evs[1].RV != "102" || evs[2].Type != "DELETED" || evs[2].Grant.Namespace != "app-a" || evs[2].RV != "103" {
		t.Fatalf("events %+v", evs)
	}
}

// The Lease REST calls: the path, a create without a resourceVersion, an update (PUT) guarded by it, 404 and 409 mapped.
func TestLeaseREST(t *testing.T) {
	var bodies []string
	state := 0
	k := standIn(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, r.Method+" "+r.URL.Path+" "+string(b))
		if !strings.HasPrefix(r.URL.Path, "/apis/coordination.k8s.io/v1/namespaces/clearance-system/leases") {
			t.Errorf("unexpected %s", r.URL.Path)
		}
		switch {
		case r.Method == "GET" && state == 0:
			w.WriteHeader(404)
		case r.Method == "GET":
			_, _ = w.Write([]byte(`{"metadata":{"name":"agent","namespace":"clearance-system","resourceVersion":"5"},` +
				`"spec":{"holderIdentity":"pod-a","leaseDurationSeconds":15,"renewTime":"2026-11-20T12:00:00.000000Z","leaseTransitions":1}}`))
		case r.Method == "POST":
			state = 1
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == "PUT":
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"reason":"Conflict"}`))
		}
	})
	ctx := context.Background()
	if _, err := k.GetLease(ctx, "clearance-system", "agent"); !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("404: %v", err)
	}
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	if err := k.CreateLease(ctx, agent.Lease{Namespace: "clearance-system", Name: "agent", ResourceVersion: "9", Holder: "pod-a", DurationSeconds: 15, RenewTime: at}); err != nil {
		t.Fatal(err)
	}
	if b := bodies[len(bodies)-1]; !strings.HasPrefix(b, "POST /apis/coordination.k8s.io/v1/namespaces/clearance-system/leases {") ||
		strings.Contains(b, "resourceVersion") || !strings.Contains(b, `"holderIdentity":"pod-a"`) || !strings.Contains(b, `"renewTime":"2026-11-20T12:00:00.000000Z"`) {
		t.Fatalf("create body: %s", b)
	}
	l, err := k.GetLease(ctx, "clearance-system", "agent")
	if err != nil || l.Holder != "pod-a" || l.ResourceVersion != "5" || !l.RenewTime.Equal(at) || l.Transitions != 1 {
		t.Fatalf("get: %+v %v", l, err)
	}
	if err := k.UpdateLease(ctx, l); !errors.Is(err, agent.ErrConflict) {
		t.Fatalf("409 on update: %v", err)
	}
	if b := bodies[len(bodies)-1]; !strings.HasPrefix(b, "PUT /apis/coordination.k8s.io/v1/namespaces/clearance-system/leases/agent ") ||
		!strings.Contains(b, `"resourceVersion":"5"`) {
		t.Fatalf("update body: %s", b)
	}
}

// The list is paged: limit on every page, continue followed until it is empty, the last page's resourceVersion kept.
func TestActiveGrantsListIsPaged(t *testing.T) {
	old := agent.SetActiveGrantsPage(1)
	defer agent.SetActiveGrantsPage(old)
	var queries []string
	k := standIn(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		queries = append(queries, q.Get("limit")+"|"+q.Get("continue"))
		item := func(name string) string {
			return `{"metadata":{"namespace":"app-a","name":"` + name + `","labels":{"clearance.hangar.io/active":"true"}},"spec":{}}`
		}
		switch q.Get("continue") {
		case "":
			_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"10","continue":"c1"},"items":[` + item("g1") + `]}`))
		case "c1":
			_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"11","continue":"c2"},"items":[` + item("g2") + `]}`))
		case "c2":
			_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"12"},"items":[` + item("g3") + `]}`))
		}
	})
	gs, rv, err := k.ListActiveGrants(context.Background())
	if err != nil || rv != "12" || len(gs) != 3 || gs[2].Name != "g3" {
		t.Fatalf("paged list: %v %q %v", gs, rv, err)
	}
	if strings.Join(queries, ",") != "1|,1|c1,1|c2" {
		t.Fatalf("pages asked for: %v", queries)
	}
}
