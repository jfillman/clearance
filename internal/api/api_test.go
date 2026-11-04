package api

// Ported from tests/test_api.py (and the read-API tests of test_gate.py, test_definitions.py and test_evidence.py)
// for the routes clearance-api kept. Each HTTP test runs twice: on memStore (no database) and on Postgres
// (CLEARANCE_TEST_DSN, a scratch database per test; skipped without it), through the same assertions.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfillman/clearance/internal/decide/decidetest"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/profile"
	"github.com/jfillman/clearance/internal/review"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
	"github.com/jfillman/clearance/internal/store/pg"
)

var bg = context.Background()

// quiet is the tests' logger (CLEARANCE_API_TEST_LOG=1 shows it).
var quiet = func() *slog.Logger {
	if os.Getenv("CLEARANCE_API_TEST_LOG") != "" {
		return slog.Default()
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}()

const (
	tower    = "hangar-prod/app-backstage-prod/backstage-ingestor"
	agents   = "../../tests/fixtures/agents"
	platform = "group:default/platform"
)

// fakeAuth is test_api.py's Auth: a token per principal.
var principals = map[string]authn.Principal{
	"alice": {ID: "user:alice", Kind: authn.KindPerson}, "bob": {ID: "user:bob", Kind: authn.KindPerson},
	"carol": {ID: "user:carol", Kind: authn.KindPerson}, "erin": {ID: "user:erin", Kind: authn.KindPerson},
	"sam": {ID: "user:sam", Kind: authn.KindPerson}, "audit": {ID: "user:auditor", Kind: authn.KindPerson},
	"tower": {ID: tower, Kind: authn.KindForeignWorkload}, "svc": {ID: "ns/svc", Kind: authn.KindServiceAccount},
}

var fakeAuth = authn.AuthenticatorFunc(func(_ context.Context, token string) (authn.Principal, error) {
	p, ok := principals[token]
	if !ok {
		return authn.Principal{}, errors.New("no")
	}
	return p, nil
})

type groups map[string][]string

func (g groups) Groups(_ context.Context, p string) []string { return g[p] }

type owns map[string][]string

func (o owns) Apps(_ context.Context, p string) []string { return o[p] }

func loadAgents(t *testing.T) map[string]profile.AgentDefinition {
	t.Helper()
	defs, err := profile.LoadDir(agents)
	if err != nil {
		t.Fatal(err)
	}
	return defs
}

// -- the fixture chain ---------------------------------------------------------------------------------------------

const digest = "bb1e5855a74b2579ac3db9b82084f6ff341604610cbf82676c2f8ebf2965c71d"

func ev(m map[string]any) store.Event {
	base := store.Event{"ts": "2026-10-30T12:00:00Z", "task_id": nil, "session": nil, "parent": nil, "tier": nil,
		"rule": nil, "target": nil, "args_sha256": digest, "result": "ok", "decision": "allow"}
	for k, v := range m {
		base[k] = v
	}
	return base
}

// fixtureEvents is test_api.py's client fixture: four repo.pr.open calls (alice, bob, dave on flight-api, alice),
// each in its own session and task, now with the session.open records that make them a person's own (the
// sessions table is the gateway's), a deny, an outcome, and a sessionless provenance verdict.
func fixtureEvents() []store.Event {
	var out []store.Event
	who := []struct{ p, agent, app string }{{"user:alice", "coding-agent", ""}, {"user:bob", "orchestrator", ""},
		{"user:dave", "coding-agent", "flight-api"}, {"user:alice", "coding-agent", ""}}
	for i, w := range who {
		out = append(out, ev(map[string]any{"ts": fmt.Sprintf("2026-10-30T11:5%d:00Z", i), "task_id": fmt.Sprintf("t-%d", i),
			"session": fmt.Sprintf("s-%d", i), "principal": w.p, "agent": w.agent, "tool": "session.open", "result": "opened"}))
	}
	for i, w := range who {
		e := ev(map[string]any{"ts": fmt.Sprintf("2026-10-30T12:0%d:00Z", i), "task_id": fmt.Sprintf("t-%d", i),
			"session": fmt.Sprintf("s-%d", i), "principal": w.p, "agent": w.agent, "tool": "repo.pr.open", "tier": 1,
			"effect": map[string]any{"repo": "jfillman/flight-api", "pr": i}})
		if w.app != "" {
			e["app"] = w.app
		}
		out = append(out, e)
	}
	// seq 8: bob's orchestrator is denied; seq 9: the outcome of alice's seq 4; seq 10: a verdict, no session.
	out = append(out,
		ev(map[string]any{"ts": "2026-10-30T12:10:00Z", "task_id": "t-1", "session": "s-1", "principal": "user:bob",
			"agent": "orchestrator", "tool": "repo.pr.open", "decision": "deny", "rule": "R006", "result": "denied"}),
		ev(map[string]any{"ts": "2026-10-30T12:11:00Z", "task_id": "t-0", "session": "s-0", "principal": "user:alice",
			"agent": "coding-agent", "tool": "repo.pr.open", "tier": 1, "result": "opened PR 0",
			"effect":     map[string]any{"repo": "jfillman/flight-api", "pr": 0},
			"outcome_of": map[string]any{"seq": 4, "hash": strings.Repeat("a", 64)}}),
		ev(map[string]any{"ts": "2026-10-30T12:12:00Z", "principal": "ci/verifier", "tool": "provenance.verify",
			"target": "jfillman/flight-api#1", "result": "ok"}),
	)
	return out
}

func seed(t *testing.T, st store.Store, events []store.Event) {
	t.Helper()
	err := st.Atomic(bg, func(tx store.Tx) error {
		for _, e := range events {
			if _, err := tx.Append(bg, e, evidence.Core("test")); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// -- the gate's changes --------------------------------------------------------------------------------------------

func change(id, app, state, owner string, tier int, updated string, outside []string) store.Change {
	ts := func(s string) gate.PyTime {
		tm, _ := time.Parse(time.RFC3339, s)
		return gate.PyTime{Time: tm}
	}
	c := &gate.Change{ID: id, App: app, Env: "prod", Repo: "jfillman/gitops-" + app, PR: 7, Head: strings.Repeat("1", 40),
		Owner: owner, Tier: tier, State: state, CreatedAt: ts(updated), UpdatedAt: ts(updated),
		ExpiresAt: ts("2026-11-10T00:00:00Z"), Reasons: []gate.Reason{{Rule: "kind:Rollout"}},
		Requirement: &gate.Requirement{OutsideGroups: outside}}
	if state == "cleared" {
		by := "policy"
		c.ClearedBy = &by
	}
	raw, _ := json.Marshal(c.View())
	return store.Change{ID: id, App: app, Env: "prod", State: state, Repo: c.Repo, PR: 7, Head: c.Head,
		ExpiresAt: c.ExpiresAt.Time, Record: raw}
}

func fixtureChanges() []store.Change {
	return []store.Change{
		change("c-1", "gate-api", "holding", "group:default/team-gate", 2, "2026-11-01T10:00:00Z", []string{platform}),
		change("c-2", "other-app", "cleared", "group:default/team-other", 0, "2026-11-01T11:00:00Z", nil),
	}
}

// -- the stores ------------------------------------------------------------------------------------------------

var dbN atomic.Int64

func newDB(t *testing.T) string {
	t.Helper()
	admin := os.Getenv("CLEARANCE_TEST_DSN")
	if admin == "" {
		t.Skip("CLEARANCE_TEST_DSN not set")
	}
	conn, err := pgx.Connect(bg, admin)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("clr_api_%d_%d", os.Getpid(), dbN.Add(1))
	if _, err := conn.Exec(bg, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(bg, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		conn.Close(bg)
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

type world struct {
	events  []store.Event
	changes []store.Change
	defs    []store.Definition
	raw     []map[string]any // stored rows written as they are (v0 fixtures), instead of events
}

// backend builds the world on one kind of store and returns the api Store over it (and the writer DSN for pg).
type backend struct {
	name  string
	build func(t *testing.T, w world) (Store, string)
}

var backends = []backend{
	{"memory", func(t *testing.T, w world) (Store, string) {
		st := memory.New()
		seed(t, st, w.events)
		m, err := fromReader(bg, st)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range w.raw {
			c := map[string]any{"assurance": "recorded-not-checkpointed"}
			for k, v := range r {
				c[k] = v
			}
			m.recs = append(m.recs, c)
		}
		m.changes, m.defs = w.changes, w.defs
		return m, ""
	}},
	{"postgres", func(t *testing.T, w world) (Store, string) {
		dsn := newDB(t)
		if len(w.raw) > 0 {
			insertRaw(t, dsn, w.raw)
		}
		if len(w.raw) > 0 && len(w.events) == 0 && len(w.changes) == 0 && w.defs == nil {
			return openReader(t, dsn), dsn // the writer verifies the chain on open: a tampered one would not
		}
		st, err := pg.Open(bg, dsn, pg.Options{Logger: quiet})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(st.Close)
		seed(t, st, w.events)
		err = st.Atomic(bg, func(tx store.Tx) error {
			for _, c := range w.changes {
				if err := tx.PutChange(bg, c); err != nil {
					return err
				}
			}
			if w.defs != nil {
				return tx.ReplaceDefinitions(bg, w.defs)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return openReader(t, dsn), dsn
	}},
}

func openReader(t *testing.T, dsn string) *PG {
	t.Helper()
	rd, err := pg.OpenReader(bg, dsn, pg.Options{MaxConns: 2, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rd.Close)
	return &PG{R: rd}
}

// insertRaw writes stored rows as they are (the schema first): v0-draft fixtures and the live chain dump.
func insertRaw(t testing.TB, dsn string, rows []map[string]any) {
	t.Helper()
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	if _, err := conn.Exec(bg, pg.Schema); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		text, err := canon.Canonical(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(bg, "INSERT INTO clearance_evidence (seq, hash, prev_hash, record) VALUES ($1, $2, $3, $4::jsonb)",
			r["seq"].(json.Number).String(), r["hash"], r["prev_hash"], string(text)); err != nil {
			t.Fatal(err)
		}
	}
}

type harness struct {
	t   *testing.T
	srv *Server
	dsn string
}

type option func(*Options)

func noPolicy(o *Options)     { o.Engine = nil }
func noGatePolicy(o *Options) { o.GatePolicy = nil }

func newHarness(t *testing.T, b backend, w world, opts ...option) *harness {
	t.Helper()
	st, dsn := b.build(t, w)
	defs := NewDefinitions(loadAgents(t))
	if _, err := defs.Refresh(bg, st); err != nil {
		t.Fatal(err)
	}
	eng := decidetest.Engine(t)
	gp := gate.DefaultPolicy().View()
	o := Options{Store: st, Auth: fakeAuth, Log: quiet,
		Access: &Access{Delegates: []string{tower}, Notifiers: []string{tower}, Auditors: []string{"user:auditor"},
			Directory: groups{"user:bob": {platform}, "user:erin": {"group:default/team-gate"}},
			Ownership: owns{"user:carol": {"flight-api"}}, Owners: defs.Owners},
		Engine: eng, GatePolicy: &gp, Definitions: defs, GatewayURL: "http://clearance.example",
		Clock: func() time.Time { return time.Date(2026, 10, 30, 12, 30, 0, 0, time.UTC) }}
	for _, f := range opts {
		f(&o)
	}
	srv, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, srv: srv, dsn: dsn}
}

type resp struct {
	status int
	body   []byte
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(r.body))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("%s: %v", r.body, err)
	}
	return m
}

func (h *harness) do(method, path, token, who string) resp {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if who != "" {
		req.Header.Set(vocabtest.Lab().OnBehalfOfHeader, who)
	}
	rec := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(rec, req)
	return resp{rec.Code, rec.Body.Bytes()}
}

func (h *harness) get(path, token string) resp { return h.do("GET", path, token, "") }

func (h *harness) ok(path, token string) map[string]any {
	h.t.Helper()
	r := h.get(path, token)
	if r.status != 200 {
		h.t.Fatalf("GET %s as %s: %d %s", path, token, r.status, r.body)
	}
	return r.json(h.t)
}

func (h *harness) status(t *testing.T, want int, method, path, token, who string) {
	t.Helper()
	if r := h.do(method, path, token, who); r.status != want {
		t.Errorf("%s %s as %q for %q: %d, want %d (%s)", method, path, token, who, r.status, want, r.body)
	}
}

func items(m map[string]any) []map[string]any {
	var out []map[string]any
	for _, x := range m["items"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

func seqs(m map[string]any) []int64 {
	out := []int64{}
	for _, it := range items(m) {
		n, _ := it["seq"].(json.Number).Int64()
		out = append(out, n)
	}
	return out
}

func num(v any) int64 {
	n, _ := v.(json.Number).Int64()
	return n
}

func eqSeqs(t *testing.T, what string, got []int64, want ...int64) {
	t.Helper()
	if want == nil {
		want = []int64{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: seqs %v, want %v", what, got, want)
	}
}

func each(t *testing.T, w world, fn func(t *testing.T, h *harness), opts ...option) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) { fn(t, newHarness(t, b, w, opts...)) })
	}
}

// -- tests ---------------------------------------------------------------------------------------------------------

func TestTheCommittedContractIsCurrent(t *testing.T) {
	want, err := ContractJSON()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../" + ContractPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: run go generate ./internal/api and commit it", ContractPath)
	}
	doc, _ := ContractDoc()
	ops := map[string]bool{}
	for _, o := range doc.Operations {
		ops[o.OperationID] = true
	}
	for _, id := range []string{"listEvidence", "getEvidence", "verifyEvidence", "countEvidence", "getPolicy",
		"explainPolicy", "listReceipts", "listProvenance", "listClearances", "countClearances", "getClearance",
		"getClearancePolicy", "listDefinitions", "getContract"} {
		if !ops[id] {
			t.Errorf("the contract has no %s", id)
		}
	}
	// Every route the mux serves is in the contract, and every one has a 200 schema.
	for _, rt := range Routes() {
		if _, ok := doc.Responses[rt.OperationID]["200"]; !ok {
			t.Errorf("%s has no 200 schema", rt.OperationID)
		}
	}
}

func TestViewers(t *testing.T) {
	defs := NewDefinitions(loadAgents(t))
	a := &Access{Delegates: []string{tower}, Notifiers: []string{tower}, Auditors: []string{"user:auditor"},
		Directory: groups{"user:bob": {platform}}, Ownership: owns{"user:carol": {"Flight-API"}}, Owners: defs.Owners}
	v := func(tok, who string) (*Viewer, *apiError) { return a.Viewer(bg, principals[tok], who) }
	bob, _ := v("bob", "")
	if bob.Role != RolePerson || !in(bob.Agents, "orchestrator") || len(bob.Apps) != 0 {
		t.Errorf("bob: %+v", bob)
	}
	if carol, _ := v("carol", ""); !reflect.DeepEqual(carol.Apps, []string{"flight-api"}) {
		t.Errorf("carol owns %v (lower-cased)", carol.Apps)
	}
	if au, _ := v("audit", ""); !au.All() {
		t.Error("the auditor sees all")
	}
	if n, _ := v("tower", ""); n.Role != RoleNotifier {
		t.Errorf("tower alone is a notifier: %+v", n)
	}
	d, _ := v("tower", "user:bob")
	if d.Role != RolePerson || d.Person != "user:bob" || d.Via != tower || !in(d.Agents, "orchestrator") || d.role() != RoleDelegate {
		t.Errorf("tower for bob: %+v", d)
	}
	for _, c := range []struct {
		tok, who string
		status   int
	}{{"svc", "", 403}, {"svc", "user:bob", 403}, {"tower", "bob", 400}, {"tower", "user:" + strings.Repeat("x", 200), 400}} {
		if _, err := v(c.tok, c.who); err == nil || err.status != c.status {
			t.Errorf("%s for %q: %v, want %d", c.tok, c.who, err, c.status)
		}
	}
}

func TestHTTPScopesByViewer(t *testing.T) {
	each(t, world{events: fixtureEvents()}, func(t *testing.T, h *harness) {
		h.status(t, 401, "GET", "/v1/evidence", "", "")
		h.status(t, 401, "GET", "/v1/evidence", "nope", "")
		// alice: her two sessions' opens, calls and the outcome (sessions t-0 and t-3).
		eqSeqs(t, "alice", seqs(h.ok("/v1/evidence", "alice")), 9, 7, 4, 3, 0)
		// tower for bob: bob's session, and the orchestrator's records (his team's agent).
		eqSeqs(t, "tower for bob", seqs(mustJSON200(t, h, "/v1/evidence", "tower", "user:bob")), 8, 5, 1)
		eqSeqs(t, "carol (owns flight-api)", seqs(h.ok("/v1/evidence", "carol")), 6)
		if n := len(items(h.ok("/v1/evidence", "audit"))); n != 11 {
			t.Errorf("the auditor sees %d records", n)
		}
		page := h.ok("/v1/evidence?limit=1", "alice")
		one := h.ok("/v1/evidence/9", "alice")
		if num(page["next"]) != 9 || !reflect.DeepEqual(items(page)[0], one) {
			t.Errorf("page of one: %v vs %v", page, one)
		}
		eqSeqs(t, "after 7", seqs(h.ok("/v1/evidence?after=7", "alice")), 4, 3, 0)
		if p := h.ok("/v1/evidence", "alice"); p["next"] != nil {
			t.Errorf("a short page has no next: %v", p["next"])
		}
		h.status(t, 404, "GET", "/v1/evidence/1", "alice", "")
		h.status(t, 400, "GET", "/v1/evidence/x", "alice", "")
		h.status(t, 400, "GET", "/v1/evidence?after=x", "alice", "")
		h.status(t, 400, "GET", "/v1/evidence?limit=x", "alice", "")
		if n := len(items(h.ok("/v1/evidence?limit=1000", "audit"))); n != 11 {
			t.Errorf("limit is capped, not refused: %d", n)
		}
		// filters
		eqSeqs(t, "decision=deny", seqs(h.ok("/v1/evidence?decision=deny", "audit")), 8)
		eqSeqs(t, "rule", seqs(h.ok("/v1/evidence?rule=R006", "audit")), 8)
		eqSeqs(t, "task", seqs(h.ok("/v1/evidence?task=t-2", "audit")), 6, 2)
		eqSeqs(t, "session", seqs(h.ok("/v1/evidence?session=s-3", "audit")), 7, 3)
		eqSeqs(t, "principal+tool", seqs(h.ok("/v1/evidence?principal=user:alice&tool=session.open", "audit")), 3, 0)
		eqSeqs(t, "app", seqs(h.ok("/v1/evidence?app=flight-api", "audit")), 6)
		eqSeqs(t, "since/until", seqs(h.ok("/v1/evidence?since=2026-10-30T12:01:00Z&until=2026-10-30T12:03:00Z", "audit")), 6, 5)
		// since and until compare as text with the record's ts, as api.py does: a ts with no fraction sorts after
		// every fraction of its own second ('Z' > '.'), so Tower's toISOString (milliseconds) is second-granular.
		eqSeqs(t, "since, ms (Tower's toISOString)", seqs(h.ok("/v1/evidence?since=2026-10-30T12:10:00.001Z", "audit")), 10, 9, 8)
		eqSeqs(t, "since, next second", seqs(h.ok("/v1/evidence?since=2026-10-30T12:10:01.000Z", "audit")), 10, 9)
		eqSeqs(t, "outcomes=only", seqs(h.ok("/v1/evidence?outcomes=only", "audit")), 9)
		if n := len(items(h.ok("/v1/evidence?outcomes=exclude", "audit"))); n != 10 {
			t.Errorf("outcomes=exclude: %d", n)
		}
		h.status(t, 400, "GET", "/v1/evidence?outcomes=some", "audit", "")
		h.status(t, 400, "GET", "/v1/evidence?since=yesterday", "audit", "")
		// every record served is projected, with its assurance
		for _, r := range items(h.ok("/v1/evidence", "audit")) {
			if r["assurance"] != "recorded-not-checkpointed" || r["projected"] == nil || r["provider"] == nil {
				t.Errorf("not projected: %v", r)
			}
		}
	})
}

func mustJSON200(t *testing.T, h *harness, path, token, who string) map[string]any {
	t.Helper()
	r := h.do("GET", path, token, who)
	if r.status != 200 {
		t.Fatalf("GET %s: %d %s", path, r.status, r.body)
	}
	return r.json(t)
}

func TestHTTPRoles(t *testing.T) {
	each(t, world{events: fixtureEvents()}, func(t *testing.T, h *harness) {
		person := []string{"/v1/evidence", "/v1/evidence/1", "/v1/evidence/counts", "/v1/policy",
			"/v1/policy/explain?agent=coding-agent&tool=metrics.query", "/v1/receipts?repo=jfillman/flight-api",
			"/v1/provenance?repo=jfillman/flight-api", "/v1/clearances", "/v1/clearances/counts",
			"/v1/clearance-policy", "/v1/definitions"}
		for _, p := range person {
			h.status(t, 403, "GET", p, "tower", "")         // a notifier reads none of Clearance's records
			h.status(t, 403, "GET", p, "svc", "")           // a workload is no role
			h.status(t, 403, "GET", p, "svc", "user:bob")   // nor a delegate
			h.status(t, 400, "GET", p, "tower", "bob")      // a delegate names a person
			h.status(t, 401, "GET", p, "", "")              // no token
			h.status(t, 401, "GET", p, "forged", "")        // a refused one
			h.status(t, 200, "GET", p, "tower", "user:bob") // the delegate model
			h.status(t, 200, "GET", p, "audit", "")         // an auditor may call a person's route
		}
		h.status(t, 403, "GET", "/v1/evidence/verify", "alice", "")
		h.status(t, 403, "GET", "/v1/evidence/verify", "tower", "user:auditor")
		h.status(t, 403, "GET", "/v1/evidence/verify", "tower", "")
		if v := h.ok("/v1/evidence/verify", "audit"); v["ok"] != true || num(v["count"]) != 11 || v["bad_seq"] != nil {
			t.Errorf("verify: %v", v)
		}
		h.status(t, 400, "GET", "/v1/receipts", "alice", "")
		h.status(t, 400, "GET", "/v1/receipts?repo=flight-api", "alice", "")
		h.status(t, 400, "GET", "/v1/receipts?repo=jfillman/flight-api&pr=x", "alice", "")
		h.status(t, 400, "GET", "/v1/receipts?repo=jfillman/flight-api&pr=", "alice", "")
		if n := len(items(h.ok("/v1/receipts?repo=JFillman/Flight-API", "audit"))); n != 5 {
			t.Errorf("receipts (4 PRs and an outcome): %d", n)
		}
		eqSeqs(t, "receipts for pr 2", seqs(h.ok("/v1/receipts?repo=jfillman/flight-api&pr=2", "audit")), 6)
		eqSeqs(t, "alice's receipts", seqs(h.ok("/v1/receipts?repo=jfillman/flight-api", "alice")), 9, 7, 4)
		eqSeqs(t, "verdicts", seqs(h.ok("/v1/provenance?repo=jfillman/flight-api&pr=1", "audit")), 10)
		eqSeqs(t, "verdicts, any PR", seqs(h.ok("/v1/provenance?repo=jfillman/flight-api", "audit")), 10)
		eqSeqs(t, "no verdicts for another repo", seqs(h.ok("/v1/provenance?repo=jfillman/flight_api", "audit")))
		eqSeqs(t, "a verdict with no session is its principal's", seqs(h.ok("/v1/provenance?repo=jfillman/flight-api", "alice")))
		c := h.ok("/v1/contract", "")
		if c["gateway"] != "http://clearance.example" || c["api"] != "clearance-api" {
			t.Errorf("contract: %v %v", c["gateway"], c["api"])
		}
		if h.get("/healthz", "").status != 200 || h.get("/readyz", "").status != 200 {
			t.Error("health")
		}
		// strict requests
		h.status(t, 400, "GET", "/v1/evidence?agnet=x", "audit", "")
		h.status(t, 400, "GET", "/v1/evidence?agent=a&agent=b", "audit", "")
		h.status(t, 400, "GET", "/v1/evidence?%zz", "audit", "")
		h.status(t, 405, "POST", "/v1/evidence", "audit", "")
		h.status(t, 405, "DELETE", "/v1/clearances/c-1", "audit", "")
		h.status(t, 404, "GET", "/v1/sessions", "audit", "") // the gateway's (R-3)
		h.status(t, 404, "GET", "/v1/agents", "audit", "")
		req := httptest.NewRequest("GET", "/v1/evidence", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer audit")
		rec := httptest.NewRecorder()
		h.srv.Handler().ServeHTTP(rec, req)
		if rec.Code != 413 {
			t.Errorf("a body: %d", rec.Code)
		}
	})
}

func TestTheStoreFailingIs503(t *testing.T) {
	m := &memStore{fail: errors.New("connection refused to secret-host:5432")}
	h := &harness{t: t}
	srv, _ := New(Options{Store: m, Auth: fakeAuth, Log: quiet, Access: &Access{Auditors: []string{"user:auditor"}}})
	h.srv = srv
	for _, p := range []string{"/v1/evidence", "/v1/evidence/counts", "/v1/evidence/verify", "/v1/clearances"} {
		r := h.get(p, "audit")
		if p == "/v1/evidence/verify" {
			continue // memStore's Verify does not fail
		}
		if r.status != 503 || strings.Contains(string(r.body), "secret-host") {
			t.Errorf("%s: %d %s", p, r.status, r.body)
		}
	}
	if r := h.get("/readyz", ""); r.status != 503 || strings.Contains(string(r.body), "secret-host") {
		t.Errorf("readyz: %d %s", r.status, r.body)
	}
}

func TestCountsAreScopedAndGrouped(t *testing.T) {
	each(t, world{events: fixtureEvents()}, func(t *testing.T, h *harness) {
		got := h.ok("/v1/evidence/counts?by=agent", "audit")
		want := `{"by":"agent","items":[{"count":6,"key":"coding-agent"},{"count":3,"key":"orchestrator"},{"count":1,"key":null}],"outcomes":"exclude","total":10}`
		if b, _ := json.Marshal(got); string(b) != want {
			t.Errorf("by agent:\n got %s\nwant %s", b, want)
		}
		// outcomes: the outcome copies the decision's tool, so including it counts alice's call twice
		if n := num(h.ok("/v1/evidence/counts?by=tool&outcomes=include", "audit")["total"]); n != 11 {
			t.Errorf("outcomes=include total %d", n)
		}
		if n := num(h.ok("/v1/evidence/counts?by=tool&outcomes=only", "audit")["total"]); n != 1 {
			t.Errorf("outcomes=only total %d", n)
		}
		if n := num(h.ok("/v1/evidence/counts?by=tool", "alice")["total"]); n != 4 {
			t.Errorf("alice's records without the outcome: %d", n)
		}
		if b, _ := json.Marshal(items(h.ok("/v1/evidence/counts?by=app&decision=allow", "carol"))); string(b) != `[{"count":1,"key":"flight-api"}]` {
			t.Errorf("carol by app: %s", b)
		}
		// the list's filters count too (api.py ignored rule, task, session and principal here)
		if n := num(h.ok("/v1/evidence/counts?by=decision&rule=R006", "audit")["total"]); n != 1 {
			t.Errorf("rule filter: %d", n)
		}
		if b, _ := json.Marshal(items(h.ok("/v1/evidence/counts", "audit"))); !strings.HasPrefix(string(b), `[{"count":9,"key":null},{"count":1,"key":"R006"}]`) {
			t.Errorf("default by rule: %s", b)
		}
		h.status(t, 400, "GET", "/v1/evidence/counts?by=nope", "alice", "")
		h.status(t, 400, "GET", "/v1/evidence/counts?limit=5", "alice", "")
	})
}

func TestPolicyIsServedAsData(t *testing.T) {
	each(t, world{}, func(t *testing.T, h *harness) {
		p := h.ok("/v1/policy", "alice")
		var orders []int64
		byID := map[string]map[string]any{}
		for _, r := range p["rules"].([]any) {
			m := r.(map[string]any)
			orders = append(orders, num(m["order"]))
			byID[m["id"].(string)] = m
		}
		if !sort.SliceIsSorted(orders, func(i, j int) bool { return orders[i] < orders[j] }) {
			t.Errorf("not in evaluation order: %v", orders)
		}
		if byID["R001"]["pack"] != "core" || byID["R021"]["pack"] != "hangar" || byID["R001"]["expression"] != "!ctx.owns_session" {
			t.Errorf("R001 %v R021 %v", byID["R001"], byID["R021"])
		}
		tools := map[string]map[string]any{}
		for _, x := range p["tools"].([]any) {
			m := x.(map[string]any)
			tools[m["name"].(string)] = m
		}
		if tools["repo.pr.open_upper"]["tier"] != "T2" || tools["repo.pr.open_upper"]["propose_only"] != true ||
			tools["glidepath.run.rerun"]["tier"] != "T1" {
			t.Errorf("tools: %v %v", tools["repo.pr.open_upper"], tools["glidepath.run.rerun"])
		}
		if b, _ := json.Marshal(p["packs"]); string(b) != `["core","hangar"]` {
			t.Errorf("packs %s", b)
		}
		h.status(t, 403, "GET", "/v1/policy", "tower", "")
	})
}

func TestExplainIsADryRunWithThePathThroughTheRules(t *testing.T) {
	each(t, world{events: fixtureEvents()}, func(t *testing.T, h *harness) {
		ok := h.ok("/v1/policy/explain?agent=coding-agent&tool=metrics.query&args="+url.QueryEscape(`{"promql":"up"}`), "alice")
		dec := ok["decision"].(map[string]any)
		if dec["allow"] != true || ok["dry_run"] != true || ok["known_tool"] != true || dec["rule"] != nil {
			t.Errorf("allowed: %v", ok)
		}
		path, all := ok["path"].([]any), ok["all_rules"].([]any)
		for _, r := range path {
			if r.(map[string]any)["matched"] != false {
				t.Errorf("a rule matched on an allowed call: %v", r)
			}
		}
		if len(path) != len(all) {
			t.Errorf("path %d of %d", len(path), len(all))
		}
		args := url.QueryEscape(`{"repo":"jfillman/x","branch":"b","title":"t","files":[{"path":"a","content":"c"}]}`)
		deny := h.ok("/v1/policy/explain?agent=orchestrator&tool=repo.pr.open&args="+args, "alice")
		dd := deny["decision"].(map[string]any)
		dp := deny["path"].([]any)
		last := dp[len(dp)-1].(map[string]any)
		if dd["allow"] != false || dd["rule"] != "R006" || last["id"] != "R006" || last["matched"] != true {
			t.Errorf("orchestrator has no repo.pr.open: %v", deny)
		}
		for _, r := range dp[:len(dp)-1] {
			if r.(map[string]any)["matched"] != false {
				t.Errorf("before R006: %v", r)
			}
		}
		for q, status := range map[string]int{"agent=nope&tool=metrics.query": 404, "agent=coding-agent": 400,
			"agent=coding-agent&tool=metrics.query&args=%5B1%5D": 400, "agent=coding-agent&tool=metrics.query&args=nope": 400,
			"agent=coding-agent&tool=metrics.query&args=" + strings.Repeat("a", MaxExplainArgs+1): 400} {
			h.status(t, status, "GET", "/v1/policy/explain?"+q, "alice", "")
		}
		// Nothing was recorded.
		if n := len(items(h.ok("/v1/evidence", "audit"))); n != 11 {
			t.Errorf("explain recorded something: %d records", n)
		}
	})
}

func TestExplainWithoutAPolicyIs404(t *testing.T) {
	each(t, world{}, func(t *testing.T, h *harness) {
		h.status(t, 404, "GET", "/v1/policy", "alice", "")
		h.status(t, 404, "GET", "/v1/policy/explain?agent=coding-agent&tool=metrics.query", "alice", "")
	}, noPolicy)
}

// test_gate.py test_the_api_lists_changes_the_person_may_clear_or_owns
func TestTheAPIListsChangesThePersonMayClearOrOwns(t *testing.T) {
	each(t, world{changes: fixtureChanges()}, func(t *testing.T, h *harness) {
		if n := len(items(h.ok("/v1/clearances", "audit"))); n != 2 {
			t.Errorf("everything: %d", n)
		}
		mine := items(h.ok("/v1/clearances", "erin"))
		if len(mine) != 1 || mine[0]["app"] != "gate-api" {
			t.Errorf("erin's: %v", mine)
		}
		if n := len(items(h.ok("/v1/clearances", "sam"))); n != 0 {
			t.Errorf("sam's: %d", n)
		}
		if n := len(items(mustJSON200(t, h, "/v1/clearances", "tower", "user:bob"))); n != 1 {
			t.Errorf("bob is in c-1's outside group: %d", n)
		}
		one := h.ok("/v1/clearances/c-1", "erin")
		if num(one["tier"]) != 2 || one["reasons"].([]any)[0].(map[string]any)["rule"] != "kind:Rollout" {
			t.Errorf("one: %v", one)
		}
		h.status(t, 404, "GET", "/v1/clearances/c-2", "erin", "")
		h.status(t, 404, "GET", "/v1/clearances/nope", "audit", "")
		counts := h.ok("/v1/clearances/counts?by=state", "audit")
		keys := map[string]bool{}
		for _, it := range items(counts) {
			keys[it["key"].(string)] = true
		}
		if num(counts["total"]) != 2 || !keys["holding"] || !keys["cleared"] {
			t.Errorf("counts: %v", counts)
		}
		if b, _ := json.Marshal(items(h.ok("/v1/clearances/counts?by=cleared_by&state=cleared", "audit"))); string(b) != `[{"count":1,"key":"policy"}]` {
			t.Errorf("cleared_by: %s", b)
		}
		if b, _ := json.Marshal(items(h.ok("/v1/clearances/counts?by=tier&app=Gate-API", "audit"))); string(b) != `[{"count":1,"key":"2"}]` {
			t.Errorf("by tier (the key is text, as api.py): %s", b)
		}
		h.status(t, 400, "GET", "/v1/clearances/counts?by=nope", "audit", "")
		h.status(t, 400, "GET", "/v1/clearances/counts?state=odd", "audit", "")
		h.status(t, 400, "GET", "/v1/clearances/counts?since=nope", "audit", "")
		h.status(t, 400, "GET", "/v1/clearances?state=odd", "audit", "")
		h.status(t, 400, "GET", "/v1/clearances?pr=x", "audit", "")
		h.status(t, 400, "GET", "/v1/clearances?since=nope", "audit", "")
		for q, want := range map[string]int{"state=holding": 1, "tier=0": 1, "pr=7": 2, "pr=8": 0,
			"repo=JFillman/gitops-other-app": 1, "env=prod": 2, "since=2026-11-01T10:30:00%2B00:00": 1} {
			if n := len(items(h.ok("/v1/clearances?"+q, "audit"))); n != want {
				t.Errorf("%s: %d, want %d", q, n, want)
			}
		}
		page := h.ok("/v1/clearances?limit=1", "audit")
		if page["next"] != "2026-11-01T11:00:00+00:00" || items(page)[0]["id"] != "c-2" {
			t.Errorf("page: %v", page)
		}
		if p := h.ok("/v1/clearances?after="+url.QueryEscape("2026-11-01T11:00:00+00:00"), "audit"); len(items(p)) != 1 || items(p)[0]["id"] != "c-1" {
			t.Errorf("after: %v", p)
		}
		pol := h.ok("/v1/clearance-policy", "erin")
		appr := pol["approvers"].(map[string]any)["3"].(map[string]any)
		kinds := pol["tiers"].(map[string]any)["3"].(map[string]any)["kinds"].([]any)
		if num(appr["owner"]) != 1 || num(appr["outside"]) != 1 || num(pol["ttlDays"]) != 7 || !anyIs(kinds, "Secret") {
			t.Errorf("policy: %v", pol)
		}
	})
}

func anyIs(xs []any, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestTheAPIWithoutAGatePolicyAnswers404(t *testing.T) {
	each(t, world{}, func(t *testing.T, h *harness) {
		h.status(t, 404, "GET", "/v1/clearance-policy", "audit", "")
	}, noGatePolicy)
}

// test_definitions.py test_the_api_shows_source_and_rejected, on /v1/definitions.
func TestTheAPIShowsSourceAndRejected(t *testing.T) {
	doc := loadAgents(t)["triage-agent"].Raw
	pinned := map[string]any{}
	for k, v := range doc {
		pinned[k] = v
	}
	pinned["name"], pinned["owner"] = "gate-triage", "group:default/team-gate"
	pinned["identity"] = map[string]any{"type": "workload", "serviceAccount": "autopilot-runs/gate-triage"}
	src := definitions.Source{Kind: "cluster", Repo: definitions.Str("jfillman/gate-api"), Path: definitions.Str("agents/gate-triage.yaml"),
		Commit: definitions.Str(strings.Repeat("a", 40)), Namespace: definitions.Str("app-gate-api"), XR: definitions.Str("gate-triage"),
		LoadedAt: definitions.Str("2026-10-31T10:00:00Z")}
	bad := src
	bad.XR = definitions.Str("gate-two")
	rows := []definitions.Row{{Name: "gate-triage", State: "loaded", Source: src.View(), Doc: pinned}}
	reason := "schema: boom"
	rows = append(rows, definitions.Row{Name: "gate-two", State: "rejected", Source: bad.View(), Reason: &reason})
	var defs []store.Definition
	for _, r := range rows {
		raw, _ := json.Marshal(r)
		defs = append(defs, store.Definition{Name: r.Name, State: r.State, Record: raw})
	}
	each(t, world{defs: defs}, func(t *testing.T, h *harness) {
		out := h.ok("/v1/definitions", "audit")
		by := map[string]map[string]any{}
		for _, it := range items(out) {
			by[it["name"].(string)] = it
		}
		gs, _ := json.Marshal(by["gate-triage"]["source"])
		ws := resorted(src.View())
		if string(gs) != string(ws) {
			t.Errorf("source %s, want %s", gs, ws)
		}
		if b, _ := json.Marshal(by["triage-agent"]["source"]); string(b) != `{"kind":"bundled","pin":"bundled"}` {
			t.Errorf("bundled: %s", b)
		}
		rj, _ := json.Marshal(out["rejected"])
		wr := resorted([]definitions.RejectedView{{Name: "gate-two", Source: bad.View(), Reason: "schema: boom"}})
		if string(rj) != string(wr) {
			t.Errorf("rejected %s, want %s", rj, wr)
		}
		if by["gate-triage"]["owner"] != "group:default/team-gate" || by["gate-triage"]["instructions"] != nil {
			t.Errorf("gate-triage: %v", by["gate-triage"])
		}
		if _, has := by["orchestrator"]["instructions"]; has {
			t.Error("instructions without full=1")
		}
		full := h.ok("/v1/definitions?full=1", "audit")
		for _, it := range items(full) {
			if _, has := it["instructions"]; !has {
				t.Errorf("%s: no instructions with full=1", it["name"])
			}
		}
		for _, it := range items(h.ok("/v1/definitions?full=1", "alice")) {
			if _, has := it["instructions"]; has {
				t.Errorf("a person got %s's instructions", it["name"])
			}
		}
		// erin is in gate-triage's owner group: its records are hers to see
		if h.srv.opt.Access.Owners()["gate-triage"] != "group:default/team-gate" {
			t.Error("the pin's owner is not known to Access")
		}
	})
}

// test_evidence.py: v0-draft rows are served projected (provider, subject, projected), assurance beside them, and
// evidence.Stored of a served record is the stored row.
func TestV0RowsAreServedProjected(t *testing.T) {
	stored := readJSONL(t, "../evidence/testdata/python-chain.jsonl")
	projected := readJSONL(t, "../evidence/testdata/python-projected.jsonl")
	each(t, world{raw: stored}, func(t *testing.T, h *harness) {
		for i := range stored {
			got := h.ok(fmt.Sprintf("/v1/evidence/%d", i), "audit")
			want := map[string]any{}
			for k, v := range projected[i] {
				want[k] = v
			}
			want["assurance"] = "recorded-not-checkpointed"
			gb, _ := canon.Canonical(normalize(got))
			wb, _ := canon.Canonical(normalize(want))
			if string(gb) != string(wb) {
				t.Errorf("seq %d:\n got %s\nwant %s", i, gb, wb)
			}
			back, _ := canon.Canonical(evidence.Stored(normalize(got)))
			orig, _ := canon.Canonical(stored[i])
			if string(back) != string(orig) {
				t.Errorf("seq %d: Stored of the served record is not the row", i)
			}
		}
		if v := h.ok("/v1/evidence/verify", "audit"); v["ok"] != true || num(v["count"]) != int64(len(stored)) {
			t.Errorf("verify: %v", v)
		}
	})
}

// resorted is v's JSON with object keys sorted, as a decoded answer re-encodes.
func resorted(v any) []byte {
	b, _ := json.Marshal(v)
	var x any
	_ = json.Unmarshal(b, &x)
	b, _ = json.Marshal(x)
	return b
}

// normalize turns decoded JSON (json.Number) into canon.Parse's values.
func normalize(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	v, _ := canon.Parse(b)
	return v.(map[string]any)
}

func readJSONL(t testing.TB, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		v, err := canon.Parse(sc.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v.(map[string]any))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyFindsTheFirstBadRecord(t *testing.T) {
	stored := readJSONL(t, "../evidence/testdata/python-chain.jsonl")
	tampered := make([]map[string]any, len(stored))
	for i, r := range stored {
		c := map[string]any{}
		for k, v := range r {
			c[k] = v
		}
		tampered[i] = c
	}
	tampered[2]["tool"] = "edited"
	each(t, world{raw: tampered}, func(t *testing.T, h *harness) {
		v := h.ok("/v1/evidence/verify", "audit")
		if v["ok"] != false || num(v["count"]) != 2 || num(v["bad_seq"]) != 2 || v["head"] != stored[1]["hash"] {
			t.Errorf("verify: %v", v)
		}
	})
}

func TestThePostgresReaderIsReadOnly(t *testing.T) {
	dsn := newDB(t)
	st, err := pg.Open(bg, dsn, pg.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seed(t, st, fixtureEvents())
	rd, err := pg.OpenReader(bg, dsn, pg.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	rows, done, err := rd.Query(bg, "DELETE FROM clearance_evidence")
	if err == nil {
		for rows.Next() {
		}
		err = rows.Err()
		rows.Close()
		done()
	}
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("a delete through the reader: %v", err)
	}
}

// G-TF-1: clearance-api lists a terraform-plan change, as the core stored it, with its subject (kind, workspace,
// digests); a manifest change lists as kind manifest-tree.
func TestTheAPIListsATerraformPlanChangeWithItsSubject(t *testing.T) {
	sha := func(s string) string { return canon.SHA256Hex([]byte(s)) }
	body := map[string]any{"app": "network", "env": "lab", "repo": "jfillman/hangar-infra", "pr": json.Number("12"),
		"head": strings.Repeat("2", 40), "proposer": "user:dana", "owner": "group:default/team-gate",
		"checks": map[string]any{"ci": "pass", "provenance": "not-agent"},
		"subject": map[string]any{"kind": "terraform-plan", "planDigest": sha("plan"), "planJsonDigest": sha("plan json"),
			"variableSetDigest": sha("vars"), "workspace": map[string]any{"backend": "s3", "key": "network/lab/terraform.tfstate", "name": "default"},
			"versions":  map[string]any{"terraform": "1.9.8"},
			"summary":   map[string]any{"create": json.Number("0"), "update": json.Number("0"), "replace": json.Number("0"), "destroy": json.Number("1"), "destroyedAddresses": []any{"aws_instance.bastion"}},
			"resources": []any{map[string]any{"address": "aws_instance.bastion", "type": "aws_instance", "actions": []any{"delete"}}}}}
	req, err := gate.ParseRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := gate.Classify(req, gate.DefaultPolicy(), review.Registry{}, nil)
	if err != nil || cl.Tier != 3 {
		t.Fatal(cl, err)
	}
	c := gate.Open(req, cl, time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), "app-infra-cicd/pipeline-runner")
	raw, _ := json.Marshal(c)
	tf := store.Change{ID: c.ID, App: c.App, Env: c.Env, State: c.State, Repo: c.Repo, PR: int(c.PR), Head: c.Head,
		ExpiresAt: c.ExpiresAt.Time, Record: raw}
	each(t, world{changes: append(fixtureChanges(), tf)}, func(t *testing.T, h *harness) {
		kinds := map[string]string{}
		for _, it := range items(h.ok("/v1/clearances", "audit")) {
			s, _ := it["subject"].(map[string]any)
			kinds[it["id"].(string)], _ = s["kind"].(string)
		}
		if kinds[c.ID] != "terraform-plan" || len(kinds) != 3 {
			t.Fatalf("%v", kinds)
		}
		one := h.ok("/v1/clearances/"+c.ID, "audit")
		s := one["subject"].(map[string]any)
		if s["workspace"].(map[string]any)["key"] != "network/lab/terraform.tfstate" || s["digests"].(map[string]any)["planJson"] != sha("plan json") ||
			s["summary"].(map[string]any)["destroyedAddresses"].([]any)[0] != "aws_instance.bastion" || num(one["tier"]) != 3 {
			t.Fatalf("%v", one)
		}
	})
}
