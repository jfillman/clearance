package provenance_test

// Ported from tests/test_provenance.py. The gateway's own repo.pr.open call (which writes the receipt) is R-1a/R-1d's;
// here the receipt is appended to the store as that call records it.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
)

const (
	gateID = "app-flight-api-cicd/pipeline-runner"
	bot    = "hangar-autopilot-agents[bot]"
	commit = "0000000000000000000000000000000000000001"
)

type fixture struct {
	svc *provenance.Service
	st  *memory.Store
	ctx context.Context
}

func newFixture(t *testing.T) *fixture {
	coding := definitions.Definition{Name: "coding-agent", ReposAllow: []string{"jfillman/*"}, DenyPaths: deftest.BaselineDenyPaths}
	reg := definitions.NewRegistry(map[string]definitions.Definition{"coding-agent": coding})
	st := memory.New()
	svc := &provenance.Service{Config: provenance.Config{Verifiers: []string{"app-*-cicd/pipeline-runner"}, AgentLogins: []string{bot}},
		Store: st, Clock: func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) }, Defs: reg}
	return &fixture{svc, st, context.Background()}
}

// opened writes the receipt of a PR the agent's session opened: task t-0000, session s-000001.
func (f *fixture) opened(t *testing.T, paths ...string) map[string]string {
	if len(paths) == 0 {
		paths = []string{"charts/values.yaml", "src/app.js"}
	}
	err := f.st.Atomic(f.ctx, func(tx store.Tx) error {
		_, err := tx.Append(f.ctx, store.Event{"ts": "2026-09-26T12:00:00Z", "task_id": "t-000000000001", "session": "s-000001", "parent": nil,
			"principal": "user:alice", "agent": "coding-agent", "tool": "repo.pr.open", "tier": "T1", "decision": "allow", "rule": nil,
			"target": "jfillman/flight-api", "args_sha256": strings.Repeat("0", 64), "result": "ok",
			"effect": map[string]any{"pr": json.Number("1"), "commit": commit, "branch": "agent/t-1", "repo": "jfillman/flight-api",
				"paths": anyList(paths)}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"task": "t-000000000001", "session": "s-000001", "agent": "coding-agent"}
}

func anyList(xs []string) []any {
	out := []any{}
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

func body(over map[string]any) map[string]any {
	b := map[string]any{"repo": "jfillman/flight-api", "pr": 1, "head": commit, "paths": anyList([]string{"charts/values.yaml", "src/app.js"}), "author": bot}
	for k, v := range over {
		b[k] = v
	}
	raw, _ := json.Marshal(b)
	v, _ := pycompat.Decode(strings.NewReader(string(raw)))
	return v.(map[string]any)
}

var gate = authn.Principal{ID: gateID, Kind: authn.KindServiceAccount}

func (f *fixture) ask(t *testing.T, over map[string]any) provenance.Verdict {
	t.Helper()
	v, err := f.svc.Provenance(f.ctx, gate, body(over))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *fixture) last(t *testing.T) store.Record {
	recs, _ := f.st.Records(f.ctx, 0, 1000)
	return recs[len(recs)-1]
}

func rule(c provenance.Check) string {
	if c.Rule == nil {
		return ""
	}
	return *c.Rule
}

func TestAPrClearanceOpenedIsConfirmedAndInScope(t *testing.T) {
	f := newFixture(t)
	tr := f.opened(t)
	v := f.ask(t, map[string]any{"trailers": map[string]any{"Task": tr["task"], "Session": tr["session"], "Agent": "coding-agent"}})
	if !v.AgentPR || v.Identity.Status != "confirmed" || !v.Identity.OK || v.Scope.Status != "in-scope" || !v.Scope.OK {
		t.Fatal(v)
	}
	if v.Record.Session != "s-000001" || v.Record.Tool != "repo.pr.open" {
		t.Fatal(v.Record)
	}
	last := f.last(t)
	if last["tool"] != "provenance.verify" || last["principal"] != gateID || last["result"] != "identity:confirmed scope:in-scope" || last["target"] != "jfillman/flight-api#1" {
		t.Fatal(last)
	}
	if last["session"] != "s-000001" || last["agent"] != "coding-agent" || last["rule"] != nil {
		t.Fatal(last)
	}
}

func TestAPersonsPrIsNotAnAgentPr(t *testing.T) {
	f := newFixture(t)
	v := f.ask(t, map[string]any{"author": "jfillman", "pr": 7})
	if v.AgentPR || v.Identity.Status != "not-agent" || !v.Identity.OK || !v.Scope.OK || v.Record != nil {
		t.Fatal(v)
	}
	raw, _ := json.Marshal(v.Scope)
	if strings.Contains(string(raw), "violations") {
		t.Fatal("a not-agent scope carries no violations key", string(raw))
	}
}

func TestAForgedTrailerFailsIdentity(t *testing.T) {
	f := newFixture(t)
	f.opened(t)
	v := f.ask(t, map[string]any{"pr": 2, "author": "jfillman", "trailers": map[string]any{"task": "t-0123456789ab"}})
	if rule(v.Identity) != "AI001" || v.Identity.OK || v.Scope.OK || rule(v.Scope) != "AI001" {
		t.Fatal(v)
	}
}

func TestAnAgentsAppPrWithoutARecordFailsIdentity(t *testing.T) {
	f := newFixture(t)
	if v := f.ask(t, map[string]any{"pr": 9}); rule(v.Identity) != "AI002" || v.Identity.OK {
		t.Fatal(v)
	}
}

func TestCommitsAfterTheAgentsFailIdentityAndExtraPathsFailScope(t *testing.T) {
	f := newFixture(t)
	f.opened(t)
	v := f.ask(t, map[string]any{"head": strings.Repeat("f", 40), "paths": anyList([]string{"charts/values.yaml", "src/app.js", "README.md"})})
	if rule(v.Identity) != "AI003" {
		t.Fatal(v)
	}
	if vs := *v.Scope.Violations; len(vs) != 1 || vs[0].Rule != "AS001" || vs[0].Path != "README.md" {
		t.Fatal(vs)
	}
}

func TestEditedTrailersFailIdentity(t *testing.T) {
	f := newFixture(t)
	tr := f.opened(t)
	if v := f.ask(t, map[string]any{"trailers": map[string]any{"task": "t-ffffffffffff", "session": tr["session"]}}); rule(v.Identity) != "AI004" {
		t.Fatal(v)
	}
}

func TestADeniedPathFailsScopeEvenInTheAgentsOwnCommit(t *testing.T) {
	f := newFixture(t)
	f.opened(t, "charts/values.yaml", "src/app.js", ".tekton/pr.yaml")
	v := f.ask(t, map[string]any{"paths": anyList([]string{"charts/values.yaml", ".tekton/pr.yaml"})})
	var got []string
	for _, x := range *v.Scope.Violations {
		got = append(got, x.Rule)
	}
	if !v.Identity.OK || !reflect.DeepEqual(got, []string{"AS002"}) {
		t.Fatal(v)
	}
}

func TestARetiredAgentAndARepoOutOfScope(t *testing.T) {
	f := newFixture(t)
	f.opened(t)
	f.svc.Defs = definitions.NewRegistry(map[string]definitions.Definition{"coding-agent": {Name: "coding-agent", ReposAllow: []string{"other/*"}}})
	if v := f.ask(t, nil); rule(v.Scope) != "AS003" || (*v.Scope.Violations)[0].Path != "" {
		t.Fatal(v.Scope)
	}
	f.svc.Defs = definitions.NewRegistry(nil)
	if v := f.ask(t, nil); rule(v.Scope) != "AS004" || v.Scope.Message != "agent definition 'coding-agent' is not in this deployment" {
		t.Fatal(v.Scope)
	}
}

func TestOnlyAVerifierMayAsk(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Provenance(f.ctx, authn.Principal{ID: "user:alice", Kind: authn.KindPerson}, body(nil))
	var nv *provenance.NotVerifier
	if !errors.As(err, &nv) {
		t.Fatal(err)
	}
}

func TestBadRequestsAreRefused(t *testing.T) {
	f := newFixture(t)
	z := strings.Repeat("0", 40)
	for _, b := range []map[string]any{{}, {"repo": "nope", "pr": 1, "head": z, "paths": []any{}},
		{"repo": "a/b", "pr": 0, "head": z, "paths": []any{}}, {"repo": "a/b", "pr": 1, "head": "abc", "paths": []any{}},
		{"repo": "a/b", "pr": 1, "head": z, "paths": "x"}, {"repo": "a/b", "pr": 1, "head": z, "paths": []any{}, "extra": 1}} {
		raw, _ := json.Marshal(b)
		v, _ := pycompat.Decode(strings.NewReader(string(raw)))
		_, err := f.svc.Provenance(f.ctx, gate, v)
		var br *provenance.BadRequest
		if !errors.As(err, &br) {
			t.Errorf("%v: %v", b, err)
		}
	}
}

func TestHTTPRoute(t *testing.T) {
	f := newFixture(t)
	f.opened(t)
	mux := http.NewServeMux()
	(&provenance.Handler{Svc: f.svc}).Routes(mux)
	post := func(p *authn.Principal, b any) (int, map[string]any) {
		raw, _ := json.Marshal(b)
		r := httptest.NewRequest("POST", "/v1/provenance", strings.NewReader(string(raw)))
		if p != nil {
			r = r.WithContext(authn.WithPrincipal(r.Context(), *p))
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	b := map[string]any{"repo": "jfillman/flight-api", "pr": 1, "head": commit, "paths": []string{"charts/values.yaml", "src/app.js"}}
	alice := authn.Principal{ID: "user:alice", Kind: authn.KindPerson}
	if code, _ := post(nil, b); code != 401 {
		t.Fatal(code)
	}
	if code, _ := post(&alice, b); code != 403 {
		t.Fatal(code)
	}
	if code, _ := post(&gate, map[string]any{"repo": 1}); code != 400 {
		t.Fatal(code)
	}
	code, out := post(&gate, b)
	if code != 200 || out["identity"].(map[string]any)["status"] != "confirmed" || out["audit_seq"] == nil {
		t.Fatal(code, out)
	}
}

func TestTheAppInstallationRecord(t *testing.T) {
	f := newFixture(t)
	rec, err := f.svc.RecordInstallation(f.ctx, "9", "created", "jfillman", []string{"jfillman/flight-api", "jfillman/gate-api"})
	if err != nil || rec["tool"] != "app.installation" || rec["principal"] != "app:9" || rec["target"] != "jfillman" || rec["result"] != "created: 2 repositories" {
		t.Fatal(rec, err)
	}
}
