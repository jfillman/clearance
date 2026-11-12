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
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/provenance"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
	"github.com/jfillman/clearance/internal/vocab"
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
				"paths": anyList(paths)}}, evidence.Core(""))
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

// -- AI co-author trailers: agent work outside Clearance (warn-only, user decision 2026-11-04) ----------------------

const claude = "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"

func coauthors(lines ...string) []any {
	out := []any{}
	for _, l := range lines {
		out = append(out, map[string]any{"commit": commit, "trailer": l})
	}
	return out
}

func TestAPrWithOnlyAClaudeTrailerIsUnattested(t *testing.T) {
	f := newFixture(t)
	v := f.ask(t, map[string]any{"author": "jfillman", "pr": 7, "coauthors": coauthors("Co-authored-by: Dana <dana@example.com>", claude)})
	if !v.AgentPR || v.Identity.Status != provenance.Unattested || !v.Identity.OK || v.Identity.Rule != nil || v.Record != nil {
		t.Fatal(v)
	}
	if v.Scope.Status != provenance.Unattested || !v.Scope.OK || v.Scope.Rule != nil || v.Scope.Violations != nil {
		t.Fatal(v.Scope)
	}
	if c := v.Identity.Coauthor; c == nil || c.Commit != commit || c.Trailer != claude || v.Scope.Coauthor == nil {
		t.Fatal(v.Identity.Coauthor)
	}
	if !strings.Contains(v.Identity.Message, "co-authored by an AI agent outside Clearance") || !strings.Contains(v.Identity.Message, "noreply@anthropic.com") ||
		!strings.Contains(v.Identity.Message, "no Clearance attestation") {
		t.Fatal(v.Identity.Message)
	}
	// the evidence record carries the verdict, so auditors can count unattested PRs; it is no rule and no deny
	last := f.last(t)
	if last["tool"] != "provenance.verify" || last["result"] != "identity:unattested scope:unattested" || last["rule"] != nil || last["decision"] != "allow" {
		t.Fatal(last)
	}
	raw, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if id := out["identity"].(map[string]any); id["status"] != "unattested" || id["coauthor"].(map[string]any)["trailer"] != claude {
		t.Fatal(string(raw))
	}
}

func TestAPrWithNoAICoauthorIsStillNotAnAgentPr(t *testing.T) {
	f := newFixture(t)
	for _, cs := range [][]any{nil, coauthors(), coauthors("Co-authored-by: Dana <dana@example.com>")} {
		over := map[string]any{"author": "jfillman", "pr": 7}
		if cs != nil {
			over["coauthors"] = cs
		}
		v := f.ask(t, over)
		if v.AgentPR || v.Identity.Status != "not-agent" || v.Scope.Status != "not-agent" || v.Identity.Coauthor != nil {
			t.Fatal(v)
		}
		raw, _ := json.Marshal(v.Identity)
		if strings.Contains(string(raw), "coauthor") {
			t.Fatal("a not-agent verdict carries no coauthor key", string(raw))
		}
	}
	// an empty matcher list turns the check off
	prev := vocab.Get()
	off := prev
	off.AICoauthors = nil
	vocab.Set(off)
	t.Cleanup(func() { vocab.Set(prev) })
	if v := f.ask(t, map[string]any{"author": "jfillman", "pr": 7, "coauthors": coauthors(claude)}); v.Identity.Status != "not-agent" {
		t.Fatal(v)
	}
}

func TestTheExistingAgentSignalsWinOverAnAICoauthor(t *testing.T) {
	f := newFixture(t)
	// a Hangar-* trailer without a record is still forged (AI001)
	v := f.ask(t, map[string]any{"pr": 2, "author": "jfillman", "trailers": map[string]any{"task": "t-0123456789ab"}, "coauthors": coauthors(claude)})
	if rule(v.Identity) != "AI001" || v.Identity.OK || rule(v.Scope) != "AI001" || v.Identity.Coauthor != nil {
		t.Fatal(v)
	}
	// the agents' login without a record is still AI002
	if v := f.ask(t, map[string]any{"pr": 9, "coauthors": coauthors(claude)}); rule(v.Identity) != "AI002" || v.Identity.OK {
		t.Fatal(v)
	}
	// with a record, the record decides: confirmed, and a later commit is still AI003
	tr := f.opened(t)
	v = f.ask(t, map[string]any{"trailers": map[string]any{"task": tr["task"], "session": tr["session"]}, "coauthors": coauthors(claude)})
	if v.Identity.Status != "confirmed" || v.Scope.Status != "in-scope" || v.Identity.Coauthor != nil {
		t.Fatal(v)
	}
	if v := f.ask(t, map[string]any{"head": strings.Repeat("f", 40), "coauthors": coauthors(claude)}); rule(v.Identity) != "AI003" {
		t.Fatal(v)
	}
}

func TestBadCoauthorsAreRefused(t *testing.T) {
	f := newFixture(t)
	for _, cs := range []any{"x", []any{"x"}, []any{map[string]any{"commit": "abc", "trailer": claude}},
		[]any{map[string]any{"commit": commit}}, []any{map[string]any{"commit": commit, "trailer": "Signed-off-by: Dana <d@e.f>"}},
		[]any{map[string]any{"commit": commit, "trailer": "no colon"}}, []any{map[string]any{"commit": commit, "trailer": claude, "x": 1}},
		[]any{map[string]any{"commit": commit, "trailer": claude + "\nCo-Authored-By: x <y@z>"}},
		[]any{map[string]any{"commit": commit, "trailer": "Co-Authored-By: " + strings.Repeat("a", provenance.MaxTrailer)}},
		coauthors(make([]string, provenance.MaxCoauthors+1)...)} {
		_, err := f.svc.Provenance(f.ctx, gate, body(map[string]any{"coauthors": cs}))
		var br *provenance.BadRequest
		if !errors.As(err, &br) {
			t.Errorf("%v: %v", cs, err)
		}
	}
}

// --- Glidepath's propose scope class: a PR that needs a person (docs/provenance-app.md) ---------------------------------

// openedForAPerson writes the receipt of a PR an agent opened with its tool's human-merge mark: merge: person and the
// paths that need a person (what the tool, not the agent, sets).
func (f *fixture) openedForAPerson(t *testing.T, needs []string, paths ...string) map[string]string {
	t.Helper()
	err := f.st.Atomic(f.ctx, func(tx store.Tx) error {
		_, err := tx.Append(f.ctx, store.Event{"ts": "2026-09-26T12:00:00Z", "task_id": "t-000000000001", "session": "s-000001", "parent": nil,
			"principal": "user:alice", "agent": "coding-agent", "tool": "glidepath.cicd.propose", "tier": "T1", "decision": "allow", "rule": nil,
			"target": "jfillman/flight-api", "args_sha256": strings.Repeat("0", 64), "result": "ok",
			"effect": map[string]any{"pr": json.Number("1"), "commit": commit, "branch": "agent/t-1", "repo": "jfillman/flight-api",
				"merge": "person", "needsPerson": anyList(needs), "paths": anyList(paths)}}, evidence.Core(""))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"task": "t-000000000001", "session": "s-000001", "agent": "coding-agent"}
}

func (f *fixture) askProposal(t *testing.T, tr map[string]string, over map[string]any) provenance.Verdict {
	t.Helper()
	o := map[string]any{"trailers": tr, "paths": anyList([]string{"cicd.yaml"})}
	for k, v := range over {
		o[k] = v
	}
	return f.ask(t, o)
}

func TestAnOpenProposalNeedsAPersonAndIsNeverPlainSuccess(t *testing.T) {
	f := newFixture(t)
	tr := f.openedForAPerson(t, []string{"cicd.yaml"}, "cicd.yaml")
	v := f.askProposal(t, tr, nil)
	if !v.Scope.OK || v.Scope.Status != provenance.NeedsPerson || !strings.HasPrefix(v.Scope.Message, "needs a person: cicd.yaml") {
		t.Fatalf("%+v", v.Scope)
	}
	if !reflect.DeepEqual(v.Scope.NeedsPerson, []string{"cicd.yaml"}) {
		t.Fatalf("%v", v.Scope.NeedsPerson)
	}
	if !v.Identity.OK || v.Identity.Status != "confirmed" {
		t.Fatalf("identity %+v", v.Identity)
	}
	if got := f.last(t)["result"]; got != "identity:confirmed scope:needs-person" {
		t.Fatalf("recorded %v", got)
	}
}

func TestAProposalMergedByAPersonPasses(t *testing.T) {
	f := newFixture(t)
	tr := f.openedForAPerson(t, []string{"cicd.yaml"}, "cicd.yaml")
	v := f.askProposal(t, tr, map[string]any{"merged": true, "mergedBy": "riley", "mergedByBot": false})
	if !v.Scope.OK || v.Scope.Status != provenance.PersonMerged || v.Scope.MergedBy != "riley" {
		t.Fatalf("%+v", v.Scope)
	}
}

func TestAProposalMergedByABotOrAnAgentLoginFailsAS005(t *testing.T) {
	for name, over := range map[string]map[string]any{
		"a bot account":     {"merged": true, "mergedBy": "some-app[bot]", "mergedByBot": true},
		"the agents' login": {"merged": true, "mergedBy": strings.ToUpper(bot), "mergedByBot": false},
		"nobody named":      {"merged": true, "mergedBy": "", "mergedByBot": false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			tr := f.openedForAPerson(t, []string{"cicd.yaml"}, "cicd.yaml")
			v := f.askProposal(t, tr, over)
			if v.Scope.OK || rule(v.Scope) != "AS005" || !strings.Contains(v.Scope.Message, "not a person") {
				t.Fatalf("%+v", v.Scope)
			}
			if v.Scope.Violations == nil || len(*v.Scope.Violations) != 1 || (*v.Scope.Violations)[0].Path != "cicd.yaml" {
				t.Fatalf("%+v", v.Scope.Violations)
			}
		})
	}
}

func TestOnlyThePathsTheReceiptNamesAndThePRChangedNeedAPerson(t *testing.T) {
	f := newFixture(t)
	// The tool said only cicd.yaml needs a person; the PR also changes build.yaml (carried, in scope): one needs-person path.
	tr := f.openedForAPerson(t, []string{"cicd.yaml", "not-in-the-pr.yaml"}, "cicd.yaml", "build.yaml")
	v := f.askProposal(t, tr, map[string]any{"paths": anyList([]string{"cicd.yaml", "build.yaml"})})
	if v.Scope.Status != provenance.NeedsPerson || !reflect.DeepEqual(v.Scope.NeedsPerson, []string{"cicd.yaml"}) {
		t.Fatalf("%+v", v.Scope)
	}
	// None of them in the PR: an ordinary in-scope agent PR.
	f2 := newFixture(t)
	tr = f2.openedForAPerson(t, []string{"cicd.yaml"}, "build.yaml")
	v = f2.askProposal(t, tr, map[string]any{"paths": anyList([]string{"build.yaml"})})
	if v.Scope.Status != "in-scope" {
		t.Fatalf("%+v", v.Scope)
	}
}

func TestTheMarkIsTheReceiptsNotThePRs(t *testing.T) {
	// A receipt without merge: person is not a proposal, whatever else it carries; a PR that lists paths the receipt never
	// carried fails AS001 before the mark is read.
	f := newFixture(t)
	tr := f.opened(t, "cicd.yaml")
	if v := f.askProposal(t, tr, nil); v.Scope.Status != "in-scope" {
		t.Fatalf("%+v", v.Scope)
	}
	f2 := newFixture(t)
	tr = f2.openedForAPerson(t, []string{"cicd.yaml"}, "cicd.yaml")
	v := f2.askProposal(t, tr, map[string]any{"paths": anyList([]string{"cicd.yaml", "extra.yaml"})})
	if v.Scope.OK || rule(v.Scope) != "AS001" {
		t.Fatalf("%+v", v.Scope)
	}
}

func TestMergedFieldsAreTypedAndAbsentWhenOpen(t *testing.T) {
	for _, bad := range []map[string]any{{"merged": "yes"}, {"mergedBy": 3}, {"mergedByBot": "no"}} {
		if _, err := provenance.ParseRequest(body(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	r, err := provenance.ParseRequest(body(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, has := r.Body()["merged"]; has {
		t.Fatal("an open PR's request digests with a merged field")
	}
}
