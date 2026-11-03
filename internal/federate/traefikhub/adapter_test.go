package traefikhub_test

// The recorded-format tests. testdata/published-*.log are the two examples Traefik Labs publishes on its
// Transparency Logs page (https://doc.traefik.io/traefik-hub/api-gateway/observability/transparency-logs), copied
// field for field; the access example's e-mail address is a placeholder because the page obfuscates it.
// testdata/lab-*.log are constructed from the same pages' field lists and notes (a key written twice when an earlier
// middleware ran, a bypass, a deny with an error field, an error line with no decision, a decision with tracing off,
// chained requests sharing a trace): no running Hub wrote them. When a real Hub's lines exist, they join this
// directory and these tests run on them unchanged.

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/federate/traefikhub"
	"github.com/jfillman/clearance/internal/server"
)

func open(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func TestTheKindMatchesTheCore(t *testing.T) {
	if traefikhub.Kind != server.FederatedKind || traefikhub.CoverageObserved != server.CoverageObserved ||
		traefikhub.CoverageAttributed != server.CoverageAttributed {
		t.Fatal("the adapter's kind and coverage values differ from the core's")
	}
	if !slices.Contains(client.RecordKinds, traefikhub.Kind) {
		t.Fatal("the Go client does not list federated.decision")
	}
}

func TestPublishedExamples(t *testing.T) {
	recs, st, err := traefikhub.Ingest(open(t, "published-hub.log"), open(t, "published-access.log"), traefikhub.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || st.Records != 1 || st.Paired != 1 || st.Correlated != 0 {
		t.Fatalf("records %d stats %+v", len(recs), st)
	}
	r := recs[0]
	e := r.Record
	if r.Provider != "traefik-hub" || r.Kind != "federated.decision" {
		t.Fatal(r.Provider, r.Kind)
	}
	if str(e.Decision) != "allow" || str(e.Result) != "Request allowed" || str(e.Coverage) != "observed-not-attributed" ||
		e.TaskID != nil || str(e.Principal) != "alice@example.com" || str(e.Agent) != "agent-1" ||
		str(e.Target) != "/refunds" || e.Rule != nil || e.Tier != nil {
		t.Fatalf("%+v", e)
	}
	src := e.Source
	want := map[string]any{"system": "traefik-hub", "middleware": "apps-user-policy@kubernetescrd",
		"middleware_type": "authzen-mcp", "hub_decision": "allow", "policy": "user-tool-call",
		"trace_id": "5e5e8662ec810c75a0a215e2d8d7e56b", "gateway_id": "6ff586e3-9fe2-4e6a-af4c-437c58f56579",
		"decision_log_id": "a5499d5c-7cd8-439b-88a8-47924b9db2ab", "time": "2026-10-06T05:21:10Z",
		"access_log_id": "d5b33cf1-1386-4254-b597-6f6fd40dc9af", "downstream_status": 403}
	for k, v := range want {
		if src[k] != v {
			t.Errorf("source.%s = %v, want %v", k, src[k], v)
		}
	}
	d := e.Subject["digests"].(map[string]any)
	if e.Subject["kind"] != "tool-call" || e.Subject["name"] != "/refunds" || len(d["decisionLine"].(string)) != 64 ||
		len(d["accessLine"].(string)) != 64 {
		t.Fatal(e.Subject)
	}
}

func TestLabLines(t *testing.T) {
	recs, st, err := traefikhub.Ingest(open(t, "lab-hub.log"), open(t, "lab-access.log"), traefikhub.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Hub log: a config line and a jwt line are not decisions; the error line has no decision; "not json" is skipped.
	if st.Decisions.Lines != 8 || st.Decisions.Accepted != 4 || st.Decisions.NotOurs != 2 || st.Decisions.Skipped != 2 {
		t.Fatalf("decisions %+v", st.Decisions)
	}
	// Access log: the /health line has no trace id.
	if st.Access.Accepted != 4 || st.Access.NotOurs != 1 {
		t.Fatalf("access %+v", st.Access)
	}
	if len(recs) != 4 || st.Paired != 1 || st.Correlated != 3 || st.NoTrace != 1 {
		t.Fatalf("records %d stats %+v", len(recs), st)
	}
	deny, bypass, refund, untraced := recs[0].Record, recs[1].Record, recs[2].Record, recs[3].Record

	// A key written twice (an earlier jwt middleware ran): the last occurrence is the decision's.
	if deny.Source["middleware"] != "apps-authzen-mcp@kubernetescrd" || deny.Source["middleware_type"] != "authzen-mcp" {
		t.Fatal(deny.Source)
	}
	// Two decisions and two requests share the trace (chained calls forwarding traceparent): not paired, but both
	// requests name task-42, so both decisions are correlated.
	if str(deny.Decision) != "deny" || str(deny.Reason) != "amount 50 over limit 20" || str(deny.TaskID) != "task-42" ||
		str(deny.Coverage) != "authorized-and-verified" || deny.Target != nil || deny.Agent != nil ||
		deny.Source["policy"] != "transfer-limit" {
		t.Fatalf("deny %+v", deny)
	}
	if str(bypass.Decision) != "allow" || str(bypass.Result) != "bypass: Request bypassed" ||
		str(bypass.TaskID) != "task-42" || bypass.Source["hub_decision"] != "bypass" {
		t.Fatalf("bypass %+v", bypass)
	}
	// A deny the mapping caused (error, no reason), paired through TraceId and a lower-case header field.
	if str(refund.Decision) != "deny" || str(refund.Reason) != "error: no such key: X-Amount" ||
		str(refund.TaskID) != "task-7" || str(refund.Principal) != "carol@example.com" ||
		str(refund.Target) != "shop.example/refunds" || refund.Source["method"] != "POST" ||
		refund.Source["router"] != "apps-refunds@kubernetescrd" {
		t.Fatalf("refund %+v", refund)
	}
	// Tracing off: nothing to join, observed only.
	if str(untraced.Coverage) != "observed-not-attributed" || untraced.TaskID != nil || untraced.Source["trace_id"] != nil {
		t.Fatalf("untraced %+v", untraced)
	}
}

func TestConflictingTaskIDsAreNotCorrelated(t *testing.T) {
	hub := `{"middlewareType":"authzen","decision":"allow","trace_id":"t1","message":"Request allowed"}` + "\n"
	access := `{"request_X-Clearance-Task-Id":"a","trace_id":"t1"}` + "\n" +
		`{"request_X-Clearance-Task-Id":"b","trace_id":"t1"}` + "\n"
	recs, st, err := traefikhub.Ingest(strings.NewReader(hub), strings.NewReader(access), traefikhub.Options{})
	if err != nil || len(recs) != 1 || recs[0].Record.TaskID != nil || st.Correlated != 0 || st.Paired != 0 {
		t.Fatal(err, st, recs)
	}
}

func TestMapCorrelatorAndHeaders(t *testing.T) {
	hub := `{"middlewareType":"authzen","decision":"deny","trace_id":"t1"}` + "\n"
	access := `{"ClientUsername":"-","request_X-User":"dana","request_X-Agent":"bot","trace_id":"t1"}`
	recs, _, err := traefikhub.Ingest(strings.NewReader(hub), strings.NewReader(access), traefikhub.Options{
		Correlator: traefikhub.MapCorrelator{"t1": "task-9"}, AgentHeader: "X-Agent", PrincipalHeader: "X-User"})
	if err != nil || len(recs) != 1 {
		t.Fatal(err, recs)
	}
	e := recs[0].Record
	if str(e.TaskID) != "task-9" || str(e.Principal) != "dana" || str(e.Agent) != "bot" || str(e.Result) != "deny" {
		t.Fatalf("%+v", e)
	}
}

func TestLongAndHostileLines(t *testing.T) {
	long := `{"middlewareType":"authzen","decision":"allow","message":"` + strings.Repeat("x", traefikhub.MaxLine) + `"}`
	ctrl := `{"middlewareType":"authzen","decision":"allow","message":"a\u0000b\u001bc","reason":"` +
		strings.Repeat("é", 2000) + `"}`
	in := long + "\n" + ctrl + "\n\n   \n"
	recs, st, err := traefikhub.Ingest(strings.NewReader(in), nil, traefikhub.Options{})
	if err != nil || st.Decisions.TooLong != 1 || st.Decisions.Lines != 2 || len(recs) != 1 {
		t.Fatal(err, st)
	}
	if r := str(recs[0].Record.Result); r != "abc" {
		t.Fatalf("%q", r)
	}
	if r := str(recs[0].Record.Reason); len(r) > 1024 || !strings.HasPrefix(r, "é") {
		t.Fatalf("%d", len(r))
	}
}

// TestRecordsThroughTheCore posts the recorded-format records through POST /v1/records on an in-memory core and
// checks what the ledger holds: provider traefik-hub, only provider and ts verified, the chain intact.
func TestRecordsThroughTheCore(t *testing.T) {
	f := newCore(t)
	var recs []client.RecordRequest
	for _, pair := range [][2]string{{"published-hub.log", "published-access.log"}, {"lab-hub.log", "lab-access.log"}} {
		rs, _, err := traefikhub.Ingest(open(t, pair[0]), open(t, pair[1]), traefikhub.Options{})
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rs...)
	}
	if err := traefikhub.Post(context.Background(), f.client, recs, nil); err != nil {
		t.Fatal(err)
	}
	chain := f.records(t)
	if len(chain) != len(recs) {
		t.Fatalf("%d records, posted %d", len(chain), len(recs))
	}
	for i, r := range chain {
		prov := r["provider"].(map[string]any)
		if prov["name"] != "traefik-hub" || r["tool"] != "federated.decision" || r["boundary"] != "runtime" {
			t.Fatalf("%d: %v", i, r)
		}
		v := anyStrings(r["verified"])
		slices.Sort(v)
		if !slices.Equal(v, []string{"provider", "ts"}) {
			t.Fatalf("%d verified %v", i, v)
		}
		if cl := anyStrings(r["claimed"]); !slices.Contains(cl, "decision") || !slices.Contains(cl, "source") ||
			!slices.Contains(cl, "subject") {
			t.Fatalf("%d claimed %v", i, cl)
		}
		if r["coverage"] != str(recs[i].Record.Coverage) {
			t.Fatalf("%d coverage %v", i, r["coverage"])
		}
	}
	if ok, bad := f.verify(chain); !ok {
		t.Fatalf("chain breaks at %d", bad)
	}
}

func TestTheCoreHoldsFederatedRecordsToObservation(t *testing.T) {
	f := newCore(t)
	base := func() client.RecordRequest {
		return client.RecordRequest{Provider: "traefik-hub", Kind: "federated.decision", Record: client.ProviderEvent{
			Decision: client.String("allow"), Result: client.String("Request allowed"),
			Coverage: client.String("observed-not-attributed")}}
	}
	if _, err := f.client.Record(context.Background(), ptr(base())); err != nil {
		t.Fatal(err)
	}
	tier := 2
	for name, edit := range map[string]func(*client.ProviderEvent){
		"attributed without a task": func(e *client.ProviderEvent) { e.Coverage = client.String("authorized-and-verified") },
		"another coverage":          func(e *client.ProviderEvent) { e.Coverage = client.String("coverage-unavailable") },
		"a rule":                    func(e *client.ProviderEvent) { e.Rule = client.String("R021") },
		"a tier":                    func(e *client.ProviderEvent) { e.Tier = &tier },
		"an effect":                 func(e *client.ProviderEvent) { e.Effect = map[string]any{"pr": 1} },
		"a tool":                    func(e *client.ProviderEvent) { e.Tool = client.String("repo.read") },
		"no coverage":               func(e *client.ProviderEvent) { e.Coverage = nil },
		"no result":                 func(e *client.ProviderEvent) { e.Result = nil },
	} {
		r := base()
		edit(&r.Record)
		if _, err := f.client.Record(context.Background(), &r); err == nil {
			t.Errorf("%s: recorded", name)
		}
	}
	// Another provider's principal may not write as traefik-hub.
	other := f.clientAs(t, "autopilot-system/clearance", "traefik-hub")
	if _, err := other.Record(context.Background(), ptr(base())); err == nil {
		t.Error("a principal outside traefik-hub's globs wrote as it")
	}
	if n := len(f.records(t)); n != 1 {
		t.Fatalf("%d records", n)
	}
}

func ptr[T any](v T) *T { return &v }

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
