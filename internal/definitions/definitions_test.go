package definitions_test

// Ported from tests/test_definitions.py. The two read-API tests (test_the_api_shows_source_and_rejected,
// test_the_api_over_a_plain_dict_has_no_source) belong to clearance-api; test_a_loaded_pin_is_a_real_agent_for_sessions
// keeps its definition half (sessions are the gateway's).

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
)

const ownerG = "group:default/team-gate"

func src(over func(*definitions.Source)) definitions.Source {
	s := definitions.Source{Kind: "cluster", Repo: definitions.Str("jfillman/gate-api"), Path: definitions.Str("agents/gate-triage.yaml"),
		Commit: definitions.Str("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"), Namespace: definitions.Str("app-gate-api-cicd"),
		XR: definitions.Str("gate-triage"), LoadedAt: definitions.Str("2026-10-31T12:00:00Z")}
	if over != nil {
		over(&s)
	}
	return s
}

var pin = src(nil)

// triage is tests/fixtures/agents/triage-agent.yaml.
const triage = `{"name": "triage-agent", "description": "Reads a failed Glidepath run and proposes a fix as one pull request on the app's repository.",
 "kind": "event", "identity": {"type": "workload", "serviceAccount": "holmesgpt/holmes"},
 "profile": {"tierCeiling": "T1", "tools": ["catalog.read", "metrics.query", "logs.query", "argo.app.get", "repo.pr.open", "human.request"],
  "repos": {"allow": ["jfillman/*"]}, "models": ["claude-sonnet-5"], "network": "clearance+model", "compute": "small",
  "limits": {"ttlMinutes": 15, "toolCalls": 80, "githubCalls": 60, "openPrs": 1, "modelTokens": 200000, "children": 0}},
 "runtime": {"image": "ghcr.io/jfillman/agent-triage@sha256:e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3", "framework": "generic"},
 "triggers": [{"type": "alert", "match": {"alertname": "RolloutDegraded"}}]}`

func doc(name, owner, sa string) map[string]any {
	v, _ := pycompat.Decode(strings.NewReader(triage))
	d := v.(map[string]any)
	if sa == "" {
		sa = "autopilot-runs/" + name
	}
	d["name"], d["owner"] = name, owner
	d["identity"] = map[string]any{"type": "workload", "serviceAccount": sa}
	return d
}

func bundled(t *testing.T) map[string]definitions.Definition {
	d, err := parseDef(doc("triage-agent", ownerG, "holmesgpt/holmes"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]definitions.Definition{"triage-agent": d}
}

func fromPin(d any, s definitions.Source, reserved func(string) bool) (*definitions.Loaded, *definitions.Rejected) {
	return definitions.FromPin(d, s, ownerG, reserved, parseDef)
}

func TestAGoodPinLoadsWithItsSource(t *testing.T) {
	l, r := fromPin(doc("gate-triage", ownerG, ""), pin, nil)
	if r != nil {
		t.Fatal(r)
	}
	if l.Name() != "gate-triage" || l.Source.Pin() != "jfillman/gate-api@1a2b3c4 agents/gate-triage.yaml" || l.Definition.Owner != ownerG || l.Doc["name"] != "gate-triage" {
		t.Fatal(l)
	}
}

func TestABadPinIsRejectedWithTheReason(t *testing.T) {
	badCeiling := doc("gate-triage", ownerG, "")
	badCeiling["profile"].(map[string]any)["tierCeiling"] = "T9"
	cases := []struct {
		bad    any
		reason string
	}{
		{"not a mapping", "not a YAML mapping"},
		{doc("other-name", ownerG, ""), "a pin named 'gate-triage' must pin a definition named 'gate-triage'"},
		{doc("gate-triage", "group:default/someone-else", ""), "they must agree"},
		{doc("gate-triage", ownerG, "autopilot-runs/triage-agent"), "workload identity is autopilot-runs/gate-triage"},
		{badCeiling, "schema:"},
	}
	for _, c := range cases {
		l, r := fromPin(c.bad, pin, nil)
		if l != nil || r == nil || !strings.Contains(r.Reason, c.reason) || r.Name != "gate-triage" {
			t.Errorf("%s: %v %v", c.reason, l, r)
		}
	}
}

func TestAPinCannotTakeABundledName(t *testing.T) {
	defs := bundled(t)
	s := src(func(s *definitions.Source) {
		s.Path, s.Commit, s.XR, s.LoadedAt = definitions.Str("agents/triage-agent.yaml"), definitions.Str(strings.Repeat("f", 40)), definitions.Str("triage-agent"), nil
	})
	reg := definitions.NewRegistry(defs)
	_, r := fromPin(doc("triage-agent", ownerG, ""), s, reg.Bundled)
	if r == nil || !strings.Contains(r.Reason, "bundled platform definition") {
		t.Fatal(r)
	}
	// and the registry refuses it too, whoever built the Loaded
	ch := reg.ReplaceCluster([]definitions.Loaded{{Definition: defs["triage-agent"], Source: s}}, nil)
	if len(ch.Added) != 0 || len(ch.Rejected) != 1 || ch.Rejected[0].Name != "triage-agent" {
		t.Fatal(ch)
	}
	if got, _ := reg.Source("triage-agent"); got.Kind != "bundled" {
		t.Fatal(got)
	}
}

func TestTheRegistryIsAMappingOverBundledAndCluster(t *testing.T) {
	defs := bundled(t)
	reg := definitions.NewRegistry(defs)
	if reg.Len() != 1 {
		t.Fatal(reg.Len())
	}
	if _, ok := reg.Get("nope"); ok {
		t.Fatal("nope")
	}
	if _, ok := reg.Source("nope"); ok {
		t.Fatal("nope source")
	}
	loaded, _ := fromPin(doc("gate-triage", ownerG, ""), pin, nil)
	ch := reg.ReplaceCluster([]definitions.Loaded{*loaded}, nil)
	if !reflect.DeepEqual(ch.Added, []string{"gate-triage"}) || len(ch.Changed)+len(ch.Removed) != 0 || reg.Version() != 1 {
		t.Fatal(ch)
	}
	d, _ := reg.Get("gate-triage")
	s, _ := reg.Source("gate-triage")
	if reg.Len() != 2 || d.Owner != ownerG || !s.Equal(pin) {
		t.Fatal(d, s)
	}
	rows := reg.Records()
	if len(rows) != 1 || rows[0].Name != "gate-triage" || rows[0].State != "loaded" {
		t.Fatal(rows)
	}
	// the same set again: no change, no version bump
	if ch := reg.ReplaceCluster([]definitions.Loaded{*loaded}, nil); ch.Any() || reg.Version() != 1 {
		t.Fatal(ch)
	}
	repin, _ := fromPin(doc("gate-triage", ownerG, ""), src(func(s *definitions.Source) { s.Commit = definitions.Str(strings.Repeat("b", 40)) }), nil)
	ch = reg.ReplaceCluster([]definitions.Loaded{*repin}, nil)
	if s, _ := reg.Source("gate-triage"); !reflect.DeepEqual(ch.Changed, []string{"gate-triage"}) || *s.Commit != strings.Repeat("b", 40) {
		t.Fatal(ch)
	}
	ch = reg.ReplaceCluster(nil, nil)
	if _, ok := reg.Get("gate-triage"); !reflect.DeepEqual(ch.Removed, []string{"gate-triage"}) || *ch.Sources["gate-triage"].Commit != strings.Repeat("b", 40) || ok {
		t.Fatal(ch)
	}
}

func TestTwoPinsWithOneNameLoadNeither(t *testing.T) {
	reg := definitions.NewRegistry(nil)
	a, _ := fromPin(doc("gate-triage", ownerG, ""), pin, nil)
	b, _ := fromPin(doc("gate-triage", ownerG, ""), src(func(s *definitions.Source) { s.Namespace = definitions.Str("app-other-cicd") }), nil)
	ch := reg.ReplaceCluster([]definitions.Loaded{*a, *b}, nil)
	var ns []string
	for _, r := range ch.Rejected {
		ns = append(ns, *r.Source.Namespace)
	}
	sort.Strings(ns)
	if _, ok := reg.Get("gate-triage"); ok || !reflect.DeepEqual(ns, []string{"app-gate-api-cicd", "app-other-cicd"}) {
		t.Fatal(ns)
	}
}

func TestRejectionsAreReportedOnceAndClearedWhenFixed(t *testing.T) {
	reg := definitions.NewRegistry(nil)
	_, rej := fromPin(doc("gate-triage", "group:default/x", ""), pin, nil)
	ch := reg.ReplaceCluster(nil, []definitions.Rejected{*rej})
	if len(ch.Rejected) != 1 || ch.Rejected[0].Name != "gate-triage" || len(reg.Rejected()) != 1 {
		t.Fatal(ch)
	}
	if ch := reg.ReplaceCluster(nil, []definitions.Rejected{*rej}); ch.Any() {
		t.Fatal("same rejection reported twice")
	}
	good, _ := fromPin(doc("gate-triage", ownerG, ""), pin, nil)
	ch = reg.ReplaceCluster([]definitions.Loaded{*good}, nil)
	if !reflect.DeepEqual(ch.Added, []string{"gate-triage"}) || len(ch.Cleared) != 1 || !ch.Cleared[0].Equal(*rej) || len(reg.Rejected()) != 0 {
		t.Fatal(ch)
	}
}

func rowsOf(t *testing.T, rows []definitions.Row) []map[string]any {
	raw, _ := json.Marshal(rows)
	var out []map[string]any
	v, err := pycompat.Decode(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range v.([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

func TestApplyRecordsRebuildsFromTheStore(t *testing.T) {
	srcReg := definitions.NewRegistry(nil)
	good, _ := fromPin(doc("gate-triage", ownerG, ""), pin, nil)
	srcReg.ReplaceCluster([]definitions.Loaded{*good}, []definitions.Rejected{{Name: "bad-one", Source: src(func(s *definitions.Source) { s.XR = definitions.Str("bad-one") }), Reason: "schema: x"}})
	rows := rowsOf(t, srcReg.Records())
	reader := definitions.NewRegistry(nil)
	ch := reader.ApplyRecords(rows, parseDef)
	if !reflect.DeepEqual(ch.Added, []string{"gate-triage"}) || len(ch.Rejected) != 1 || ch.Rejected[0].Name != "bad-one" {
		t.Fatal(ch)
	}
	d, _ := reader.Get("gate-triage")
	s, _ := reader.Source("gate-triage")
	if d.Owner != ownerG || !s.Equal(pin) {
		t.Fatal(d, s)
	}
	rows[0]["doc"].(map[string]any)["profile"].(map[string]any)["tierCeiling"] = "T9" // shown, not dropped
	ch = definitions.NewRegistry(nil).ApplyRecords(rows, parseDef)
	var names []string
	for _, r := range ch.Rejected {
		names = append(names, r.Name)
	}
	if !reflect.DeepEqual(names, []string{"bad-one", "gate-triage"}) {
		t.Fatal(names)
	}
}

func service(t *testing.T) (*definitions.Service, *memory.Store) {
	st := memory.New()
	return &definitions.Service{Registry: definitions.NewRegistry(bundled(t)), Store: st,
		Clock: func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) }}, st
}

func records(t *testing.T, st *memory.Store) []store.Record {
	r, err := st.Records(context.Background(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func storedRows(t *testing.T, st *memory.Store) []store.Definition {
	d, err := st.Definitions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTheGatewayRecordsEachChangeOnceAndPersistsTheSet(t *testing.T) {
	svc, st := service(t)
	ctx := context.Background()
	loaded, _ := fromPin(doc("gate-triage", ownerG, ""), pin, nil)
	ch, err := svc.Apply(ctx, []definitions.Loaded{*loaded}, nil)
	if err != nil || !reflect.DeepEqual(ch.Added, []string{"gate-triage"}) {
		t.Fatal(ch, err)
	}
	recs := records(t, st)
	r := recs[0]
	if len(recs) != 1 || r["tool"] != "definition.load" || r["agent"] != "gate-triage" || r["principal"] != "pin:app-gate-api-cicd/gate-triage" ||
		r["decision"] != "allow" || r["target"] != pin.Pin() || r["result"] != "loaded "+pin.Pin() || r["session"] != nil {
		t.Fatal(r)
	}
	if rows := storedRows(t, st); len(rows) != 1 || rows[0].Name != "gate-triage" {
		t.Fatal(rows)
	}
	// the same poll again: no record
	if ch, _ := svc.Apply(ctx, []definitions.Loaded{*loaded}, nil); ch.Any() || len(records(t, st)) != 1 {
		t.Fatal(ch)
	}
	_, bad := fromPin(doc("gate-two", "group:default/x", ""), src(func(s *definitions.Source) { s.XR = definitions.Str("gate-two") }), nil)
	repin, _ := fromPin(doc("gate-triage", ownerG, ""), src(func(s *definitions.Source) { s.Commit = definitions.Str(strings.Repeat("c", 40)) }), nil)
	if _, err := svc.Apply(ctx, []definitions.Loaded{*repin}, []definitions.Rejected{*bad}); err != nil {
		t.Fatal(err)
	}
	recs = records(t, st)[1:]
	var got [][3]any
	for _, r := range recs {
		got = append(got, [3]any{r["tool"], r["decision"], r["rule"]})
	}
	if !reflect.DeepEqual(got, [][3]any{{"definition.load", "allow", nil}, {"definition.reject", "deny", "DF-PIN"}}) {
		t.Fatal(got)
	}
	if !strings.HasPrefix(recs[0]["result"].(string), "re-pinned ") || !strings.Contains(recs[1]["result"].(string), "they must agree") {
		t.Fatal(recs)
	}
	var states []string
	for _, d := range storedRows(t, st) {
		states = append(states, d.State)
	}
	sort.Strings(states)
	if !reflect.DeepEqual(states, []string{"loaded", "rejected"}) {
		t.Fatal(states)
	}
	if _, err := svc.Apply(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	all := records(t, st)
	if all[len(all)-1]["tool"] != "definition.unload" || len(storedRows(t, st)) != 0 {
		t.Fatal(all[len(all)-1], storedRows(t, st))
	}
	if _, err := memory.Load(all); err != nil {
		t.Fatal("chain does not verify:", err)
	}
}

func TestALoadedPinIsARealAgentForSessions(t *testing.T) {
	svc, _ := service(t)
	l, _ := fromPin(doc("gate-triage", ownerG, ""), pin, nil)
	if _, err := svc.Apply(context.Background(), []definitions.Loaded{*l}, nil); err != nil {
		t.Fatal(err)
	}
	tighter := doc("gate-triage", ownerG, "")
	tighter["profile"].(map[string]any)["tools"] = []any{"glidepath.runs.list"}
	l2, _ := fromPin(tighter, src(func(s *definitions.Source) { s.Commit = definitions.Str(strings.Repeat("d", 40)) }), nil)
	if _, err := svc.Apply(context.Background(), []definitions.Loaded{*l2}, nil); err != nil {
		t.Fatal(err)
	}
	if d, _ := svc.Registry.Get("gate-triage"); !reflect.DeepEqual(d.Tools, []string{"glidepath.runs.list"}) {
		t.Fatal(d.Tools)
	}
}

func TestAPlainDictGatewayRefusesClusterDefinitions(t *testing.T) {
	svc := &definitions.Service{Store: memory.New()}
	if _, err := svc.Apply(context.Background(), nil, nil); !errors.Is(err, definitions.ErrNotRegistry) {
		t.Fatal(err)
	}
}

// -- definitions that ship with the provider (source kind provider) ---------------------------------------------

func provided(t *testing.T, name, version string) definitions.Loaded {
	t.Helper()
	d := doc(name, ownerG, "")
	src := definitions.Source{Kind: "provider", Provider: definitions.Str("autopilot-gateway"), Version: definitions.Str(version)}
	l, r := definitions.FromProvided(d, name, src, parseDef)
	if r != nil {
		t.Fatal(r)
	}
	return *l
}

func TestAProvidedDefinitionLoadsAndIsRecordedOnce(t *testing.T) {
	svc, st := service(t)
	l := provided(t, "parachute", "gateway-v0.9.0")
	if l.Source.Pin() != "provider:autopilot-gateway@gateway-v0.9.0" {
		t.Fatal(l.Source.Pin())
	}
	ch, err := svc.Apply(context.Background(), []definitions.Loaded{l}, nil)
	if err != nil || !reflect.DeepEqual(ch.Added, []string{"parachute"}) {
		t.Fatal(ch, err)
	}
	if _, ok := svc.Registry.Get("parachute"); !ok {
		t.Fatal("the provided definition is not live")
	}
	rs := records(t, st)
	if len(rs) != 1 || rs[0]["tool"] != "definition.load" || rs[0]["principal"] != "provider:autopilot-gateway" ||
		rs[0]["target"] != "provider:autopilot-gateway@gateway-v0.9.0" {
		t.Fatal(rs)
	}
	// Again: nothing. A new build with the same document is a change (the evidence names the build), once.
	if ch, _ := svc.Apply(context.Background(), []definitions.Loaded{l}, nil); ch.Any() || len(records(t, st)) != 1 {
		t.Fatal(ch)
	}
	ch, _ = svc.Apply(context.Background(), []definitions.Loaded{provided(t, "parachute", "gateway-v0.9.1")}, nil)
	if !reflect.DeepEqual(ch.Changed, []string{"parachute"}) || len(records(t, st)) != 2 {
		t.Fatal(ch)
	}
	// The stored row reads back as a provider definition after a restart.
	var rows []map[string]any
	for _, r := range storedRows(t, st) {
		var m map[string]any
		dec := json.NewDecoder(strings.NewReader(string(r.Record)))
		dec.UseNumber()
		_ = dec.Decode(&m)
		rows = append(rows, m)
	}
	fresh := definitions.NewRegistry(nil)
	fresh.ApplyRecords(rows, parseDef)
	if s, ok := fresh.Source("parachute"); !ok || s.Kind != "provider" || s.Pin() != "provider:autopilot-gateway@gateway-v0.9.1" {
		t.Fatal(s, ok)
	}
}

func TestAPinCannotShadowAProvidedDefinition(t *testing.T) {
	svc, _ := service(t)
	prov := provided(t, "gate-triage", "v1")
	pinned, r := fromPin(doc("gate-triage", ownerG, ""), pin, nil)
	if r != nil {
		t.Fatal(r)
	}
	ch, err := svc.Apply(context.Background(), []definitions.Loaded{*pinned, prov}, nil)
	if err != nil || !reflect.DeepEqual(ch.Added, []string{"gate-triage"}) || len(ch.Rejected) != 1 ||
		!strings.Contains(ch.Rejected[0].Reason, "provided by autopilot-gateway") {
		t.Fatal(ch, err)
	}
	if s, _ := svc.Registry.Source("gate-triage"); s.Kind != "provider" {
		t.Fatal(s)
	}
}

func TestAProvidedNameThatIsBundledIsRejected(t *testing.T) {
	svc, _ := service(t)
	ch, _ := svc.Apply(context.Background(), []definitions.Loaded{provided(t, "triage-agent", "v1")}, nil)
	if len(ch.Rejected) != 1 || !strings.Contains(ch.Rejected[0].Reason, "bundled platform definition") {
		t.Fatal(ch)
	}
}

func TestAMalformedProvidedDefinitionIsRejected(t *testing.T) {
	src := definitions.Source{Kind: "provider", Provider: definitions.Str("p"), Version: definitions.Str("v1")}
	if _, r := definitions.FromProvided(doc("agent-a", ownerG, ""), "agent-b", src, parseDef); r == nil || !strings.Contains(r.Reason, "published as 'agent-b'") {
		t.Fatal(r)
	}
	if _, r := definitions.FromProvided(map[string]any{"name": "agent-a"}, "agent-a", src, parseDef); r == nil || !strings.HasPrefix(r.Reason, "schema: ") {
		t.Fatal(r)
	}
	if _, r := definitions.FromProvided("x", "agent-a", src, parseDef); r == nil {
		t.Fatal("not a mapping")
	}
}

func TestKeepingProvidedSurvivesAPublishWithoutThem(t *testing.T) {
	svc, _ := service(t)
	ctx := context.Background()
	if _, err := svc.Apply(ctx, []definitions.Loaded{provided(t, "parachute", "v1")}, nil); err != nil {
		t.Fatal(err)
	}
	ch, err := svc.ApplyKeeping(ctx, nil, nil, svc.Writer.OrCore(), nil, true)
	if err != nil || ch.Any() {
		t.Fatal(ch, err)
	}
	if _, ok := svc.Registry.Get("parachute"); !ok {
		t.Fatal("dropped")
	}
	ch, _ = svc.ApplyKeeping(ctx, nil, nil, svc.Writer.OrCore(), nil, false)
	if !reflect.DeepEqual(ch.Removed, []string{"parachute"}) {
		t.Fatal(ch)
	}
}
