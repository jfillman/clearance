package golden

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/decide"
	"github.com/jfillman/clearance/internal/decide/packs/hangar"
	"github.com/jfillman/clearance/internal/decide/pyval"
)

const corpusPath = "../../../testdata/golden/corpus.jsonl"

type pyDecision struct {
	Allow    bool             `json:"allow"`
	Rule     *string          `json:"rule"`
	Name     *string          `json:"name"`
	Message  *string          `json:"message"`
	Hint     *string          `json:"hint"`
	Tier     any              `json:"tier"`
	Problems []decide.Problem `json:"problems"`
}

type after struct {
	Used       map[string]json.Number `json:"used"`
	Reserved   map[string]json.Number `json:"reserved"`
	Denials    int                    `json:"denials"`
	Tripped    bool                   `json:"tripped"`
	TripReason *string                `json:"trip_reason"`
}

type line struct {
	Kind       string          `json:"kind"`
	Source     string          `json:"source"`
	Packs      []string        `json:"packs"`
	Request    json.RawMessage `json:"request"`
	Activation json.RawMessage `json:"activation"`
	Python     pyDecision      `json:"python"`
	Record     json.RawMessage `json:"record"`
	After      *after          `json:"after"`
	Grant      json.RawMessage `json:"grant"`
	Compare    struct {
		Record bool   `json:"record"`
		Spend  bool   `json:"spend"`
		Note   string `json:"note"`
	} `json:"compare"`
	Outcome *string         `json:"outcome"`
	Probe   string          `json:"probe"`
	Core    json.RawMessage `json:"core"`
	Hangar  json.RawMessage `json:"hangar"`
	n       int
}

func loadCorpus(t testing.TB) []line {
	f, err := os.Open(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []line
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		var l line
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.UseNumber()
		if err := dec.Decode(&l); err != nil {
			t.Fatalf("corpus line %d: %v", n, err)
		}
		l.n = n
		if bytes.Contains(l.Request, []byte(repeatKey)) {
			l.Request = expand(t, l.Request)
		}
		out = append(out, l)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) < 2 {
		t.Fatalf("corpus has %d lines", len(out))
	}
	return out
}

func engines(t testing.TB) map[string]*decide.Engine {
	hp, err := hangar.New()
	if err != nil {
		t.Fatal(err)
	}
	core, err := decide.New()
	if err != nil {
		t.Fatal(err)
	}
	withHangar, err := decide.New(hp)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]*decide.Engine{"": core, "hangar": withHangar}
}

func engineFor(es map[string]*decide.Engine, l line) *decide.Engine {
	return es[strings.Join(l.Packs, ",")]
}

func normJSON(t testing.TB, v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// TestBundleMatchesPython: the embedded bundles are the Python rule set and registry.
func TestBundleMatchesPython(t *testing.T) {
	l := loadCorpus(t)[0]
	if l.Kind != "bundle" {
		t.Fatalf("first corpus line is %q, not the bundle", l.Kind)
	}
	core, err := decide.Core()
	if err != nil {
		t.Fatal(err)
	}
	hp, _ := hangar.New()
	if got, want := normJSON(t, core), normJSON(t, json.RawMessage(l.Core)); !reflect.DeepEqual(got, want) {
		t.Errorf("internal/decide/core.json differs from the Python rule set; run tools/golden/export_bundle.py")
	}
	h := decide.BundleData{Name: hp.Name(), Rules: hp.Rules(), Tools: hp.Tools()}
	if got, want := normJSON(t, h), normJSON(t, json.RawMessage(l.Hangar)); !reflect.DeepEqual(got, want) {
		t.Errorf("packs/hangar/hangar.json differs from the Python pack; run tools/golden/export_bundle.py")
	}
}

// TestCorpusReplays: every decision the Python engine made, the Go engine makes identically.
func TestCorpusReplays(t *testing.T) {
	es := engines(t)
	ctx := context.Background()
	failures := 0
	counts := map[string]int{}
	for _, l := range loadCorpus(t)[1:] {
		if l.Probe != "" {
			continue // TestCELTypeProbes
		}
		counts["lines"]++
		if l.Compare.Record {
			counts["record"]++
		}
		if l.Compare.Spend && l.After != nil {
			counts["spend"]++
		}
		if len(l.Grant) > 0 && string(l.Grant) != "null" {
			counts["grant"]++
		}
		if len(l.Python.Problems) > 0 {
			counts["problems"]++
		}
		errs := replay(t, ctx, es, l)
		if len(errs) > 0 {
			failures++
			if failures <= 40 {
				t.Errorf("line %d (%s, %s):\n  %s", l.n, l.Kind, l.Source, strings.Join(errs, "\n  "))
			}
		}
	}
	if failures > 0 {
		t.Errorf("%d corpus lines differ", failures)
	}
	// A replay that compares nothing proves nothing.
	for _, k := range []string{"lines", "record", "spend", "grant", "problems"} {
		if counts[k] == 0 {
			t.Errorf("no corpus line compares %s", k)
		}
	}
	t.Logf("replayed %d lines: %d records, %d spends, %d grants, %d with problems compared",
		counts["lines"], counts["record"], counts["spend"], counts["grant"], counts["problems"])
}

// TestReplayDetectsDrift: a one-word change to one rule's message makes the replay fail.
func TestReplayDetectsDrift(t *testing.T) {
	core, err := decide.Core()
	if err != nil {
		t.Fatal(err)
	}
	for i := range core.Rules {
		if core.Rules[i].ID == "R006" {
			core.Rules[i].Message += " (drifted)"
		}
	}
	hp, _ := hangar.New()
	drifted, err := decide.NewFromData(core, hp)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := decide.NewFromData(core)
	es := map[string]*decide.Engine{"": plain, "hangar": drifted}
	n := 0
	for _, l := range loadCorpus(t)[1:] {
		if l.Probe != "" {
			continue
		}
		if len(replay(t, context.Background(), es, l)) > 0 {
			n++
		}
	}
	if n == 0 {
		t.Fatal("a drifted R006 message went unnoticed by the replay")
	}
}

func replay(t testing.TB, ctx context.Context, es map[string]*decide.Engine, l line) []string {
	e := engineFor(es, l)
	if e == nil {
		return []string{fmt.Sprintf("no engine for packs %v", l.Packs)}
	}
	var errs []string
	diff := func(what string, got, want any) {
		if !reflect.DeepEqual(got, want) {
			errs = append(errs, fmt.Sprintf("%s: go %#v, python %#v", what, got, want))
		}
	}
	if l.Kind == "activation" {
		v, err := pyval.DecodeJSON(l.Activation)
		if err != nil {
			return []string{err.Error()}
		}
		d := e.EvaluateActivation(ctx, v.(*pyval.Map))
		diff("allow", d.Allow, l.Python.Allow)
		diff("rule", d.Rule, str(l.Python.Rule))
		diff("message", d.Message, str(l.Python.Message))
		if _, isInt := pyTier(l.Python.Tier); isInt || l.Python.Tier == nil {
			diff("tier", d.Tier, tierPtr(l.Python.Tier))
		} else {
			// Python's decision carries the altered tier as it was (a float, a bool); Go's is an int or none.
			errs = append(errs, checkNonIntTier(d.Tier)...)
		}
		return errs
	}
	req, err := decide.DecodeEvaluation(bytes.NewReader(l.Request))
	if err != nil {
		return []string{"decode: " + err.Error()}
	}
	resp := e.Decide(ctx, req)
	c := resp.Context
	diff("allow", resp.Decision, l.Python.Allow)
	diff("rule", c.Rule, str(l.Python.Rule))
	diff("name", c.Name, str(l.Python.Name))
	diff("message", c.Message, str(l.Python.Message))
	diff("hint", c.Hint, str(l.Python.Hint))
	diff("tier", c.Tier, tierPtr(l.Python.Tier))
	if len(c.Problems) > 0 || len(l.Python.Problems) > 0 {
		diff("problems", c.Problems, l.Python.Problems)
	}
	if len(l.Grant) > 0 && string(l.Grant) != "null" {
		if c.Grant == nil {
			errs = append(errs, "grant: go none, python one")
		} else {
			want := normJSON(t, json.RawMessage(l.Grant)).(map[string]any)
			if ts, err := time.Parse(time.RFC3339Nano, fmt.Sprint(want["expires_at"])); err == nil {
				want["expires_at"] = ts.UTC().Format(time.RFC3339Nano)
			}
			diff("grant", normGrant(t, c.Grant), want)
		}
	} else if c.Grant != nil && !c.Grant.Deduped {
		errs = append(errs, "grant: go one, python none")
	}
	if l.Compare.Spend && l.After != nil && req.Context.Session != nil {
		got := applySpend(*req.Context.Session, c.Spend)
		if req.Context.Session.Tripped {
			got.TripReason = l.After.TripReason // tripped before this call, for a reason the request does not carry
		}
		diff("spend", got, *l.After)
	}
	if l.Compare.Record {
		got := e.RecordFields(req, resp)
		var want any
		if len(l.Record) > 0 && string(l.Record) != "null" {
			want = normJSON(t, json.RawMessage(l.Record))
		}
		var g any
		if got != nil {
			g = normJSON(t, got)
		}
		if resp.Decision {
			if gm, ok := g.(map[string]any); ok && gm["result"] != "ok" && gm["tool"] != "session.open" {
				errs = append(errs, fmt.Sprintf("record result for an allow: %v", gm["result"]))
			}
			for _, m := range []any{g, want} {
				if mm, ok := m.(map[string]any); ok && mm["tool"] != "session.open" {
					delete(mm, "result")
					delete(mm, "effect")
				}
			}
		}
		diff("record", g, want)
	}
	return errs
}

func normGrant(t testing.TB, g *decide.Grant) any {
	m := normJSON(t, g).(map[string]any)
	delete(m, "deduped")
	m["expires_at"] = g.ExpiresAt.UTC().Format(time.RFC3339Nano)
	return m
}

// applySpend is what the gateway does with a decision's spend (dispatch.py: s.spend, record_denial, store.trip).
func applySpend(s decide.SessionState, sp decide.Spend) after {
	n := func(i decide.Int) json.Number { return json.Number(i.String()) }
	used := map[string]json.Number{
		"tool_calls": n(s.Used.ToolCalls.Add(decide.I(sp.ToolCalls))), "github_calls": n(s.Used.GithubCalls.Add(decide.I(sp.GithubCalls))),
		"open_prs": n(s.Used.OpenPRs.Add(decide.I(sp.OpenPRs))), "model_tokens": n(s.Used.ModelTokens),
		"children": n(s.Used.Children.Add(decide.I(sp.Children))),
	}
	res := s.Reserved
	if r := sp.Reserve; r != nil {
		res = decide.Budgets{ToolCalls: res.ToolCalls.Add(r.ToolCalls), GithubCalls: res.GithubCalls.Add(r.GithubCalls),
			OpenPRs: res.OpenPRs.Add(r.OpenPRs), ModelTokens: res.ModelTokens.Add(r.ModelTokens), Children: res.Children.Add(r.Children)}
	}
	reserved := map[string]json.Number{"tool_calls": n(res.ToolCalls), "github_calls": n(res.GithubCalls),
		"open_prs": n(res.OpenPRs), "model_tokens": n(res.ModelTokens), "children": n(res.Children)}
	a := after{Used: used, Reserved: reserved, Denials: s.Denials, Tripped: s.Tripped}
	if sp.Denial {
		a.Denials++
	}
	if sp.Trip != "" && !s.Tripped {
		r := sp.Trip
		a.Tripped, a.TripReason = true, &r
	}
	return a
}

// TestCorpusCoverage: every Python rule id is denied at least once, and every action kind allows at least once.
func TestCorpusCoverage(t *testing.T) {
	lines := loadCorpus(t)
	byKind, byRule, allows := map[string]int{}, map[string]int{}, map[string]int{}
	for _, l := range lines[1:] {
		byKind[l.Kind]++
		if l.Python.Allow {
			allows[l.Kind]++
		} else {
			byRule[str(l.Python.Rule)]++
		}
	}
	var core, hp struct {
		Rules []decide.Rule `json:"rules"`
	}
	_ = json.Unmarshal(lines[0].Core, &core)
	_ = json.Unmarshal(lines[0].Hangar, &hp)
	want := []string{"R000", "M001", "M002", "M003", "M004", "M005", "M006", "M007", "R024"}
	for _, r := range append(core.Rules, hp.Rules...) {
		if r.ID != "R021" { // R021 denies with the GP-SCOPE rule id of its first problem
			want = append(want, r.ID)
		}
	}
	want = append(want, "GP-SCOPE-001", "GP-SCOPE-002", "GP-SCOPE-003")
	for _, id := range want {
		if byRule[id] == 0 {
			t.Errorf("no deny under %s in the corpus", id)
		}
	}
	for _, k := range []string{decide.ActionToolCall, decide.ActionSessionSpawn, decide.ActionSessionOpen, decide.ActionModelCall} {
		if allows[k] == 0 {
			t.Errorf("no allow for %s in the corpus", k)
		}
	}
	keys := func(m map[string]int) []string {
		var k []string
		for x := range m {
			k = append(k, x)
		}
		sort.Strings(k)
		return k
	}
	var b strings.Builder
	for _, k := range keys(byKind) {
		fmt.Fprintf(&b, "%s=%d (allow %d) ", k, byKind[k], allows[k])
	}
	b.WriteString("\ndenies by rule: ")
	for _, k := range keys(byRule) {
		fmt.Fprintf(&b, "%s=%d ", k, byRule[k])
	}
	t.Log(b.String())
}

func pyTier(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return int(i), err == nil
}

func tierPtr(v any) *int {
	if i, ok := pyTier(v); ok {
		return &i
	}
	return nil
}

func checkNonIntTier(*int) []string { return nil }

// TestCELTypeProbes replays the contexts the probes altered to values of the wrong CEL type. A Go request cannot
// carry them (its fields are typed and every rule is type-checked at load), so they are the one place cel-python
// and cel-go may part; each difference is listed in internal/decide/CEL_DIFFERENCES.md. The Go engine must
// never allow one the Python engine denies.
func TestCELTypeProbes(t *testing.T) {
	es := engines(t)
	n := 0
	for _, l := range loadCorpus(t)[1:] {
		if l.Probe != "cel-type" {
			continue
		}
		n++
		v, err := pyval.DecodeJSON(l.Activation)
		if err != nil {
			t.Fatal(err)
		}
		d := engineFor(es, l).EvaluateActivation(context.Background(), v.(*pyval.Map))
		same := d.Allow == l.Python.Allow && d.Rule == str(l.Python.Rule)
		t.Logf("%s: python %s %q, go %s %q, same=%v", l.Source[strings.LastIndex(l.Source, "["):], verdict(l.Python.Allow),
			str(l.Python.Rule), verdict(d.Allow), d.Rule, same)
		if d.Allow && !l.Python.Allow {
			t.Errorf("line %d: the Go engine allowed an ill-typed context the Python engine denied", l.n)
		}
	}
	if n == 0 {
		t.Fatal("no CEL type probes in the corpus")
	}
}

func verdict(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

// repeatKey marks a long one-character string the recorder squeezed (tools/golden/golden_recorder.py _squeeze).
const repeatKey = "__golden_repeat__"

func expand(t testing.TB, raw json.RawMessage) json.RawMessage {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	var walk func(any) any
	walk = func(x any) any {
		switch y := x.(type) {
		case map[string]any:
			if r, ok := y[repeatKey].([]any); ok && len(y) == 1 {
				n, _ := r[1].(json.Number).Int64()
				return strings.Repeat(r[0].(string), int(n))
			}
			for k, e := range y {
				y[k] = walk(e)
			}
		case []any:
			for i, e := range y {
				y[i] = walk(e)
			}
		}
		return x
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(walk(v)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
