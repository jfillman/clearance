package statement_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/jfillman/clearance/internal/statement"
	"github.com/jfillman/clearance/schemas"
)

// packetJSON is a small, hand-written packet.json with every field a statement reads, and values that must never reach one.
func packetJSON(mod func(map[string]any)) []byte {
	pk := map[string]any{
		"schema": "clearance.packet/v1",
		"header": map[string]any{"from": "2026-10-10T00:00:00Z", "to": "2026-11-10T00:00:00Z", "observation_scopes": []any{"cluster-secret-name", "acct-secret-id"}},
		"coverage_statement": map[string]any{
			"total_records": 7,
			"by_coverage":   []any{map[string]any{"state": "authorized-and-verified", "count": 5}, map[string]any{"state": "out-of-band-detected", "count": 2}},
			"degraded_windows": []any{
				map[string]any{"kind": "feed-blind", "scope": "acct-secret-id", "from": "2026-10-12T00:00:00Z", "to": "2026-10-12T06:00:00Z", "seconds": 21600},
				map[string]any{"kind": "core-outage", "scope": "", "from": "2026-10-20T00:00:00Z", "to": "2026-10-20T00:10:00Z", "seconds": 600},
			},
			"observation_health": []any{
				map[string]any{"scope": "cluster-secret-name", "collector": true, "statement": map[string]any{"state": "healthy", "clean": true, "cleared_and_verified": map[string]any{"count": 4}, "seen_not_cleared": map[string]any{"count": 0}, "could_not_see": map[string]any{"seconds": 0}}},
				map[string]any{"scope": "acct-secret-id", "collector": true, "statement": map[string]any{"state": "degraded", "clean": false, "cleared_and_verified": map[string]any{"count": 1}, "seen_not_cleared": map[string]any{"count": 2}, "could_not_see": map[string]any{"seconds": 21600}}},
			},
			"window_verified": false,
		},
		"changes": []any{
			map[string]any{"id": "ch-1", "tier": 3, "clear_seq": 1, "agent": "triage-agent-secret"},
			map[string]any{"id": "ch-2", "tier": 3, "clear_seq": 2},
			map[string]any{"id": "ch-3", "tier": 3, "clear_seq": 3},
			map[string]any{"id": "ch-4", "tier": 1, "clear_seq": 4},
		},
		"human_cleared_changes": []any{
			map[string]any{"change": "ch-1", "tier": 3, "approvers": []any{map[string]any{"sub": "alice", "iss": "i", "kind": "person"}, map[string]any{"sub": "bob", "iss": "i", "kind": "person"}}},
			map[string]any{"change": "ch-2", "tier": 3, "approvers": []any{map[string]any{"sub": "alice", "iss": "i", "kind": "person"}, map[string]any{"sub": "alice", "iss": "i", "kind": "person"}}},
			map[string]any{"change": "ch-3", "tier": 3, "approvers": []any{map[string]any{"sub": "alice", "iss": "i", "kind": "person"}, map[string]any{"sub": "ci", "iss": "i", "kind": ""}}},
		},
		"exceptions": map[string]any{
			"by_class": []any{map[string]any{"state": "out-of-band", "count": 2}, map[string]any{"state": "break-glass", "count": 0}, map[string]any{"state": "attempted-refused", "count": 0},
				map[string]any{"state": "monitoring-protection", "count": 0}, map[string]any{"state": "degraded-mode-auto-clear", "count": 0}, map[string]any{"state": "invalidated-token", "count": 0}, map[string]any{"state": "provider-correlation-failure", "count": 0}},
			"rows": []any{
				map[string]any{"class": "out-of-band", "seq": 4, "resolution": "none recorded"},
				map[string]any{"class": "out-of-band", "seq": 5, "resolution": "reverted"},
			},
		},
		"acceptances":  map[string]any{"receipts": []any{map[string]any{"verdict": "accepted", "recipient": "firm-secret"}, map[string]any{"verdict": "questioned", "recipient": "firm-two-secret"}}},
		"verification": map[string]any{"ledger": map[string]any{"state": "checkpointed", "origin": "log.example.invalid/secret", "size": 10, "root": strings.Repeat("a", 64), "records_checkpointed": 7, "records_not_checkpointed": 0}},
	}
	if mod != nil {
		mod(pk)
	}
	b, _ := json.Marshal(pk)
	return b
}

func build(t *testing.T, profile string, mod func(map[string]any)) *statement.Document {
	t.Helper()
	d, err := statement.Build(statement.Input{ID: "st-" + strings.Repeat("1", 32), Issuer: "clearance", IssuedAt: "2026-11-14T00:00:00Z", Profile: profile, ScopeLabel: "Production",
		PolicyVersion: "gate-1", PacketID: "pk-" + strings.Repeat("2", 32), PacketDigest: strings.Repeat("2", 64), PacketJSON: packetJSON(mod)})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestEveryStateAndClassIsListedAndNoNameReachesTheStatement(t *testing.T) {
	d := build(t, statement.ProfileInsurer, nil)
	if len(d.Summary.ByCoverage) != 6 || len(d.Summary.Exceptions.ByClass) != 7 || len(d.Summary.Receipts.ByVerdict) != 4 {
		t.Fatalf("a state was left out: %+v", d.Summary)
	}
	if d.Summary.Exceptions.Total != 2 || d.Summary.Exceptions.Unresolved != 1 || d.Summary.Receipts.Count != 2 {
		t.Fatalf("%+v", d.Summary)
	}
	if d.Summary.Health.BlindSeconds != 21600 || len(d.Summary.Health.BlindWindows) != 2 || d.Summary.Health.BlindWindows[0].Index != 2 || d.Summary.Health.BlindWindows[1].Index != 0 {
		t.Fatalf("%+v", d.Summary.Health)
	}
	raw, _ := d.Canonical()
	for _, s := range []string{"cluster-secret-name", "acct-secret-id", "triage-agent-secret", "alice", "bob", "firm-secret", "firm-two-secret", "log.example.invalid", "ch-1"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("the statement carries %q", s)
		}
	}
	// Three critical changes: ch-1 has two distinct people; ch-2 the same person twice; ch-3 an approver that is not a person.
	in := d.Insurer
	if in.CriticalChanges != 3 || in.WithTwoApprovers != 1 || in.SharePerMille == nil || *in.SharePerMille != 333 || in.AgentChanges != 1 || *in.AgentSharePerMille != 250 {
		t.Fatalf("%+v", in)
	}
	if len(in.Unresolved) != 1 || in.Unresolved[0].Disposition != "none-recorded" || in.Telemetry[0].PerMille != 1000 || in.Telemetry[1].PerMille != 991 {
		t.Fatalf("%+v", in)
	}
	if build(t, statement.ProfileStandard, nil).Insurer != nil {
		t.Error("a standard statement carries the insurer figures")
	}
	// No division by zero: no critical change is "none", not a share.
	d = build(t, statement.ProfileInsurer, func(p map[string]any) { p["changes"], p["human_cleared_changes"] = []any{}, []any{} })
	if d.Insurer.SharePerMille != nil || d.Insurer.AgentSharePerMille != nil {
		t.Errorf("%+v", d.Insurer)
	}
}

func TestAPacketThatDisagreesWithItselfOrHidesAStateIsNotCut(t *testing.T) {
	for name, mod := range map[string]func(map[string]any){
		"by-class is not the rows": func(p map[string]any) {
			p["exceptions"].(map[string]any)["by_class"].([]any)[0].(map[string]any)["count"] = 1
		},
		"an unknown class": func(p map[string]any) {
			p["exceptions"].(map[string]any)["rows"].([]any)[0].(map[string]any)["class"] = "mystery"
		},
		"an unknown coverage state": func(p map[string]any) {
			c := p["coverage_statement"].(map[string]any)
			c["by_coverage"] = append(c["by_coverage"].([]any), map[string]any{"state": "mystery", "count": 1})
		},
		"an unknown verdict": func(p map[string]any) {
			p["acceptances"].(map[string]any)["receipts"].([]any)[0].(map[string]any)["verdict"] = "great"
		},
		"not a packet": func(p map[string]any) { p["schema"] = "other" },
		"no period":    func(p map[string]any) { p["header"].(map[string]any)["to"] = "2026-10-01T00:00:00Z" },
	} {
		if _, err := statement.Build(statement.Input{ID: "st-" + strings.Repeat("1", 32), Issuer: "c", IssuedAt: "2026-11-14T00:00:00Z", ScopeLabel: "x", PolicyVersion: "v",
			PacketID: "pk-" + strings.Repeat("2", 32), PacketDigest: strings.Repeat("2", 64), PacketJSON: packetJSON(mod)}); err == nil {
			t.Errorf("%s: a statement was cut", name)
		}
	}
	if _, err := statement.Build(statement.Input{ID: "st-" + strings.Repeat("1", 32), Issuer: "c", IssuedAt: "x", ScopeLabel: "<b>", PolicyVersion: "v", PacketID: "pk-" + strings.Repeat("2", 32), PacketDigest: strings.Repeat("2", 64), PacketJSON: packetJSON(nil)}); err == nil {
		t.Error("a scope with markup was accepted")
	}
}

func TestTheDocumentValidatesAgainstTheSchemaAndTheSchemaIsClosed(t *testing.T) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemas.StatementV1))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	const url = "https://clearance.hangarplatform.dev/schemas/statement/v1.json"
	if err := c.AddResource(url, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Compile(url + "#/$defs/status")
	if err != nil {
		t.Fatal(err)
	}
	valid := func(s *jsonschema.Schema, raw []byte) error {
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		return s.Validate(inst)
	}
	for _, profile := range []string{statement.ProfileStandard, statement.ProfileInsurer} {
		raw, _ := build(t, profile, nil).Canonical()
		if err := valid(sch, raw); err != nil {
			t.Errorf("%s: %v", profile, err)
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		for name, mod := range map[string]func(){
			"unknown field": func() { m["recipient"] = "x" },
			"bad id":        func() { m["id"] = "st-1" },
			"no checkpoint": func() { delete(m, "checkpoint") },
			"no mapping":    func() { delete(m, "questionnaire_mapping") },
			"markup label":  func() { m["scope"].(map[string]any)["label"] = "<script>" },
			"a float share": func() { m["summary"].(map[string]any)["total_records"] = 1.5 },
		} {
			var c map[string]any
			_ = json.Unmarshal(raw, &c)
			m = c
			mod()
			b, _ := json.Marshal(m)
			if err := valid(sch, b); err == nil {
				t.Errorf("%s/%s: the schema accepted it", profile, name)
			}
		}
	}
	good := `{"_type":"clearance.statement-status/v1","id":"st-` + strings.Repeat("a", 32) + `","state":"valid","as_of":"2026-11-14T00:00:00Z"}`
	if err := valid(st, []byte(good)); err != nil {
		t.Error(err)
	}
	if err := valid(st, []byte(strings.Replace(good, "valid", "great", 1))); err == nil {
		t.Error("an unknown state")
	}
}

func TestIDsHaveTheShapeAndTheEntropy(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		id, err := statement.NewID()
		if err != nil || !statement.ValidID(id) || seen[id] {
			t.Fatalf("%q %v", id, err)
		}
		seen[id] = true
	}
	for _, bad := range []string{"", "st-", "st-" + strings.Repeat("A", 32), "st-" + strings.Repeat("a", 31), "st-" + strings.Repeat("a", 33), "pk-" + strings.Repeat("a", 32),
		"st-" + strings.Repeat("a", 31) + "g", " st-" + strings.Repeat("a", 32), "st-" + strings.Repeat("a", 32) + "\n", "st-" + strings.Repeat("a", 32) + "/", "../" + strings.Repeat("a", 35)} {
		if statement.ValidID(bad) {
			t.Errorf("%q is a valid id", bad)
		}
	}
}

func TestTheQuestionnaireMappingIsDataAndSaysEvidenceFor(t *testing.T) {
	var q struct {
		Standard, Insurer []statement.MappingEntry
	}
	if err := json.Unmarshal(statement.QuestionnaireJSON(), &q); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, m := range q.Standard {
		have[m.Framework+" "+m.Ref] = true
	}
	for _, want := range []string{"SOC 2 CC8.1", "SOC 2 CC6", "ISO/IEC 27001:2022 A.8.32", "NIST SP 800-53 Rev. 5 CM-3", "NIST SP 800-53 Rev. 5 CM-5", "SIG Change control", "SIG AI"} {
		if !have[want] {
			t.Errorf("the standard mapping lacks %s", want)
		}
	}
	have = map[string]bool{}
	for _, m := range q.Insurer {
		have[m.Ref] = true
	}
	for _, want := range []string{"Privileged change", "Separation of duties", "Unauthorized-change detection"} {
		if !have[want] {
			t.Errorf("the insurer mapping lacks %s", want)
		}
	}
	for _, m := range append(q.Standard, q.Insurer...) {
		if s := strings.ToLower(m.Evidence + m.Objective); strings.Contains(s, "compliant") || strings.Contains(s, "certif") || strings.Contains(s, "guarantee") {
			t.Errorf("%s %s claims more than evidence: %q", m.Framework, m.Ref, s)
		}
	}
}

func FuzzParse(f *testing.F) {
	raw, _ := json.Marshal(map[string]any{"_type": statement.Schema})
	f.Add(raw)
	f.Add([]byte(`{"_type":"clearance.statement/v1","id":"st-00000000000000000000000000000000"}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if d, err := statement.Parse(b); err == nil {
			if _, err := d.Canonical(); err != nil {
				t.Fatal(err)
			}
		}
		_, _ = statement.ParseStatus(b)
	})
}

func FuzzSummarize(f *testing.F) {
	f.Add(packetJSON(nil), []byte(""))
	f.Add([]byte(`{"schema":"clearance.packet/v1"}`), []byte("{}\n"))
	f.Fuzz(func(t *testing.T, pj, rj []byte) {
		_, _ = statement.Summarize(pj, rj, statement.ProfileInsurer)
	})
}

func FuzzValidID(f *testing.F) {
	f.Add("st-00000000000000000000000000000000")
	f.Fuzz(func(t *testing.T, s string) {
		if statement.ValidID(s) && (len(s) != 35 || strings.ContainsAny(s, "/. \n")) {
			t.Fatalf("%q", s)
		}
		_ = statement.ValidLabel(s)
		_ = statement.ValidPolicyVersion(s)
	})
}
