package server_test

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
)

// G-ARGO-10c: the protected pairs a cluster's agent reports. Its own providers, so the shared fixture's are untouched.
const (
	agentProd = "hangar-prod/clearance-system/clearance-argocd-agent"
	agentDev  = "hangar-dev/clearance-system/clearance-argocd-agent"
	agentOdd  = "hangar-x/clearance-system/clearance-argocd-agent"
	noBinding = "hangar-prod/argocd/clearance-sync"
)

const protectionProviders = `[
 {"name": "agent-prod", "version": "0.1.0", "principals": ["hangar-prod/clearance-system/*"],
  "kinds": ["deploy.outcome", "deploy.exception"], "protection": ["hangar-prod/clearance-system/clearance-argocd-agent=hangar-prod"]},
 {"name": "agent-dev", "version": "0.1.0", "principals": ["hangar-dev/clearance-system/*"],
  "protection": ["hangar-dev/clearance-system/clearance-argocd-agent=hangar-dev"]},
 {"name": "agent-both", "version": "0.1.0", "principals": ["hangar-x/clearance-system/*"],
  "protection": ["hangar-x/clearance-system/clearance-argocd-agent=hangar-x", "hangar-x/clearance-system/clearance-argocd-agent=hangar-prod"]},
 {"name": "argo-gate", "version": "0.1.0", "principals": ["hangar-prod/argocd/*"], "kinds": ["deploy.exception"]}]`

func protectionFixture(t *testing.T, dsn string) *fixture {
	ps, err := server.ParseProviders(protectionProviders)
	if err != nil {
		t.Fatal(err)
	}
	cfg := core.Config{Memory: dsn == "", DSN: dsn, Version: "test", Providers: ps, Auth: core.DevAuthenticator(),
		MaxClockSkew: -1, AgentLogins: []string{vocabtest.AgentLogin}}
	cfg.Gate.Verifiers = []string{"app-*-cicd/pipeline-runner"}
	cfg.Gate.VerifierAppBindingOff = true // registers several apps from one pipeline
	cfg.Gate.Protected = []string{"hangar-prod/prod"}
	return newFixture(t, cfg)
}

var seqCounter atomic.Int64

// pairs is a report body with a fresh number (reports must carry one, and one that only goes up).
func pairs(ps ...string) map[string]any {
	l := []any{}
	for _, p := range ps {
		app, env, _ := strings.Cut(p, "/")
		l = append(l, map[string]any{"app": app, "env": env})
	}
	return map[string]any{"pairs": l, "seq": seqCounter.Add(1)}
}

func protectionRecords(f *fixture) []map[string]any {
	var out []map[string]any
	for _, r := range f.records() {
		if r["tool"] == "protection.report" {
			out = append(out, r)
		}
	}
	return out
}

func devRegistration(app string) map[string]any {
	r := registration(headSHA)
	r["app"], r["env"], r["cluster"] = app, "dev", "hangar-dev"
	return r
}

func TestProtectionReportIsRecordedOncePerChange(t *testing.T) {
	reportedProtection(t, protectionFixture(t, ""))
}

func TestProtectionReportIsRecordedOncePerChangeOnPostgres(t *testing.T) {
	reportedProtection(t, protectionFixture(t, pgDSN(t)))
}

func reportedProtection(t *testing.T, f *fixture) {
	a := f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("web/dev", "api/dev")).want(t, 200, "")
	digest, _ := a.body["digest"].(string)
	if a.body["changed"] != true || a.body["pairs"] != float64(2) || len(digest) != 64 || a.body["cluster"] != "hangar-dev" ||
		len(a.body["added"].([]any)) != 2 || len(a.body["removed"].([]any)) != 0 {
		t.Fatalf("first report: %v", a.body)
	}
	recs := protectionRecords(f)
	if len(recs) != 1 || recs[0]["decision"] != "allow" || recs[0]["target"] != "protection:hangar-dev" || recs[0]["args_sha256"] != digest ||
		!strings.Contains(fmt.Sprint(recs[0]["result"]), "added api/dev, web/dev") ||
		fmt.Sprint(recs[0]["seq"]) != fmt.Sprint(a.body["seq"]) {
		t.Fatalf("protection.report: %v", recs)
	}
	// The same set in another order: content-addressed, nothing recorded, but the report's time moves.
	before, _ := f.core.Store.Protections(context.Background())
	again := f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("api/dev", "web/dev")).want(t, 200, "")
	after, _ := f.core.Store.Protections(context.Background())
	if again.body["changed"] != false || again.body["digest"] != digest || again.body["seq"] != nil || len(protectionRecords(f)) != 1 ||
		len(after) != 1 || after[0].ReportedAt.Before(before[0].ReportedAt) || !after[0].ChangedAt.Equal(before[0].ChangedAt) {
		t.Fatalf("an unchanged report: %v", again.body)
	}
	// A removal is a record that names the pair, with the reason the agent gave (claimed).
	body := pairs("api/dev")
	body["reason"] = "Application web opted out"
	gone := f.do("PUT", "/v1/protection/hangar-dev", agentDev, body).want(t, 200, "")
	rm := gone.body["removed"].([]any)
	if gone.body["changed"] != true || len(rm) != 1 || rm[0].(map[string]any)["app"] != "web" || len(protectionRecords(f)) != 2 {
		t.Fatalf("removal: %v", gone.body)
	}
	res := fmt.Sprint(protectionRecords(f)[1]["result"])
	if !strings.Contains(res, "removed web/dev") || !strings.Contains(res, "was sha256:"+digest) || !strings.Contains(res, "reason (claimed): Application web opted out") {
		t.Fatalf("the removal record: %s", res)
	}
	// An empty report withdraws everything and is a change.
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs()).want(t, 200, "")
	if len(protectionRecords(f)) != 3 {
		t.Fatal("a withdrawal is a change")
	}
}

func TestProtectionReportTrust(t *testing.T) {
	f := protectionFixture(t, "")
	good := func() map[string]any { return pairs("web/dev") }
	f.do("PUT", "/v1/protection/hangar-dev", "", good()).want(t, 401, "")
	f.do("PUT", "/v1/protection/hangar-dev", "someone/else", good()).want(t, 403, "not a registered provider")
	// A provider with no protection list reports nothing.
	f.do("PUT", "/v1/protection/hangar-prod", noBinding, good()).want(t, 403, "may not report protection")
	// An agent reports for its own cluster only: neither dev's for prod nor prod's for dev.
	f.do("PUT", "/v1/protection/hangar-prod", agentDev, good()).want(t, 403, "may not report protection")
	f.do("PUT", "/v1/protection/hangar-dev", agentProd, good()).want(t, 403, "may not report protection")
	// A cluster belongs to the first provider that lists it: a second provider that also lists hangar-prod is refused.
	f.do("PUT", "/v1/protection/hangar-prod", agentOdd, good()).want(t, 403, "belongs to provider")
	f.do("PUT", "/v1/protection/hangar-x", agentOdd, good()).want(t, 200, "")
	f.do("PUT", "/v1/protection/Hangar_Dev", agentDev, good()).want(t, 400, "cluster is a name")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, `{"pairs": [], "seq": 1, "extra": 1}`).want(t, 400, "unknown field")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, `{"seq": 1}`).want(t, 400, "pairs is required")
	// A report with no number (or 0) cannot bypass the ordering check.
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, `{"pairs": []}`).want(t, 400, "seq is required")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, `{"pairs": [], "seq": 0}`).want(t, 400, "seq is required")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("Web/dev")).want(t, 400, "names")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("web/dev", "web/dev")).want(t, 400, "twice")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, map[string]any{"pairs": []any{}, "seq": 1, "reason": strings.Repeat("x", 501)}).want(t, 400, "reason")
	many := make([]string, 0, 5001)
	for i := 0; i < 5001; i++ {
		many = append(many, fmt.Sprintf("a%d/dev", i))
	}
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs(many...)).want(t, 400, "at most")
	if n := len(protectionRecords(f)); n != 1 {
		t.Fatalf("refused reports recorded %d protection.report records, want the 1 accepted", n)
	}
	got, _ := f.core.Store.Protections(context.Background())
	if len(got) != 1 || got[0].Cluster != "hangar-x" {
		t.Fatalf("a refused report changed what is held: %v", got)
	}
}

func TestProvidersProtectionIsChecked(t *testing.T) {
	for _, bad := range []string{
		`[{"name":"x","version":"1","principals":["a/b/c"],"protection":["a/b/c"]}]`,
		`[{"name":"x","version":"1","principals":["a/b/c"],"protection":["=a"]}]`,
		`[{"name":"x","version":"1","principals":["a/b/c"],"protection":["a/b/c=Not A Name"]}]`,
		`[{"name":"x","version":"1","principals":["a/b/c"],"protection":["other/principal=a"]}]`,
		`[{"name":"x","version":"1","class":"assurance","keys":["k"],"protection":["a/b/c=a"]}]`,
	} {
		if _, err := server.ParseProviders(bad); err == nil {
			t.Fatalf("%s was accepted", bad)
		}
	}
	// A reporting provider with no record kinds is a provider that does something.
	if _, err := server.ParseProviders(`[{"name":"x","version":"1","principals":["a/b/c"],"kinds":[],"protection":["a/b/c=a"]}]`); err != nil {
		t.Fatal(err)
	}
}

// The core protects a pair that the list does not name when its cluster's agent reports it, and never un-protects what
// the list names.
func TestReportedPairsAreProtected(t *testing.T) {
	protects(t, protectionFixture(t, ""))
}

func TestReportedPairsAreProtectedOnPostgres(t *testing.T) {
	protects(t, protectionFixture(t, pgDSN(t)))
}

func protects(t *testing.T, f *fixture) {
	n := 0
	state := func(app string) string {
		n++
		r := devRegistration(app)
		r["head"] = strings.Repeat(fmt.Sprintf("%x", n), 40)
		return fmt.Sprint(f.do("POST", "/v1/clearances", ci, r).want(t, 200, "").body["state"])
	}
	// hangar-dev/dev is not on the list: a change is cleared at tier 0 as unprotected.
	if s := state("web"); s != "cleared" {
		t.Fatalf("an unlisted environment, nothing reported: state %s", s)
	}
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("web/dev")).want(t, 200, "")
	// A new head of the reported pair is protected: it holds for a person. Another app in the same environment is not.
	r := devRegistration("web")
	r["head"] = strings.Repeat("d", 40)
	if s := fmt.Sprint(f.do("POST", "/v1/clearances", ci, r).want(t, 200, "").body["state"]); s != "holding" {
		t.Fatalf("a reported pair: state %s, want holding", s)
	}
	if s := state("api"); s != "cleared" {
		t.Fatalf("an app that was not reported: state %s", s)
	}
	// Another cluster's report does not protect this cluster's pair.
	f.do("PUT", "/v1/protection/hangar-x", agentOdd, pairs("api/dev")).want(t, 200, "")
	if s := state("api"); s != "cleared" {
		t.Fatalf("a report for another cluster protected hangar-dev: state %s", s)
	}
	// The list still protects what it names whatever an agent reports (hangar-prod/prod), reports or not.
	f.do("PUT", "/v1/protection/hangar-prod", agentProd, pairs()).want(t, 200, "")
	prod := registration(strings.Repeat("e", 40))
	if s := fmt.Sprint(f.do("POST", "/v1/clearances", ci, prod).want(t, 200, "").body["state"]); s != "holding" {
		t.Fatalf("a listed environment with an empty report: state %s", s)
	}
	// An agent that stops reporting leaves the last report in force: nothing here depends on its age.
	got, _ := f.core.Store.Protections(context.Background())
	if len(got) != 3 {
		t.Fatalf("held: %v", got)
	}
	// An opt-out removes the pair; the next change to it is cleared as unprotected again.
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs()).want(t, 200, "")
	r2 := devRegistration("web")
	r2["head"] = strings.Repeat("f", 40)
	if s := fmt.Sprint(f.do("POST", "/v1/clearances", ci, r2).want(t, 200, "").body["state"]); s != "cleared" {
		t.Fatalf("after the removal: state %s", s)
	}
}

func TestStaticPairsAreNotUnprotectedByAReport(t *testing.T) {
	f := protectionFixture(t, "")
	f.do("PUT", "/v1/protection/hangar-prod", agentProd, pairs("gate-api/prod")).want(t, 200, "")
	gone := f.do("PUT", "/v1/protection/hangar-prod", agentProd, pairs()).want(t, 200, "")
	sr := gone.body["static_removed"].([]any)
	if len(sr) != 1 || sr[0].(map[string]any)["app"] != "gate-api" {
		t.Fatalf("a removed pair the list protects is named: %v", gone.body)
	}
	if res := fmt.Sprint(protectionRecords(f)[1]["result"]); !strings.Contains(res, "still protected by CLEARANCE_PROTECTED_ENVIRONMENTS") {
		t.Fatalf("the record says so: %s", res)
	}
	held := f.do("POST", "/v1/clearances", ci, registration(headSHA)).want(t, 200, "")
	if held.body["state"] != "holding" {
		t.Fatalf("the list still protects hangar-prod/prod: %v", held.body["state"])
	}
}

// A core with an empty list protects every environment: an agent's report cannot make anything less protected.
func TestEmptyListProtectsEverything(t *testing.T) {
	ps, _ := server.ParseProviders(protectionProviders)
	cfg := core.Config{Memory: true, Version: "test", Providers: ps, Auth: core.DevAuthenticator(), MaxClockSkew: -1, AgentLogins: []string{vocabtest.AgentLogin}}
	cfg.Gate.Verifiers = []string{"app-*-cicd/pipeline-runner"}
	cfg.Gate.VerifierAppBindingOff = true // registers several apps from one pipeline
	f := newFixture(t, cfg)
	if s := f.do("POST", "/v1/clearances", ci, devRegistration("web")).want(t, 200, "").body["state"]; s != "holding" {
		t.Fatalf("empty list: %v", s)
	}
	got := f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("web/dev")).want(t, 200, "")
	if got.body["changed"] != true {
		t.Fatal(got.body)
	}
	gone := f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs()).want(t, 200, "")
	if len(gone.body["static_removed"].([]any)) != 1 {
		t.Fatalf("an empty list protects everything, so a removal is static: %v", gone.body)
	}
}

func TestProtectionStalenessIsShown(t *testing.T) {
	f := protectionFixture(t, "")
	f.do("GET", "/v1/protection", "", nil).want(t, 401, "")
	f.do("GET", "/v1/protection", "someone/else", nil).want(t, 403, "not a registered provider")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("web/dev")).want(t, 200, "")
	st := f.do("GET", "/v1/protection", agentDev, nil).want(t, 200, "")
	cl := st.body["clusters"].([]any)
	if len(cl) != 1 || cl[0].(map[string]any)["stale"] != false || st.body["stale_after_seconds"] != float64(900) ||
		fmt.Sprint(st.body["static"]) != "[hangar-prod/prod]" {
		t.Fatalf("state: %v", st.body)
	}
	// An agent that stopped reporting leaves its pair protected: nothing in the gate reads the report's age.
	if s := f.do("POST", "/v1/clearances", ci, devRegistration("web")).want(t, 200, "").body["state"]; s != "holding" {
		t.Fatalf("a reported pair: %v", s)
	}
}

func withSeq(m map[string]any, n int) map[string]any { m["seq"] = n; return m }

func TestAnOldOrReplayedReportCannotReplaceANewerOne(t *testing.T) {
	seqBounds(t, protectionFixture(t, ""))
}

func TestAnOldOrReplayedReportCannotReplaceANewerOneOnPostgres(t *testing.T) {
	seqBounds(t, protectionFixture(t, pgDSN(t)))
}

func seqBounds(t *testing.T, f *fixture) {
	a := f.do("PUT", "/v1/protection/hangar-dev", agentDev, withSeq(pairs("web/dev"), 5)).want(t, 200, "")
	if a.body["held_seq"] != float64(5) {
		t.Fatalf("held_seq: %v", a.body)
	}
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, withSeq(pairs("web/dev", "api/dev"), 6)).want(t, 200, "")
	// An older report (a replay of seq 5's set, or an old set at 3) is refused, recorded once, and changes nothing.
	n := len(protectionRecords(f))
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, withSeq(pairs("web/dev"), 5)).want(t, 409, "not above the held report")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, withSeq(pairs("web/dev"), 5)).want(t, 409, "")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, withSeq(pairs("other/dev"), 6)).want(t, 409, "") // equal number, another set
	got, _ := f.core.Store.Protections(context.Background())
	if len(got) != 1 || got[0].Seq != 6 || !strings.Contains(string(got[0].Doc), "api") {
		t.Fatalf("held after the refusals: %+v", got)
	}
	var refused int
	for _, r := range f.records() {
		if r["tool"] == "protection.refused" {
			refused++
		}
	}
	if refused != 2 || len(protectionRecords(f)) != n {
		t.Fatalf("a replay is recorded once: %d refusal records for 2 distinct replays", refused)
	}
	// The same set again with the same or a lower number is a heartbeat (nothing is replaced), and the number never goes down.
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, withSeq(pairs("web/dev", "api/dev"), 4)).want(t, 200, "")
	got, _ = f.core.Store.Protections(context.Background())
	if got[0].Seq != 6 {
		t.Fatalf("seq went down: %d", got[0].Seq)
	}
	st := f.do("GET", "/v1/protection", agentDev, nil).want(t, 200, "")
	if st.body["clusters"].([]any)[0].(map[string]any)["seq"] != float64(6) {
		t.Fatalf("GET shows the held number: %v", st.body)
	}
}

func TestRemovalsAreBoundedPerHourAndAdditionsAreNot(t *testing.T) {
	f := protectionFixture(t, "")
	n := server.MaxProtectionRecordsPerHour
	// One tenant flips its pair on and off: each removal is counted.
	for i := 0; i < n; i++ {
		f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("flip/dev")).want(t, 200, "")
		f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs()).want(t, 200, "")
	}
	// The budget is spent. Another team's pure ADDITION is still taken, on any number of such reports.
	for i := 0; i < 40; i++ {
		var names []string
		for j := 0; j <= i; j++ {
			names = append(names, fmt.Sprintf("team%d/dev", j))
		}
		f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs(names...)).want(t, 200, "")
	}
	// A removal (or a mix) now is refused with 429, and nothing changes.
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("team0/dev")).want(t, 429, "at most")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("team0/dev", "new/dev")).want(t, 429, "at most")
	got, _ := f.core.Store.Protections(context.Background())
	if !strings.Contains(string(got[0].Doc), "team39") {
		t.Fatalf("held: %s", got[0].Doc)
	}
	// An unchanged report (the heartbeat) is never refused. Another cluster has its own bound.
	last := pairs()
	var names []string
	for j := 0; j < 40; j++ {
		names = append(names, fmt.Sprintf("team%d/dev", j))
	}
	last = pairs(names...)
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, last).want(t, 200, "")
	f.do("PUT", "/v1/protection/hangar-x", agentOdd, pairs("x/dev")).want(t, 200, "")
}

func TestTheRefusedReportMemoryIsBounded(t *testing.T) {
	f := protectionFixture(t, "")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, withSeq(pairs("web/dev"), 5000)).want(t, 200, "")
	for i := 1; i <= 40; i++ { // 40 distinct stale numbers: only the hourly bound's worth are recorded
		f.do("PUT", "/v1/protection/hangar-dev", agentDev, withSeq(pairs(fmt.Sprintf("a%d/dev", i)), i)).want(t, 409, "")
	}
	var refused int
	for _, r := range f.records() {
		if r["tool"] == "protection.refused" {
			refused++
		}
	}
	if refused > server.MaxProtectionRecordsPerHour {
		t.Fatalf("%d refusals recorded: more than the hourly bound", refused)
	}
}

// Opting out of one of two Applications that share a pair changes no set, and is still recorded when the agent says why.
func TestAReasonIsRecordedEvenWhenTheSetDidNotChange(t *testing.T) {
	f := protectionFixture(t, "")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("web/dev")).want(t, 200, "")
	r := pairs("web/dev")
	r["reason"] = "argocd/web-b opted out (pair still protected by argocd/web-a)"
	a := f.do("PUT", "/v1/protection/hangar-dev", agentDev, r).want(t, 200, "")
	recs := protectionRecords(f)
	if a.body["changed"] != false || len(recs) != 2 || !strings.Contains(fmt.Sprint(recs[1]["result"]), "unchanged") ||
		!strings.Contains(fmt.Sprint(recs[1]["result"]), "web-b opted out") {
		t.Fatalf("%v %v", a.body, recs)
	}
}

// Who reads GET /v1/protection: the agent that reports a cluster reads that cluster (its last number) and the static list;
// another cluster's agent does not see it; a provider that reports nothing is refused.
func TestOnlyAReportingAgentReadsItsOwnClusterAndTheStaticList(t *testing.T) {
	f := protectionFixture(t, "")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("web/dev")).want(t, 200, "")
	f.do("PUT", "/v1/protection/hangar-prod", agentProd, pairs("gate/prod")).want(t, 200, "")
	dev := f.do("GET", "/v1/protection", agentDev, nil).want(t, 200, "")
	cl := dev.body["clusters"].([]any)
	if len(cl) != 1 || cl[0].(map[string]any)["cluster"] != "hangar-dev" || cl[0].(map[string]any)["seq"] == nil || fmt.Sprint(dev.body["static"]) != "[hangar-prod/prod]" {
		t.Fatalf("hangar-dev's agent: %v", dev.body)
	}
	prod := f.do("GET", "/v1/protection", agentProd, nil).want(t, 200, "")
	if cl := prod.body["clusters"].([]any); len(cl) != 1 || cl[0].(map[string]any)["cluster"] != "hangar-prod" {
		t.Fatalf("hangar-prod's agent: %v", prod.body)
	}
	f.do("GET", "/v1/protection", noBinding, nil).want(t, 403, "may not read")
	f.do("GET", "/v1/protection", "someone/else", nil).want(t, 403, "not a registered provider")
	f.do("GET", "/v1/protection", "", nil).want(t, 401, "")
}

func TestAdditionsHaveTheirOwnHourlyBoundAndRemovalsNeverSpendIt(t *testing.T) {
	f := protectionFixture(t, "")
	// Spend the removal budget.
	for i := 0; i < server.MaxProtectionRecordsPerHour; i++ {
		f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("flip/dev")).want(t, 200, "")
		f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs()).want(t, 200, "")
	}
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs("flip/dev")).want(t, 200, "") // an addition: not refused for the spent removals
	// The additions used by the flipping count against the add bound too: 30 so far; add one at a time to the bound.
	names := []string{"flip/dev"}
	for i := 0; i < server.MaxProtectionAddsPerHour-server.MaxProtectionRecordsPerHour-1; i++ {
		names = append(names, fmt.Sprintf("n%d/dev", i))
		f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs(names...)).want(t, 200, "")
	}
	names = append(names, "over/dev")
	f.do("PUT", "/v1/protection/hangar-dev", agentDev, pairs(names...)).want(t, 429, "additions")
	// Another cluster has its own.
	f.do("PUT", "/v1/protection/hangar-x", agentOdd, pairs("x/dev")).want(t, 200, "")
}
