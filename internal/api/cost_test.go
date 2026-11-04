package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/store"
)

// A-4 (AP-C2): counts by=cost sums the model-call outcomes' usage and the run.finish records' runs and seconds,
// per task tree, run, agent or principal, scoped like every other read.

func modelOutcome(task, session, principal, agent string, charged, in, out, cacheRead int) store.Event {
	return ev(map[string]any{"ts": "2026-10-30T12:20:00Z", "task_id": task, "session": session, "principal": principal,
		"agent": agent, "tool": "model.call", "target": "claude-sonnet-5-5", "model_version": "claude-sonnet-5-5-20261015",
		"usage": map[string]any{"input_tokens": in, "output_tokens": out, "cache_creation_input_tokens": 0,
			"cache_read_input_tokens": cacheRead, "charged_tokens": charged},
		"outcome_of": map[string]any{"seq": 1, "hash": strings.Repeat("b", 64)}})
}

func runFinish(task, session, principal, agent string, charged, wall int) store.Event {
	return ev(map[string]any{"ts": "2026-10-30T12:25:00Z", "task_id": task, "session": session, "principal": principal,
		"agent": agent, "tool": "run.finish", "result": "ok", "model_version": "claude-sonnet-5-5",
		"preflight": map[string]any{"result": "not-run", "definition": agent},
		"cost":      map[string]any{"charged_tokens": charged, "wall_seconds": wall, "model_calls": 2}})
}

// costEvents: alice's task t-0 is a tree (s-0 and its child s-0c, a researcher), bob's t-1 one run; a model.call
// decision and an outcome without usage (an older gateway) are not summed.
func costEvents() []store.Event {
	out := fixtureEvents()
	out = append(out,
		modelOutcome("t-0", "s-0", "user:alice", "coding-agent", 100, 80, 10, 100),
		modelOutcome("t-0", "s-0", "user:alice", "coding-agent", 25, 20, 5, 0),
		modelOutcome("t-0", "s-0c", "user:alice", "researcher", 50, 40, 10, 0),
		modelOutcome("t-1", "s-1", "user:bob", "orchestrator", 40, 30, 10, 0),
		ev(map[string]any{"task_id": "t-0", "session": "s-0", "principal": "user:alice", "agent": "coding-agent",
			"tool": "model.call", "target": "claude-sonnet-5-5"}),
		ev(map[string]any{"task_id": "t-0", "session": "s-0", "principal": "user:alice", "agent": "coding-agent",
			"tool": "model.call", "outcome_of": map[string]any{"seq": 2, "hash": strings.Repeat("c", 64)}}),
		runFinish("t-0", "s-0", "user:alice", "coding-agent", 125, 60),
		runFinish("t-0", "s-0c", "user:alice", "researcher", 50, 30),
	)
	return out
}

func TestCostCountsSumTheChargedTokens(t *testing.T) {
	each(t, world{events: costEvents()}, func(t *testing.T, h *harness) {
		got := h.ok("/v1/evidence/counts?by=cost", "audit")
		want := `{"by":"cost","cost":{"cache_creation_input_tokens":0,"cache_read_input_tokens":100,"charged_tokens":215,` +
			`"input_tokens":170,"model_calls":4,"output_tokens":35,"runs":2,"wall_seconds":90},"items":[` +
			`{"cost":{"cache_creation_input_tokens":0,"cache_read_input_tokens":100,"charged_tokens":175,"input_tokens":140,` +
			`"model_calls":3,"output_tokens":25,"runs":2,"wall_seconds":90},"count":3,"key":"t-0"},` +
			`{"cost":{"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"charged_tokens":40,"input_tokens":30,` +
			`"model_calls":1,"output_tokens":10,"runs":0,"wall_seconds":0},"count":1,"key":"t-1"}],"per":"task","total":4}`
		if b, _ := json.Marshal(got); string(b) != want {
			t.Errorf("per task:\n got %s\nwant %s", b, want)
		}
		charged := func(path, token string) string {
			var parts []string
			for _, it := range items(h.ok(path, token)) {
				c := it["cost"].(map[string]any)
				parts = append(parts, fmt.Sprintf("%v=%v/%v", it["key"], c["charged_tokens"], c["runs"]))
			}
			return strings.Join(parts, " ")
		}
		for _, c := range []struct{ path, token, want string }{
			{"/v1/evidence/counts?by=cost&per=session", "audit", "s-0=125/1 s-0c=50/1 s-1=40/0"},
			{"/v1/evidence/counts?by=cost&per=agent", "audit", "coding-agent=125/1 researcher=50/1 orchestrator=40/0"},
			{"/v1/evidence/counts?by=cost&per=principal", "audit", "user:alice=175/2 user:bob=40/0"},
			// alice sees her own task tree, not bob's
			{"/v1/evidence/counts?by=cost", "alice", "t-0=175/2"},
			{"/v1/evidence/counts?by=cost&per=session&task=t-0", "audit", "s-0=125/1 s-0c=50/1"},
			// the list's filters apply: tool=model.call leaves the runs out
			{"/v1/evidence/counts?by=cost&tool=model.call", "audit", "t-0=175/0 t-1=40/0"},
			{"/v1/evidence/counts?by=cost&agent=nobody", "audit", ""},
		} {
			if g := charged(c.path, c.token); g != c.want {
				t.Errorf("%s as %s: %q, want %q", c.path, c.token, g, c.want)
			}
		}
		// The run's own summary agrees with the outcomes summed for it.
		if g := charged("/v1/evidence/counts?by=cost&per=session&tool=model.call", "audit"); g != "s-0=125/0 s-0c=50/0 s-1=40/0" {
			t.Errorf("per session: %s", g)
		}
		h.status(t, 400, "GET", "/v1/evidence/counts?by=cost&per=nope", "audit", "")
		h.status(t, 400, "GET", "/v1/evidence/counts?by=cost&outcomes=only", "audit", "")
		h.status(t, 400, "GET", "/v1/evidence/counts?by=agent&per=task", "audit", "")
		h.status(t, 400, "GET", "/v1/evidence/counts?by=cost&since=nope", "audit", "")
	})
}

// TestCostCountsUseTheIndex: the planner can answer counts by=cost from the core's clearance_evidence_cost partial
// index (pg.Schema), for an auditor and for a person's scoped read.
func TestCostCountsUseTheIndex(t *testing.T) {
	_, dsn := backends[1].build(t, world{events: costEvents()})
	conn, err := pgx.Connect(bg, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(bg)
	if _, err := conn.Exec(bg, "SET enable_seqscan = off"); err != nil {
		t.Fatal(err)
	}
	for _, v := range []*Viewer{{Role: RoleAuditor, Person: "user:auditor"}, {Role: RolePerson, Person: "user:alice", Agents: []string{}, Apps: []string{}}} {
		sql, args, err := costSQL(EvidenceFilter{}, v, "task")
		if err != nil {
			t.Fatal(err)
		}
		rows, err := conn.Query(bg, "EXPLAIN "+sql, args...)
		if err != nil {
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var l string
			_ = rows.Scan(&l)
			plan.WriteString(l + "\n")
		}
		rows.Close()
		if !strings.Contains(plan.String(), "clearance_evidence_cost") {
			t.Fatalf("counts by=cost does not use the index:\n%s", plan.String())
		}
	}
}

// TestCostTotalsAreOverEveryGroup: the answer's total and cost sum every matching group, not the page of MaxLimit.
func TestCostTotalsAreOverEveryGroup(t *testing.T) {
	var events []store.Event
	n := MaxLimit + 5
	want := 0
	for i := 0; i < n; i++ {
		c := i + 1
		want += c
		events = append(events, modelOutcome("t-many", fmt.Sprintf("s-%04d", i), "user:x", "researcher", c, c, 0, 0))
	}
	each(t, world{events: events}, func(t *testing.T, h *harness) {
		got := h.ok("/v1/evidence/counts?by=cost&per=session", "audit")
		if len(items(got)) != MaxLimit {
			t.Fatalf("items: %d", len(items(got)))
		}
		cost := got["cost"].(map[string]any)
		if num(got["total"]) != int64(n) || num(cost["charged_tokens"]) != int64(want) || num(cost["model_calls"]) != int64(n) {
			t.Fatalf("total %v cost %v, want %d calls and %d charged", got["total"], cost, n, want)
		}
		// The page is the most charged sessions.
		if first := items(got)[0]; first["key"] != fmt.Sprintf("s-%04d", n-1) {
			t.Fatalf("first item %v", first["key"])
		}
	})
}
