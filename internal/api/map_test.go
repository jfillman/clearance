package api

// GET /v1/targets and GET /v1/map: a declared registry joined with a world of gate, observation and health records,
// on memStore and on Postgres through the same assertions.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/targets"
)

var mapNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func tgt(id string, edit func(*targets.Target)) targets.Target {
	t := targets.Target{ID: id, Name: id, Kind: "k8s-namespace", Group: "hangar-prod", Env: "prod", App: "gate-api", Owner: "group:default/team-gate",
		Registry: "flight", Scope: "hangar-prod",
		Gates:     []targets.Gate{{Type: "glidepath", Instance: "gate-api-cicd", Mode: "enforce"}},
		Observers: []targets.Observer{{Provider: "observe-k8s", Source: "observe-k8s"}}}
	if edit != nil {
		edit(&t)
	}
	return t
}

func targetSet(source string, ts ...targets.Target) store.TargetSet {
	sorted, err := targets.Normalize(ts)
	if err != nil {
		panic(err)
	}
	doc, _ := json.Marshal(sorted)
	return store.TargetSet{Source: source, Digest: targets.Digest(sorted), Doc: doc, UpdatedAt: mapNow}
}

func registered(id, app, env, state, by string, tier int, created string) store.Change {
	c := change(id, app, state, "group:default/team-"+app, tier, created, nil)
	var m map[string]any
	_ = json.Unmarshal(c.Record, &m)
	m["registered_by"], m["env"] = by, env
	c.Env = env
	c.Record, _ = json.Marshal(m)
	return c
}

var _ = gate.States

func deploy(ts, tool, app, id, decision string, extra map[string]any) store.Event {
	e := ev(map[string]any{"ts": ts, "tool": tool, "app": app, "decision": decision, "boundary": "deployment",
		"change": map[string]any{"id": id, "app": app, "env": "prod", "tier": 2}})
	for k, v := range extra {
		e[k] = v
	}
	return e
}

// mapWorld is a fleet in miniature: one cluster with two apps behind a CI gate and a flag-mode Argo gate, an AWS account
// whose observer has gone blind, a GitHub environment nobody guards, and a dev namespace whose declared gate never
// spoke. Seqs: 0-2 observations of hangar-prod, 3-5 their assessments.
func mapWorld() world {
	obs := func(ts, id string) store.Event {
		return ev(map[string]any{"ts": ts, "tool": "observation", "scope": "hangar-prod", "boundary": "deployment", "coverage": "observed-not-attributed",
			"source": map[string]any{"name": "observe-k8s", "event_id": id}})
	}
	assess := func(ts string, about int, cov string) store.Event {
		return ev(map[string]any{"ts": ts, "tool": "assessment", "scope": "hangar-prod", "boundary": "deployment", "coverage": cov,
			"about": map[string]any{"seq": about}})
	}
	health := func(ts, scope, source, state string) store.Event {
		return ev(map[string]any{"ts": ts, "tool": "observation.health", "scope": scope, "boundary": "deployment", "_provider": "observe-k8s",
			"source": map[string]any{"name": source}, "health": map[string]any{"state": state, "interval_seconds": 60, "checks": []any{}}})
	}
	events := []store.Event{
		obs("2026-11-10T10:00:00Z", "e1"), obs("2026-11-10T10:01:00Z", "e2"), obs("2026-11-10T10:02:00Z", "e3"),
		assess("2026-11-10T10:00:01Z", 0, "authorized-and-verified"), assess("2026-11-10T10:01:01Z", 1, "authorized-and-verified"),
		assess("2026-11-10T10:02:01Z", 2, "out-of-band-detected"),
		// before the window: counted nowhere
		deploy("2026-11-08T09:00:00Z", "deploy.request", "gate-api", "c-old", "", nil),
		deploy("2026-11-10T09:00:00Z", "deploy.request", "gate-api", "c-1", "", nil),
		deploy("2026-11-10T09:01:00Z", "deploy.request", "flight-api", "c-2", "", nil),
		deploy("2026-11-10T09:02:00Z", "deploy.request", "flight-api", "c-3", "", nil),
		deploy("2026-11-10T09:03:00Z", "deploy.clear", "flight-api", "c-2", "allow", nil),
		deploy("2026-11-10T09:04:00Z", "deploy.deny", "flight-api", "c-3", "deny", nil),
		deploy("2026-11-10T09:30:00Z", "deploy.outcome", "flight-api", "c-2", "", map[string]any{"_provider": "argo-gate", "matched": true,
			"outcome": map[string]any{"applied": true}}),
		deploy("2026-11-10T09:40:00Z", "deploy.exception", "gate-api", "", "deny", map[string]any{"_provider": "argo-gate",
			"coverage": "out-of-band-detected", "change": nil}),
		// a runtime decision from a gate no target declares
		ev(map[string]any{"ts": "2026-11-10T10:30:00Z", "tool": "github.pr.open", "boundary": "runtime", "decision": "deny", "_provider": "mystery-gate",
			"policy": map[string]any{"ref": "x"}, "agent": "coding-agent"}),
		ev(map[string]any{"ts": "2026-11-10T10:31:00Z", "tool": "github.pr.open", "boundary": "runtime", "decision": "allow", "_provider": "mystery-gate",
			"policy": map[string]any{"ref": "x"}, "agent": "coding-agent"}),
		health("2026-11-10T11:59:30Z", "hangar-prod", "observe-k8s", "healthy"),
		health("2026-11-10T08:00:00Z", "aws:123456789012", "cloudtrail", "healthy"), // stale at 12:00: blind
	}
	return world{
		events: events,
		changes: []store.Change{
			registered("c-old", "gate-api", "prod", "expired", "gate-api-cicd", 1, "2026-11-08T09:00:00Z"),
			registered("c-1", "gate-api", "prod", "holding", "gate-api-cicd", 2, "2026-11-10T09:00:00Z"),
			registered("c-2", "flight-api", "prod", "cleared", "gate-api-cicd", 1, "2026-11-10T09:01:00Z"),
			registered("c-3", "flight-api", "prod", "denied", "gate-api-cicd", 3, "2026-11-10T09:02:00Z"),
		},
		targets: []store.TargetSet{
			targetSet("hangar-prod",
				tgt("gate-api-prod", func(t *targets.Target) {
					t.Gates = append(t.Gates, targets.Gate{Type: "g-argo", Instance: "argo-gate", Mode: "flag"})
				}),
				tgt("flight-api-prod", func(t *targets.Target) {
					t.App = "flight-api"
					t.Gates = append(t.Gates, targets.Gate{Type: "g-argo", Instance: "argo-gate", Mode: "enforce"})
				}),
				tgt("sandbox-tools", func(t *targets.Target) {
					t.Kind, t.Group, t.App, t.Env, t.Scope = "github-environment", "github", "", "", ""
					t.Gates, t.Observers = []targets.Gate{}, []targets.Observer{}
				}),
				tgt("acct-prod", func(t *targets.Target) {
					t.Kind, t.Group, t.App, t.Env, t.Scope = "aws-account", "aws-prod", "", "", "aws:123456789012"
					t.Gates = []targets.Gate{{Type: "g-tf", Instance: "tf-gate", Mode: "enforce"}}
					t.Observers = []targets.Observer{{Provider: "observe-aws", Source: "cloudtrail"}}
				})),
			targetSet("hangar-dev", tgt("dev-ns", func(t *targets.Target) {
				t.Group, t.App, t.Scope = "hangar-dev", "dev-app", "hangar-dev"
				t.Gates = []targets.Gate{{Type: "glidepath", Instance: "ghost-gate", Mode: "enforce"}}
				t.Observers = []targets.Observer{{Provider: "observe-k8s", Source: "observe-k8s"}}
			})),
		},
	}
}

func mapEach(t *testing.T, w world, fn func(t *testing.T, h *harness)) {
	each(t, w, fn, func(o *Options) { o.Clock = func() time.Time { return mapNow } })
}

func pick(t *testing.T, list any, key, val string) map[string]any {
	t.Helper()
	for _, x := range list.([]any) {
		if m := x.(map[string]any); m[key] == val {
			return m
		}
	}
	t.Fatalf("no %s=%s in %v", key, val, list)
	return nil
}

func sub(m map[string]any, k string) map[string]any { return m[k].(map[string]any) }

func kinds(m map[string]any) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, x := range m["attention"].([]any) {
		a := x.(map[string]any)
		out[a["kind"].(string)] = append(out[a["kind"].(string)], a)
	}
	return out
}

func TestTargetsListsTheUnionOfTheDeclaredSets(t *testing.T) {
	w := mapWorld()
	w.targets = append(w.targets, targetSet("hangar-shared", tgt("gate-api-prod", func(t *targets.Target) { t.Name = "duplicate" })))
	mapEach(t, w, func(t *testing.T, h *harness) {
		m := h.ok("/v1/targets", "alice")
		if n := len(m["items"].([]any)); n != 5 {
			t.Fatalf("%d targets: %v", n, m["items"])
		}
		it := pick(t, m["items"], "id", "gate-api-prod")
		if it["source"] != "hangar-prod" || it["name"] != "gate-api-prod" || len(it["gates"].([]any)) != 2 {
			t.Fatalf("first source wins: %v", it)
		}
		if c := m["conflicts"].([]any); len(c) != 1 || !strings.Contains(c[0].(string), "gate-api-prod") {
			t.Fatalf("conflicts: %v", c)
		}
		if len(m["sources"].([]any)) != 3 || pick(t, m["sources"], "source", "hangar-dev")["targets"] != json.Number("1") {
			t.Fatalf("sources: %v", m["sources"])
		}
		if n := len(h.ok("/v1/targets?group=aws-prod", "alice")["items"].([]any)); n != 1 {
			t.Fatalf("group filter: %d", n)
		}
		if n := len(h.ok("/v1/targets?kind=k8s-namespace&env=prod&app=flight-api", "alice")["items"].([]any)); n != 1 {
			t.Fatalf("filters: %d", n)
		}
		h.status(t, 400, "GET", "/v1/targets?kind=vm", "alice", "")
		h.status(t, 400, "GET", "/v1/targets?nope=1", "alice", "")
		h.status(t, 401, "GET", "/v1/targets", "", "")
		h.status(t, 403, "GET", "/v1/targets", "sync", "") // a feed reader reads nothing else
	})
}

func TestMapJoinsTheRegistryWithTheRecords(t *testing.T) {
	mapEach(t, mapWorld(), func(t *testing.T, h *harness) {
		m := h.ok("/v1/map", "audit")
		if m["from"] != "2026-11-09T12:00:00Z" || m["to"] != "2026-11-10T12:00:00Z" {
			t.Fatalf("window: %v %v", m["from"], m["to"])
		}
		nodes := sub(m, "nodes")

		// gate types: instances, mode mix, decisions and lanes
		gt := nodes["gate_types"].([]any)
		if len(gt) != 3 {
			t.Fatalf("gate types: %v", gt)
		}
		gp := pick(t, gt, "type", "glidepath")
		if num(gp["instances"]) != 2 || num(gp["targets"]) != 3 || num(sub(gp, "mix")["enforce"]) != 2 || num(sub(gp, "mix")["silent"]) != 1 {
			t.Fatalf("glidepath: %v", gp)
		}
		// gate-api-cicd registered c-1 (holding), c-2, c-3: three requests, two decided (a clear and a deny), a refusal
		if l := sub(gp, "lanes"); num(l["requested"]) != 3 || num(l["tiered"]) != 3 || num(l["decided"]) != 2 || num(l["applied"]) != 1 {
			t.Fatalf("glidepath lanes: %v", l)
		}
		if num(gp["decisions"]) != 2 || num(gp["refused"]) != 1 || num(gp["holding"]) != 1 || gp["status"] != "attention" {
			t.Fatalf("glidepath: %v", gp)
		}
		ar := pick(t, gt, "type", "g-argo")
		if num(sub(ar, "mix")["flag"]) != 1 || num(ar["instances"]) != 1 || num(ar["exceptions"]) != 1 ||
			num(sub(ar, "coverage")["out-of-band-detected"]) != 1 || ar["status"] != "down" {
			t.Fatalf("g-argo: %v", ar)
		}
		if l := sub(ar, "lanes"); num(l["applied"]) != 1 || num(l["applied_matched"]) != 1 {
			t.Fatalf("g-argo lanes: %v", l)
		}
		tf := pick(t, gt, "type", "g-tf")
		if num(sub(tf, "mix")["silent"]) != 1 || num(tf["decisions"]) != 0 {
			t.Fatalf("g-tf: %v", tf)
		}

		// targets
		ts := nodes["targets"].([]any)
		if len(ts) != 5 {
			t.Fatalf("targets: %d", len(ts))
		}
		gaProd := pick(t, ts, "id", "gate-api-prod")
		cov := sub(gaProd, "coverage")
		if num(cov["authorized-and-verified"]) != 2 || num(cov["out-of-band-detected"]) != 1 || num(cov["unassessed"]) != 0 ||
			gaProd["verified_pct"].(json.Number).String() != "66.7" || gaProd["status"] != "down" {
			t.Fatalf("gate-api-prod coverage: %v", gaProd)
		}
		if l := sub(gaProd, "lanes"); num(l["requested"]) != 1 || num(l["observed"]) != 3 || num(l["verified"]) != 2 || num(gaProd["holding"]) != 1 {
			t.Fatalf("gate-api-prod lanes: %v %v", l, gaProd["holding"])
		}
		gates := gaProd["gates"].([]any)
		cicd, argo := gates[0].(map[string]any), gates[1].(map[string]any)
		if cicd["instance"] != "gate-api-cicd" || num(cicd["holding"]) != 1 || num(sub(cicd, "lanes")["requested"]) != 1 ||
			argo["mode"] != "flag" || num(argo["exceptions"]) != 1 || argo["attributed"] != true {
			t.Fatalf("gate refs: %v", gates)
		}
		if ob := gaProd["observers"].([]any)[0].(map[string]any); ob["state"] != "healthy" || ob["stale"] != false {
			t.Fatalf("observer: %v", ob)
		}
		flight := pick(t, ts, "id", "flight-api-prod")
		if l := sub(flight, "lanes"); num(l["requested"]) != 2 || num(l["decided"]) != 2 || num(l["applied"]) != 1 {
			t.Fatalf("flight lanes: %v", l)
		}
		if g := flight["gates"].([]any)[0].(map[string]any); num(g["decisions"]) != 2 || num(g["refused"]) != 1 {
			t.Fatalf("flight gate: %v", g)
		}
		acct := pick(t, ts, "id", "acct-prod")
		if ob := acct["observers"].([]any)[0].(map[string]any); ob["state"] != "blind" || ob["stale"] != true || acct["status"] != "down" {
			t.Fatalf("a stale feed is blind: %v", acct)
		}
		if g := acct["gates"].([]any)[0].(map[string]any); g["attributed"] != false || g["silent"] != true {
			t.Fatalf("acct gate: %v", g)
		}
		sandbox := pick(t, ts, "id", "sandbox-tools")
		if sandbox["status"] != "attention" || len(sandbox["gates"].([]any)) != 0 {
			t.Fatalf("sandbox: %v", sandbox)
		}
		dev := pick(t, ts, "id", "dev-ns")
		if ob := dev["observers"].([]any)[0].(map[string]any); ob["state"] != "blind" {
			t.Fatalf("a declared feed with no health record is blind: %v", ob)
		}

		// groups roll up their targets
		gs := nodes["groups"].([]any)
		if len(gs) != 4 {
			t.Fatalf("groups: %v", gs)
		}
		hp := pick(t, gs, "group", "hangar-prod")
		if num(hp["targets"]) != 2 || num(sub(hp, "coverage")["authorized-and-verified"]) != 2 || hp["status"] != "down" || num(hp["holding"]) != 1 {
			t.Fatalf("hangar-prod group counts its shared scope once: %v", hp)
		}
		if g := pick(t, gs, "group", "github"); num(g["no_gate"]) != 1 {
			t.Fatalf("github: %v", g)
		}
		obs := nodes["observers"].([]any)
		if o := pick(t, obs, "id", "observer:observe-aws/cloudtrail"); o["status"] != "down" || num(sub(o, "states")["blind"]) != 1 {
			t.Fatalf("observer node: %v", o)
		}

		// edges: a gate type to each group it guards, width = decisions, colour = worst state
		edges := m["edges"].([]any)
		var cicdEdge map[string]any
		for _, x := range edges {
			e := x.(map[string]any)
			if e["from"] == "gate:glidepath" && e["to"] == "group:hangar-prod" {
				cicdEdge = e
			}
			if strings.HasPrefix(e["to"].(string), "target:") {
				t.Fatalf("an unexpanded map has group edges only: %v", e)
			}
		}
		if cicdEdge == nil || num(cicdEdge["volume"]) != 2 || num(cicdEdge["refused"]) != 1 || cicdEdge["status"] != "down" || num(cicdEdge["targets"]) != 2 {
			t.Fatalf("edge: %v", cicdEdge)
		}
		w := pick(t, edges, "from", "observer:observe-aws/cloudtrail")
		if w["kind"] != "watches" || w["status"] != "down" {
			t.Fatalf("watches: %v", w)
		}

		// the needs-attention list
		at := kinds(m)
		if len(at["no-gate"]) != 1 || at["no-gate"][0]["targets"].([]any)[0] != "sandbox-tools" || at["no-gate"][0]["severity"] != "attention" {
			t.Fatalf("no-gate: %v", at["no-gate"])
		}
		if len(at["blind-observer"]) != 2 || at["blind-observer"][0]["severity"] != "down" {
			t.Fatalf("blind: %v", at["blind-observer"])
		}
		if f := at["flag-mode"]; len(f) != 1 || f[0]["gate_type"] != "g-argo" || num(f[0]["count"]) != 1 {
			t.Fatalf("flag: %v", f)
		}
		if h := at["holding"]; len(h) != 1 || num(h[0]["count"]) != 1 || !strings.Contains(h[0]["detail"].(string), "1 at tier 2") {
			t.Fatalf("holding: %v", h)
		}
		if s := at["gate-silent"]; len(s) != 2 { // ghost-gate and tf-gate
			t.Fatalf("silent: %v", s)
		}
		if u := at["undeclared-gate"]; len(u) != 1 || u[0]["instance"] != "mystery-gate" || num(u[0]["count"]) != 2 || u[0]["severity"] != "info" {
			t.Fatalf("undeclared: %v", u)
		}
		if first := m["attention"].([]any)[0].(map[string]any); first["severity"] != "down" {
			t.Fatalf("worst first: %v", first)
		}

		// what could not be derived is said, not faked
		var fields []string
		for _, p := range m["partial"].([]any) {
			fields = append(fields, p.(map[string]any)["field"].(string))
		}
		if got := strings.Join(fields, " "); !strings.Contains(got, "lanes.observed,lanes.verified") || !strings.Contains(got, "targets.attribution") ||
			!strings.Contains(got, "targets.coverage") {
			t.Fatalf("partial: %v", fields)
		}
		if m["truncated"] != false || num(sub(m, "registry")["targets"]) != 5 {
			t.Fatalf("registry: %v", m["registry"])
		}
	})
}

func TestMapExpandsAGroupAndNarrowsToATarget(t *testing.T) {
	mapEach(t, mapWorld(), func(t *testing.T, h *harness) {
		m := h.ok("/v1/map?expand=hangar-prod", "audit")
		var n int
		for _, x := range m["edges"].([]any) {
			if e := x.(map[string]any); strings.HasPrefix(e["to"].(string), "target:") {
				n++
			}
		}
		if n == 0 {
			t.Fatal("expand=hangar-prod added no target edges")
		}

		g := h.ok("/v1/map?group=hangar-prod", "audit")
		if len(sub(g, "nodes")["targets"].([]any)) != 2 || len(sub(g, "nodes")["groups"].([]any)) != 1 {
			t.Fatalf("group: %v", sub(g, "nodes"))
		}
		if len(kinds(g)["undeclared-gate"]) != 0 || len(kinds(g)["gate-silent"]) != 0 {
			t.Fatal("a narrowed view leaves the fleet-wide reconciliation out")
		}

		d := h.ok("/v1/map?target=gate-api-prod", "audit")
		if len(sub(d, "nodes")["targets"].([]any)) != 1 {
			t.Fatalf("one target: %v", sub(d, "nodes"))
		}
		det := sub(d, "target")
		ch := det["changes"].([]any)
		if len(ch) != 1 || ch[0].(map[string]any)["id"] != "c-1" || ch[0].(map[string]any)["state"] != "holding" || num(ch[0].(map[string]any)["tier"]) != 2 ||
			num(ch[0].(map[string]any)["age_seconds"]) != 3*3600 {
			t.Fatalf("changes moving: %v", ch)
		}
		if ex := det["exceptions"].([]any); len(ex) != 1 || ex[0].(map[string]any)["tool"] != "deploy.exception" {
			t.Fatalf("exceptions: %v", det["exceptions"])
		}
		if ev := det["evidence"].([]any); len(ev) != 2 || ev[0].(map[string]any)["tool"] != "deploy.exception" { // newest first; the window's request and the exception
			t.Fatalf("evidence: %v", det["evidence"])
		}
		var toTarget int
		for _, x := range d["edges"].([]any) {
			if strings.HasPrefix(x.(map[string]any)["to"].(string), "target:") {
				toTarget++
			}
		}
		if toTarget == 0 {
			t.Fatal("the one-target detail has edges to the target itself")
		}
		h.status(t, 404, "GET", "/v1/map?target=nope", "audit", "")
		// a target that declares no app has no changes to list: said, not empty-and-silent
		nd := h.ok("/v1/map?target=acct-prod", "audit")
		if len(sub(nd, "target")["changes"].([]any)) != 0 || !strings.Contains(fmt.Sprint(nd["partial"]), "target.changes") {
			t.Fatalf("acct-prod detail: %v", nd["partial"])
		}
	})
}

func TestMapWindowAndParameters(t *testing.T) {
	mapEach(t, mapWorld(), func(t *testing.T, h *harness) {
		// a window before the activity: the declared gates are all silent, the old request is the only record
		old := h.ok("/v1/map?from="+url.QueryEscape("2026-11-08T00:00:00Z")+"&to="+url.QueryEscape("2026-11-09T00:00:00Z"), "audit")
		gp := pick(t, sub(old, "nodes")["gate_types"], "type", "glidepath")
		if num(sub(gp, "lanes")["requested"]) != 1 || num(gp["decisions"]) != 0 {
			t.Fatalf("old window: %v", gp)
		}
		h.status(t, 400, "GET", "/v1/map?from=yesterday", "audit", "")
		h.status(t, 400, "GET", "/v1/map?from="+url.QueryEscape("2026-11-10T12:00:00Z"), "audit", "")
		h.status(t, 400, "GET", "/v1/map?from="+url.QueryEscape("2026-01-01T00:00:00Z"), "audit", "")
		h.status(t, 400, "GET", "/v1/map?scope=x", "audit", "")
		h.status(t, 401, "GET", "/v1/map", "", "")
		h.status(t, 403, "GET", "/v1/map", "sync", "")
	})
}

// A person reads the observation facts whole (coverage, health) and the gate records they may see, as every read.
func TestMapScopesTheGateRecordsToWhatThePersonMaySee(t *testing.T) {
	mapEach(t, mapWorld(), func(t *testing.T, h *harness) {
		m := h.ok("/v1/map", "carol") // owns flight-api
		nodes := sub(m, "nodes")
		gaProd := pick(t, nodes["targets"], "id", "gate-api-prod")
		if num(sub(gaProd, "coverage")["authorized-and-verified"]) != 2 {
			t.Fatalf("coverage is the whole scope's: %v", gaProd["coverage"])
		}
		if num(sub(gaProd, "lanes")["requested"]) != 0 || num(gaProd["holding"]) != 0 {
			t.Fatalf("carol does not own gate-api: %v", gaProd)
		}
		flight := pick(t, nodes["targets"], "id", "flight-api-prod")
		if num(sub(flight, "lanes")["requested"]) != 2 {
			t.Fatalf("carol owns flight-api: %v", flight)
		}
		// an unrelated person sees no changes or decisions, but every exception, as /v1/exceptions says (O-5)
		m = h.ok("/v1/map?target=gate-api-prod", "sam")
		if d := sub(m, "target"); len(d["changes"].([]any)) != 0 || len(d["evidence"].([]any)) != 0 || len(d["exceptions"].([]any)) != 1 {
			t.Fatalf("sam: %v", d)
		}
	})
}

func TestMapOfAnEmptyRegistryIsEmptyNotAnError(t *testing.T) {
	mapEach(t, world{events: fixtureEvents()}, func(t *testing.T, h *harness) {
		m := h.ok("/v1/map", "audit")
		if len(sub(m, "nodes")["targets"].([]any)) != 0 || len(m["edges"].([]any)) != 0 || len(m["partial"].([]any)) != 0 {
			t.Fatalf("empty: %v", m)
		}
		if got := h.ok("/v1/targets", "audit"); len(got["items"].([]any)) != 0 {
			t.Fatalf("targets: %v", got)
		}
	})
}

func countOf(m map[string]any, key string) int64 {
	for _, x := range m["items"].([]any) {
		c := x.(map[string]any)
		if (c["key"] == nil && key == "") || c["key"] == key {
			return num(c["count"])
		}
	}
	return -1
}

func TestCountsByProviderScopeAndBucket(t *testing.T) {
	mapEach(t, mapWorld(), func(t *testing.T, h *harness) {
		p := h.ok("/v1/evidence/counts?by=provider&outcomes=include", "audit")
		if countOf(p, "argo-gate") != 2 || countOf(p, "mystery-gate") != 2 || countOf(p, "observe-k8s") != 2 || countOf(p, "clearance") < 10 {
			t.Fatalf("by provider: %v", p)
		}
		b := h.ok("/v1/evidence/counts?by=boundary&outcomes=include&since=2026-11-10T00:00:00Z", "audit")
		if countOf(b, "runtime") != 2 || countOf(b, "deployment") < 10 {
			t.Fatalf("by boundary: %v", b)
		}
		sc := h.ok("/v1/evidence/counts?by=coverage&scope=hangar-prod&outcomes=include", "carol") // a person reads a scope whole
		if countOf(sc, "authorized-and-verified") != 3 || countOf(sc, "observed-not-attributed") != 3 || countOf(sc, "out-of-band-detected") != 1 || sc["total"] != json.Number("7") {
			t.Fatalf("by coverage in a scope: %v", sc)
		}
		if n := countOf(h.ok("/v1/evidence/counts?by=coverage&outcomes=include", "carol"), "observed-not-attributed"); n != -1 {
			t.Fatalf("without the scope a person sees only their own records, not the observations: %d", n)
		}

		bk := h.ok("/v1/evidence/counts?by=tool&bucket=1h&since=2026-11-10T09:00:00Z&until=2026-11-10T11:00:00Z", "audit")
		if bk["bucket"] != "1h" {
			t.Fatalf("bucket: %v", bk)
		}
		got := map[string]int64{}
		var prev string
		for _, x := range bk["items"].([]any) {
			c := x.(map[string]any)
			at := c["bucket"].(string)
			if at < prev {
				t.Fatalf("buckets are in time order: %v", bk["items"])
			}
			prev = at
			got[at+" "+c["key"].(string)] = num(c["count"])
		}
		want := map[string]int64{"2026-11-10T09:00:00Z deploy.request": 3, "2026-11-10T09:00:00Z deploy.clear": 1, "2026-11-10T09:00:00Z deploy.deny": 1,
			"2026-11-10T09:00:00Z deploy.outcome": 1, "2026-11-10T09:00:00Z deploy.exception": 1,
			"2026-11-10T10:00:00Z observation": 3, "2026-11-10T10:00:00Z assessment": 3, "2026-11-10T10:00:00Z github.pr.open": 2}
		for k, n := range want {
			if got[k] != n {
				t.Errorf("bucket %s: %d, want %d (all: %v)", k, got[k], n, got)
			}
		}
		h5 := h.ok("/v1/evidence/counts?by=provider&bucket=5m&since=2026-11-10T10:30:00Z&until=2026-11-10T10:40:00Z", "audit")
		if its := h5["items"].([]any); len(its) != 1 || its[0].(map[string]any)["bucket"] != "2026-11-10T10:30:00Z" || countOf(h5, "mystery-gate") != 2 {
			t.Fatalf("5m: %v", h5["items"])
		}
		for _, bad := range []string{"bucket=2m&since=2026-11-10T00:00:00Z", "bucket=1h", "bucket=1m&since=2026-01-01T00:00:00Z&until=2026-11-01T00:00:00Z",
			"bucket=1h&since=2026-11-10T00:00:00Z&until=2026-11-09T00:00:00Z", "scope=has%20space", "by=cost&bucket=1h&since=2026-11-10T00:00:00Z"} {
			h.status(t, 400, "GET", "/v1/evidence/counts?"+bad, "audit", "")
		}
	})
}
