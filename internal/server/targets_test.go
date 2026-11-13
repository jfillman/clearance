package server_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/targets"
)

const (
	tgtProd = "hangar-prod/gitops/targets"
	tgtDev  = "hangar-dev/gitops/targets"
)

func target(id string, edit func(map[string]any)) map[string]any {
	t := map[string]any{"id": id, "name": id, "kind": "k8s-namespace", "group": "hangar-prod", "env": "prod", "app": "gate-api",
		"owner": "group:default/team-gate", "registry": "flight", "scope": "hangar-prod",
		"gates":     []any{map[string]any{"type": "glidepath", "instance": "gate-api-cicd", "mode": "enforce"}},
		"observers": []any{map[string]any{"provider": "observe-k8s", "source": "observe-k8s"}}}
	if edit != nil {
		edit(t)
	}
	return t
}

func targetsBody(ts ...any) map[string]any { return map[string]any{"targets": append([]any{}, ts...)} }

func targetRecords(f *fixture) []map[string]any {
	var out []map[string]any
	for _, r := range f.records() {
		if r["tool"] == "targets.load" {
			out = append(out, r)
		}
	}
	return out
}

func TestPublishedTargetsAreRecordedOncePerChange(t *testing.T) {
	publishedTargets(t, memFixture(t))
}

func TestPublishedTargetsAreRecordedOncePerChangeOnPostgres(t *testing.T) {
	publishedTargets(t, newFixture(t, config(t, pgDSN(t))))
}

func publishedTargets(t *testing.T, f *fixture) {
	body := targetsBody(target("gate-api-prod", nil), target("flight-api-prod", func(m map[string]any) { m["app"] = "flight-api" }))
	a := f.do("PUT", "/v1/targets/hangar-prod", tgtProd, body).want(t, 200, "")
	digest, _ := a.body["digest"].(string)
	if a.body["changed"] != true || a.body["targets"] != float64(2) || len(digest) != 64 || a.body["source"] != "hangar-prod" {
		t.Fatalf("first publish: %v", a.body)
	}
	recs := targetRecords(f)
	if len(recs) != 1 || recs[0]["decision"] != "allow" || recs[0]["target"] != "targets:hangar-prod" ||
		!strings.Contains(fmt.Sprint(recs[0]["result"]), digest) || recs[0]["args_sha256"] != digest {
		t.Fatalf("targets.load: %v", recs)
	}
	if fmt.Sprint(a.body["seq"]) != fmt.Sprint(recs[0]["seq"]) {
		t.Fatalf("seq %v, record %v", a.body["seq"], recs[0]["seq"])
	}

	// the same set again, in another order: content-addressed, so nothing changes and nothing is recorded
	again := f.do("PUT", "/v1/targets/hangar-prod", tgtProd, targetsBody(body["targets"].([]any)[1], body["targets"].([]any)[0])).want(t, 200, "")
	if again.body["changed"] != false || again.body["digest"] != digest || again.body["seq"] != nil || len(targetRecords(f)) != 1 {
		t.Fatalf("republish: %v", again.body)
	}

	// a change is a new record naming the old digest
	changed := f.do("PUT", "/v1/targets/hangar-prod", tgtProd, targetsBody(target("gate-api-prod", func(m map[string]any) { m["env"] = "staging" }))).want(t, 200, "")
	if changed.body["changed"] != true || changed.body["digest"] == digest || len(targetRecords(f)) != 2 ||
		!strings.Contains(fmt.Sprint(targetRecords(f)[1]["result"]), "was sha256:"+digest) {
		t.Fatalf("changed: %v %v", changed.body, targetRecords(f))
	}
	// an empty list withdraws the source
	f.do("PUT", "/v1/targets/hangar-prod", tgtProd, targetsBody()).want(t, 200, "")
	if len(targetRecords(f)) != 3 {
		t.Fatal("a withdrawal is a change")
	}
	got, err := f.core.Store.Targets(context.Background())
	if err != nil || len(got) != 1 || got[0].Source != "hangar-prod" || string(got[0].Doc) != "[]" {
		t.Fatalf("stored: %v %v", got, err)
	}
}

func TestTargetsAreReplacedPerSourceOnly(t *testing.T) {
	f := memFixture(t)
	f.do("PUT", "/v1/targets/hangar-prod", tgtProd, targetsBody(target("a", nil))).want(t, 200, "")
	f.do("PUT", "/v1/targets/hangar-dev", tgtDev, targetsBody(target("b", func(m map[string]any) { m["group"] = "hangar-dev" }))).want(t, 200, "")
	f.do("PUT", "/v1/targets/hangar-prod", tgtProd, targetsBody(target("c", nil))).want(t, 200, "")
	got, _ := f.core.Store.Targets(context.Background())
	if len(got) != 2 || !strings.Contains(string(got[0].Doc), `"id":"b"`) && !strings.Contains(string(got[1].Doc), `"id":"b"`) {
		t.Fatalf("stored: %v", got)
	}
	for _, g := range got {
		if g.Source == "hangar-prod" && (!strings.Contains(string(g.Doc), `"id":"c"`) || strings.Contains(string(g.Doc), `"id":"a"`)) {
			t.Fatalf("hangar-prod was not replaced: %s", g.Doc)
		}
	}
}

func TestPublishingTargetsIsRefused(t *testing.T) {
	f := memFixture(t)
	good := func() map[string]any { return targetsBody(target("a", nil)) }
	with := func(edit func(m map[string]any)) map[string]any { m := target("a", edit); return targetsBody(m) }
	f.do("PUT", "/v1/targets/hangar-prod", "", good()).want(t, 401, "")
	f.do("PUT", "/v1/targets/hangar-prod", "someone/else", good()).want(t, 403, "not a registered provider")
	f.do("PUT", "/v1/targets/hangar-prod", argo, good()).want(t, 403, "may not publish targets")
	f.do("PUT", "/v1/targets/hangar-dev", tgtProd, good()).want(t, 403, "may not publish targets")
	f.do("PUT", "/v1/targets/hangar-shared", tgtDev, good()).want(t, 403, "belongs to provider")
	f.do("PUT", "/v1/targets/hangar-shared", tgtProd, good()).want(t, 200, "")
	f.do("PUT", "/v1/targets/Hangar_Prod", tgtProd, good()).want(t, 400, "source is")
	f.do("PUT", "/v1/targets/hangar-prod", tgtProd, `{"targets": [], "extra": 1}`).want(t, 400, "unknown field")
	f.do("PUT", "/v1/targets/hangar-prod", tgtProd, `{}`).want(t, 400, "targets is required")
	f.do("PUT", "/v1/targets/hangar-prod", tgtProd, good()).want(t, 200, "")
	bad := map[string]func(m map[string]any){
		"id":        func(m map[string]any) { m["id"] = "Not An ID" },
		"kind":      func(m map[string]any) { m["kind"] = "vm" },
		"registry":  func(m map[string]any) { m["registry"] = "Not A Tier" },
		"scope":     func(m map[string]any) { m["scope"] = "has space" },
		"name":      func(m map[string]any) { m["name"] = "" },
		"group":     func(m map[string]any) { delete(m, "group") },
		"gates":     func(m map[string]any) { delete(m, "gates") },
		"observers": func(m map[string]any) { m["observers"] = nil },
		"mode": func(m map[string]any) {
			m["gates"] = []any{map[string]any{"type": "glidepath", "instance": "x", "mode": "warn"}}
		},
		"type": func(m map[string]any) {
			m["gates"] = []any{map[string]any{"type": "Bad", "instance": "x", "mode": "flag"}}
		},
		"twice": func(m map[string]any) {
			g := map[string]any{"type": "glidepath", "instance": "x", "mode": "flag"}
			m["gates"] = []any{g, g}
		},
		"source": func(m map[string]any) {
			m["observers"] = []any{map[string]any{"provider": "p", "source": "Bad Source"}}
		},
		"extra": func(m map[string]any) { m["colour"] = "red" },
	}
	for field, edit := range bad {
		f.do("PUT", "/v1/targets/hangar-prod", tgtProd, with(edit)).want(t, 400, "")
		_ = field
	}
	f.do("PUT", "/v1/targets/hangar-prod", tgtProd, targetsBody(target("a", nil), target("a", nil))).want(t, 400, "listed twice")
	// the caps
	many := make([]any, targets.MaxTargets+1)
	for i := range many {
		many[i] = target(fmt.Sprintf("t-%d", i), nil)
	}
	f.do("PUT", "/v1/targets/hangar-prod", tgtProd, targetsBody(many...)).want(t, 400, "at most")
	gates := make([]any, 33)
	for i := range gates {
		gates[i] = map[string]any{"type": "glidepath", "instance": fmt.Sprint("i", i), "mode": "enforce"}
	}
	f.do("PUT", "/v1/targets/hangar-prod", tgtProd, with(func(m map[string]any) { m["gates"] = gates })).want(t, 400, "at most 32 gates")
	if n := len(targetRecords(f)); n != 2 {
		t.Fatalf("refused publishes recorded %d targets.load records, want the 2 accepted", n)
	}
}

func TestProvidersTargetsAreChecked(t *testing.T) {
	for _, bad := range []string{`[{"name":"x","version":"1","principals":["a/b"],"targets":[""]}]`} {
		if _, err := server.ParseProviders(bad); err == nil {
			t.Fatalf("%s was accepted", bad)
		}
	}
}
