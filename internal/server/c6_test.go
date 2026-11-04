package server_test

// C-6 through the whole core over HTTP: break-glass recorded before the change it covers, a provider's exception
// and degraded-mode report acting on the change they name, and the open windows a provider reads.

import (
	"strings"
	"testing"
	"time"
)

func degraded(decision string, changeID string) map[string]any {
	now := time.Now().UTC()
	rec := map[string]any{"principal": argo, "target": "gate-api-prod", "app": "gate-api",
		"result": "synced on the outage policy", "decision": decision, "coverage": "coverage-unavailable",
		"outage": map[string]any{"from": now.Add(-20 * time.Minute).Format(time.RFC3339),
			"to": now.Add(-time.Minute).Format(time.RFC3339)},
		"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}}
	if changeID != "" {
		rec["change"] = map[string]any{"id": changeID}
	}
	return map[string]any{"provider": "argo-gate", "kind": "deploy.degraded", "record": rec}
}

func outOfBand() map[string]any {
	return map[string]any{"provider": "argo-gate", "kind": "deploy.exception", "record": map[string]any{
		"principal": "kubernetes-admin", "target": "apps/v1/Deployment/app-gate-api-prod/gate-api",
		"result": "applied without a grant", "app": "gate-api",
		"exception": map[string]any{"kind": "out-of-band", "objects": []any{map[string]any{"apiVersion": "apps/v1",
			"kind": "Deployment", "namespace": "app-gate-api-prod", "name": "gate-api"}}},
		"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}}}
}

func registration(head string) map[string]any {
	return map[string]any{"app": "gate-api", "env": "prod", "cluster": "hangar-prod", "repo": "jfillman/gitops-gate-api",
		"pr": 7, "head": head, "base": strings.Repeat("b", 40), "proposer": "user:dana", "proposerKind": "person",
		"owner": owner, "treeDigest": strings.Repeat("c", 64), "paths": []any{"hangar-prod/prod/release.yaml"},
		"objects": []any{map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "app-gate-api-prod",
			"name": "gate-api", "op": "changed", "fields": []any{"/spec/replicas"}}},
		"checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok"}}
}

func TestBreakGlassAndReportsThroughTheCore(t *testing.T) {
	f := memFixture(t)
	held := f.do("POST", "/v1/clearances", ci, registration(headSHA)).want(t, 200, "")
	id := held.body["id"].(string)
	if held.body["state"] != "holding" || held.body["outage"] != "hold" {
		t.Fatal(held.body)
	}
	off := registration(strings.Repeat("e", 40))
	off["protected"] = false
	if r := f.do("POST", "/v1/clearances", ci, off).want(t, 400, ""); r.body["rule"] != "DG-PROTECTED" {
		t.Fatal(r.body)
	}

	glass := map[string]any{"reason": "prod is down", "ttl": "45m", "cluster": "hangar-prod", "env": "prod"}
	f.do("POST", "/v1/breakglass", "user:dana", glass).want(t, 403, "not a Clearance admin")
	g := f.do("POST", "/v1/breakglass", "user:admin", glass).want(t, 200, "")
	bgID := g.body["id"].(string)

	f.do("GET", "/v1/breakglass", "user:dana", nil).want(t, 403, "")
	f.do("GET", "/v1/breakglass?colour=red", argo, nil).want(t, 400, "")
	open := f.do("GET", "/v1/breakglass?cluster=hangar-prod", argo, nil).want(t, 200, "")
	if items := open.body["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != bgID {
		t.Fatal(open.body)
	}
	if items := f.do("GET", "/v1/breakglass?cluster=elsewhere", "user:admin", nil).want(t, 200, "").body["items"].([]any); len(items) != 0 {
		t.Fatal(items)
	}

	ex := f.do("POST", "/v1/records", argo, outOfBand()).want(t, 200, "")
	recs := f.records()
	last := recs[len(recs)-1]
	if last["breakglass"] != bgID || last["coverage"] != "out-of-band-detected" || last["hash"] != ex.body["hash"] {
		t.Fatal(last)
	}
	var openSeq, exSeq any
	for _, r := range recs {
		switch r["tool"] {
		case "breakglass.open":
			openSeq = r["seq"]
		case "deploy.exception":
			exSeq = r["seq"]
		}
	}
	if openSeq == nil || exSeq == nil || !(asInt(openSeq) < asInt(exSeq)) {
		t.Fatalf("break-glass %v is not recorded before the change %v", openSeq, exSeq)
	}

	f.do("POST", "/v1/records", argo, degraded("allow", id)).want(t, 200, "")
	c := f.do("GET", "/v1/clearances/"+id, argo, nil).want(t, 200, "")
	if c.body["state"] != "degraded" || c.body["token"] != nil {
		t.Fatal(c.body)
	}
	recs = f.records()
	op := recs[len(recs)-1]["outage_policy"].(map[string]any)
	if op["action"] != "hold" || op["source"] != "change" || op["conforms"] != false {
		t.Fatal(op)
	}
	// shape refusals come back as 400 with the gate's message
	bad := degraded("allow", "")
	bad["record"].(map[string]any)["coverage"] = "authorized-and-verified"
	f.do("POST", "/v1/records", argo, bad).want(t, 400, "coverage-unavailable")
	bad = outOfBand()
	bad["record"].(map[string]any)["outage"] = map[string]any{"from": "x"}
	f.do("POST", "/v1/records", argo, bad).want(t, 400, "outage")
	bad = outOfBand()
	delete(bad["record"].(map[string]any), "exception")
	f.do("POST", "/v1/records", argo, bad).want(t, 400, "exception")

	closed := f.do("POST", "/v1/breakglass/"+bgID+"/close", "user:admin", nil).want(t, 200, "")
	if closed.body["state"] != "closed" || asInt(closed.body["reported"]) != 2 {
		t.Fatal(closed.body)
	}
}

func asInt(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case interface{ Int64() (int64, error) }:
		n, _ := x.Int64()
		return n
	}
	return -1
}
