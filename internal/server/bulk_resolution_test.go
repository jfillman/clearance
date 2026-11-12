package server_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/vocab"
)

// Bulk resolution: one record per item with a shared batch id; skips are reported; admin only; capped at 200.
func TestBulkResolutionWritesOneRecordPerItem(t *testing.T) {
	f := memFixture(t)
	postExc := func(rec map[string]any) int64 {
		t.Helper()
		f.do("POST", "/v1/records", argo, map[string]any{"provider": "argo-gate", "kind": "deploy.exception", "record": rec}).want(t, 200, "")
		recs := f.records()
		return seqOfRec(recs[len(recs)-1])
	}
	oob := outOfBand()["record"].(map[string]any)
	a, b, c := postExc(oob), postExc(oob), postExc(oob)
	refused := postExc(map[string]any{"principal": "dana", "target": "t", "result": "refused", "app": "gate-api",
		"exception": map[string]any{"kind": "attempted-refused", "actor": "dana", "detail": "refused by policy"}, "destination": oob["destination"]})
	const path = "/v1/observations/resolutions"
	body := func(items []int64, extra map[string]any) map[string]any {
		m := map[string]any{"items": items, "state": "ratified", "note": "[bulk] reviewed"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// who may, and what is refused for the whole call: nothing is written.
	f.do("POST", path, "user:dana", body([]int64{a}, nil)).want(t, 403, "not a Clearance admin")
	f.do("POST", path, gw, body([]int64{a}, nil)).want(t, 403, "")
	f.do("POST", path, "", body([]int64{a}, nil)).want(t, 401, "")
	f.do("POST", path, "user:admin", body([]int64{}, nil)).want(t, 400, "items")
	f.do("POST", path, "user:admin", map[string]any{"state": "ratified"}).want(t, 400, "items")
	f.do("POST", path, "user:admin", body([]int64{a}, map[string]any{"state": "reverted", "note": nil})).want(t, 400, "cause")
	f.do("POST", path, "user:admin", body([]int64{a}, map[string]any{"state": "reverted", "cause": "bad-luck"})).want(t, 400, "cause")
	f.do("POST", path, "user:admin", body([]int64{a}, map[string]any{"state": "fixed"})).want(t, 400, "state")
	f.do("POST", path, "user:admin", body([]int64{a}, map[string]any{"cause": "human-initiated"})).want(t, 400, "cause")
	f.do("POST", path, "user:admin", body([]int64{a}, map[string]any{"by": "user:someone-else"})).want(t, 400, "")
	over := make([]int64, 201)
	for i := range over {
		over[i] = a
	}
	f.do("POST", path, "user:admin", body(over, nil)).want(t, 400, "at most 200")
	exactly := make([]int64, 200)
	for i := range exactly {
		exactly[i] = a + 100000 // none exists: all skipped, none written, the cap is inclusive
	}
	if r := f.do("POST", path, "user:admin", body(exactly, nil)).want(t, 200, ""); len(r.body["skipped"].([]any)) != 200 {
		t.Fatalf("200 items are accepted and each skipped: %v", r.body)
	}
	if n := countTool(f, "resolution"); n != 0 {
		t.Fatalf("refused calls wrote %d resolution records", n)
	}

	// the batch: a, b recorded; the refused exception, an unknown seq and a repeat are skipped with reasons.
	r := f.do("POST", path, "user:admin", body([]int64{a, b, refused, a + 100000, a}, nil)).want(t, 200, "")
	batch, _ := r.body["batch"].(string)
	rec, _ := r.body["recorded"].([]any)
	skipped, _ := r.body["skipped"].([]any)
	if batch == "" || len(rec) != 2 || len(skipped) != 3 || len(r.body["failed"].([]any)) != 0 || r.body["by"] != "user:admin" {
		t.Fatalf("answer: %v", r.body)
	}
	reasons := map[float64]string{}
	for _, s := range skipped {
		m := s.(map[string]any)
		reasons[m["seq"].(float64)], _ = m["reason"].(string)
	}
	if !strings.Contains(reasons[float64(refused)], "attempted-refused") || reasons[float64(a+100000)] == "" {
		t.Fatalf("skip reasons: %v", reasons)
	}
	var rs []store.Record
	for _, x := range f.records() {
		if x["tool"] == "resolution" {
			rs = append(rs, x)
		}
	}
	if len(rs) != 2 {
		t.Fatalf("%d resolution records, want one per recorded item", len(rs))
	}
	ids := map[float64]bool{}
	for i, x := range rs {
		res := x["resolution"].(map[string]any)
		bt := res["batch"].(map[string]any)
		if bt["id"] != batch || num(bt["size"]) != 2 || res["by"] != "user:admin" || res["state"] != "ratified" || res["note"] != "[bulk] reviewed" ||
			x["principal"] != "user:admin" || x["initiator"].(map[string]any)["sub"] != "user:admin" || x["scope"] != "hangar-prod" {
			t.Fatalf("record %d does not name the person and the batch: %v", i, x)
		}
		ids[num(x["about"].(map[string]any)["seq"])] = true
		if rec[i].(map[string]any)["record_seq"] != float64(seqOfRec(x)) || rec[i].(map[string]any)["seq"] != num(x["about"].(map[string]any)["seq"]) {
			t.Fatalf("recorded[%d] = %v does not point at record %d", i, rec[i], seqOfRec(x))
		}
	}
	if !ids[float64(a)] || !ids[float64(b)] || len(ids) != 2 {
		t.Fatalf("one record per item: %v", ids)
	}

	// the same call again: a and b already say the same, so they are skipped; c is recorded in a batch of 1.
	r = f.do("POST", path, "user:admin", body([]int64{a, b, c}, nil)).want(t, 200, "")
	if rec := r.body["recorded"].([]any); len(rec) != 1 || rec[0].(map[string]any)["seq"] != float64(c) || len(r.body["skipped"].([]any)) != 2 {
		t.Fatalf("same-as-newest is skipped: %v", r.body)
	}
	// a different note on a is a new record (an edit), batch size 1.
	r = f.do("POST", path, "user:admin", body([]int64{a, b}, map[string]any{"note": "[bulk] a different note"})).want(t, 200, "")
	if len(r.body["recorded"].([]any)) != 2 {
		t.Fatalf("a different note is an edit: %v", r.body)
	}
	if n := countTool(f, "resolution"); n != 5 {
		t.Fatalf("%d resolution records, want 5 (2 + 1 + 2)", n)
	}

	// reverted with a cause works, and a delegate naming the admin records the person, not the delegate.
	req, _ := http.NewRequest("POST", f.srv.URL+path, strings.NewReader(`{"items": [`+strconv.FormatInt(a, 10)+`,`+strconv.FormatInt(b, 10)+`], "state": "reverted", "cause": "human-initiated"}`))
	req.Header.Set("Authorization", "Bearer "+tower)
	req.Header.Set(vocab.Get().OnBehalfOfHeader, "user:admin")
	d := f.send(req).want(t, 200, "")
	if d.body["by"] != "user:admin" || d.body["via"] != tower || len(d.body["recorded"].([]any)) != 2 {
		t.Fatalf("a delegate's answer names the person and the delegate: %v", d.body)
	}
	last := f.records()
	lr := last[len(last)-1]
	if lr["tool"] != "resolution" || lr["initiator"].(map[string]any)["iss"] != "delegate:"+tower || containsAny(lr["verified"].([]any), "initiator") ||
		lr["resolution"].(map[string]any)["by"] != "user:admin" {
		t.Fatalf("a delegate's record names the person and does not claim they signed in: %v", lr)
	}
	// a delegate naming a non-admin is refused.
	req, _ = http.NewRequest("POST", f.srv.URL+path, strings.NewReader(`{"items": [`+strconv.FormatInt(a, 10)+`], "state": "ratified"}`))
	req.Header.Set("Authorization", "Bearer "+tower)
	req.Header.Set(vocab.Get().OnBehalfOfHeader, "user:dana")
	f.send(req).want(t, 403, "not a Clearance admin")
}

// num reads a number out of a stored record (json.Number) or a decoded answer (float64).
func num(v any) float64 {
	switch n := v.(type) {
	case json.Number:
		f, _ := n.Float64()
		return f
	case float64:
		return n
	}
	return -1
}
