package packet_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/store"
)

func kubeObservation(ts, scope, ns, name string) store.Event {
	return store.Event{"ts": ts, "tool": "observation", "boundary": "deployment", "coverage": "observed-not-attributed", "scope": scope,
		"source":   map[string]any{"name": "k8s-audit-webhook", "event_id": "a-" + ts + name, "level": "RequestResponse"},
		"resource": map[string]any{"kind": "Deployment", "name": name, "namespace": ns}, "actor": map[string]any{"subject": "dana@example.com"},
		"action": map[string]any{"verb": "patch", "api": "patch.deployments", "succeeded": true}, "principal": nil, "agent": nil, "decision": "allow",
		"args_sha256": hexOf('0'), "result": "observed"}
}

func gateException(ts, cluster string, objs ...map[string]any) store.Event {
	l := make([]any, len(objs))
	for i, o := range objs {
		l[i] = o
	}
	return gate(ts, "deploy.exception", "gate-api", "prod", map[string]any{"coverage": "out-of-band-detected", "principal": "field manager kubectl-client-side-apply",
		"destination": map[string]any{"cluster": cluster, "environment": "prod"},
		"exception":   map[string]any{"kind": "out-of-band", "objects": l, "detail": "the object carries no clearance.hangar.io/rendered annotation"}})
}

func dep(ns, name string) map[string]any {
	return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "namespace": ns, "name": name}
}

func healthFor(ts, scope string) store.Event {
	h := health(ts, scope, "healthy", 5184000)
	h["source"] = map[string]any{"name": "k8s-audit-webhook"}
	return h
}

func exceptionRows(t *testing.T, st store.Reader) []packet.Exception {
	t.Helper()
	q := packet.Params{From: mustTime(t, winFrom), To: mustTime(t, winTo), Now: mustTime(t, nowAt), Version: "test", Scopes: []string{"hangar-prod"}}
	res, err := packet.Build(bg, st, q)
	if err != nil {
		t.Fatal(err)
	}
	return res.Packet.Exceptions.Rows
}

type packetChain struct {
	store.Reader
	Store store.Reader
}

// One kubectl apply, reported by the audit collector (who and what) and by the Argo CD agent's scan (what is there
// that no grant covers), is one exception row, whichever arrived first. Rows that are not the same object stay two.
func TestReconcilerAndCollectorReportOneException(t *testing.T) {
	const scope = "hangar-prod"
	withAssessment := func(ts, name string) (store.Event, func(seq int64) store.Event) {
		return kubeObservation(ts, scope, "gate-api", name), func(seq int64) store.Event {
			return assessment(ts, scope, seq, "out-of-band-detected", nil)
		}
	}
	build := func(order string) []packet.Exception {
		l := []store.Event{healthFor("2026-10-09T00:00:00Z", scope)}
		o, as := withAssessment("2026-11-02T10:00:10Z", "gate-api")
		gx := gateException("2026-11-02T10:00:50Z", scope, dep("gate-api", "gate-api"))
		st := miniChain(t, l...)
		lb := &labber{t: t, st: st}
		switch order {
		case "collector first":
			rec := lb.add(obsW, o)
			lb.add(obsW, as(seqI(rec)))
			lb.add(argoW, gx)
		case "reconciler first":
			lb.add(argoW, gateException("2026-11-02T10:00:05Z", scope, dep("gate-api", "gate-api")))
			rec := lb.add(obsW, o)
			lb.add(obsW, as(seqI(rec)))
		}
		return exceptionRows(t, st)
	}
	for _, order := range []string{"collector first", "reconciler first"} {
		t.Run(order, func(t *testing.T) {
			rows := build(order)
			if len(rows) != 1 {
				t.Fatalf("%d exception rows, want 1: %+v", len(rows), rows)
			}
			r := rows[0]
			if r.Source != "observation" || r.Actor != "dana@example.com" || !strings.Contains(r.Diff, "patch.deployments") ||
				len(r.AlsoSeq) != 1 || !strings.Contains(r.Detail, "also reported by the gate's agent") {
				t.Fatalf("the folded row keeps the collector's actor and diff and names the other reporter: %+v", r)
			}
		})
	}

	t.Run("different objects stay two", func(t *testing.T) {
		st := miniChain(t, healthFor("2026-10-09T00:00:00Z", scope))
		lb := &labber{t: t, st: st}
		rec := lb.add(obsW, kubeObservation("2026-11-02T10:00:10Z", scope, "gate-api", "gate-api"))
		lb.add(obsW, assessment("2026-11-02T10:00:10Z", scope, seqI(rec), "out-of-band-detected", nil))
		lb.add(argoW, gateException("2026-11-02T10:00:50Z", scope, dep("gate-api", "other")))
		if rows := exceptionRows(t, st); len(rows) != 2 {
			t.Fatalf("%d rows, want 2", len(rows))
		}
	})
	t.Run("the same object a day later is another change", func(t *testing.T) {
		st := miniChain(t, healthFor("2026-10-09T00:00:00Z", scope))
		lb := &labber{t: t, st: st}
		rec := lb.add(obsW, kubeObservation("2026-11-02T10:00:10Z", scope, "gate-api", "gate-api"))
		lb.add(obsW, assessment("2026-11-02T10:00:10Z", scope, seqI(rec), "out-of-band-detected", nil))
		lb.add(argoW, gateException("2026-11-03T10:00:50Z", scope, dep("gate-api", "gate-api")))
		if rows := exceptionRows(t, st); len(rows) != 2 {
			t.Fatalf("%d rows, want 2", len(rows))
		}
	})
	t.Run("another cluster's exception is not the same object", func(t *testing.T) {
		st := miniChain(t, healthFor("2026-10-09T00:00:00Z", scope))
		lb := &labber{t: t, st: st}
		rec := lb.add(obsW, kubeObservation("2026-11-02T10:00:10Z", scope, "gate-api", "gate-api"))
		lb.add(obsW, assessment("2026-11-02T10:00:10Z", scope, seqI(rec), "out-of-band-detected", nil))
		lb.add(argoW, gateException("2026-11-02T10:00:50Z", "hangar-dev", dep("gate-api", "gate-api")))
		if rows := exceptionRows(t, st); len(rows) != 2 {
			t.Fatalf("%d rows: the same name in another cluster is another object", len(rows))
		}
	})
	t.Run("a gate exception of two objects stays unless both were observed", func(t *testing.T) {
		st := miniChain(t, healthFor("2026-10-09T00:00:00Z", scope))
		lb := &labber{t: t, st: st}
		rec := lb.add(obsW, kubeObservation("2026-11-02T10:00:10Z", scope, "gate-api", "a"))
		lb.add(obsW, assessment("2026-11-02T10:00:10Z", scope, seqI(rec), "out-of-band-detected", nil))
		lb.add(argoW, gateException("2026-11-02T10:00:50Z", scope, dep("gate-api", "a"), dep("gate-api", "b")))
		rows := exceptionRows(t, st)
		if len(rows) != 2 || !strings.Contains(rows[1].Detail+rows[0].Detail, "1 of its 2 objects") {
			t.Fatalf("%+v", rows)
		}
	})
}

// A collector's noise-filtered checks in its health records are the packet's "filtered: N events under rule X": summed
// over the window, per rule and rule set, and nothing outside it.
func TestPacketSumsTheCollectorsFilteredCountsFromTheChain(t *testing.T) {
	const scope = "hangar-prod"
	detail := func(set string, counts map[string]int) string {
		f := map[string]any{"schema": observe.FilteredSchema, "since": "x", "until": "y", "rule_set": set}
		var rs []map[string]any
		for r, n := range counts {
			rs = append(rs, map[string]any{"rule": r, "count": n, "why": "because " + r})
		}
		f["filtered"] = rs
		b, _ := json.Marshal(f)
		return string(b)
	}
	h := func(ts, d string) store.Event {
		e := healthFor(ts, scope)
		cs := e["health"].(map[string]any)["checks"].([]any)
		e["health"].(map[string]any)["checks"] = append(cs, map[string]any{"name": observe.FilteredCheck, "ok": true, "detail": d})
		return e
	}
	set := "observe-default@2026.11.1"
	st := miniChain(t,
		healthFor("2026-10-09T00:00:00Z", scope),
		h("2026-10-09T23:59:00Z", detail(set, map[string]int{"hpa-scale": 100})), // before the window
		h("2026-10-20T00:00:00Z", detail(set, map[string]int{"hpa-scale": 2, "argo-application-bookkeeping": 5})),
		h("2026-10-21T00:00:00Z", detail(set, map[string]int{"hpa-scale": 3})),
		h("2026-10-22T00:00:00Z", detail("observe-default@2026.12.0", map[string]int{"hpa-scale": 1})),
	)
	q := packet.Params{From: mustTime(t, winFrom), To: mustTime(t, winTo), Now: mustTime(t, nowAt), Version: "test", Scopes: []string{scope}}
	res, err := packet.Build(bg, st, q)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range res.Packet.Exceptions.Filtered {
		got = append(got, fmt.Sprintf("%s|%s|%d", f.Rule, f.RuleSet, f.Count))
	}
	want := "argo-application-bookkeeping|observe-default@2026.11.1|5 hpa-scale|observe-default@2026.11.1|5 hpa-scale|observe-default@2026.12.0|1"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %v", got)
	}
	if res.Packet.Exceptions.Filtered[0].Line() == "" || res.Packet.Exceptions.Filtered[0].Why == "" {
		t.Fatalf("%+v", res.Packet.Exceptions.Filtered[0])
	}
	// the caller's own counts win
	q.Filtered = []packet.FilteredRule{{Rule: "x", RuleSet: "y@1", Count: 9}}
	res, _ = packet.Build(bg, st, q)
	if len(res.Packet.Exceptions.Filtered) != 1 || res.Packet.Exceptions.Filtered[0].Rule != "x" {
		t.Fatalf("%+v", res.Packet.Exceptions.Filtered)
	}
}

// A person's resolution of a gate exception (the Argo CD agent's out-of-band report has no change id) is the row's
// resolution, newest first, instead of "none recorded".
func TestAPersonsResolutionOfAGateExceptionIsTheRowsResolution(t *testing.T) {
	const scope = "hangar-prod"
	st := miniChain(t, healthFor("2026-10-09T00:00:00Z", scope))
	lb := &labber{t: t, st: st}
	gx := seqI(lb.add(argoW, gateException("2026-11-02T10:00:50Z", scope, dep("gate-api", "gate-api"))))
	if rows := exceptionRows(t, st); len(rows) != 1 || rows[0].Resolution != "none recorded" || rows[0].ResolutionSeq != nil {
		t.Fatalf("before: %+v", rows)
	}
	lb.add(coreW, personResolution("2026-11-03T08:00:00Z", scope, gx, "user:dana", "human-initiated"))
	edit := seqI(lb.add(coreW, func() store.Event {
		r := personResolution("2026-11-03T09:00:00Z", scope, gx, "user:jfillman", "")
		r["resolution"] = map[string]any{"state": "ratified", "by": "user:jfillman", "note": "a false out-of-band report"}
		return r
	}()))
	rows := exceptionRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Seq != gx || r.Resolution != "ratified" || r.Cause != "" || r.ResolvedBy != "user:jfillman" || r.ResolutionSeq == nil || *r.ResolutionSeq != edit {
		t.Fatalf("the newest person's resolution is the row's: %+v", r)
	}
}
