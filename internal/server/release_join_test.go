package server_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/token"
)

// G-ARGO-6: the chain of a release, joined by ids. PR -> change -> grant (the cleared token) -> deploy.outcome with
// release {id} -> attestation carrying it -> the change's view showing the outcome, whose seq and hash are the
// record's. The Argo CD agent's older placement, change.release.id, joins the same way.
func TestAReleaseIsJoinedToItsChangeOutcomeAndAttestation(t *testing.T) {
	const releaseID = "d41d51f7-e16c-4df6-934e-1952b5723e99:hangar-prod/prod"
	for name, place := range map[string]func(rec, chg map[string]any){
		"release {id}":           func(rec, _ map[string]any) { rec["release"] = map[string]any{"id": releaseID} },
		"change.release.id only": func(_, chg map[string]any) { chg["release"] = map[string]any{"id": releaseID} },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config(t, "")
			sg := signer(t)
			cfg.Signer, cfg.TokenIssuer, cfg.TokenTTL = sg, "clearance", 15*time.Minute
			asg := signer(t)
			cfg.Attest = &attest.Static{Signer: asg}
			f := newFixture(t, cfg)

			// PR -> change -> grant
			id := f.do("POST", "/v1/clearances", ci, change("pass")).want(t, 200, "").body["id"].(string)
			a := f.do("GET", "/v1/clearances/"+id, argo, nil).want(t, 200, "")
			if a.body["state"] != "cleared" || a.body["token"] == nil || a.body["outcome"] != nil || a.body["pr"] != float64(7) {
				t.Fatalf("before the deploy: %v", a.body)
			}

			// outcome: what the Argo CD agent posts
			tree := strings.Repeat("c", 64)
			chg := map[string]any{"id": id, "tree": "sha256:" + tree}
			rec := map[string]any{"app": "gate-api", "target": "app-gate-api-prod/gate-api@abc123", "result": "applied",
				"destination": map[string]any{"cluster": "hangar-prod", "environment": "prod"}, "change": chg, "outcome": map[string]any{"applied": true, "digests": map[string]any{"sha256": tree},
					"observed_revision": "abc123", "finished_at": time.Now().UTC().Format(time.RFC3339)}}
			place(rec, chg)
			ref := f.do("POST", "/v1/records", argo, map[string]any{"provider": "argo-gate", "kind": "deploy.outcome", "record": rec}).
				want(t, 200, "").body
			f.core.Attestor.Drain(context.Background())

			// the record names the release in its one place, whichever way it was sent
			var outcomeRec map[string]any
			for _, r := range f.records() {
				if r["tool"] == "deploy.outcome" {
					outcomeRec = r
				}
			}
			if rl, _ := outcomeRec["release"].(map[string]any); rl["id"] != releaseID {
				t.Fatalf("the record's release: %v", outcomeRec["release"])
			}

			// the change shows the outcome, joined to the record by seq and hash
			a = f.do("GET", "/v1/clearances/"+id, argo, nil).want(t, 200, "")
			oc, _ := a.body["outcome"].(map[string]any)
			if oc == nil || oc["release"] != releaseID || oc["applied"] != true || oc["matched"] != true ||
				oc["seq"] != ref["seq"] || oc["hash"] != outcomeRec["hash"] || oc["digest"] != tree || oc["provider"] == "" {
				t.Fatalf("the change's outcome: %v (record %v)", oc, ref)
			}

			// the attestation carries the same ids
			at, err := f.core.Store.Attestation(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			res, err := attest.Verify(at.Bundle, attest.VerifyOptions{Keys: token.KeySet{asg.KeyID(): asg.Public()}})
			if err != nil {
				t.Fatal(err)
			}
			p := res.Statement.Predicate
			if p.Release == nil || p.Release.ID != releaseID || p.Clearance.ID != id || p.Outcome.Seq != int64(oc["seq"].(float64)) {
				t.Fatalf("the attestation: %+v", p)
			}
			if at.OutcomeSeq != int64(oc["seq"].(float64)) {
				t.Fatalf("the attestation row names outcome %d, the change %v", at.OutcomeSeq, oc["seq"])
			}
			if ok, bad := evidence.Verify(f.records()); !ok {
				t.Fatalf("the chain breaks at %d", bad)
			}
		})
	}
}

func TestAReleaseOnARecordIsCheckedAndOnlyOnAnOutcome(t *testing.T) {
	f := memFixture(t)
	post := func(kind string, rec map[string]any) answer {
		return f.do("POST", "/v1/records", argo, map[string]any{"provider": "argo-gate", "kind": kind, "record": rec})
	}
	out := func(rel any) map[string]any {
		return map[string]any{"app": "gate-api", "target": "t", "outcome": map[string]any{"applied": true}, "release": rel}
	}
	post("deploy.outcome", out(map[string]any{"id": ""})).want(t, 400, "release is {id}")
	post("deploy.outcome", out(map[string]any{"id": "r", "x": "y"})).want(t, 400, "release is {id}")
	post("deploy.outcome", out(map[string]any{"id": strings.Repeat("r", 5000)})).want(t, 400, "release.id")
	post("deploy.outcome", out(map[string]any{"id": "r1"})).want(t, 200, "")
	post("deploy.exception", map[string]any{"principal": "p", "target": "t", "result": "r", "release": map[string]any{"id": "r1"}}).
		want(t, 400, "release is a deploy.outcome field")
}

// An outcome whose objects carried no grant names no change id (the agent sends change {tree}): it is still recorded.
func TestAnOutcomeWithNoChangeIdIsStillRecorded(t *testing.T) {
	f := memFixture(t)
	for _, chg := range []map[string]any{{"tree": "sha256:" + strings.Repeat("c", 64)}, {"id": "not-a-change-id"}} {
		f.do("POST", "/v1/records", argo, map[string]any{"provider": "argo-gate", "kind": "deploy.outcome",
			"record": map[string]any{"app": "gate-api", "target": "t", "outcome": map[string]any{"applied": true}, "change": chg,
				"release": map[string]any{"id": "r1"}}}).want(t, 200, "")
	}
}
