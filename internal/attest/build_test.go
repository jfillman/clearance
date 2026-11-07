package attest_test

import (
	"errors"
	"testing"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
)

func manifestChange() *gate.Change {
	by := "people"
	at := gate.PyTime{Time: mustTime("2026-11-07T00:00:00Z")}
	return (&gate.Change{ID: "chg-9", App: "app", Env: "prod", Cluster: "hangar-dev", Repo: "o/gitops", PR: 4, Head: commit,
		Base: "base", Proposer: "agent-x", ProposerKind: "agent", TreeDigest: "sha256:" + treeRoot, Tier: 2, State: "cleared",
		ClearedBy: &by, DecidedAt: &at, Checks: map[string]string{"provenance": "confirmed"},
		Objects: []gate.ObjectChange{{Kind: "Deployment", Name: "app", Op: "update",
			Images: []string{"ghcr.io/o/app@sha256:" + imageHex, "ghcr.io/o/side:latest"}}}}).View()
}

func outcomeRec(applied bool, digest string) store.Record {
	oc := map[string]any{"applied": applied, "observed_revision": commit, "finished_at": "2026-11-07T00:02:00Z"}
	if digest != "" {
		oc["digests"] = map[string]any{"sha256": digest}
	}
	return store.Record{"tool": "deploy.outcome", "seq": int64(12), "ts": "2026-11-07T00:02:01Z", "provider": "argocd-agent",
		"coverage": "authorized-and-verified", "change": map[string]any{"id": "chg-9", "tree": "sha256:" + treeRoot}, "outcome": oc}
}

func TestAManifestOutcomeBecomesAStatement(t *testing.T) {
	st, err := attest.BuildStatement(manifestChange(), outcomeRec(true, treeRoot), "clearance")
	if err != nil {
		t.Fatal(err)
	}
	if !st.HasSubject("sha256:"+treeRoot) || !st.HasSubject("gitCommit:"+commit) || !st.HasSubject("sha256:"+imageHex) || len(st.Subject) != 3 {
		t.Fatalf("%+v", st.Subject)
	}
	p := st.Predicate
	if p.Clearance.ID != "chg-9" || p.Tier != 2 || p.Policy.Ref == "" || p.Provenance.Level != "confirmed-agent" ||
		p.Outcome.Seq != 12 || p.Outcome.Provider != "argocd-agent" || p.Outcome.Matched == nil || !*p.Outcome.Matched ||
		p.Outcome.At != "2026-11-07T00:02:00Z" || p.Coverage != "authorized-and-verified" || p.Cleared.TreeRoot != "sha256:"+treeRoot {
		t.Fatalf("%+v", p)
	}
	found := false
	for _, l := range p.Limitations {
		found = found || l == "1 image reference(s) carry no digest and are not subjects."
	}
	if !found {
		t.Fatalf("%v", p.Limitations)
	}
	withRelease := outcomeRec(true, treeRoot)
	withRelease["release"] = map[string]any{"id": "rel-42"}
	if st, err := attest.BuildStatement(manifestChange(), withRelease, "clearance"); err != nil || st.Predicate.Release == nil || st.Predicate.Release.ID != "rel-42" {
		t.Fatalf("release: %+v %v", st, err)
	}
	// release {id} wins; the Argo CD agent's older placement, change.release.id, still counts.
	legacy := outcomeRec(true, treeRoot)
	legacy["change"].(map[string]any)["release"] = map[string]any{"id": "rel-old"}
	if st, err := attest.BuildStatement(manifestChange(), legacy, "clearance"); err != nil || st.Predicate.Release == nil || st.Predicate.Release.ID != "rel-old" {
		t.Fatalf("legacy release: %+v %v", st, err)
	}
	legacy["release"] = map[string]any{"id": "rel-new"}
	if st, _ := attest.BuildStatement(manifestChange(), legacy, "clearance"); st.Predicate.Release.ID != "rel-new" {
		t.Fatalf("release {id} must win: %+v", st.Predicate.Release)
	}
	// A provider that reports no digest still gets an attestation, with matched null and a limitation saying so.
	st, err = attest.BuildStatement(manifestChange(), outcomeRec(true, ""), "clearance")
	if err != nil || st.Predicate.Outcome.Matched != nil || len(st.Predicate.Limitations) < 3 {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestNoStatementForAnOutcomeThatIsNotAnAppliedClearedDeploy(t *testing.T) {
	other := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	held := manifestChange()
	held.ClearedBy, held.DecidedAt, held.State = nil, nil, "holding"
	exc := manifestChange()
	exc.State = gate.StateException
	wrongChange := outcomeRec(true, treeRoot)
	wrongChange["change"] = map[string]any{"id": "other"}
	notOutcome := outcomeRec(true, treeRoot)
	notOutcome["tool"] = "deploy.clear"
	for name, c := range map[string]struct {
		c   *gate.Change
		rec store.Record
	}{
		"not applied":    {manifestChange(), outcomeRec(false, treeRoot)},
		"another tree":   {manifestChange(), outcomeRec(true, other)},
		"never cleared":  {held, outcomeRec(true, treeRoot)},
		"exception":      {exc, outcomeRec(true, treeRoot)},
		"another change": {manifestChange(), wrongChange},
		"not an outcome": {manifestChange(), notOutcome},
	} {
		if _, err := attest.BuildStatement(c.c, c.rec, "clearance"); !errors.Is(err, attest.ErrNoAttestation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
