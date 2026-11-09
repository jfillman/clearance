package attestor

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
)

// ErrNoAttestation is why a change gets none. It is not a failure: nothing is retried.
var ErrNoAttestation = errors.New("attest: no attestation for this change")

// BuildStatement assembles the attestation of change c from its deploy.outcome record. Refused with
// ErrNoAttestation (wrapped, with the reason) when the change was never cleared, the outcome says the deploy did not
// apply, or what it applied is not what was cleared: an approved change that never synced gets none.
func BuildStatement(c *gate.Change, rec store.Record, issuer string) (*attest.Statement, error) {
	no := func(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrNoAttestation, fmt.Sprintf(f, a...)) }
	if c.ClearedBy == nil || c.DecidedAt == nil {
		return nil, no("the change was never cleared")
	}
	if c.State == gate.StateException || c.State == gate.StateDenied {
		return nil, no("the change is %s", c.State)
	}
	if tool, _ := rec["tool"].(string); tool != "deploy.outcome" {
		return nil, no("record is %q, not deploy.outcome", tool)
	}
	if id := mapStr(rec, "change", "id"); id != c.ID {
		return nil, no("the outcome names change %q, not %q", id, c.ID)
	}
	oc, _ := rec["outcome"].(map[string]any)
	if applied, _ := oc["applied"].(bool); !applied {
		return nil, no("the deploy did not apply (no sync reported)")
	}
	seq, ok := gate.SeqInt(rec["seq"])
	if !ok {
		return nil, no("the outcome record has no seq")
	}
	var matched *bool
	digest := ""
	if dg, _ := oc["digests"].(map[string]any); dg != nil {
		digest, _ = dg["sha256"].(string)
	}
	digest = strings.TrimPrefix(digest, "sha256:")
	cleared := strings.TrimPrefix(c.TreeDigest, "sha256:")
	if c.Subject != nil && c.Subject.Kind == gate.KindTerraformPlan {
		cleared = strings.TrimPrefix(c.Subject.PlanDigest, "sha256:")
	}
	if digest != "" {
		m := digest == cleared
		matched = &m
		if !m {
			return nil, no("the deploy applied sha256:%s, not the cleared sha256:%s", digest, cleared)
		}
	}
	if m, ok := rec["matched"].(bool); ok && !m {
		return nil, no("the outcome is recorded as not matching the clearance")
	}

	claims := (&gate.Tokens{Issuer: issuer}).Claims(c, "", time.Time{}, time.Time{})
	var lim []string
	lim = append(lim,
		"Attests the core's clearance decision and the deploy provider's recorded outcome; it does not attest the "+
			"live state of the target after the deploy.",
		"The outcome is the provider's own report, recorded by the core; the core did not observe the target.")
	if matched == nil {
		lim = append(lim, "The provider reported no digest of what it applied, so the attestation binds the clearance, "+
			"not the applied artifact.")
	}
	coverage, _ := rec["coverage"].(string)
	if coverage == "" {
		coverage = "unspecified"
	}
	if coverage != "authorized-and-verified" {
		lim = append(lim, fmt.Sprintf("The outcome's coverage is %s.", coverage))
	}

	st := &attest.Statement{Type: attest.StatementType, PredicateType: attest.PredicateType}
	switch claims.Subjects.Kind {
	case gate.KindTerraformPlan:
		st.Subject = append(st.Subject, attest.Subject{Name: "terraform-plan:" + c.Repo + "/" + c.App + "/" + c.Env,
			Digest: map[string]string{"sha256": claims.Subjects.PlanDigest}})
	default:
		st.Subject = append(st.Subject, attest.Subject{Name: "manifest-tree:" + c.Repo + "/" + c.App + "/" + c.Env,
			Digest: map[string]string{"sha256": strings.TrimPrefix(claims.Subjects.TreeRoot, "sha256:")}})
	}
	if claims.Subjects.Commit != "" {
		st.Subject = append(st.Subject, attest.Subject{Name: "commit:" + c.Repo, Digest: map[string]string{"gitCommit": claims.Subjects.Commit}})
	}
	skipped := 0
	for _, im := range claims.Subjects.Images {
		name, hex, ok := strings.Cut(im, "@sha256:")
		if !ok || name == "" || hex == "" {
			skipped++
			continue
		}
		st.Subject = append(st.Subject, attest.Subject{Name: name, Digest: map[string]string{"sha256": hex}})
	}
	if skipped > 0 {
		lim = append(lim, fmt.Sprintf("%d image reference(s) carry no digest and are not subjects.", skipped))
	}
	sort.SliceStable(st.Subject[1:], func(i, j int) bool { return st.Subject[1+i].Name < st.Subject[1+j].Name })

	at, _ := rec["ts"].(string)
	if fin, _ := oc["finished_at"].(string); fin != "" {
		at = fin
	}
	if at == "" {
		return nil, no("the outcome record has no time")
	}
	obs, _ := oc["observed_revision"].(string)
	prov, _ := rec["provider"].(string)
	st.Predicate = attest.Predicate{
		Clearance: claims.Clearance, Target: claims.Target, Tier: claims.Tier, Policy: claims.Policy,
		Approvals: claims.Approvals, Provenance: claims.Provenance, Cleared: claims.Subjects,
		Outcome: attest.Outcome{Seq: seq, Provider: prov, Applied: true, Matched: matched, Digest: digest,
			ObservedRevision: obs, At: at},
		Coverage: coverage, Limitations: lim,
	}
	id := mapStr(rec, "release", "id")
	if id == "" {
		id = mapStr(rec, "change", "release", "id") // an outcome from before release {id} (the Argo CD agent <= v0.32)
	}
	if id != "" {
		st.Predicate.Release = &attest.Release{ID: id}
	}
	if err := st.Check(); err != nil {
		return nil, err
	}
	return st, nil
}

func mapStr(m map[string]any, path ...string) string {
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[k]
	}
	s, _ := cur.(string)
	return s
}
