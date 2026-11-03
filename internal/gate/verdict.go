package gate

import (
	"regexp"
	"slices"

	"github.com/jfillman/clearance/internal/pycompat"
)

// The policy-engine verdict a deployment decision records (C-8, docs/gate.md "The policy in the record").
//
// Two policies stand behind a deployment decision. Clearance's own: the baseline tier table, tightened by the
// repo's clearance.yaml, which the core applies itself. And the target cluster's admission policies, which the
// verifier evaluates offline before it registers the change (on Hangar, the clearance-gate task runs the Kyverno CLI
// over the rendered tree against the cluster's policy bundle, the policy-validation gate's mechanism) and sends as a
// check result. Every deploy.* record names both in its `policy` group:
//
//	{"ref": "clearance.yaml@<commit>", "version": "<baseline>[+sha256:<clearance.yaml digest>]",
//	 "engine": "kyverno/<version>", "verdict": "pass", "bundle": "<repo>//<path>@<commit>"}
//
// ref and version are what reproduce the tier decision (the core holds the baseline by version; the clearance.yaml
// is named by the commit that last changed it and pinned by its content digest); engine, verdict and bundle are the
// admission result and the rule set it was evaluated against, as the verifier reported them (claimed). A change
// registered with no admission result records engine "none" and verdict "not-evaluated". The verdict is recorded,
// not enforced: the tier rules do not read it (the admission check is the verifier's own required check).

// AdmissionVerdicts are what an offline admission evaluation may report: pass, warn (Audit/Warn findings only, or a
// rule offline evaluation could not decide), fail (a Deny/Enforce policy fails: the cluster would refuse the sync),
// skipped (nothing to evaluate: the cluster has no admission policy), error (the evaluation could not run).
var AdmissionVerdicts = []string{"pass", "warn", "fail", "skipped", "error"}

// NoEngine and NotEvaluated are a record's engine and verdict when the verifier sent no admission result.
const (
	NoEngine     = "none"
	NotEvaluated = "not-evaluated"
	// BaselineRef is a record's policy ref when the repo has no clearance.yaml: the baseline alone decided.
	BaselineRef = "baseline"
	maxBundle   = 512
	maxFindings = 1 << 20
)

var (
	engineRx = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}/v?[0-9][0-9A-Za-z.+-]{0,63}\z`)
	bundleRx = regexp.MustCompile(`^[\x21-\x7e]{1,512}\z`)
)

var admissionKeys = setOf("engine", "verdict", "bundle", "deny", "warn")

// Admission is the verifier's offline admission result for the change's rendered tree (request field `admission`):
// the engine and its version, the verdict, the rule set it ran (repo, path and commit, as one string) and how many
// findings blocked (deny) or only warned.
type Admission struct {
	Engine  string `json:"engine"`
	Verdict string `json:"verdict"`
	Bundle  string `json:"bundle,omitempty"`
	Deny    int64  `json:"deny"`
	Warn    int64  `json:"warn"`
}

// parseAdmission reads the request's `admission` object strictly.
func parseAdmission(v any) (*Admission, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, bad("admission is {engine, verdict, bundle, deny, warn}")
	}
	if k := unknownKey(m, admissionKeys); k != "" {
		return nil, bad("admission has an unknown field %s", pycompat.Repr(k))
	}
	a := &Admission{}
	a.Engine, _ = m["engine"].(string)
	if !engineRx.MatchString(a.Engine) {
		return nil, bad("admission.engine is <engine>/<version>, such as kyverno/1.19.0")
	}
	a.Verdict, _ = m["verdict"].(string)
	if !slices.Contains(AdmissionVerdicts, a.Verdict) {
		return nil, bad("admission.verdict is pass, warn, fail, skipped or error")
	}
	if b, present := m["bundle"]; present && b != nil && b != "" {
		s, isStr := b.(string)
		if !isStr || !bundleRx.MatchString(s) {
			return nil, bad("admission.bundle names the rule set: <repo>//<path>@<commit>, at most %d printable characters", maxBundle)
		}
		a.Bundle = s
	}
	for _, k := range []string{"deny", "warn"} {
		x, present := m[k]
		if !present {
			continue
		}
		n, isInt := pycompat.AsInt(x)
		if !isInt || n < 0 || n > maxFindings {
			return nil, bad("admission.%s is a non-negative integer", k)
		}
		if k == "deny" {
			a.Deny = n
		} else {
			a.Warn = n
		}
	}
	return a, nil
}

// policyRefOf is the ref a change records for its tier policy: the clearance.yaml at the commit the verifier names,
// else at its content digest, else the baseline alone.
func policyRefOf(req ChangeRequest) string {
	if req.Policy == nil {
		return BaselineRef
	}
	if req.PolicyCommit != "" {
		return "clearance.yaml@" + req.PolicyCommit
	}
	if d, err := repoPolicyDigest(req.Policy); err == nil {
		return "clearance.yaml@sha256:" + d
	}
	return "clearance.yaml"
}

// PolicyGroup is the `policy` group of a deploy.* record about this change (the evidence schema's Decision group).
func (c *Change) PolicyGroup() map[string]any {
	ref := c.PolicyRef
	if ref == "" { // a change registered before C-8
		ref = BaselineRef
		if c.RepoPolicyDigest != nil {
			ref = "clearance.yaml@sha256:" + *c.RepoPolicyDigest
		}
	}
	version := c.PolicyVersion
	if c.RepoPolicyDigest != nil {
		version += "+sha256:" + *c.RepoPolicyDigest
	}
	g := map[string]any{"ref": ref, "version": version, "engine": NoEngine, "verdict": NotEvaluated}
	if a := c.Admission; a != nil {
		g["engine"], g["verdict"] = a.Engine, a.Verdict
		if a.Bundle != "" {
			g["bundle"] = a.Bundle
		}
	}
	return g
}

// baselineGroup is the policy group of a deployment decision with no change on record (DG-UNREGISTERED).
func baselineGroup(p Policy) map[string]any {
	return map[string]any{"ref": BaselineRef, "version": p.Version, "engine": NoEngine, "verdict": NotEvaluated}
}
