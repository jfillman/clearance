// Package vocabtest is the vocabulary of the lab deployment the ported tests and the golden corpus were written
// against (tests only): its header, trailer prefix, run namespace, baseline paths and fields, groups, v0 provider,
// and the PR tools and profile sections its policy bundle adds.
package vocabtest

import (
	"testing"

	"github.com/jfillman/clearance/internal/vocab"
)

// AgentLogin is the lab's agents' GitHub App login (its AGENT_LOGINS).
const AgentLogin = "hangar-autopilot-agents[bot]"

// Lab is the lab deployment's vocabulary.
func Lab() vocab.Vocabulary {
	return vocab.Vocabulary{
		OnBehalfOfHeader: "X-Hangar-On-Behalf-Of", TrailerPrefix: "Hangar-", RunIdentityNamespace: "autopilot-runs",
		BaselineDenyPaths: []string{".tekton/**", "**/.tekton/**", "CODEOWNERS", "**/CODEOWNERS", ".github/**",
			"**/appproject*.yaml", "**/AppProject*.yaml", "release.yaml", "**/release.yaml", "*.release.yaml", "**/*.release.yaml"},
		BaselineDenyFields: []string{"/extraManifests", "/networkPolicy", "/httpRoute", "/release", "/releaseTracking", "/rollout/image"},
		OutsideGroups:      []string{"group:default/admins"}, OwnerFallback: "group:default/admins",
		V0ProviderName: "autopilot-gateway", V0ProviderVersion: "unrecorded",
		AICoauthors:     vocab.DefaultAICoauthors(),
		PRTools:         []string{"repo.pr.open", "repo.pr.open_upper", "glidepath.cicd.propose"},
		ProfileSections: []string{"glidepath", "airframe"},
	}
}

// Env is Lab as the environment variables a deployment passes (vocab.FromEnv), plus AGENT_LOGINS.
func Env() map[string]string {
	return map[string]string{
		"CLEARANCE_ON_BEHALF_OF_HEADER": "X-Hangar-On-Behalf-Of", "CLEARANCE_TRAILER_PREFIX": "Hangar-",
		"CLEARANCE_RUN_IDENTITY_NAMESPACE": "autopilot-runs",
		"CLEARANCE_BASELINE_DENY_PATHS":    ".tekton/**,**/.tekton/**,CODEOWNERS,**/CODEOWNERS,.github/**,**/appproject*.yaml,**/AppProject*.yaml,release.yaml,**/release.yaml,*.release.yaml,**/*.release.yaml",
		"CLEARANCE_BASELINE_DENY_FIELDS":   "/extraManifests,/networkPolicy,/httpRoute,/release,/releaseTracking,/rollout/image",
		"CLEARANCE_GATE_OUTSIDE_GROUPS":    "group:default/admins", "CLEARANCE_GATE_OWNER_FALLBACK": "group:default/admins",
		"CLEARANCE_V0_PROVIDER": "autopilot-gateway/unrecorded", "AGENT_LOGINS": AgentLogin,
	}
}

// Use sets v for the test (and its subtests) and restores the previous vocabulary after.
func Use(t testing.TB, v vocab.Vocabulary) {
	prev := vocab.Get()
	vocab.Set(v)
	t.Cleanup(func() { vocab.Set(prev) })
}

// UseLab is Use(t, Lab()).
func UseLab(t testing.TB) { Use(t, Lab()) }

// Main is a TestMain body: the whole package's tests run with the lab vocabulary.
func Main(m *testing.M) int {
	vocab.Set(Lab())
	return m.Run()
}

// UseMainVocabulary sets the lab vocabulary for a package whose TestMain does more than run the tests.
func UseMainVocabulary() { vocab.Set(Lab()) }
