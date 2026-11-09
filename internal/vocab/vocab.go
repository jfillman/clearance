// Package vocab is the deployment's vocabulary: the names Clearance reads and writes that belong to the platform it
// is deployed in, not to Clearance (a header a portal sends, the prefix of the commit trailers its gateway writes,
// the namespace its workload agents run in, the paths and fields no agent may touch, the group that stands in for
// an owner, the provider of rows written before providers were recorded), plus what the loaded policy bundles add
// (the PR tools, the profile sections that scope an agent). The core and clearance-api set it once at start from
// their configuration (FromEnv, then the engine's bundles); every default is Clearance's own, product-neutral one.
//
//	CLEARANCE_ON_BEHALF_OF_HEADER     the header a delegate names a person in (default X-Clearance-On-Behalf-Of)
//	CLEARANCE_TRAILER_PREFIX          the prefix of the commit trailers an agent's commit carries
//	                                  (<prefix>Task:, <prefix>Session:, ...; default Clearance-)
//	CLEARANCE_RUN_IDENTITY_NAMESPACE  the namespace a workload agent's service account lives in (default agent-runs)
//	CLEARANCE_BASELINE_DENY_PATHS     path globs every agent is denied, whatever its definition says
//	                                  (default CODEOWNERS,**/CODEOWNERS,.github/**)
//	CLEARANCE_BASELINE_DENY_FIELDS    JSON pointers every agent is denied (default none)
//	CLEARANCE_GATE_OUTSIDE_GROUPS     the gate baseline's outside groups, group refs (default none)
//	CLEARANCE_GATE_OWNER_FALLBACK     the owner group of a change nobody names an owner for, when there is no outside
//	                                  group (default none: such a change has no owner group)
//	CLEARANCE_GATE_RELEASE_STAMPS     JSON pointers of the fields a release stamps on what it renders (a version label, a
//	                                  release id), which the gate does not count as changes (default the standard
//	                                  app.kubernetes.io/version label, on the object and its pod template)
//	CLEARANCE_V0_PROVIDER             name/version of the provider rows written before providers were recorded are
//	                                  projected with (default unrecorded/unrecorded)
//	CLEARANCE_MONITORING_PROTECTION_OPS  operations on the controls that watch the environment (a log trail, an audit
//	                                  policy, a configuration recorder), as globs on the observed operation's api name
//	                                  ("<api>" or "<source>:<api>"): an observation that matches is tier 3 whether or
//	                                  not it succeeded, and flips its scope's health (O-1). Default none: a provider may
//	                                  also mark such an operation itself (action.protects_monitoring)
//	CLEARANCE_AI_COAUTHORS            comma-separated matchers on a commit's Co-Authored-By, Assisted-by and
//	                                  Generated-by trailers that name an AI coding agent: "<email>" or "Name <email>"
//	                                  (case-insensitive, whitespace collapsed). A PR Clearance has no record of whose
//	                                  head commit carries one is agent-unattested, a warning (provenance). Default
//	                                  DefaultAICoauthors; "none" turns the check off
package vocab

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Vocabulary is the deployment's vocabulary.
type Vocabulary struct {
	OnBehalfOfHeader     string
	TrailerPrefix        string
	RunIdentityNamespace string
	BaselineDenyPaths    []string
	BaselineDenyFields   []string
	OutsideGroups        []string
	OwnerFallback        string
	GateReleaseStamps    []string
	V0ProviderName       string
	V0ProviderVersion    string
	// MonitoringProtectionOps are the globs on an observed operation that protect monitoring (default none).
	MonitoringProtectionOps []string
	// AICoauthors match the commit trailers an AI coding agent outside Clearance leaves (empty: the check is off).
	AICoauthors []Coauthor
	// From the policy bundles (decide.Engine), not the environment.
	PRTools         []string
	ProfileSections []string
}

// EnvVars are the variables FromEnv reads.
var EnvVars = []string{"CLEARANCE_ON_BEHALF_OF_HEADER", "CLEARANCE_TRAILER_PREFIX", "CLEARANCE_RUN_IDENTITY_NAMESPACE",
	"CLEARANCE_BASELINE_DENY_PATHS", "CLEARANCE_BASELINE_DENY_FIELDS", "CLEARANCE_GATE_OUTSIDE_GROUPS",
	"CLEARANCE_GATE_OWNER_FALLBACK", "CLEARANCE_GATE_RELEASE_STAMPS", "CLEARANCE_V0_PROVIDER", "CLEARANCE_AI_COAUTHORS",
	"CLEARANCE_MONITORING_PROTECTION_OPS"}

// Default is Clearance's own vocabulary.
func Default() Vocabulary {
	return Vocabulary{
		OnBehalfOfHeader: "X-Clearance-On-Behalf-Of", TrailerPrefix: "Clearance-", RunIdentityNamespace: "agent-runs",
		BaselineDenyPaths: []string{"CODEOWNERS", "**/CODEOWNERS", ".github/**"}, BaselineDenyFields: []string{},
		OutsideGroups: []string{}, GateReleaseStamps: []string{"/metadata/labels/app.kubernetes.io~1version", "/spec/template/metadata/labels/app.kubernetes.io~1version"},
		V0ProviderName: "unrecorded", V0ProviderVersion: "unrecorded", MonitoringProtectionOps: []string{},
		AICoauthors: DefaultAICoauthors(),
		PRTools:     []string{"repo.pr.open", "repo.pr.open_upper"}, ProfileSections: []string{},
	}
}

var current atomic.Pointer[Vocabulary]

func init() {
	v := Default()
	current.Store(&v)
}

// Get is the vocabulary in force.
func Get() Vocabulary { return *current.Load() }

// Set replaces the vocabulary (at start; tests restore what they replace).
func Set(v Vocabulary) { current.Store(&v) }

func list(v string) []string {
	out := []string{}
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// FromEnv is Default with the environment's values (PRTools and ProfileSections are left at the default: the
// engine's bundles set them, WithPolicy).
func FromEnv(get func(string) string) (Vocabulary, error) {
	v := Default()
	if s := get("CLEARANCE_ON_BEHALF_OF_HEADER"); s != "" {
		if strings.ContainsAny(s, " :\t\r\n") {
			return v, fmt.Errorf("CLEARANCE_ON_BEHALF_OF_HEADER: %q is not a header name", s)
		}
		v.OnBehalfOfHeader = s
	}
	if s := get("CLEARANCE_TRAILER_PREFIX"); s != "" {
		if strings.ContainsAny(s, " :\t\r\n") {
			return v, fmt.Errorf("CLEARANCE_TRAILER_PREFIX: %q is not a trailer-key prefix", s)
		}
		v.TrailerPrefix = s
	}
	if s := get("CLEARANCE_RUN_IDENTITY_NAMESPACE"); s != "" {
		v.RunIdentityNamespace = s
	}
	if s := get("CLEARANCE_BASELINE_DENY_PATHS"); s != "" {
		v.BaselineDenyPaths = list(s)
	}
	if s := get("CLEARANCE_BASELINE_DENY_FIELDS"); s != "" {
		v.BaselineDenyFields = list(s)
	}
	if s := get("CLEARANCE_GATE_OUTSIDE_GROUPS"); s != "" {
		v.OutsideGroups = list(s)
	}
	if s := get("CLEARANCE_GATE_RELEASE_STAMPS"); s != "" {
		v.GateReleaseStamps = list(s)
	}
	if s := get("CLEARANCE_MONITORING_PROTECTION_OPS"); s != "" {
		v.MonitoringProtectionOps = list(s)
	}
	v.OwnerFallback = get("CLEARANCE_GATE_OWNER_FALLBACK")
	if s := get("CLEARANCE_V0_PROVIDER"); s != "" {
		name, ver, ok := strings.Cut(s, "/")
		if !ok || name == "" || ver == "" {
			return v, fmt.Errorf("CLEARANCE_V0_PROVIDER: %q is not name/version", s)
		}
		v.V0ProviderName, v.V0ProviderVersion = name, ver
	}
	if s := get("CLEARANCE_AI_COAUTHORS"); s != "" {
		cs, err := ParseCoauthors(s)
		if err != nil {
			return v, fmt.Errorf("CLEARANCE_AI_COAUTHORS: %w", err)
		}
		v.AICoauthors = cs
	}
	return v, nil
}

// Policy is what the loaded policy adds to the vocabulary.
type Policy interface {
	PRTools() []string
	ProfileSections() []string
}

// WithPolicy is v with the policy's PR tools and profile sections.
func (v Vocabulary) WithPolicy(p Policy) Vocabulary {
	v.PRTools, v.ProfileSections = p.PRTools(), p.ProfileSections()
	return v
}
