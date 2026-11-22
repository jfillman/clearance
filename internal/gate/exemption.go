package gate

import (
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/store"
)

// Gate exemptions (docs/gate.md, "The gate rule and exemptions").
//
// A deploy.exception of kind gate-exemption is an agent saying that the platform's gate rule has let one Application
// out of the gate until a date: the platform wrote an `exempt` entry in the agent's rule file, and the git history of
// that change is the record of who. The record names the Application's app (record.app) and environment
// (destination.environment) and carries exception.exemption:
//
//	state        requested | active | expiring | expired | refused
//	application  <namespace>/<name> of the Application
//	entry        the exempt entry's application glob, as written in the rule file
//	rule         the name of the rule entry that selects the Application
//	rule_digest  sha256 (64 hex) of the rule file the agent read
//	reason       the entry's reason, 10 to 500 characters
//	expires      the entry's expiry, an RFC 3339 time
//	ref          optional: a strip, ticket or pull request
//	why          optional: why the state is what it is (an expired one that lapsed, was revoked or is stale)
//
// The core decides every exemption. An agent honours one only after the core has taken its `requested` record, and
// asks again whenever the pair, the Application, the entry or the rule file changes and at an interval. The core
// refuses (409, "refused: static") a requested, active or expiring exemption whose environment
// CLEARANCE_PROTECTED_ENVIRONMENTS protects: an Application released there would disagree with a pair the core
// keeps protected whatever the agent reports. An empty CLEARANCE_PROTECTED_ENVIRONMENTS protects every environment,
// so it refuses every exemption. An expired or refused record is always taken: it closes or explains one.
//
// A gate exemption names no change (change.id is refused): it is a gap in coverage for an Application, not an
// exception to one change, and it never moves a change's state.

// KindGateExemption is deploy.exception's kind for a platform exemption from the gate rule.
const KindGateExemption = "gate-exemption"

// The states of a gate exemption's record.
const (
	ExemptionRequested    = "requested"
	ExemptionActive       = "active"
	ExemptionExpiring     = "expiring"
	ExemptionExpired      = "expired"
	ExemptionStateRefused = "refused"
)

// ExemptionStates are a gate exemption's states.
var ExemptionStates = []string{ExemptionRequested, ExemptionActive, ExemptionExpiring, ExemptionExpired, ExemptionStateRefused}

// MaxExemptionDays bounds how far past the record's time an exemption may run. The agent's own bound
// (--gate-exempt-max, default 90 days) can only be lower.
const MaxExemptionDays = 90

var (
	exemptionKs = setOf("state", "application", "entry", "rule", "rule_digest", "reason", "expires", "ref", "why")
	appKeyRx    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?/[a-z0-9]([-.a-z0-9]{0,251}[a-z0-9])?\z`)
	digestRx    = regexp.MustCompile(`^[0-9a-f]{64}\z`)
	ruleNameRx  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\z`)
)

// ExemptionRefused is a gate exemption the core refuses to take (409): the reason is short and machine-readable
// ("static"), Message says why.
type ExemptionRefused struct {
	Reason  string
	Message string
}

func (e *ExemptionRefused) Error() string { return "refused: " + e.Reason + ": " + e.Message }

func exemptionText(v any, lo, hi int) (string, bool) {
	s, ok := v.(string)
	n := utf8.RuneCountInString(s)
	return s, ok && utf8.ValidString(s) && n >= lo && n <= hi && !slices.Contains([]rune(s), 0)
}

func checkExemption(ev store.Event, x map[string]any) error {
	if _, present := ev["change"]; present {
		return badReport("a %s exception names no change (change.id): it is a gap for an Application, not an exception to a change", KindGateExemption)
	}
	if app, _ := ev["app"].(string); !nameRx.MatchString(app) {
		return badReport("a %s exception names the Application's app (record.app)", KindGateExemption)
	}
	m, ok := x["exemption"].(map[string]any)
	if !ok {
		return badReport("exception.exemption is {state, application, entry, rule, rule_digest, reason, expires, ref, why}")
	}
	if k := unknownKey(m, exemptionKs); k != "" {
		return badReport("exception.exemption has an unknown field %q", k)
	}
	if st, _ := m["state"].(string); !slices.Contains(ExemptionStates, st) {
		return badReport("exception.exemption.state is one of %v", ExemptionStates)
	}
	if a, _ := m["application"].(string); !appKeyRx.MatchString(a) {
		return badReport("exception.exemption.application is <namespace>/<name> of the Application")
	}
	if _, ok := exemptionText(m["entry"], 1, 253); !ok {
		return badReport("exception.exemption.entry is the exempt entry's application glob (1 to 253 characters)")
	}
	if r, _ := m["rule"].(string); !ruleNameRx.MatchString(r) {
		return badReport("exception.exemption.rule is the name of the rule entry that selects the Application (a DNS label)")
	}
	if d, _ := m["rule_digest"].(string); !digestRx.MatchString(d) {
		return badReport("exception.exemption.rule_digest is the rule file's sha256 (64 lowercase hex)")
	}
	if _, ok := exemptionText(m["reason"], 10, 500); !ok {
		return badReport("exception.exemption.reason is 10 to 500 characters")
	}
	if s, _ := m["expires"].(string); s == "" {
		return badReport("exception.exemption.expires is an RFC 3339 time")
	} else if _, err := time.Parse(time.RFC3339, s); err != nil {
		return badReport("exception.exemption.expires is an RFC 3339 time")
	}
	for _, k := range []string{"ref", "why"} {
		if v, present := m[k]; present {
			if _, ok := exemptionText(v, 1, 200); !ok {
				return badReport("exception.exemption.%s is 1 to 200 characters", k)
			}
		}
	}
	return nil
}

// DecideExemption is the core's decision on a gate exemption, nil for any other record: an exemption that would
// release an Application (requested, active, expiring) is refused when CLEARANCE_PROTECTED_ENVIRONMENTS protects its
// environment, or when it runs past MaxExemptionDays from now. The record is checked first (CheckReport); a malformed
// one is a *BadReport.
func (s *Service) DecideExemption(ev store.Event) error {
	if ev["tool"] != KindException {
		return nil
	}
	x, _ := ev["exception"].(map[string]any)
	if x["kind"] != KindGateExemption {
		return nil
	}
	if err := CheckReport(ev, s.now()); err != nil {
		return err
	}
	m := x["exemption"].(map[string]any)
	switch m["state"] {
	case ExemptionExpired, ExemptionStateRefused:
		return nil
	}
	cluster, env, _ := where(ev)
	if s.StaticProtects(cluster, env) {
		return &ExemptionRefused{"static", fmt.Sprintf("%s/%s is protected by CLEARANCE_PROTECTED_ENVIRONMENTS, which no "+
			"exemption lifts (an empty list protects every environment)", cluster, env)}
	}
	exp, _ := time.Parse(time.RFC3339, m["expires"].(string))
	if exp.After(s.now().Add(MaxExemptionDays * 24 * time.Hour)) {
		return &ExemptionRefused{"too-long", fmt.Sprintf("expires %s is more than %d days away", exp.UTC().Format(time.RFC3339), MaxExemptionDays)}
	}
	return nil
}

// RefuseExemptedStatic is the core's check of a protection report's exempted pairs (the pairs it removes because an
// exemption released their Application): one whose environment CLEARANCE_PROTECTED_ENVIRONMENTS protects is refused,
// as its exemption would be.
func (s *Service) RefuseExemptedStatic(cluster string, exempted []ProtectedPair) error {
	for _, p := range exempted {
		if s.StaticProtects(cluster, p.Env) {
			return &ExemptionRefused{"static", fmt.Sprintf("the report removes %s/%s for an exemption, and %s/%s is protected by "+
				"CLEARANCE_PROTECTED_ENVIRONMENTS, which no exemption lifts", p.App, p.Env, cluster, p.Env)}
		}
	}
	return nil
}
