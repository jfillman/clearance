// Package observe is the observation side of the evidence record (clearance.evidence/v1.1, O-1): what a registered
// observed provider reports about changes it saw rather than decided (observation), what was made of one
// (assessment, resolution), whether the feed it came through could be trusted (observation.health) and the gap a feed
// dropping leaves (observation.audit-gap). It checks a provider's record before the core seals it, derives what the
// core decides (the coverage of an observation, tier 3 for an operation on monitoring, whether completeness is
// supported by the feed's health), and reads a window's records back as the three-part coverage statement
// (Statement, GET /v1/coverage). docs/evidence.md "Observations" is the contract.
package observe

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/vocab"
)

// Health states of a feed (observation.health's health.state).
const (
	Healthy  = "healthy"
	Degraded = "degraded"
	Blind    = "blind"
)

// HealthStates are the states, best first.
var HealthStates = []string{Healthy, Degraded, Blind}

// Resolution states and causes (resolution's resolution.state and resolution.cause).
var (
	ResolutionStates = []string{"reverted", "ratified", "declared-break-glass", "still-live"}
	RevertCauses     = []string{"agent-caused", "policy-triggered", "human-initiated", "automated-remediation",
		"requirement-changed", "external-dependency", "unattributed"}
)

// Limits.
const (
	MaxText        = 4 << 10
	MaxObject      = 64 << 10 // the canonical size of each object a provider reports (state_change before or after, attributes)
	MaxChecks      = 32
	MaxChain       = 32
	DefaultCadence = 15 * time.Minute
)

// Fields are the record fields only observation kinds carry. A provider may not set one on another kind.
var Fields = []string{"scope", "resource", "actor", "action", "state_change", "correlation", "integrity", "times",
	"health", "about", "rule_set", "attribution", "resolution", "verification"}

var required = map[string][]string{
	evidence.KindObservation:  {"scope", "source", "resource", "actor", "action", "integrity", "times"},
	evidence.KindAssessment:   {"scope", "about", "coverage", "tier", "rule_set", "attribution"},
	evidence.KindResolution:   {"scope", "about", "resolution"},
	evidence.KindHealth:       {"scope", "source", "health"},
	evidence.KindVerification: {"scope", "source", "about", "verification"},
}

var allowed = map[string][]string{
	evidence.KindObservation:  {"scope", "resource", "actor", "action", "state_change", "correlation", "integrity", "times", "app", "tier"},
	evidence.KindAssessment:   {"scope", "about", "rule_set", "attribution", "app", "tier"},
	evidence.KindResolution:   {"scope", "about", "resolution", "app"},
	evidence.KindHealth:       {"scope", "health", "app"},
	evidence.KindVerification: {"scope", "about", "verification", "app"},
}

var (
	scopeRx  = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)
	sourceRx = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	eventRx  = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)
	checkRx  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
)

// Is says whether kind is one a provider posts through POST /v1/records for observation (audit-gap is the core's).
func Is(kind string) bool { return slices.Contains(required2(), kind) }

func required2() []string {
	return []string{evidence.KindObservation, evidence.KindAssessment, evidence.KindResolution, evidence.KindHealth, evidence.KindVerification}
}

// Kinds are the kinds a provider posts, in the order they build on each other.
func Kinds() []string { return required2() }

// Result is what Check decided beyond the record's shape.
type Result struct {
	// Monitoring: the observation is an operation on the controls that watch the environment (vocab or the
	// provider's own mark): tier 3, whether or not it succeeded, and it flips its scope's health.
	Monitoring bool
	// Succeeded is the observation's action.succeeded (monitoring flips to blind when it did, degraded when it did not).
	Succeeded bool
	// Source and EventID are the provider's own identity for the event (source.name, source.event_id); the core
	// de-duplicates on them. EventID is "" for a record that names none (a health record).
	Source, EventID string
}

func bad(format string, a ...any) error { return fmt.Errorf(format, a...) }

func str(m map[string]any, k string) (string, bool) { s, ok := m[k].(string); return s, ok }

func text(what string, v any, max int) (string, error) {
	s, ok := v.(string)
	if !ok || s == "" || len(s) > max || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return "", bad("%s is a non-empty string of at most %d bytes", what, max)
	}
	return s, nil
}

func obj(ev map[string]any, k string) (map[string]any, error) {
	m, ok := ev[k].(map[string]any)
	if !ok {
		return nil, bad("%s is an object", k)
	}
	return m, nil
}

func only(what string, m map[string]any, keys ...string) error {
	for k := range m {
		if !slices.Contains(keys, k) {
			return bad("%s has an unknown field %q (one of %v)", what, k, keys)
		}
	}
	return nil
}

func size(what string, v any) error {
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxObject {
		return bad("%s is at most %d bytes", what, MaxObject)
	}
	return nil
}

func boolean(what string, m map[string]any, k string, req bool) (bool, error) {
	v, present := m[k]
	if !present {
		if req {
			return false, bad("%s.%s is true or false", what, k)
		}
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, bad("%s.%s is true or false", what, k)
	}
	return b, nil
}

func rfc3339(what string, v any) (time.Time, error) {
	s, _ := v.(string)
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return t, bad("%s is an RFC 3339 time", what)
	}
	return t, nil
}

// Check holds a provider's record of kind to its shape, rejects what it must not carry, and sets what the core
// decides in ev: an observation's coverage (always observed-not-attributed: seeing a change is not clearing it) and
// the tier of an operation on monitoring (3). ev is the event as records.go built it, with Parse's value types.
func Check(kind string, ev map[string]any, v vocab.Vocabulary) (Result, error) {
	var res Result
	if !Is(kind) {
		for _, f := range Fields {
			if _, present := ev[f]; present {
				return res, bad("%s is a field of the observation kinds %v", f, Kinds())
			}
		}
		return res, nil
	}
	for _, f := range Fields {
		if _, present := ev[f]; present && !slices.Contains(allowed[kind], f) {
			return res, bad("%s is not a field of a %s record", f, kind)
		}
	}
	scope, err := text("scope", ev["scope"], 256)
	if err != nil || !scopeRx.MatchString(scope) {
		return res, bad("scope is 1 to 256 printable characters without spaces (an account, a cluster, a workspace)")
	}
	switch kind {
	case evidence.KindObservation:
		return checkObservation(ev, v)
	case evidence.KindAssessment:
		return res, checkAssessment(ev)
	case evidence.KindResolution:
		return res, checkResolution(ev)
	case evidence.KindVerification:
		res.Source, res.EventID, err = checkVerification(ev)
		return res, err
	default:
		res.Source, err = checkHealth(ev)
		return res, err
	}
}

func checkSource(ev map[string]any, needEvent bool) (name, event string, err error) {
	src, ok := ev["source"].(map[string]any)
	if !ok {
		return "", "", bad("source is {name[, event_id]}")
	}
	if err := only("source", src, "name", "event_id", "level", "kind"); err != nil {
		return "", "", err
	}
	name, _ = str(src, "name")
	if !sourceRx.MatchString(name) {
		return "", "", bad("source.name is a lowercase name (%s)", sourceRx)
	}
	if e, present := src["event_id"]; present {
		if event, err = text("source.event_id", e, 256); err != nil || !eventRx.MatchString(event) {
			return "", "", bad("source.event_id is 1 to 256 printable characters without spaces")
		}
	} else if needEvent {
		return "", "", bad("source.event_id is the provider's own id for the event (the core de-duplicates on it)")
	}
	for _, k := range []string{"level", "kind"} {
		if x, present := src[k]; present {
			if _, err := text("source."+k, x, 64); err != nil {
				return "", "", err
			}
		}
	}
	return name, event, nil
}

func checkObservation(ev map[string]any, v vocab.Vocabulary) (Result, error) {
	var res Result
	var err error
	if res.Source, res.EventID, err = checkSource(ev, true); err != nil {
		return res, err
	}
	if c, present := ev["coverage"]; present && c != evidence.CoverageObservedNotAttributed {
		return res, bad("an observation's coverage is %s: an assessment says what was made of it", evidence.CoverageObservedNotAttributed)
	}
	ev["coverage"] = evidence.CoverageObservedNotAttributed
	// resource
	r, err := obj(ev, "resource")
	if err != nil {
		return res, err
	}
	if err := only("resource", r, "kind", "name", "namespace", "id", "type", "group", "api_version", "region"); err != nil {
		return res, err
	}
	for k, x := range r {
		if _, err := text("resource."+k, x, 1024); err != nil {
			return res, err
		}
	}
	if r["kind"] == nil || (r["name"] == nil && r["id"] == nil) {
		return res, bad("resource names its kind and a name or an id")
	}
	// actor
	a, err := obj(ev, "actor")
	if err != nil {
		return res, err
	}
	if err := only("actor", a, "subject", "chain", "issuer", "client", "attributes"); err != nil {
		return res, err
	}
	if _, err := text("actor.subject", a["subject"], 1024); err != nil {
		return res, err
	}
	if c, present := a["chain"]; present {
		l, ok := c.([]any)
		if !ok || len(l) > MaxChain {
			return res, bad("actor.chain is a list of at most %d subjects (who assumed whom, first to last)", MaxChain)
		}
		for _, x := range l {
			if _, err := text("actor.chain[]", x, 1024); err != nil {
				return res, err
			}
		}
	}
	if i, present := a["issuer"]; present {
		if _, err := text("actor.issuer", i, 1024); err != nil {
			return res, err
		}
	}
	if c, present := a["client"]; present { // self-reported by the actor: a user agent, a tool name
		if _, err := text("actor.client", c, 1024); err != nil {
			return res, err
		}
	}
	if x, present := a["attributes"]; present {
		if _, ok := x.(map[string]any); !ok {
			return res, bad("actor.attributes is an object")
		}
		if err := size("actor.attributes", x); err != nil {
			return res, err
		}
	}
	// action
	ac, err := obj(ev, "action")
	if err != nil {
		return res, err
	}
	if err := only("action", ac, "verb", "api", "succeeded", "refused_reason", "protects_monitoring"); err != nil {
		return res, err
	}
	for _, k := range []string{"verb", "api"} {
		if _, err := text("action."+k, ac[k], 256); err != nil {
			return res, err
		}
	}
	if res.Succeeded, err = boolean("action", ac, "succeeded", true); err != nil {
		return res, err
	}
	if rr, present := ac["refused_reason"]; present {
		if res.Succeeded {
			return res, bad("action.refused_reason is for an action that did not succeed")
		}
		if _, err := text("action.refused_reason", rr, MaxText); err != nil {
			return res, err
		}
	}
	protects, err := boolean("action", ac, "protects_monitoring", false)
	if err != nil {
		return res, err
	}
	api, _ := ac["api"].(string)
	res.Monitoring = protects || monitoring(v, res.Source, api)
	// integrity
	ig, err := obj(ev, "integrity")
	if err != nil {
		return res, err
	}
	if err := only("integrity", ig, "sourceVerified", "completenessClaimed", "method", "health_seq"); err != nil {
		return res, err
	}
	for _, k := range []string{"sourceVerified", "completenessClaimed"} {
		if _, err := boolean("integrity", ig, k, true); err != nil {
			return res, err
		}
	}
	if m, present := ig["method"]; present {
		if _, err := text("integrity.method", m, 128); err != nil {
			return res, err
		}
	}
	if h, present := ig["health_seq"]; present {
		if n, ok := h.(json.Number); !ok || strings.ContainsAny(string(n), ".eE-") {
			return res, bad("integrity.health_seq is the seq of the health record that supports completeness")
		}
	}
	// times
	tm, err := obj(ev, "times")
	if err != nil {
		return res, err
	}
	if err := only("times", tm, "requested", "observed", "delivered"); err != nil {
		return res, err
	}
	if _, err := rfc3339("times.observed", tm["observed"]); err != nil {
		return res, err
	}
	for _, k := range []string{"requested", "delivered"} {
		if x, present := tm[k]; present {
			if _, err := rfc3339("times."+k, x); err != nil {
				return res, err
			}
		}
	}
	// state_change, correlation
	if x, present := ev["state_change"]; present {
		sc, ok := x.(map[string]any)
		if !ok {
			return res, bad("state_change is {before, after}")
		}
		if err := only("state_change", sc, "before", "after"); err != nil {
			return res, err
		}
		for _, k := range []string{"before", "after"} {
			if err := size("state_change."+k, sc[k]); err != nil {
				return res, err
			}
		}
	}
	if x, present := ev["correlation"]; present {
		c, ok := x.(map[string]any)
		if !ok {
			return res, bad("correlation is {grant, plan, task_id, run_id, operation_id}")
		}
		if err := only("correlation", c, "grant", "plan", "task_id", "run_id", "operation_id"); err != nil {
			return res, err
		}
		for k, y := range c {
			if _, err := text("correlation."+k, y, 256); err != nil {
				return res, err
			}
		}
	}
	if err := secretGuard(ev, r); err != nil {
		return res, err
	}
	if res.Monitoring {
		ev["tier"] = json.Number("3")
	}
	return res, nil
}

// Monitoring says whether an observed operation matches the vocabulary's monitoring-protection globs (the same test
// Check applies to an observation). The pipeline (internal/observe/pipeline) uses it next to its rule set's own
// per-provider lists, so there is one vocabulary of what protects monitoring and not two.
func Monitoring(v vocab.Vocabulary, source, api string) bool { return monitoring(v, source, api) }

// monitoring says whether the observed operation matches a configured monitoring-protection glob: "<api>" or
// "<source>:<api>".
func monitoring(v vocab.Vocabulary, source, api string) bool {
	if len(v.MonitoringProtectionOps) == 0 {
		return false
	}
	return pycompat.MatchAny(api, v.MonitoringProtectionOps) || pycompat.MatchAny(source+":"+api, v.MonitoringProtectionOps)
}

func checkAbout(ev map[string]any) error {
	ab, err := obj(ev, "about")
	if err != nil {
		return err
	}
	if err := only("about", ab, "seq"); err != nil {
		return err
	}
	if n, ok := ab["seq"].(json.Number); !ok || strings.ContainsAny(string(n), ".eE-") {
		return bad("about is {seq}: the seq of the record this is about")
	}
	return nil
}

// About is the seq of the record an assessment or a resolution is about (checkAbout has run).
func About(ev map[string]any) (int64, bool) {
	ab, _ := ev["about"].(map[string]any)
	n, ok := ab["seq"].(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func checkAssessment(ev map[string]any) error {
	if err := checkAbout(ev); err != nil {
		return err
	}
	c, _ := ev["coverage"].(string)
	if !slices.Contains(evidence.Coverage, c) {
		return bad("coverage is one of %v", evidence.Coverage)
	}
	t, ok := ev["tier"].(json.Number)
	if !ok || (t != "0" && t != "1" && t != "2" && t != "3") {
		return bad("tier is 0 to 3")
	}
	rs, err := obj(ev, "rule_set")
	if err != nil {
		return err
	}
	if err := only("rule_set", rs, "version", "name"); err != nil {
		return err
	}
	if _, err := text("rule_set.version", rs["version"], 128); err != nil {
		return err
	}
	if n, present := rs["name"]; present {
		if _, err := text("rule_set.name", n, 128); err != nil {
			return err
		}
	}
	at, err := obj(ev, "attribution")
	if err != nil {
		return err
	}
	if err := only("attribution", at, "signal", "detail", "grant"); err != nil {
		return err
	}
	if _, err := text("attribution.signal", at["signal"], 256); err != nil {
		return err
	}
	for _, k := range []string{"detail", "grant"} {
		if x, present := at[k]; present {
			if _, err := text("attribution."+k, x, MaxText); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkResolution(ev map[string]any) error {
	if err := checkAbout(ev); err != nil {
		return err
	}
	if c, present := ev["coverage"]; present && c != evidence.CoverageObservedNotAttributed {
		return bad("a resolution is not a coverage statement: leave coverage unset")
	}
	ev["coverage"] = evidence.CoverageObservedNotAttributed
	r, err := obj(ev, "resolution")
	if err != nil {
		return err
	}
	if err := only("resolution", r, "state", "cause", "by", "note"); err != nil {
		return err
	}
	st, _ := r["state"].(string)
	if !slices.Contains(ResolutionStates, st) {
		return bad("resolution.state is one of %v", ResolutionStates)
	}
	cause, has := r["cause"]
	switch {
	case st == "reverted" && !slices.Contains(RevertCauses, fmt.Sprint(cause)):
		return bad("a reverted resolution names its cause: one of %v", RevertCauses)
	case st != "reverted" && has:
		return bad("resolution.cause is for a reverted resolution")
	}
	for _, k := range []string{"by", "note"} {
		if x, present := r[k]; present {
			if _, err := text("resolution."+k, x, MaxText); err != nil {
				return err
			}
		}
	}
	return nil
}

// Verification methods an observation.verification may name are free text (the feed's own name for how it verified);
// what the core holds it to is that it says it verified, and of which observation.
func checkVerification(ev map[string]any) (source, event string, err error) {
	if source, event, err = checkSource(ev, true); err != nil {
		return "", "", err
	}
	if c, present := ev["coverage"]; present && c != evidence.CoverageObservedNotAttributed {
		return "", "", bad("a verification is not a coverage statement: leave coverage unset")
	}
	ev["coverage"] = evidence.CoverageObservedNotAttributed
	if err := checkAbout(ev); err != nil {
		return "", "", err
	}
	v, err := obj(ev, "verification")
	if err != nil {
		return "", "", err
	}
	if err := only("verification", v, "method", "verified", "reference"); err != nil {
		return "", "", err
	}
	if ok, err := boolean("verification", v, "verified", true); err != nil || !ok {
		return "", "", bad("verification.verified is true: a feed that could not verify an event says nothing about it")
	}
	for _, k := range []string{"method", "reference"} {
		if x, present := v[k]; present || k == "method" {
			if _, err := text("verification."+k, x, 256); err != nil {
				return "", "", err
			}
		}
	}
	return source, event, nil
}

func checkHealth(ev map[string]any) (string, error) {
	name, _, err := checkSource(ev, false)
	if err != nil {
		return "", err
	}
	return name, checkHealthBody(ev)
}

func checkHealthBody(ev map[string]any) error {
	if c, present := ev["coverage"]; present && c != evidence.CoverageObservedNotAttributed {
		return bad("a health record is not a coverage statement: leave coverage unset")
	}
	ev["coverage"] = evidence.CoverageObservedNotAttributed
	h, err := obj(ev, "health")
	if err != nil {
		return err
	}
	if err := only("health", h, "state", "checks", "interval_seconds"); err != nil {
		return err
	}
	st, _ := h["state"].(string)
	if !slices.Contains(HealthStates, st) {
		return bad("health.state is one of %v", HealthStates)
	}
	checks, ok := h["checks"].([]any)
	if !ok || len(checks) == 0 || len(checks) > MaxChecks {
		return bad("health.checks lists the checks that produced the state (1 to %d)", MaxChecks)
	}
	failed := 0
	seen := map[string]bool{}
	for _, x := range checks {
		c, ok := x.(map[string]any)
		if !ok {
			return bad("health.checks[] are {name, ok[, detail]}")
		}
		if err := only("health.checks[]", c, "name", "ok", "detail"); err != nil {
			return err
		}
		n, _ := c["name"].(string)
		if !checkRx.MatchString(n) || seen[n] {
			return bad("health.checks[].name is a unique lowercase name (%s)", checkRx)
		}
		seen[n] = true
		pass, err := boolean("health.checks[]", c, "ok", true)
		if err != nil {
			return err
		}
		if !pass {
			failed++
		}
		if d, present := c["detail"]; present {
			if _, err := text("health.checks[].detail", d, MaxText); err != nil {
				return err
			}
		}
	}
	if st == Healthy && failed > 0 {
		return bad("health.state is healthy but %d check(s) failed: a feed with a failing check is degraded or blind", failed)
	}
	if st != Healthy && failed == 0 {
		return bad("health.state is %s but no check failed: name the check that did", st)
	}
	if i, present := h["interval_seconds"]; present {
		n, ok := i.(json.Number)
		v, err := n.Int64()
		if !ok || err != nil || v < 10 || v > 7*24*3600 {
			return bad("health.interval_seconds is how often the provider reports, 10 to 604800")
		}
	}
	return nil
}

// secretGuard is the observation's guard rail for Kubernetes Secrets and anything shaped like one: a Secret is
// observed at Metadata only, so an observation of one carries no state_change and says its source level is Metadata;
// and no observation carries a Secret's body anywhere in what the provider reported.
func secretGuard(ev, resource map[string]any) error {
	if isSecretKind(resource["kind"]) {
		if _, present := ev["state_change"]; present {
			return bad("a Secret is observed at Metadata only: an observation of one carries no state_change")
		}
		src, _ := ev["source"].(map[string]any)
		if lvl, _ := src["level"].(string); lvl != "Metadata" {
			return bad("a Secret is observed at Metadata only: source.level is Metadata")
		}
	}
	for _, k := range []string{"state_change", "actor", "correlation", "action", "resource", "source"} {
		if hasSecretBody(ev[k]) {
			return bad("an observation does not carry a Secret's body (%s holds one)", k)
		}
	}
	return nil
}

func isSecretKind(v any) bool {
	s, _ := v.(string)
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "secret" || s == "secrets" || s == "secretlist"
}

// hasSecretBody finds an object of kind Secret (or a list of them) anywhere in v, or the data and stringData a Secret
// body is made of next to a kind or apiVersion key.
func hasSecretBody(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if isSecretKind(x["kind"]) && x["resource"] == nil {
			_, d := x["data"]
			_, sd := x["stringData"]
			if d || sd || x["apiVersion"] != nil || x["metadata"] != nil {
				return true
			}
		}
		for k, y := range x {
			if k == "stringData" {
				return true
			}
			if hasSecretBody(y) {
				return true
			}
		}
	case []any:
		for _, y := range x {
			if hasSecretBody(y) {
				return true
			}
		}
	}
	return false
}

func fmtf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

// HealthState is the state a health record reports ("" for nil or a record that is not one).
func HealthState(r Record) string {
	h, _ := r["health"].(map[string]any)
	s, _ := h["state"].(string)
	return s
}

// Rank orders health states, healthy 0; an unknown or empty state ranks as blind.
func Rank(state string) int { return rank(state) }

// Supports says whether a health record supports an observation's completeness claim at now: the feed was healthy,
// and the record is not stale (twice its reporting interval has not passed).
func Supports(r Record, now time.Time) bool {
	if HealthState(r) != Healthy {
		return false
	}
	iv := DefaultCadence
	if h, ok := r["health"].(map[string]any); ok {
		if n, ok := intOf(h["interval_seconds"]); ok && n > 0 {
			iv = time.Duration(n) * time.Second
		}
	}
	return now.Before(tsOf(r).Add(2 * iv))
}

// PrevRank is Rank of the health record before this one: -1 when the scope's source has none (never seen).
func PrevRank(r Record) int {
	if r == nil {
		return -1
	}
	return rank(HealthState(r))
}
