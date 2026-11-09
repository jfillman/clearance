package gate

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
)

// Provider reports the gate acts on (C-6), written through POST /v1/records by a registered deployment-gate
// provider and sealed with its name.
//
// deploy.exception is a change that landed outside a clearance, as a provider saw it. Its `exception` object says
// which kind, and what each kind must carry:
//
//	out-of-band     objects (>= 1): live objects with no grant, or a hash no grant lists (the Argo agent, G-ARGO-3)
//	drift           addresses or objects (>= 1): an unexpected plan diff or live drift (G-TF-3 drift detection)
//	untraced-apply  actor: the principal behind a state write no deploy.outcome explains (G-TF-3, CloudTrail)
//	digest-mismatch expected and observed digests, and change.id: what was applied is not what was cleared
//	                (G-TF-2's outcome route; the CMP's applied-tree check)
//
// The core sets the record's coverage from the kind (out-of-band-detected, or observed-not-attributed for drift),
// tags it with the break-glass window open for its cluster and environment (breakglass, verified), and when it
// names a change (change.id) that is holding or cleared moves the change to exception, revoking its token.
//
// deploy.degraded is a provider's report, once the core answers again, of what it did while the core was
// unreachable: decision allow (it let the change land under the outage policy) or deny (it held it), coverage
// coverage-unavailable, and the outage window it saw (outage: {from, to}). The core adds outage_policy (verified):
// the action the policy names for the change (the registered change's outage, else the baseline for the claimed
// tier, else hold for an unknown tier) and whether the provider conformed. An allow naming a holding change moves
// it to degraded.
const (
	KindException = "deploy.exception"
	KindDegraded  = "deploy.degraded"
)

// ExceptionKinds are deploy.exception's kinds.
var ExceptionKinds = []string{"out-of-band", "drift", "untraced-apply", "digest-mismatch", KindAttemptedRefused, KindMonitoringProtection}

// The exception kinds O-1 adds. attempted-refused is an operation something tried and a control refused: nothing
// landed, so it never moves a change to exception. monitoring-protection is an operation on the controls that watch
// the environment (a trail, an audit policy, a recorder): a tier 3 exception whether or not it succeeded.
const (
	KindAttemptedRefused     = "attempted-refused"
	KindMonitoringProtection = "monitoring-protection"
)

// ExceptionCoverage is the coverage the core gives each exception kind.
var ExceptionCoverage = map[string]string{
	"out-of-band":            "out-of-band-detected",
	"drift":                  "observed-not-attributed",
	"untraced-apply":         "out-of-band-detected",
	"digest-mismatch":        "out-of-band-detected",
	KindAttemptedRefused:     evidence.CoverageAttemptedRefused,
	KindMonitoringProtection: "out-of-band-detected",
}

// Report caps.
const (
	MaxExceptionObjects   = MaxObjects
	MaxExceptionAddresses = 4000
	maxReportText         = 4 << 10
)

var (
	changeIDRx  = regexp.MustCompile(`^ch-[0-9a-f]{16}\z`)
	exceptionKs = setOf("kind", "objects", "addresses", "actor", "expected", "observed", "state", "detected_at", "detail")
	objectRefKs = setOf("apiVersion", "kind", "namespace", "name", "rendered", "grant")
	stateKs     = setOf("backend", "key", "version")
	outageKs    = setOf("from", "to")
)

// BadReport is a provider report the gate refuses (400).
type BadReport struct{ Message string }

func (e *BadReport) Error() string { return e.Message }

func badReport(format string, a ...any) *BadReport { return &BadReport{fmt.Sprintf(format, a...)} }

// IsReport says whether kind is a provider record the gate checks and acts on.
func IsReport(kind string) bool { return kind == KindException || kind == KindDegraded }

func shortText(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok && s != "" && len(s) <= maxReportText
}

// where is the report's destination: cluster and environment, both required. A terraform-plan change has no
// cluster, so a report about one names destination.workspace {backend, key, name} instead (the subject's workspace,
// G-TF-1); cluster is then the workspace's one-line name (Workspace.Ref) and env is its name. A destination carries
// one or the other, never both.
func where(ev store.Event) (cluster, env string, err error) {
	d, _ := ev["destination"].(map[string]any)
	if w, present := d["workspace"]; present {
		if d["cluster"] != nil || d["environment"] != nil {
			return "", "", badReport("a %s record's destination is a cluster and environment, or a workspace, not both", ev["tool"])
		}
		m, ok := w.(map[string]any)
		if !ok || unknownKey(m, workspaceKeys) != "" {
			return "", "", badReport("destination.workspace is {backend, key, name}")
		}
		backend, _ := m["backend"].(string)
		key, _ := m["key"].(string)
		name, _ := m["name"].(string)
		if !backendRx.MatchString(backend) || !printable(key, 1024) || !workspaceRx.MatchString(name) {
			return "", "", badReport("destination.workspace is {backend, key, name}: a backend type, the state key and the workspace name")
		}
		return Workspace{backend, key, name}.Ref(), name, nil
	}
	cluster, _ = d["cluster"].(string)
	env, _ = d["environment"].(string)
	if !nameRx.MatchString(cluster) || !nameRx.MatchString(env) {
		return "", "", badReport("a %s record names its destination: {cluster, environment}, or for a Terraform plan {workspace: {backend, key, name}}", ev["tool"])
	}
	return cluster, env, nil
}

// changeRef is the change the report names (change.id), "" when none.
func changeRef(ev store.Event) (string, error) {
	c, present := ev["change"]
	if !present {
		return "", nil
	}
	m, _ := c.(map[string]any)
	id, ok := m["id"].(string)
	if !ok || !changeIDRx.MatchString(id) {
		return "", badReport("change.id is a change id (ch- and 16 hex)")
	}
	return id, nil
}

func checkObjects(v any) (int, error) {
	l, ok := v.([]any)
	if !ok || len(l) > MaxExceptionObjects {
		return 0, badReport("exception.objects is a list of at most %d objects", MaxExceptionObjects)
	}
	for _, x := range l {
		o, ok := x.(map[string]any)
		if !ok {
			return 0, badReport("exception.objects[] are objects {apiVersion, kind, namespace, name, rendered, grant}")
		}
		if k := unknownKey(o, objectRefKs); k != "" {
			return 0, badReport("exception.objects[] has an unknown field %q", k)
		}
		for k, v := range o {
			if s, ok := shortText(v); !ok || ((k == "kind" || k == "name") && s == "") {
				return 0, badReport("exception.objects[].%s is a string", k)
			}
		}
		if o["kind"] == nil || o["name"] == nil {
			return 0, badReport("exception.objects[] names kind and name")
		}
	}
	return len(l), nil
}

// CheckReport checks a deploy.exception or deploy.degraded event (the record a provider posted, as the core built
// it) and sets what the core decides about it: the coverage of an exception. It needs no store; Service.Report
// adds what does.
func CheckReport(ev store.Event, now time.Time) error {
	if _, _, err := where(ev); err != nil {
		return err
	}
	if _, err := changeRef(ev); err != nil {
		return err
	}
	switch ev["tool"] {
	case KindException:
		return checkException(ev)
	case KindDegraded:
		return checkDegraded(ev, now)
	}
	return badReport("%v is not a gate report", ev["tool"])
}

func checkException(ev store.Event) error {
	x, ok := ev["exception"].(map[string]any)
	if !ok {
		return badReport("a deploy.exception record carries exception: {kind, ...} (kind: one of %v)", ExceptionKinds)
	}
	if k := unknownKey(x, exceptionKs); k != "" {
		return badReport("exception has an unknown field %q", k)
	}
	kind, _ := x["kind"].(string)
	if !slices.Contains(ExceptionKinds, kind) {
		return badReport("exception.kind is one of %v", ExceptionKinds)
	}
	objects := 0
	if v, present := x["objects"]; present {
		n, err := checkObjects(v)
		if err != nil {
			return err
		}
		objects = n
	}
	addresses := 0
	if v, present := x["addresses"]; present {
		l, ok := v.([]any)
		if !ok || len(l) > MaxExceptionAddresses {
			return badReport("exception.addresses is a list of at most %d strings", MaxExceptionAddresses)
		}
		for _, a := range l {
			if _, ok := shortText(a); !ok {
				return badReport("exception.addresses is a list of strings")
			}
		}
		addresses = len(l)
	}
	for _, k := range []string{"actor", "expected", "observed", "detail"} {
		if v, present := x[k]; present {
			if _, ok := shortText(v); !ok {
				return badReport("exception.%s is a string of at most %d bytes", k, maxReportText)
			}
		}
	}
	if v, present := x["detected_at"]; present {
		s, _ := v.(string)
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return badReport("exception.detected_at is an RFC 3339 time")
		}
	}
	if v, present := x["state"]; present {
		m, ok := v.(map[string]any)
		if !ok {
			return badReport("exception.state is {backend, key, version}")
		}
		if k := unknownKey(m, stateKs); k != "" {
			return badReport("exception.state has an unknown field %q", k)
		}
		for k, v := range m {
			if _, ok := shortText(v); !ok {
				return badReport("exception.state.%s is a string", k)
			}
		}
	}
	id, _ := changeRef(ev)
	switch kind {
	case "out-of-band":
		if objects == 0 {
			return badReport("an out-of-band exception lists the objects it found (exception.objects)")
		}
	case "drift":
		if objects == 0 && addresses == 0 {
			return badReport("a drift exception lists what drifted (exception.addresses or exception.objects)")
		}
	case "untraced-apply":
		if x["actor"] == nil {
			return badReport("an untraced-apply exception names the actor behind the write (exception.actor)")
		}
	case KindAttemptedRefused, KindMonitoringProtection:
		if x["actor"] == nil || x["detail"] == nil {
			return badReport("a %s exception names the actor and the operation (exception.actor, exception.detail)", kind)
		}
	case "digest-mismatch":
		if x["expected"] == nil || x["observed"] == nil || id == "" {
			return badReport("a digest-mismatch exception names the change (change.id) and the expected and observed digests")
		}
	}
	want := ExceptionCoverage[kind]
	if c, present := ev["coverage"]; present && c != want {
		return badReport("a %s exception's coverage is %s (the core sets it)", kind, want)
	}
	ev["coverage"] = want
	return nil
}

func checkDegraded(ev store.Event, now time.Time) error {
	if ev["coverage"] != "coverage-unavailable" {
		return badReport("a deploy.degraded record is what a provider did without the core: coverage is coverage-unavailable")
	}
	if d := ev["decision"]; d != "allow" && d != "deny" {
		return badReport("a deploy.degraded record's decision is allow (it let the change land) or deny (it held it)")
	}
	if ev["rule"] != nil {
		return badReport("a deploy.degraded record carries no rule: the core decided nothing")
	}
	o, ok := ev["outage"].(map[string]any)
	if !ok {
		return badReport("a deploy.degraded record carries outage: {from, to}, the window the core was unreachable")
	}
	if k := unknownKey(o, outageKs); k != "" {
		return badReport("outage has an unknown field %q", k)
	}
	var at [2]time.Time
	for i, k := range []string{"from", "to"} {
		s, _ := o[k].(string)
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return badReport("outage.%s is an RFC 3339 time", k)
		}
		at[i] = t
	}
	if at[1].Before(at[0]) || at[1].After(now.Add(5*time.Minute)) {
		return badReport("outage.from is before outage.to, and outage.to is not in the future")
	}
	return nil
}

// Report records a provider's deploy.exception or deploy.degraded (sealed by wr, the provider's writer) and acts on
// it in the same transaction: the break-glass window it falls in, the outage policy it was held to, and the state
// of the change it names. ev is the event the core built from the provider's record; CheckReport is run here.
// Errors: *BadReport, *ErrTransition (a bug), a store error.
func (s *Service) Report(ctx context.Context, ev store.Event, wr evidence.Writer) (store.Record, error) {
	if err := CheckReport(ev, s.now()); err != nil {
		return nil, err
	}
	cluster, env, _ := where(ev)
	id, _ := changeRef(ev)
	var out store.Record
	err := s.op(ctx, func(tx store.Tx, w *writer) error {
		verified := maps.Clone(wr.Verified)
		if verified == nil {
			verified = maps.Clone(evidence.ProviderVerified)
		}
		var c *Change
		if id != "" && !s.Config.Off {
			var err error
			if c, err = load(ctx, tx, id); err != nil {
				return err
			}
		}
		if !s.Config.Off {
			app, _ := ev["app"].(string)
			bg, err := openWindow(ctx, tx, cluster, env, &app, w.now)
			if err != nil {
				return err
			}
			if bg != nil {
				ev["breakglass"] = bg.ID
				verified["breakglass"] = true
			}
		}
		if c != nil {
			stampClass(ev, c, s.Policy)
			verified["operational_class"], verified["class_mapping"] = true, true
		}
		if ev["tool"] == KindDegraded {
			ev["outage_policy"] = s.outagePolicy(ev, c)
			verified["outage_policy"] = true
		}
		sealed := wr
		sealed.Verified = verified
		rec, err := tx.Append(ctx, ev, sealed)
		if err != nil {
			return err
		}
		out = rec
		seq, _ := SeqInt(rec["seq"])
		if c == nil {
			return nil
		}
		now := PyTime{w.now}
		switch {
		case ev["tool"] == KindException && (c.State == StateHolding || c.State == StateCleared) &&
			ev["exception"].(map[string]any)["kind"] != KindAttemptedRefused:
			kind, _ := ev["exception"].(map[string]any)["kind"].(string)
			w.move(c, StateException, "exception: "+kind, map[string]any{"exception": seq, "kind": kind})
			c.Ended = &Ended{Seq: seq, Tool: KindException, Kind: kind}
		case ev["tool"] == KindDegraded && ev["decision"] == "allow" && c.State == StateHolding:
			w.move(c, StateDegraded, "", nil)
			c.Ended = &Ended{Seq: seq, Tool: KindDegraded}
		default:
			return nil
		}
		c.DecidedAt, c.UpdatedAt = &now, now
		w.settle(c)
		w.put(c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// outagePolicy is what the outage policy said the provider should have done: the named change's outage action,
// else the baseline for the tier the provider claims, else hold (a provider that never reached the core cannot
// know the tier, and an unknown tier is held).
func (s *Service) outagePolicy(ev store.Event, c *Change) map[string]any {
	action, source := OutageHold, "unknown-tier"
	switch {
	case c != nil:
		action, source = c.Outage, "change"
		if action == "" { // a change registered before C-6 carries no outage of its own
			action, source = s.Policy.OutageFor(c.Tier), "baseline"
		}
	case ev["tier"] != nil:
		if t, ok := SeqInt(ev["tier"]); ok {
			action, source = s.Policy.OutageFor(int(t)), "baseline"
		}
	}
	return map[string]any{"action": action, "source": source,
		"conforms": ev["decision"] == "deny" || action == OutageAllow}
}

// exceptionTools are the records the packet's exceptions section lists (clearance-api GET /v1/exceptions), beside
// any record whose coverage is coverage-unavailable.
var exceptionTools = []string{KindException, KindDegraded, ToolBreakglassOpen, ToolBreakglassClose}

// ExceptionTools is exceptionTools, sorted (a copy).
func ExceptionTools() []string {
	out := slices.Clone(exceptionTools)
	sort.Strings(out)
	return out
}
