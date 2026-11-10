package collector

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/observe/pipeline"
)

// ProviderName is the provider the core registers the collector as (CLEARANCE_PROVIDERS, kinds observation,
// assessment, resolution, observation.health).
const ProviderName = "observe-k8s"

// maxState is the most a state_change side may be (observe.MaxObject is 64 KiB; the rest is headroom).
const maxState = 56 << 10

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// level is the audit level of the event as recorded; a Secret's is always Metadata (the receiver cut anything else).
func levelOf(raw map[string]any) string {
	l, _ := raw["level"].(string)
	if l == "" {
		return "Metadata"
	}
	return l
}

// stateSide is one side of state_change: the canonical object, or its digest when it is too large to carry.
func stateSide(o map[string]any, hash string) any {
	if o == nil {
		return nil
	}
	b, _ := json.Marshal(o)
	if len(b) > maxState {
		return map[string]any{"truncated": true, "sha256": hash, "bytes": len(b)}
	}
	return o
}

// observation builds the observation record of an assessed event. A Secret carries no state_change and says its
// source level is Metadata: the object is not in the event (the policy records Secrets at Metadata, the receiver cuts
// anything more), and the record names the Secret and its namespace, not its keys.
func observation(source, level string, complete bool, a *pipeline.Assessment, now time.Time) *client.RecordRequest {
	e := a.Event()
	name := e.Name
	res := map[string]any{"kind": e.Kind}
	if name != "" {
		res["name"] = name
	} else {
		res["id"] = "-" // a create by generateName, a deletecollection: the audit event names no object
	}
	if e.Namespace != "" {
		res["namespace"] = e.Namespace
	}
	attrs := map[string]any{}
	if len(e.Groups) > 0 {
		attrs["groups"] = e.Groups
	}
	if e.TaskID != "" {
		attrs["task_id"] = e.TaskID
	}
	if e.Subresource != "" {
		attrs["subresource"] = e.Subresource
	}
	actor := map[string]any{"subject": e.Subject, "attributes": attrs}
	if e.Impersonated != "" {
		actor["chain"] = []string{e.Subject, e.Impersonated}
	}
	if e.UserAgent != "" {
		actor["client"] = cut(e.UserAgent, 1000)
	}
	action := map[string]any{"verb": e.Verb, "api": e.API, "succeeded": e.Succeeded}
	if !e.Succeeded {
		reason := fmt.Sprintf("HTTP %d", e.Code)
		var keys []string
		for k := range e.AuditAnnotations {
			if strings.HasPrefix(k, "validation.policy.admission.k8s.io/") || strings.HasPrefix(k, "authorization.k8s.io/") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			reason += "; " + k + ": " + e.AuditAnnotations[k]
		}
		action["refused_reason"] = cut(reason, 3500)
	}
	if e.Monitoring {
		action["protects_monitoring"] = true
	}
	src := map[string]any{"name": source, "event_id": e.ID, "level": level}
	rec := client.ProviderEvent{
		Scope: client.String(e.Scope), Source: src, Resource: res, Actor: actor, Action: action,
		Integrity: map[string]any{"sourceVerified": true, "completenessClaimed": complete,
			"method": "kube-apiserver audit event"},
		Times: map[string]any{"observed": ts(e.Time), "delivered": ts(now)},
	}
	if !strings.EqualFold(e.Kind, "secret") && (e.Before != nil || e.After != nil) {
		rec.StateChange = map[string]any{"before": stateSide(e.Before, e.BeforeHash), "after": stateSide(e.After, e.AfterHash)}
	} else if strings.EqualFold(e.Kind, "secret") {
		src["level"] = "Metadata"
	}
	corr := map[string]any{}
	if e.TaskID != "" {
		corr["task_id"] = e.TaskID
	}
	if a.Grant != "" && (a.Outcome == pipeline.OutcomeCleared || claimsGrant(e, a.Grant)) {
		corr["grant"] = a.Grant
	}
	if len(corr) > 0 {
		rec.Correlation = corr
	}
	return &client.RecordRequest{Kind: "observation", Record: rec}
}

// claimsGrant: the object itself names the grant (a stamp annotation), as opposed to the grant being found by the
// collector's own lookup of what a grant lists.
func claimsGrant(e *pipeline.Event, grant string) bool {
	for _, v := range e.ObjAnnotations {
		if v == grant {
			return true
		}
	}
	return false
}

// assessment is what was made of the observation at seq.
func assessment(a *pipeline.Assessment, seq int64) *client.RecordRequest {
	detail := fmt.Sprintf("[%s] %s", a.Severity, a.Detail)
	if a.Confidence != "" {
		detail += " (confidence: " + a.Confidence + ")"
	}
	if len(a.Diff) > 0 {
		detail += "; diff: " + strings.Join(a.Diff, "; ")
	}
	at := map[string]any{"signal": a.Signal, "detail": cut(detail, 3900)}
	if a.Grant != "" {
		at["grant"] = a.Grant
	}
	return &client.RecordRequest{Kind: "assessment", Record: client.ProviderEvent{
		Scope: client.String(a.Scope), About: map[string]any{"seq": seq},
		Coverage: client.String(a.Coverage), Tier: &a.Tier,
		RuleSet:     map[string]any{"name": a.RuleSet.Name, "version": a.RuleSet.Version},
		Attribution: at}}
}

// resolutionReverted is the resolution of an apply-and-revert the pipeline folded into one exception.
func resolutionReverted(scope string, seq int64, note string) *client.RecordRequest {
	return &client.RecordRequest{Kind: "resolution", Record: client.ProviderEvent{
		Scope: client.String(scope), About: map[string]any{"seq": seq},
		Resolution: map[string]any{"state": "reverted", "cause": "unattributed", "by": ProviderName, "note": cut(note, 3900)}}}
}

// resolutionStillLive is the collector's own first resolution of a change it did not see put back.
func resolutionStillLive(scope string, seq int64) *client.RecordRequest {
	return &client.RecordRequest{Kind: "resolution", Record: client.ProviderEvent{
		Scope: client.String(scope), About: map[string]any{"seq": seq},
		Resolution: map[string]any{"state": "still-live", "by": ProviderName}}}
}

// HealthCheck is one check of a health record.
type HealthCheck struct {
	Name   string
	OK     bool
	Detail string
}

func healthRecord(scope, source, state string, checks []HealthCheck, every time.Duration) *client.RecordRequest {
	cs := make([]any, 0, len(checks))
	for _, c := range checks {
		m := map[string]any{"name": c.Name, "ok": c.OK}
		if c.Detail != "" {
			m["detail"] = cut(c.Detail, 3900)
		}
		cs = append(cs, m)
	}
	return &client.RecordRequest{Kind: "observation.health", Record: client.ProviderEvent{
		Scope: client.String(scope), Source: map[string]any{"name": source},
		Health: map[string]any{"state": state, "checks": cs, "interval_seconds": int(every / time.Second)}}}
}

// gapObservation and its assessment: a change the watch stream showed and no audit event reported. There is no actor:
// the source is the API server's watch, not its audit log, so the record says what changed and that nobody was
// recorded changing it.
func gapObservation(scope, source string, ch Change, hash func(map[string]any) string, now time.Time) *client.RecordRequest {
	res := map[string]any{"kind": ch.Kind, "name": ch.Name}
	if ch.Namespace != "" {
		res["namespace"] = ch.Namespace
	}
	verb := "update"
	switch {
	case ch.Created:
		verb = "create"
	case ch.Deleted:
		verb = "delete"
	}
	rec := client.ProviderEvent{
		Scope: client.String(scope),
		Source: map[string]any{"name": source, "level": "watch",
			"event_id": "gap:" + scope + ":" + ch.Kind + "/" + ch.Namespace + "/" + ch.Name + ":" + ch.RV},
		Resource: res,
		Actor:    map[string]any{"subject": "unknown (no audit event)"},
		Action:   map[string]any{"verb": verb, "api": "watch." + strings.ToLower(ch.Kind), "succeeded": true},
		Integrity: map[string]any{"sourceVerified": false, "completenessClaimed": false,
			"method": "watch stream change with no audit event"},
		Times: map[string]any{"observed": ts(ch.At), "delivered": ts(now)},
	}
	if ch.Before != nil || ch.After != nil {
		rec.StateChange = map[string]any{"before": stateSide(canon(ch.Before), hashOf(hash, ch.Before)), "after": stateSide(canon(ch.After), hashOf(hash, ch.After))}
	}
	return &client.RecordRequest{Kind: "observation", Record: rec}
}

func hashOf(h func(map[string]any) string, o map[string]any) string {
	if o == nil {
		return ""
	}
	return h(o)
}

// canon drops what is not desired state from a watch object (status, managed fields) for the record.
func canon(o map[string]any) map[string]any {
	if o == nil {
		return nil
	}
	out := make(map[string]any, len(o))
	for k, v := range o {
		if k == "status" {
			continue
		}
		out[k] = v
	}
	if m, ok := o["metadata"].(map[string]any); ok {
		mm := make(map[string]any, len(m))
		for k, v := range m {
			if !slices.Contains([]string{"managedFields", "resourceVersion", "uid", "generation", "creationTimestamp", "selfLink"}, k) {
				mm[k] = v
			}
		}
		out["metadata"] = mm
	}
	return out
}

func gapAssessment(scope string, seq int64, ch Change, rs pipeline.RuleSetRef, grace time.Duration) *client.RecordRequest {
	tier := 1
	return &client.RecordRequest{Kind: "assessment", Record: client.ProviderEvent{
		Scope: client.String(scope), About: map[string]any{"seq": seq}, Coverage: client.String("observed-not-attributed"), Tier: &tier,
		RuleSet: map[string]any{"name": rs.Name, "version": rs.Version},
		Attribution: map[string]any{"signal": "audit-gap", "detail": fmt.Sprintf(
			"[high] %s/%s/%s changed (resourceVersion %s) and the audit feed reported no write to it within %s: the policy dropped it, "+
				"the webhook lost it, or the feed was down. Who changed it is not known.", ch.Kind, ch.Namespace, ch.Name, ch.RV, grace)}}}
}
