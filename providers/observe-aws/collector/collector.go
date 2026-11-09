package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/observe/pipeline"
	"github.com/jfillman/clearance/providers/observe-aws/scope"
)

// ProviderName is the provider (and source.name) every record carries. Health is kept per (scope, source), so one
// source name gives an account one health.
const ProviderName = "observe-aws"

// Core takes the collector's records (client.Client).
type Core interface {
	Record(ctx context.Context, req *client.RecordRequest) (*client.RecordRef, error)
}

// Config is the collector's settings.
type Config struct {
	Accounts []string // the accounts observed; an event for another is counted and not assessed
	Version  string
}

// Stats are the collector's counters, for logs and the health record.
type Stats struct {
	Ingested      map[string]int `json:"ingested"` // by feed
	Posted        int            `json:"posted"`
	Duplicates    int            `json:"duplicates"` // the core already had the event (a redelivery)
	ConfigOnly    int            `json:"config_only"`
	NotWrites     int            `json:"not_writes"`
	NotEvaluated  map[string]int `json:"not_evaluated"`
	OutOfAccounts int            `json:"out_of_accounts"`
	Filtered      int            `json:"filtered"`
	Errors        int            `json:"errors"`
}

// Collector runs the feeds' items through the scope filter, the reconciler and the pipeline, and posts the result.
type Collector struct {
	Cfg    Config
	Pipe   *pipeline.Pipeline
	Filter *scope.Filter
	Rec    *Reconciler
	Core   Core
	// Lookups, when set, is refreshed before each Step (EvidenceLookups); a failed refresh is logged and the last
	// list stays in force.
	Lookups interface{ Refresh(context.Context) error }
	Now     func() time.Time
	Log     *slog.Logger

	mu    sync.Mutex
	stats Stats
	seqs  map[string]int64 // event id -> its observation's seq, for the resolutions a flush makes
	order []string
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Collector) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

func (c *Collector) count(f func(*Stats)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stats.Ingested == nil {
		c.stats.Ingested, c.stats.NotEvaluated = map[string]int{}, map[string]int{}
	}
	f(&c.stats)
}

// Stats is a copy of the counters.
func (c *Collector) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Ingested, s.NotEvaluated = map[string]int{}, map[string]int{}
	for k, v := range c.stats.Ingested {
		s.Ingested[k] = v
	}
	for k, v := range c.stats.NotEvaluated {
		s.NotEvaluated[k] = v
	}
	return s
}

func (c *Collector) governed(account string) bool {
	return len(c.Cfg.Accounts) == 0 || slices.Contains(c.Cfg.Accounts, account)
}

// Ingest takes one delivery. What the collector will not assess (a read, a change by an AWS service, an account it
// does not observe, an area outside the first-release scope) is counted and acked here: there is nothing to post for
// it. The rest is held by the reconciler until Step posts it.
func (c *Collector) Ingest(it *Item) error {
	c.count(func(s *Stats) { s.Ingested[it.Feed]++ })
	if it.Config != nil {
		cc := it.Config
		if !c.governed(cc.Account) {
			c.count(func(s *Stats) { s.OutOfAccounts++ })
			runAcks(it.Acks)
			return nil
		}
		if d := c.Filter.DecideConfig(cc.ResourceType); !d.Evaluated {
			c.count(func(s *Stats) { s.NotEvaluated[d.Area]++ })
			runAcks(it.Acks)
			return nil
		}
		c.Rec.AddConfig(it)
		return nil
	}
	v, err := parseCT(it.Raw)
	if err != nil {
		c.count(func(s *Stats) { s.Errors++ })
		return err
	}
	if !v.Write() {
		c.count(func(s *Stats) { s.NotWrites++ })
		runAcks(it.Acks)
		return nil
	}
	if !c.governed(v.Account) {
		c.count(func(s *Stats) { s.OutOfAccounts++ })
		runAcks(it.Acks)
		return nil
	}
	if d := c.Filter.Decide(v.Service, v.Name, v.Data(), v.Bucket); !d.Evaluated {
		c.count(func(s *Stats) { s.NotEvaluated[d.Area]++ })
		runAcks(it.Acks)
		return nil
	}
	c.Rec.AddCT(it, v)
	return nil
}

// Step posts everything the reconciler has due, then closes the correlation and posts the resolutions that follow
// from it. A change that could not be posted goes back and is retried; the errors are joined.
func (c *Collector) Step(ctx context.Context) error {
	if c.Lookups != nil {
		if err := c.Lookups.Refresh(ctx); err != nil {
			c.log().Warn("refreshing the lookups failed; the last list stays in force", "err", err.Error())
		}
	}
	var errs []string
	for _, m := range c.Rec.Ready() {
		if err := c.emit(ctx, m); err != nil {
			c.Rec.Fail(m)
			c.count(func(s *Stats) { s.Errors++ })
			errs = append(errs, fmt.Sprintf("%s: %v", m.ID(), err))
			continue
		}
		c.Rec.Done(m)
	}
	if err := c.resolve(ctx); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (c *Collector) remember(id string, seq int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seqs == nil {
		c.seqs = map[string]int64{}
	}
	if _, ok := c.seqs[id]; !ok {
		c.order = append(c.order, id)
	}
	c.seqs[id] = seq
	for len(c.order) > 20000 {
		delete(c.seqs, c.order[0])
		c.order = c.order[1:]
	}
}

func (c *Collector) seqOf(id string) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.seqs[id]
	return s, ok
}

func (c *Collector) post(ctx context.Context, kind string, ev client.ProviderEvent) (*client.RecordRef, error) {
	return c.Core.Record(ctx, &client.RecordRequest{Kind: kind, Record: ev})
}

// emit posts one change: its observation, the assessment of it and, when nothing cleared it, a still-live resolution.
func (c *Collector) emit(ctx context.Context, m *Merged) error {
	if m.View == nil {
		return c.emitConfigOnly(ctx, m)
	}
	it, v := m.Item, m.View
	scopeID := orElse(v.Account, "unknown")
	a, disp, _, err := c.Pipe.Process(pipeline.RawEvent{Provider: pipeline.AWS, Scope: scopeID, Raw: it.Raw})
	if err != nil {
		return fmt.Errorf("pipeline: %w", err)
	}
	if disp != pipeline.Assessed {
		c.count(func(s *Stats) { s.Filtered++ })
		return nil
	}
	ref, err := c.post(ctx, evidence.KindObservation, c.observation(m, a))
	if err != nil {
		return fmt.Errorf("posting the observation: %w", err)
	}
	c.remember(v.ID, ref.Seq)
	if ref.Duplicate {
		// The core already has this event (a redelivery, or the other feed's copy). ref.Seq is the original record's
		// seq. The chain is posted whole anyway: the assessment and resolution carry deterministic event ids, so the
		// core's de-duplication makes each post idempotent and a failed assessment is completed by the retry.
		c.count(func(s *Stats) { s.Duplicates++ })
	} else {
		c.count(func(s *Stats) { s.Posted++ })
	}
	as := c.assessment(m, a, ref.Seq)
	as.Source["event_id"] = v.ID + "/assessment"
	if _, err := c.post(ctx, evidence.KindAssessment, as); err != nil {
		return fmt.Errorf("posting the assessment of seq %d: %w", ref.Seq, err)
	}
	if a.Coverage != evidence.CoverageAuthorizedAndVerified {
		rr := resolution(scopeID, ref.Seq, "still-live", "")
		rr.Source["event_id"] = v.ID + "/resolution"
		if _, err := c.post(ctx, evidence.KindResolution, rr); err != nil {
			return fmt.Errorf("posting the resolution of seq %d: %w", ref.Seq, err)
		}
	}
	return nil
}

func resolution(scopeID string, about int64, state, cause string) client.ProviderEvent {
	r := map[string]any{"state": state}
	if cause != "" {
		r["cause"] = cause
	}
	return client.ProviderEvent{Scope: client.String(scopeID), About: map[string]any{"seq": about}, Resolution: r,
		Source: map[string]any{"name": ProviderName}}
}

// resolve closes the pipeline's correlation and posts `reverted` for the events of an apply-and-revert exception.
func (c *Collector) resolve(ctx context.Context) error {
	_, excs := c.Pipe.Flush()
	var errs []string
	for _, x := range excs {
		if !x.Reverted {
			continue
		}
		for _, id := range x.Events {
			seq, ok := c.seqOf(id)
			if !ok {
				continue
			}
			if _, err := c.post(ctx, evidence.KindResolution, resolution(x.Scope, seq, "reverted", "unattributed")); err != nil {
				errs = append(errs, fmt.Sprintf("resolution of %s: %v", id, err))
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (c *Collector) observation(m *Merged, a *pipeline.Assessment) client.ProviderEvent {
	v, it := m.View, m.Item
	actor := map[string]any{"subject": v.Subject}
	chain := []any{}
	attrs := map[string]any{"arn": v.Subject, "user_type": v.UserType}
	switch {
	case v.SourceIdentity != "":
		actor["subject"] = v.SourceIdentity // the actor the record quotes: AWS sets it at the assumption and it cannot be changed after
		attrs["source_identity"] = v.SourceIdentity
	case v.UserType == "Root":
		actor["subject"] = "root"
	}
	if v.Issuer != "" {
		actor["issuer"] = v.Issuer
		chain = append(chain, v.Issuer)
	}
	if v.Subject != "" && v.Subject != v.Issuer {
		chain = append(chain, v.Subject)
	}
	if len(chain) > 0 {
		actor["chain"] = chain
	}
	if v.SessionName != "" {
		attrs["session_name"] = v.SessionName // self-reported
	}
	if v.UserAgent != "" {
		actor["client"] = clipText(v.UserAgent, 1000) // self-reported
	}
	actor["attributes"] = attrs
	if actor["subject"] == "" {
		actor["subject"] = "unknown"
	}
	rid := a.Resource
	res := map[string]any{"kind": v.Service, "id": strings.TrimPrefix(rid, v.Service+"/")}
	if v.Region != "" {
		res["region"] = v.Region
	}
	action := map[string]any{"verb": v.Name, "api": v.Name, "succeeded": v.ErrorCode == ""}
	if v.ErrorCode != "" {
		action["refused_reason"] = clipText(strings.TrimSpace(v.ErrorCode+": "+v.ErrorMessage), 1000)
	}
	if a.Monitoring {
		action["protects_monitoring"] = true
	}
	ev := client.ProviderEvent{Scope: client.String(v.Account), Resource: res, Actor: actor, Action: action,
		Source:    map[string]any{"name": ProviderName, "event_id": v.ID},
		Integrity: map[string]any{"sourceVerified": it.Verified, "completenessClaimed": true, "method": it.Method},
		Times:     times(v.Time, it.Received)}
	if v.Data() {
		ev.Source["kind"] = "data"
	}
	if sc := stateChange(m.Config); sc != nil {
		ev.StateChange = sc
	}
	corr := map[string]any{}
	if a.Grant != "" {
		corr["grant"] = a.Grant
	} else if v.ClaimGrant != "" {
		corr["grant"] = v.ClaimGrant // claimed in the user agent; the assessment says whether it held
	}
	if v.ClaimPlan != "" {
		corr["plan"] = v.ClaimPlan
	}
	if run, ok := strings.CutPrefix(v.SourceIdentity, "run="); ok {
		corr["run_id"] = run
	}
	if len(corr) > 0 {
		ev.Correlation = corr
	}
	return ev
}

func times(observed, delivered time.Time) map[string]any {
	t := map[string]any{"observed": observed.UTC().Format(time.RFC3339)}
	if !delivered.IsZero() {
		t["delivered"] = delivered.UTC().Format(time.RFC3339)
	}
	return t
}

func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// maxStateChange keeps a diff under the core's per-object limit; past it only the pointers are kept.
const maxStateChange = 48 << 10

func stateChange(cfgs []*ConfigChange) map[string]any {
	if len(cfgs) == 0 {
		return nil
	}
	before, after := map[string]any{}, map[string]any{}
	var ptrs []string
	for _, c := range cfgs {
		for k, p := range c.Changed {
			before[k], after[k] = p.Previous, p.Updated
		}
		ptrs = append(ptrs, c.Pointers()...)
	}
	b1, _ := json.Marshal(before)
	b2, _ := json.Marshal(after)
	if len(b1) > maxStateChange || len(b2) > maxStateChange {
		sort.Strings(ptrs)
		note := map[string]any{"truncated": fmt.Sprintf("%d changed properties; the values are in the Config item", len(ptrs)), "pointers": ptrs}
		return map[string]any{"before": note, "after": note}
	}
	return map[string]any{"before": before, "after": after}
}

func (c *Collector) assessment(m *Merged, a *pipeline.Assessment, about int64) client.ProviderEvent {
	detail := a.Detail
	if len(m.Config) > 0 {
		var ptrs, ids []string
		for _, cc := range m.Config {
			ptrs = append(ptrs, cc.Pointers()...)
			ids = append(ids, cc.ID)
		}
		detail += fmt.Sprintf(" | AWS Config: %s changed %s (items %s)", m.Config[0].ResourceType, strings.Join(ptrs, ", "), strings.Join(ids, ", "))
	}
	if a.ActorQuote != "" {
		detail += " | actor quoted by the record (sourceIdentity): " + a.ActorQuote
	}
	attr := map[string]any{"signal": a.Signal, "detail": clipText(detail, 3500)}
	if a.Grant != "" {
		attr["grant"] = a.Grant
	}
	rs := map[string]any{"version": a.RuleSet.Version}
	if a.RuleSet.Name != "" {
		rs["name"] = a.RuleSet.Name
	}
	return client.ProviderEvent{Scope: client.String(a.Scope), About: map[string]any{"seq": about}, Coverage: client.String(a.Coverage),
		Tier: &a.Tier, RuleSet: rs, Attribution: attr, Source: map[string]any{"name": ProviderName}}
}

// emitConfigOnly posts a configuration item no CloudTrail event explains: the resource changed and the trail did not
// say who did it. It is observed and not attributed (tier 1), and the detail says the trail has no event for it.
func (c *Collector) emitConfigOnly(ctx context.Context, m *Merged) error {
	cc := m.Config[0]
	id := m.ID()
	res := map[string]any{"kind": cc.ResourceType, "id": cc.ResourceID}
	if cc.ResourceName != "" {
		res["name"] = cc.ResourceName
	}
	if cc.Region != "" {
		res["region"] = cc.Region
	}
	ev := client.ProviderEvent{Scope: client.String(cc.Account), Resource: res,
		Actor:     map[string]any{"subject": "unknown (no CloudTrail event explains this configuration change)"},
		Action:    map[string]any{"verb": "configuration-change", "api": "ConfigurationItemChange:" + orElse(cc.ChangeType, "UPDATE"), "succeeded": true},
		Source:    map[string]any{"name": ProviderName, "event_id": id},
		Integrity: map[string]any{"sourceVerified": false, "completenessClaimed": true, "method": MethodConfig},
		Times:     times(cc.Captured, c.now()), StateChange: stateChange(m.Config)}
	if len(cc.Related) > 0 {
		ev.Correlation = map[string]any{"operation_id": cc.Related[0]}
	}
	ref, err := c.post(ctx, evidence.KindObservation, ev)
	if err != nil {
		return fmt.Errorf("posting the observation: %w", err)
	}
	c.remember(id, ref.Seq)
	if ref.Duplicate {
		c.count(func(s *Stats) { s.Duplicates++ })
	} else {
		c.count(func(s *Stats) { s.Posted++; s.ConfigOnly++ })
	}
	tier := 1
	detail := fmt.Sprintf("AWS Config recorded %s %s changed (%s) and the trail delivered no event for it within the settle time: an effect the trail did not report, with no actor to quote", cc.ResourceType, cc.ResourceID, strings.Join(cc.Pointers(), ", "))
	if len(cc.Related) > 0 {
		detail += "; Config's related events: " + strings.Join(cc.Related, ", ")
	}
	as := client.ProviderEvent{Scope: client.String(cc.Account), About: map[string]any{"seq": ref.Seq},
		Coverage: client.String(evidence.CoverageObservedNotAttributed), Tier: &tier,
		RuleSet:     map[string]any{"version": c.Pipe.RuleSet().Version, "name": c.Pipe.RuleSet().Name},
		Attribution: map[string]any{"signal": "config.item-without-event", "detail": clipText(detail, 3500)},
		Source:      map[string]any{"name": ProviderName}}
	as.Source["event_id"] = id + "/assessment"
	if _, err := c.post(ctx, evidence.KindAssessment, as); err != nil {
		return fmt.Errorf("posting the assessment of seq %d: %w", ref.Seq, err)
	}
	rr := resolution(cc.Account, ref.Seq, "still-live", "")
	rr.Source["event_id"] = id + "/resolution"
	if _, err := c.post(ctx, evidence.KindResolution, rr); err != nil {
		return fmt.Errorf("posting the resolution of seq %d: %w", ref.Seq, err)
	}
	return nil
}
