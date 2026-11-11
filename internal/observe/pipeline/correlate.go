package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// Transaction is one change, however many events it was: a `kubectl apply -f dir/` is a dozen events, a Terraform
// resource is several calls, a Deployment cascades into a ReplicaSet and its Pods.
type Transaction struct {
	ID        string    `json:"id"`
	Scope     string    `json:"scope"`
	Actor     string    `json:"actor"`
	Context   string    `json:"context,omitempty"` // the execution context that joined the events: a grant, a session, the actor and tool
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Events    []string  `json:"events"`
	Resources []string  `json:"resources"`
	Outcome   string    `json:"outcome"` // the worst outcome of its events
	Coverage  string    `json:"coverage"`
	Tier      int       `json:"tier"`
	Severity  string    `json:"severity"`

	as     []*Assessment
	owners map[string]bool
	keys   map[string]bool
}

// Exception is a change that landed outside a clearance (or an operation on monitoring, or a refused attempt), once.
// Events lists every event it folds: the several of one transaction, or the apply and the revert.
type Exception struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"` // gate.ExceptionKinds: out-of-band, attempted-refused, monitoring-protection, drift
	Scope       string   `json:"scope"`
	Transaction string   `json:"transaction"`
	Resources   []string `json:"resources"`
	Actor       string   `json:"actor"`
	Coverage    string   `json:"coverage"`
	Tier        int      `json:"tier"`
	Severity    string   `json:"severity"`
	Events      []string `json:"events"`
	// Landed is the events that took effect: succeeded, and neither a refused attempt nor a break-glass window. Not part of
	// the exception's JSON: it says which observations the collector resolves.
	Landed     []string   `json:"-"`
	Reverted   bool       `json:"reverted"`
	Resolution string     `json:"resolution"` // still-live, or reverted (an apply and its revert: observe.ResolutionStates)
	Cause      string     `json:"cause,omitempty"`
	Signals    []string   `json:"signals"`
	Diff       []string   `json:"diff,omitempty"`
	RuleSet    RuleSetRef `json:"rule_set"`
}

// Correlator groups assessments. It holds open transactions; Flush closes them all.
type Correlator struct {
	rs   *RuleSet
	open []*Transaction
	done []*Transaction
	seq  int

	// mem is the revert memory: per scope|resource, the landed, revertible changes that no later change undid yet, by
	// event time. It outlives Flush so that an undo arriving in a later pass still finds what it undoes.
	mem    map[string][]*Assessment
	latest time.Time // the newest event time seen; the memory's clock
}

// The revert memory is bounded: per resource, and in all. The oldest by event time go first.
const (
	maxMemoryPerResource = 64
	maxMemoryTotal       = 10000
)

func newCorrelator(rs *RuleSet) *Correlator {
	return &Correlator{rs: rs, mem: map[string][]*Assessment{}}
}

func sevRank(s string) int { return slices.Index(Severities, s) }

// outcomeRank orders outcomes, worst first for a transaction's summary.
var outcomeRank = map[string]int{OutcomeMonitoring: 5, OutcomeOutOfBand: 4, OutcomeBreakGlass: 3, OutcomeRefused: 2,
	OutcomeNotAttributed: 1, OutcomeCleared: 0}

// ownerKey is how an object names one of its owners.
func ownerKey(ns, kind, name string) string { return ns + "/" + kind + "/" + name }

// Add puts an assessment in the transaction it belongs to, opening one if none does. An assessment belongs to an open
// transaction of its scope when the transaction's last event is within the window and any of:
//
//   - the same execution context: the grant a record quotes, the AWS session;
//   - a resource relationship: the object is owned by an object the transaction touched, or owns one it touched (a
//     Deployment and the ReplicaSet it cascades into);
//   - the same actor with the same tool (the Kubernetes user agent), the burst a `kubectl apply -f dir/` leaves.
func (c *Correlator) Add(a *Assessment) {
	e := a.ev
	c.expire(a.Time)
	if a.Time.After(c.latest) {
		c.latest = a.Time
	}
	for _, t := range c.open {
		if t.Scope != a.Scope || a.Time.Sub(t.To) > c.rs.window || a.Time.Before(t.From.Add(-c.rs.window)) {
			continue
		}
		if t.joins(a) {
			t.add(a, e)
			return
		}
	}
	c.seq++
	t := &Transaction{Scope: a.Scope, Actor: a.Actor, From: a.Time, To: a.Time, owners: map[string]bool{}, keys: map[string]bool{}}
	t.Context = contextOf(e)
	t.add(a, e)
	c.open = append(c.open, t)
}

func contextOf(e *Event) string {
	switch {
	case e.ExecKey != "":
		return e.ExecKey
	case e.UserAgent != "":
		return e.Subject + " via " + toolOf(e.UserAgent)
	}
	return e.Subject
}

func toolOf(ua string) string {
	for i, r := range ua {
		if r == ' ' || r == '/' {
			return ua[:i]
		}
	}
	return ua
}

func (t *Transaction) joins(a *Assessment) bool {
	e := a.ev
	if e.ExecKey != "" && t.Context == e.ExecKey {
		return true
	}
	k := ownerKey(e.Namespace, e.Kind, e.Name)
	if t.owners[k] {
		return true
	}
	for _, o := range e.Owners {
		if t.keys[ownerKey(e.Namespace, o.Kind, o.Name)] {
			return true
		}
	}
	return a.Actor == t.Actor && e.UserAgent != "" && t.Context == contextOf(e)
}

func (t *Transaction) add(a *Assessment, e *Event) {
	t.as = append(t.as, a)
	if a.Time.After(t.To) {
		t.To = a.Time
	}
	if a.Time.Before(t.From) {
		t.From = a.Time
	}
	t.keys[ownerKey(e.Namespace, e.Kind, e.Name)] = true
	for _, o := range e.Owners {
		t.owners[ownerKey(e.Namespace, o.Kind, o.Name)] = true
	}
}

func (c *Correlator) expire(now time.Time) {
	keep := c.open[:0]
	for _, t := range c.open {
		if now.Sub(t.To) > c.rs.window {
			c.done = append(c.done, t)
		} else {
			keep = append(keep, t)
		}
	}
	c.open = keep
}

// Flush closes every open transaction and returns all of them with the exceptions they hold, then resets. What it
// resets is the open transactions; the revert memory stays (see foldReverts).
func (c *Correlator) Flush() ([]Transaction, []Exception) {
	all := append(c.done, c.open...)
	c.done, c.open = nil, nil
	slices.SortStableFunc(all, func(a, b *Transaction) int {
		switch {
		case a.From.Before(b.From):
			return -1
		case a.From.After(b.From):
			return 1
		}
		return 0
	})
	for _, t := range all {
		t.seal()
	}
	folded := c.foldReverts(all)
	var exs []Exception
	txs := make([]Transaction, 0, len(all))
	for _, t := range all {
		if ex := t.exception(folded); ex != nil {
			exs = append(exs, *ex)
		}
		txs = append(txs, *t)
	}
	exs = append(exs, folded.exceptions...)
	slices.SortStableFunc(exs, func(a, b Exception) int { return strings.Compare(a.Transaction+"|"+a.ID, b.Transaction+"|"+b.ID) })
	return txs, exs
}

func (t *Transaction) seal() {
	sum := sha256.New()
	sum.Write([]byte(t.Scope + "|" + t.as[0].EventID))
	t.ID = "txn_" + hex.EncodeToString(sum.Sum(nil))[:12]
	t.Outcome, t.Severity = OutcomeCleared, "info"
	for _, a := range t.as {
		t.Events = append(t.Events, a.EventID)
		if !slices.Contains(t.Resources, a.Resource) {
			t.Resources = append(t.Resources, a.Resource)
		}
		if outcomeRank[a.Outcome] > outcomeRank[t.Outcome] || (a.Outcome == t.Outcome && sevRank(a.Severity) > sevRank(t.Severity)) {
			t.Outcome, t.Coverage = a.Outcome, a.Coverage
		}
		if a.Tier > t.Tier {
			t.Tier = a.Tier
		}
		if sevRank(a.Severity) > sevRank(t.Severity) {
			t.Severity = a.Severity
		}
	}
	if t.Coverage == "" {
		t.Coverage = t.as[0].Coverage
	}
}

// exception is the transaction's one exception: every event of it that is not cleared and not folded into an
// apply-and-revert. A transaction of cleared events has none.
func (t *Transaction) exception(f folds) *Exception {
	var bad []*Assessment
	for _, a := range t.as {
		if a.Outcome != OutcomeCleared && !f.in[a] {
			bad = append(bad, a)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return buildException(t, bad, false)
}

func exceptionKind(outcome string) string {
	switch outcome {
	case OutcomeRefused:
		return "attempted-refused"
	case OutcomeMonitoring:
		return "monitoring-protection"
	case OutcomeNotAttributed:
		return "drift"
	case OutcomeBreakGlass:
		return "break-glass" // the packet's class of the same name; not one of the gate's exception kinds
	}
	return "out-of-band"
}

func buildException(t *Transaction, as []*Assessment, reverted bool) *Exception {
	worst := as[0]
	for _, a := range as[1:] {
		if outcomeRank[a.Outcome] > outcomeRank[worst.Outcome] || (a.Outcome == worst.Outcome && sevRank(a.Severity) > sevRank(worst.Severity)) {
			worst = a
		}
	}
	ex := &Exception{Kind: exceptionKind(worst.Outcome), Scope: t.Scope, Transaction: t.ID, Actor: worst.Actor,
		Coverage: worst.Coverage, Tier: worst.Tier, Severity: worst.Severity, Reverted: reverted, Resolution: "still-live",
		RuleSet: worst.RuleSet}
	if reverted {
		ex.Resolution, ex.Cause = "reverted", "unattributed"
	}
	for _, a := range as {
		ex.Events = append(ex.Events, a.EventID)
		if a.Succeeded && a.Outcome != OutcomeRefused && a.Outcome != OutcomeBreakGlass {
			ex.Landed = append(ex.Landed, a.EventID)
		}
		if !slices.Contains(ex.Resources, a.Resource) {
			ex.Resources = append(ex.Resources, a.Resource)
		}
		if !slices.Contains(ex.Signals, a.Signal) {
			ex.Signals = append(ex.Signals, a.Signal)
		}
		if a.Tier > ex.Tier {
			ex.Tier = a.Tier
		}
		if sevRank(a.Severity) > sevRank(ex.Severity) {
			ex.Severity = a.Severity
		}
		ex.Diff = append(ex.Diff, a.Diff...)
	}
	h := sha256.Sum256([]byte(ex.Kind + "|" + ex.Events[0]))
	ex.ID = "exc_" + hex.EncodeToString(h[:])[:12]
	return ex
}

// ---- apply and revert ---------------------------------------------------------------------------------------------

type folds struct {
	in         map[*Assessment]bool
	exceptions []Exception
}

// foldReverts finds, per resource, uncleared changes that a later change put back, and folds each undone run and its
// undo into one exception, resolution `reverted`. A change is undone when a later change, within the revert window of
// its event time, either
//
//   - puts the object back as it was (its after-hash is the first's before-hash, or it deletes what the first created):
//     one change, one undo; or
//   - removes exactly the values the run of most recent changes added and adds back exactly the values they removed
//     (see undoesRun): several changes undone by one, or one by several.
//
// The changes it considers are those of this pass and the revert memory: changes of earlier passes that landed and were
// not undone yet. An apply and its undo are often settled and emitted in different passes (each event waits out its own
// settle time), so closing the transactions of a pass is not the end of a change's chance to be reverted. Changes that
// stay undone-less are remembered again for the rest of their window, by event time. A refused attempt landed nothing
// and a monitoring operation is never folded away (it is an exception whether or not it was undone).
func (c *Correlator) foldReverts(txs []*Transaction) folds {
	f := folds{in: map[*Assessment]bool{}}
	byRes := map[string][]*Assessment{}
	owner := map[*Assessment]*Transaction{}
	for k, l := range c.mem {
		byRes[k] = append(byRes[k], l...)
	}
	for _, t := range txs {
		for _, a := range t.as {
			k := a.Scope + "|" + a.Resource
			byRes[k] = append(byRes[k], a)
			owner[a] = t
		}
	}
	keys := make([]string, 0, len(byRes))
	for k := range byRes {
		keys = append(keys, k)
	}
	slices.Sort(keys) // the exceptions come out in the same order every time
	for _, k := range keys {
		list := byRes[k]
		slices.SortStableFunc(list, func(a, b *Assessment) int { return a.Time.Compare(b.Time) })
		for i, b := range list {
			if f.in[b] || !b.Succeeded || b.Outcome == OutcomeMonitoring {
				continue
			}
			var cand []*Assessment // earlier, unfolded, revertible, within the window of b: oldest first
			for _, a := range list[:i] {
				if !f.in[a] && revertible(a) && b.Time.Sub(a.Time) <= c.rs.revert {
					cand = append(cand, a)
				}
			}
			run := undoneBy(cand, b)
			if len(run) == 0 {
				continue
			}
			as := append(slices.Clone(run), b)
			for _, a := range as {
				f.in[a] = true
			}
			var t *Transaction // the transaction of the earliest change that has one still
			for _, a := range as {
				if t = owner[a]; t != nil {
					break
				}
			}
			if t == nil { // every change of it is from an earlier pass: its transaction was closed and is gone
				h := sha256.Sum256([]byte(b.Scope + "|" + b.EventID))
				t = &Transaction{Scope: b.Scope, ID: "txn_" + hex.EncodeToString(h[:])[:12]}
			}
			f.exceptions = append(f.exceptions, *buildException(t, as, true))
		}
	}
	c.remember(byRes, f)
	return f
}

// remember keeps what landed and was not undone, drops what is past its window (by event time, against the newest event
// seen) and enforces the bounds.
func (c *Correlator) remember(byRes map[string][]*Assessment, f folds) {
	mem := map[string][]*Assessment{}
	total := 0
	for k, l := range byRes {
		var keep []*Assessment
		for _, a := range l {
			if !f.in[a] && revertible(a) && c.latest.Sub(a.Time) <= c.rs.revert {
				keep = append(keep, a)
			}
		}
		if len(keep) > maxMemoryPerResource {
			keep = keep[len(keep)-maxMemoryPerResource:]
		}
		if len(keep) > 0 {
			mem[k] = keep
			total += len(keep)
		}
	}
	for total > maxMemoryTotal { // drop the oldest by event time, across resources
		var ok string
		var ot time.Time
		for k, l := range mem {
			if ok == "" || l[0].Time.Before(ot) || (l[0].Time.Equal(ot) && k < ok) {
				ok, ot = k, l[0].Time
			}
		}
		mem[ok] = mem[ok][1:]
		if len(mem[ok]) == 0 {
			delete(mem, ok)
		}
		total--
	}
	c.mem = mem
}

func revertible(a *Assessment) bool {
	return a.Succeeded && (a.Outcome == OutcomeOutOfBand || a.Outcome == OutcomeNotAttributed || a.Outcome == OutcomeBreakGlass) && !a.Monitoring
}

// undoneBy is the changes of cand (oldest first) that b undoes: the one the hash rules name, else the smallest run of
// the most recent changes that undoesRun accepts. Nil when b undoes nothing.
func undoneBy(cand []*Assessment, b *Assessment) []*Assessment {
	for _, a := range cand {
		if a.hasDelta || b.hasDelta {
			continue // a collector's property diff is a positional subset of the object: values decide, never the hashes
		}
		if undoes(a, b) {
			return []*Assessment{a}
		}
	}
	for k := 1; k <= len(cand); k++ {
		run := cand[len(cand)-k:]
		if undoesRun(run, b) {
			return run
		}
	}
	return nil
}

func undoes(a, b *Assessment) bool {
	switch {
	case a.BeforeHash != "" && b.AfterHash == a.BeforeHash:
		return true // put back as it was
	case a.BeforeHash == "" && a.AfterHash != "" && b.AfterHash == "" && b.BeforeHash == a.AfterHash:
		return true // created, then deleted
	}
	return false
}

// undoesRun: the values b removes are exactly the values the run added, and the values b adds are exactly the values the
// run removed, as multisets, whatever the property names. (Positions in a list are not stable from one change to the
// next: two rules added one after another are both element 0, and one revoke of both names elements 0 and 1.) A change
// with no value diff, or a run whose changes all have none, never matches.
func undoesRun(run []*Assessment, b *Assessment) bool {
	if !b.hasDelta || len(b.added)+len(b.removed) == 0 {
		return false
	}
	var added, removed []string
	for _, a := range run {
		if !a.hasDelta || len(a.added)+len(a.removed) == 0 {
			return false
		}
		added, removed = append(added, a.added...), append(removed, a.removed...)
	}
	slices.Sort(added)
	slices.Sort(removed)
	return slices.Equal(added, b.removed) && slices.Equal(removed, b.added)
}

// valueDelta is the multiset of canonical-JSON values in after that are not in before, and the reverse; each sorted.
// Null is no value. Property names are ignored.
func valueDelta(before, after map[string]any) (added, removed []string) {
	count := map[string]int{}
	for _, v := range after {
		if s, ok := canonicalValue(v); ok {
			count[s]++
		}
	}
	for _, v := range before {
		if s, ok := canonicalValue(v); ok {
			count[s]--
		}
	}
	for s, n := range count {
		for ; n > 0; n-- {
			added = append(added, s)
		}
		for ; n < 0; n++ {
			removed = append(removed, s)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

func canonicalValue(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	b, err := json.Marshal(v) // map keys are sorted
	if err != nil {
		return "", false
	}
	return string(b), true
}
