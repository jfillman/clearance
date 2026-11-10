package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
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
}

func newCorrelator(rs *RuleSet) *Correlator { return &Correlator{rs: rs} }

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

// Flush closes every open transaction and returns all of them with the exceptions they hold, then resets.
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
	folded := foldReverts(all, c.rs.revert)
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

// foldReverts finds, per resource, an uncleared change followed within the window by a change that puts the object
// back as it was before (its after-hash is the first change's before-hash, or it deletes what the first created), and
// folds the pair into one exception. A refused attempt landed nothing and a monitoring operation is never folded away
// (it is an exception whether or not it was undone).
func foldReverts(txs []*Transaction, window time.Duration) folds {
	f := folds{in: map[*Assessment]bool{}}
	byRes := map[string][]*Assessment{}
	owner := map[*Assessment]*Transaction{}
	for _, t := range txs {
		for _, a := range t.as {
			k := a.Scope + "|" + a.Resource
			byRes[k] = append(byRes[k], a)
			owner[a] = t
		}
	}
	for _, list := range byRes {
		for i, a := range list {
			if f.in[a] || !revertible(a) {
				continue
			}
			for _, b := range list[i+1:] {
				if f.in[b] || b.Time.Sub(a.Time) > window || !b.Succeeded || b.Outcome == OutcomeMonitoring {
					continue
				}
				if undoes(a, b) {
					f.in[a], f.in[b] = true, true
					t := owner[a]
					ex := buildException(t, []*Assessment{a, b}, true)
					f.exceptions = append(f.exceptions, *ex)
					break
				}
			}
		}
	}
	return f
}

func revertible(a *Assessment) bool {
	return a.Succeeded && (a.Outcome == OutcomeOutOfBand || a.Outcome == OutcomeNotAttributed || a.Outcome == OutcomeBreakGlass) && !a.Monitoring
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
