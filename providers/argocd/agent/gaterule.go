package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
)

// The gate rule in the agent (W-42; docs/gate.md, "The gate rule"): loading the file, keeping the last good one,
// asking the core about each exemption, and the bound on rule-caused releases. rule.go is the file's shape and matcher.

// GateRule is the rule's settings, part of OptIn. File empty (the default) is no rule: the agent behaves as before.
type GateRule struct {
	// File is the rule file (--gate-rule-file). Empty: no rule.
	File string
	// ExemptMax bounds an exemption's expiry from now (default 90 days; the core refuses more than 90 days too).
	ExemptMax time.Duration
	// ReleaseMax is how many Applications the rule may release in ReleaseWindow (default 3 an hour); the rest stay gated.
	ReleaseMax    int
	ReleaseWindow time.Duration
	// Recheck is how often an honoured exemption is asked about again (default 5 minutes); RecheckTimeout is the deadline
	// of each ask (default 30 s, below Recheck): one that misses it counts as an unreachable core.
	Recheck        time.Duration
	RecheckTimeout time.Duration
	// Read reads the file (default os.ReadFile).
	Read func(string) ([]byte, error)
}

func (g *GateRule) defaults() {
	if g.ExemptMax <= 0 {
		g.ExemptMax = DefaultExemptMax
	}
	if g.ReleaseMax <= 0 {
		g.ReleaseMax = 3
	}
	if g.ReleaseWindow <= 0 {
		g.ReleaseWindow = time.Hour
	}
	if g.Recheck <= 0 {
		g.Recheck = 5 * time.Minute
	}
	if g.RecheckTimeout <= 0 {
		g.RecheckTimeout = 30 * time.Second
	}
	if g.Read == nil {
		g.Read = os.ReadFile
	}
}

func (g *GateRule) check() error {
	switch {
	case g.File == "":
		return nil
	case g.ExemptMax > DefaultExemptMax:
		return fmt.Errorf("agent: the exemption bound %s is over the core's 90 days", g.ExemptMax)
	case g.RecheckTimeout >= g.Recheck:
		return fmt.Errorf("agent: the exemption recheck timeout %s is not below the recheck interval %s", g.RecheckTimeout, g.Recheck)
	}
	return nil
}

// ErrRuleNotReady is a configured rule that has never been read good, here or in the state: nothing new is gated and
// nothing is released until it is.
var ErrRuleNotReady = errors.New("the gate rule is configured and no good copy of it can be read (the file, or the state's copy)")

// RuleSlot is one rule-caused release (persisted). A reservation (Done false) is taken before the release starts and
// counts until the release completes or is abandoned, whatever its age; a completed one counts from when it completed (At)
// for the window.
type RuleSlot struct {
	Key  string `json:"key"`
	At   string `json:"at"`
	Done bool   `json:"done,omitempty"`
}

// acceptance is the core's last answer about one Application's exemption: for key (the pair, the Application, the entry
// and the rule digest), at at; refused says why it was not taken ("" when it was).
type acceptance struct {
	key     string
	at      time.Time
	refused string
	pair    Pair
	// What was asked about, kept so that the exemption's end can be recorded after its entry left the file.
	exempt RuleExempt
	rule   string
}

// ruleState is the gate rule's memory (ruleMu).
type ruleState struct {
	rule     *Rule
	err      string // why the file was not taken, the last time it was read
	accepted map[string]acceptance
}

// loadRule reads the rule file. A good file replaces the rule and is copied into the state; a bad or unreadable one
// keeps the last good rule (from this process, else the state's copy), and is reported once a day. No rule configured
// is (nil, nil). ErrRuleNotReady: no good copy anywhere.
func (a *Agent) loadRule(ctx context.Context) (*Rule, error) {
	g := &a.cfg.OptIn.Rule
	if g.File == "" {
		return nil, nil
	}
	raw, err := g.Read(g.File)
	var r *Rule
	if err == nil {
		r, err = ParseRule(raw, a.now(), g.ExemptMax)
	}
	a.ruleMu.Lock()
	if err == nil {
		changed := a.rs.rule == nil || a.rs.rule.Digest != r.Digest
		a.rs.rule, a.rs.err = r, ""
		a.ruleMu.Unlock()
		if changed {
			a.log.Info("gate rule loaded", "digest", r.Digest, "select", len(r.Select), "exempt", len(r.Exempt))
		}
		// The state's copy is what a restart falls back on: it is written until a write succeeds (the state says which
		// digest it holds; a failed write leaves the old copy there, and the next pass tries again).
		a.mu.Lock()
		if a.st.RuleDigest != r.Digest {
			oldRaw, oldDigest := a.st.RuleRaw, a.st.RuleDigest
			a.st.RuleRaw, a.st.RuleDigest = r.Raw, r.Digest
			if serr := a.saveLocked(ctx); serr != nil {
				a.st.RuleRaw, a.st.RuleDigest = oldRaw, oldDigest
				a.log.Warn("the gate rule's copy could not be saved in the state (tried again next pass)", "err", serr)
			}
		}
		a.mu.Unlock()
		a.forgetOnce(ctx, "gate-rule|")
		return r, nil
	}
	why := truncate(err.Error(), 300)
	if a.rs.rule == nil {
		a.mu.Lock()
		saved := a.st.RuleRaw
		a.mu.Unlock()
		if saved != "" {
			if sr, serr := ParseRule([]byte(saved), a.now(), g.ExemptMax); serr == nil {
				a.rs.rule = sr
				a.log.Warn("the gate rule file cannot be used; the copy in the state is", "digest", sr.Digest, "err", why)
			}
		}
	}
	a.rs.err = why
	cur := a.rs.rule
	a.ruleMu.Unlock()
	detail := "the gate rule file " + g.File + " cannot be used (" + why + ")"
	if cur != nil {
		detail += "; the last good rule sha256:" + shortDigest(cur.Digest) + " stays, and nothing is released for it"
	} else {
		detail += "; there is no good copy, so nothing new is gated and nothing is released until there is"
	}
	a.warnOnce("gate/rule", detail)
	if rerr := a.reportEvery(ctx, "gate-rule|invalid", 24*time.Hour, "gate rule unusable", detail,
		[]map[string]any{{"apiVersion": "v1", "kind": "ConfigMap", "name": "gate-rule"}}); rerr != nil {
		a.log.Warn("the unusable gate rule could not be reported", "err", rerr)
	}
	if cur == nil {
		return nil, ErrRuleNotReady
	}
	return cur, nil
}

// currentRule is the rule in force (nil: none, or not loaded yet).
func (a *Agent) currentRule() *Rule {
	a.ruleMu.Lock()
	defer a.ruleMu.Unlock()
	return a.rs.rule
}

func (a *Agent) ruleStatus() string {
	if a.cfg.OptIn.Rule.File == "" {
		return ""
	}
	a.ruleMu.Lock()
	defer a.ruleMu.Unlock()
	switch {
	case a.rs.rule == nil:
		return "not ready: " + a.rs.err
	case a.rs.err != "":
		return "kept the last good rule sha256:" + shortDigest(a.rs.rule.Digest) + ": " + a.rs.err
	}
	return "loaded sha256:" + shortDigest(a.rs.rule.Digest)
}

// exemptKey is what an acceptance is keyed to: the Application, its pair, the entry as written and the rule digest.
func exemptKey(c appClass, digest string) string {
	e := c.exempt
	sum := sha256.Sum256([]byte(strings.Join([]string{c.key(), c.gateApp, c.env, c.ruleName, e.Application, e.Reason,
		e.Expires, e.Ref, digest}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// honoured says whether the core has taken the Application's exemption as it stands now (and recently enough).
func (a *Agent) honoured(c appClass, digest string) bool {
	a.ruleMu.Lock()
	defer a.ruleMu.Unlock()
	acc, ok := a.rs.accepted[c.key()]
	g := a.cfg.OptIn.Rule
	return ok && acc.refused == "" && acc.key == exemptKey(c, digest) && a.now().Sub(acc.at) < g.Recheck+g.RecheckTimeout
}

func (a *Agent) answer(key string) (acceptance, bool) {
	a.ruleMu.Lock()
	defer a.ruleMu.Unlock()
	acc, ok := a.rs.accepted[key]
	return acc, ok
}

func (a *Agent) setAnswer(key string, acc *acceptance) {
	a.ruleMu.Lock()
	defer a.ruleMu.Unlock()
	if a.rs.accepted == nil {
		a.rs.accepted = map[string]acceptance{}
	}
	if acc == nil {
		delete(a.rs.accepted, key)
	} else {
		a.rs.accepted[key] = *acc
	}
}

// asked is c as it was when the core answered: the entry and the pair the acceptance is for (an entry since removed from
// the file, or a pair since changed, still names what ended).
func (acc acceptance) asked(c appClass) appClass {
	e := acc.exempt
	c.exempt, c.ruleName, c.gateApp, c.env = &e, acc.rule, acc.pair.App, acc.pair.Env
	return c
}

// candidate is an Application the rule selects and an exempt entry names, whatever the entry's state.
func (c appClass) candidate() bool { return c.ruleName != "" && c.exempt != nil }

// decideExemptions asks the core about every exemption that would release an Application, and posts the exemptions'
// records. It says whether an answer changed what is honoured (the pass classifies again).
func (a *Agent) decideExemptions(ctx context.Context, classes []appClass, digest string) bool {
	a.flushPending(ctx)
	changed := false
	present := map[string]bool{}
	for _, c := range classes {
		key := c.key()
		present[key] = true
		acc, had := a.answer(key)
		wasHonoured := had && acc.refused == ""
		// changed is measured against what this pass's classification honoured (c.exempted), not against the cache: an
		// answer that was too old to be honoured and is renewed now must make the pass classify again.
		settle := func(honoured bool) {
			if honoured != c.exempted {
				changed = true
			}
		}
		drop := func(why string) {
			a.setAnswer(key, nil)
			settle(false)
			if wasHonoured {
				a.postExemption(ctx, acc.asked(c), "expired", why, "gate-exempt-end|"+acc.key+"|"+why)
			}
		}
		if !c.candidate() || c.denied {
			if had {
				drop("withdrawn")
			}
			continue
		}
		e := c.exempt
		delete(a.opt().status, "exempt/"+key)
		switch {
		case e.Invalid != "":
			drop("withdrawn")
			a.opt().status["exempt/"+key] = "exemption ignored: " + e.Invalid
			if err := a.reportEvery(ctx, "gate-exempt-invalid|"+key+"|"+e.Application, 24*time.Hour, "gate exemption ignored",
				fmt.Sprintf("the exempt entry %q for %s is ignored, so the Application stays gated: %s", e.Application, key, e.Invalid),
				appObject(c)); err != nil {
				a.log.Warn("the ignored exemption could not be reported", "err", err)
			}
			continue
		case e.Expired(a.now()):
			if wasHonoured {
				drop("lapsed")
			} else {
				a.setAnswer(key, nil)
				settle(false)
				if a.dueEvery("gate-exempt-stale|"+key+"|"+e.Expires, 24*time.Hour) {
					a.postExemption(ctx, c, "expired", "stale", "gate-exempt-stale|"+key+"|"+e.Expires)
				}
			}
			continue
		case c.envErr != nil || c.blockedWhy != "" || !dnsLabel.MatchString(c.gateApp) || !dnsLabel.MatchString(c.env):
			// The pair is unknown or not a name: nothing can be asked, so nothing is honoured (the Application stays gated).
			if had {
				drop("revoked")
			}
			settle(false)
			continue
		}
		k := exemptKey(c, digest)
		if had && acc.key == k && a.now().Sub(acc.at) < a.cfg.OptIn.Rule.Recheck {
			settle(acc.refused == "" && a.honoured(c, digest))
			continue // answered, and not due again
		}
		refused, err := a.askExemption(ctx, c, k)
		switch {
		case err != nil: // unreachable, or the deadline passed: fail closed at once
			a.setAnswer(key, nil)
			settle(false)
			if wasHonoured {
				a.warnOnce(key, "an exemption's acceptance is dropped (the core could not be asked): the Application is gated again: "+truncate(err.Error(), 200))
				// The end of the exemption is recorded when the core is back (queued, with its event id).
				a.postExemption(ctx, acc.asked(c), "expired", "dropped", "gate-exempt-end|"+acc.key+"|dropped")
			}
		case refused != "":
			a.setAnswer(key, &acceptance{key: k, at: a.now(), refused: refused, pair: Pair{c.gateApp, c.env}, exempt: *e, rule: c.ruleName})
			settle(false)
			if wasHonoured {
				a.postExemption(ctx, acc.asked(c), "expired", "revoked", "gate-exempt-end|"+acc.key+"|revoked")
			}
			if !had || acc.key != k || acc.refused != refused {
				a.postExemption(ctx, c, "refused", refused, "gate-exempt-refused|"+k)
			}
		default:
			a.setAnswer(key, &acceptance{key: k, at: a.now(), pair: Pair{c.gateApp, c.env}, exempt: *e, rule: c.ruleName})
			settle(true)
			if !wasHonoured || acc.key != k {
				a.log.Info("gate exemption accepted by the core", "application", key, "entry", e.Application, "expires", e.Expires)
			}
			if a.dueEvery("gate-exempt-active|"+k, 24*time.Hour) {
				a.postExemption(ctx, c, "active", "", "gate-exempt-active|"+k)
			}
			if e.At.Sub(a.now()) <= 7*24*time.Hour && a.dueEvery("gate-exempt-expiring|"+k, 100*365*24*time.Hour) {
				a.postExemption(ctx, c, "expiring", "", "gate-exempt-expiring|"+k)
			}
		}
	}
	a.ruleMu.Lock()
	var gone []acceptance
	var goneKeys []string
	for k, acc := range a.rs.accepted {
		if !present[k] {
			delete(a.rs.accepted, k)
			if acc.refused == "" {
				gone, goneKeys = append(gone, acc), append(goneKeys, k)
			}
		}
	}
	a.ruleMu.Unlock()
	for i, acc := range gone { // the Application was deleted: its exemption ended with it
		ns, name, _ := strings.Cut(goneKeys[i], "/")
		a.postExemption(ctx, acc.asked(appClass{app: Application{Namespace: ns, Name: name}}), "expired", "withdrawn",
			"gate-exempt-end|"+acc.key+"|withdrawn")
	}
	return changed
}

// askExemption posts the exemption's requested record under a deadline. It returns the core's refusal ("static",
// "unknown kind", ...) when it refused, or an error when it could not be asked.
func (a *Agent) askExemption(ctx context.Context, c appClass, k string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.OptIn.Rule.RecheckTimeout)
	defer cancel()
	day := a.now().UTC().Format("2006-01-02")
	_, err := a.core.Record(ctx, a.exemptionRecord(c, "requested", "", "gx-"+k[:32]+"-"+day))
	if err == nil {
		return "", ctx.Err()
	}
	var ae *client.APIError
	if errors.As(err, &ae) {
		switch {
		case ae.Status == 409:
			why := strings.TrimPrefix(ae.Message, "refused: ")
			if r, _, ok := strings.Cut(why, ":"); ok {
				why = r
			}
			return why, nil
		case ae.Status == 400 || ae.Status == 403:
			// A core that does not know the kind (or does not let the agent write it): every exemption is ignored.
			if rerr := a.reportOnce(ctx, "gate-exempt-unknown", "gate exemptions ignored: the core refuses the record",
				"the core refuses a gate-exemption record ("+truncate(ae.Message, 200)+"): every exemption is ignored and the Applications stay gated",
				[]map[string]any{{"apiVersion": "v1", "kind": "ConfigMap", "name": "gate-rule"}}); rerr != nil {
				a.log.Warn("the refused exemption kind could not be reported", "err", rerr)
			}
			return "unknown kind", nil
		}
	}
	return "", err
}

func (a *Agent) exemptionRecord(c appClass, state, why, eventID string) *client.RecordRequest {
	e := c.exempt
	x := map[string]any{"state": state, "application": c.key(), "entry": e.Application, "rule": c.ruleName,
		"rule_digest": a.currentDigest(), "reason": e.Reason, "expires": e.At.Format(time.RFC3339)}
	if e.Ref != "" {
		x["ref"] = e.Ref
	}
	if why != "" {
		x["why"] = truncate(why, 200)
	}
	src := map[string]any{"provider": a.Provider()}
	if eventID != "" {
		src["name"], src["event_id"] = "argocd-agent", eventID
	}
	return &client.RecordRequest{Kind: "deploy.exception", Record: client.ProviderEvent{
		Principal:   client.String("argocd-agent (gate rule)"),
		Target:      client.String(c.key()),
		App:         client.String(c.gateApp),
		Result:      client.String("gate exemption " + state),
		Destination: map[string]any{"cluster": a.cfg.Cluster, "environment": c.env, "namespace": c.app.DestNS, "application": c.app.Name},
		Source:      src,
		Exception: map[string]any{"kind": "gate-exemption", "detected_at": a.now().UTC().Format(time.RFC3339),
			"exemption": x}}}
}

func (a *Agent) currentDigest() string {
	if r := a.currentRule(); r != nil {
		return r.Digest
	}
	return strings.Repeat("0", 64)
}

// postExemption posts one of an exemption's state records. once is its Once fingerprint, which also derives its event id
// (the day is part of it, so a daily repost is a new record and a retry of today's is the same one). A post the core
// cannot be reached for is queued in the state and retried every pass; the event id makes the retry idempotent.
func (a *Agent) postExemption(ctx context.Context, c appClass, state, why, once string) {
	if c.exempt == nil || c.exempt.Invalid != "" || !dnsLabel.MatchString(c.gateApp) || !dnsLabel.MatchString(c.env) {
		return
	}
	sum := sha256.Sum256([]byte(once + "|" + a.now().UTC().Format("2006-01-02")))
	event := "gs-" + hex.EncodeToString(sum[:16])
	req := a.exemptionRecord(c, state, why, event)
	if _, err := a.core.Record(ctx, req); err != nil {
		var ae *client.APIError
		if !errors.As(err, &ae) { // unreachable: delivered when the core is back
			a.queuePending(ctx, event, req)
		}
		a.log.Warn("a gate exemption's record could not be posted", "application", c.key(), "state", state, "err", err)
		return
	}
	a.mu.Lock()
	a.st.Once[once] = a.now().UTC().Format(time.RFC3339)
	if err := a.saveLocked(ctx); err != nil {
		a.log.Warn("the state could not be saved", "err", err)
	}
	a.mu.Unlock()
}

// MaxPendingRecords bounds the queue of exemption records waiting for the core.
const MaxPendingRecords = 500

func (a *Agent) queuePending(ctx context.Context, event string, req *client.RecordRequest) {
	raw, err := json.Marshal(req)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.Pending == nil {
		a.st.Pending = map[string]string{}
	}
	// The bound applies to the records that repeat (requested, active, expiring, a stale entry's daily expired): the end of
	// an acceptance (expired lapsed/revoked/dropped/withdrawn) and a refusal are never dropped. There is one of those per
	// acceptance, so they are bounded by the Applications the rule exempts.
	x, _ := req.Record.Exception["exemption"].(map[string]any)
	terminal := x["state"] == "refused" || (x["state"] == "expired" && x["why"] != "stale")
	if _, ok := a.st.Pending[event]; !ok && !terminal && len(a.st.Pending) >= MaxPendingRecords {
		a.log.Warn("the queue of exemption records waiting for the core is full: a repeating record is dropped", "event", event)
		return
	}
	a.st.Pending[event] = string(raw)
	if err := a.saveLocked(ctx); err != nil {
		a.log.Warn("the state could not be saved", "err", err)
	}
}

// flushPending posts the queued exemption records. One the core takes (or refuses: it will not take it later) leaves the
// queue; one it still cannot be reached for stays.
func (a *Agent) flushPending(ctx context.Context) {
	a.mu.Lock()
	events := make([]string, 0, len(a.st.Pending))
	for e := range a.st.Pending {
		events = append(events, e)
	}
	a.mu.Unlock()
	sort.Strings(events)
	for _, e := range events {
		a.mu.Lock()
		raw := a.st.Pending[e]
		a.mu.Unlock()
		var req client.RecordRequest
		if json.Unmarshal([]byte(raw), &req) == nil {
			if _, err := a.core.Record(ctx, &req); err != nil {
				var ae *client.APIError
				if !errors.As(err, &ae) {
					return // still unreachable: the rest wait too
				}
				a.log.Warn("a queued gate exemption record was refused by the core and is dropped", "event", e, "err", err)
			}
		}
		a.mu.Lock()
		delete(a.st.Pending, e)
		if err := a.saveLocked(ctx); err != nil {
			a.log.Warn("the state could not be saved", "err", err)
		}
		a.mu.Unlock()
	}
}

// dueEvery says whether the Once fingerprint was posted more than every ago (or never).
func (a *Agent) dueEvery(fp string, every time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	last, ok := a.st.Once[fp]
	if !ok {
		return true
	}
	t, err := time.Parse(time.RFC3339, last)
	return err != nil || a.now().Sub(t) >= every
}

func appObject(c appClass) []map[string]any {
	return []map[string]any{{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "namespace": c.app.Namespace, "name": c.app.Name}}
}

// releaseSlot says whether a rule-caused release of key may go ahead now: key already holds a reservation, or the
// reservations and the releases completed in the window leave room, and a new reservation could be saved. A reservation
// that cannot be saved is not taken (a restart must not forget a release it counted).
func (a *Agent) releaseSlot(ctx context.Context, key string) bool {
	g := a.cfg.OptIn.Rule
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := a.now().Add(-g.ReleaseWindow)
	var keep []RuleSlot
	held := false
	for _, s := range a.st.Releases {
		if s.Done {
			if t, err := time.Parse(time.RFC3339Nano, s.At); err == nil && t.After(cut) {
				keep = append(keep, s)
			}
			continue
		}
		keep = append(keep, s)
		held = held || s.Key == key
	}
	prev := a.st.Releases
	a.st.Releases = keep
	if held {
		return true
	}
	if len(keep) >= g.ReleaseMax {
		return false
	}
	a.st.Releases = append(append([]RuleSlot(nil), keep...), RuleSlot{Key: key, At: a.now().UTC().Format(time.RFC3339Nano)})
	if err := a.saveLocked(ctx); err != nil {
		a.st.Releases = prev
		a.log.Warn("a release reservation could not be saved: the release waits", "application", key, "err", err)
		return false
	}
	return true
}

// holdsReservation says whether key holds an unfinished release reservation.
func (a *Agent) holdsReservation(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.st.Releases {
		if s.Key == key && !s.Done {
			return true
		}
	}
	return false
}

// settleReservation ends key's reservation, if it holds one: released (the Application is off the plugin) counts it as a
// release completed now; otherwise (it is gated again) the release was abandoned and the reservation is dropped.
func (a *Agent) settleReservation(ctx context.Context, key string, released bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, s := range a.st.Releases {
		if s.Key != key || s.Done {
			continue
		}
		if released {
			a.st.Releases[i] = RuleSlot{Key: key, At: a.now().UTC().Format(time.RFC3339Nano), Done: true}
		} else {
			a.st.Releases = append(a.st.Releases[:i:i], a.st.Releases[i+1:]...)
		}
		if err := a.saveLocked(ctx); err != nil {
			a.log.Warn("the state could not be saved", "err", err)
		}
		return
	}
}

// markRuleGated keeps, in the state, which Applications the rule gates (a later release of one is rule-caused and
// bounded) and which were released by an exemption (gating one again does not wait for the core).
func (a *Agent) markRuleGated(ctx context.Context, key, rule string, gated bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.RuleGated == nil {
		a.st.RuleGated = map[string]string{}
	}
	cur, ok := a.st.RuleGated[key]
	switch {
	case gated && cur == rule && ok:
		return
	case gated:
		a.st.RuleGated[key] = rule
	case !ok:
		return
	default:
		delete(a.st.RuleGated, key)
	}
	if err := a.saveLocked(ctx); err != nil {
		a.log.Warn("the state could not be saved", "err", err)
	}
}

func (a *Agent) wasRuleGated(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.st.RuleGated[key]
	return ok
}

func (a *Agent) setExemptReleased(ctx context.Context, key string, released bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.ExemptReleased == nil {
		a.st.ExemptReleased = map[string]string{}
	}
	prev, ok := a.st.ExemptReleased[key]
	if ok == released {
		return nil
	}
	if released {
		a.st.ExemptReleased[key] = a.now().UTC().Format(time.RFC3339)
	} else {
		delete(a.st.ExemptReleased, key)
	}
	if err := a.saveLocked(ctx); err != nil {
		if released {
			delete(a.st.ExemptReleased, key)
		} else {
			a.st.ExemptReleased[key] = prev
		}
		return err
	}
	return nil
}

func (a *Agent) exemptReleased(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.st.ExemptReleased[key]
	return ok
}

// refuseExempted records that the core refused to drop these pairs for an exemption: the exemptions of their
// Applications are refused (asked again when the key changes or at the recheck), and the Applications stay gated.
func (a *Agent) refuseExempted(pairs []client.ProtectedPair, why string) {
	reason, _, _ := strings.Cut(why, ":")
	a.ruleMu.Lock()
	defer a.ruleMu.Unlock()
	for k, acc := range a.rs.accepted {
		for _, p := range pairs {
			if acc.refused == "" && acc.pair == (Pair{p.App, p.Env}) {
				acc.refused = reason
				a.rs.accepted[k] = acc
			}
		}
	}
}

// pruneRuleState forgets the rule's memory of Applications that no longer exist.
func (a *Agent) pruneRuleState(ctx context.Context, apps []Application) {
	live := map[string]bool{}
	for _, app := range apps {
		live[app.Namespace+"/"+app.Name] = true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	for i, s := range a.st.Releases {
		if !s.Done && !live[s.Key] { // gone: counted as a release now, so the window still holds it
			a.st.Releases[i] = RuleSlot{Key: s.Key, At: a.now().UTC().Format(time.RFC3339Nano), Done: true}
			changed = true
		}
	}
	for _, m := range []map[string]string{a.st.RuleGated, a.st.ExemptReleased} {
		for k := range m {
			if !live[k] {
				delete(m, k)
				changed = true
			}
		}
	}
	if changed {
		if err := a.saveLocked(ctx); err != nil {
			a.log.Warn("the state could not be saved", "err", err)
		}
	}
}
