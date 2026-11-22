package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
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

// RuleSlot is one rule-caused release in the window (persisted).
type RuleSlot struct {
	Key string `json:"key"`
	At  string `json:"at"`
}

// acceptance is the core's last answer about one Application's exemption: for key (the pair, the Application, the entry
// and the rule digest), at at; refused says why it was not taken ("" when it was).
type acceptance struct {
	key     string
	at      time.Time
	refused string
	pair    Pair
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
			a.mu.Lock()
			if a.st.RuleDigest != r.Digest {
				a.st.RuleRaw, a.st.RuleDigest = r.Raw, r.Digest
				if serr := a.saveLocked(ctx); serr != nil {
					a.log.Warn("the gate rule's copy could not be saved in the state", "err", serr)
				}
			}
			a.mu.Unlock()
		}
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

// candidate is an Application the rule selects and an exempt entry names, whatever the entry's state.
func (c appClass) candidate() bool { return c.ruleName != "" && c.exempt != nil }

// decideExemptions asks the core about every exemption that would release an Application, and posts the exemptions'
// records. It says whether an answer changed what is honoured (the pass classifies again).
func (a *Agent) decideExemptions(ctx context.Context, classes []appClass, digest string) bool {
	changed := false
	present := map[string]bool{}
	for _, c := range classes {
		key := c.key()
		present[key] = true
		acc, had := a.answer(key)
		wasHonoured := had && acc.refused == ""
		drop := func(why string) {
			a.setAnswer(key, nil)
			if wasHonoured {
				changed = true
				a.postExemption(ctx, c, "expired", why, "")
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
			continue
		}
		k := exemptKey(c, digest)
		if had && acc.key == k && a.now().Sub(acc.at) < a.cfg.OptIn.Rule.Recheck {
			continue // answered, and not due again
		}
		refused, err := a.askExemption(ctx, c, k)
		switch {
		case err != nil: // unreachable, or the deadline passed: fail closed at once
			a.setAnswer(key, nil)
			if wasHonoured {
				changed = true
				a.warnOnce(key, "an exemption's acceptance is dropped (the core could not be asked): the Application is gated again: "+truncate(err.Error(), 200))
			}
		case refused != "":
			a.setAnswer(key, &acceptance{key: k, at: a.now(), refused: refused, pair: Pair{c.gateApp, c.env}})
			if wasHonoured {
				changed = true
				a.postExemption(ctx, c, "expired", "revoked", "")
			}
			if !had || acc.key != k || acc.refused != refused {
				a.postExemption(ctx, c, "refused", refused, "gate-exempt-refused|"+k)
			}
		default:
			a.setAnswer(key, &acceptance{key: k, at: a.now(), pair: Pair{c.gateApp, c.env}})
			if !wasHonoured || acc.key != k {
				changed = true
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
	for k := range a.rs.accepted {
		if !present[k] {
			delete(a.rs.accepted, k)
		}
	}
	a.ruleMu.Unlock()
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

// postExemption posts one of an exemption's state records; once is the Once fingerprint that marks it posted ("": none).
func (a *Agent) postExemption(ctx context.Context, c appClass, state, why, once string) {
	if c.exempt == nil || c.exempt.Invalid != "" || !dnsLabel.MatchString(c.gateApp) || !dnsLabel.MatchString(c.env) {
		return
	}
	event := ""
	if once != "" {
		sum := sha256.Sum256([]byte(once + "|" + a.now().UTC().Format("2006-01-02")))
		event = "gs-" + hex.EncodeToString(sum[:16])
	}
	if _, err := a.core.Record(ctx, a.exemptionRecord(c, state, why, event)); err != nil {
		a.log.Warn("a gate exemption's record could not be posted", "application", c.key(), "state", state, "err", err)
		return
	}
	if once != "" {
		a.mu.Lock()
		a.st.Once[once] = a.now().UTC().Format(time.RFC3339)
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

// releaseSlot says whether a rule-caused release of key may go ahead now: it already has a slot in the window, or the
// window has room (the slot is then taken and persisted).
func (a *Agent) releaseSlot(ctx context.Context, key string) bool {
	g := a.cfg.OptIn.Rule
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := a.now().Add(-g.ReleaseWindow)
	var keep []RuleSlot
	have := false
	for _, s := range a.st.Releases {
		t, err := time.Parse(time.RFC3339Nano, s.At)
		if err != nil || !t.After(cut) {
			continue
		}
		keep = append(keep, s)
		if s.Key == key {
			have = true
		}
	}
	if have {
		a.st.Releases = keep
		return true
	}
	if len(keep) >= g.ReleaseMax {
		a.st.Releases = keep
		return false
	}
	a.st.Releases = append(keep, RuleSlot{Key: key, At: a.now().UTC().Format(time.RFC3339Nano)})
	if err := a.saveLocked(ctx); err != nil {
		a.log.Warn("the release slot could not be saved", "err", err)
	}
	return true
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

func (a *Agent) setExemptReleased(ctx context.Context, key string, released bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.ExemptReleased == nil {
		a.st.ExemptReleased = map[string]string{}
	}
	if _, ok := a.st.ExemptReleased[key]; ok == released {
		return
	}
	if released {
		a.st.ExemptReleased[key] = a.now().UTC().Format(time.RFC3339)
	} else {
		delete(a.st.ExemptReleased, key)
	}
	if err := a.saveLocked(ctx); err != nil {
		a.log.Warn("the state could not be saved", "err", err)
	}
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
