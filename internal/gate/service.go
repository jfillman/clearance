package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfillman/clearance/internal/vocab"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/review"
	"github.com/jfillman/clearance/internal/store"
)

// Config is the gate's part of the deployment (Gateway's constructor arguments; R-1d/R-2 map the environment).
type Config struct {
	// Off is a Clearance that keeps no changes: every gate route answers DG-OFF (Gateway(changes=None)).
	Off bool `json:"off"`
	// Verifiers are principal globs that may register changes (CLEARANCE_VERIFIERS).
	Verifiers []string `json:"verifiers"`
	// VerifierAppBindingOff turns off the binding of a verifier named app-<app>-cicd/<sa> to <app> (CLEARANCE_VERIFIER_APP_BINDING=off).
	VerifierAppBindingOff bool `json:"verifierAppBindingOff"`
	// Delegates are principal globs that may act for a person they name (CLEARANCE_DELEGATES).
	Delegates []string `json:"delegates"`
	// Admins are principal globs (user:<login>) that may deny any held change (CLEARANCE_ADMINS).
	Admins []string `json:"admins"`
	// TrustedRegistries narrow tier 1 to images from these prefixes (GatePolicy.trusted_registries; empty = any).
	TrustedRegistries []string `json:"trustedRegistries"`
	// Models are the deployment's model routes, for a definition release's review (nil = not checked).
	Models []string `json:"models"`
	// ImageAllow are the runtime-image globs a definition release's runtime.image must match.
	ImageAllow []string `json:"imageAllow"`
	// Protected are the environments the gate protects, "<cluster glob>/<env glob>" (CLEARANCE_PROTECTED_ENVIRONMENTS,
	// ParseProtected). Empty: every environment is protected (fail closed). A change elsewhere is cleared at tier 0,
	// reason unprotected.
	Protected []string `json:"protected"`
	// BreakglassMaxTTL caps a break-glass window (CLEARANCE_BREAKGLASS_MAX_TTL; 0 is MaxBreakglassTTL, never more).
	BreakglassMaxTTL time.Duration `json:"breakglassMaxTTL"`
	// UnboundTree is what a manifest-tree registration with a placeholder treeDigest gets (CLEARANCE_GATE_UNBOUND_TREE):
	// "flag" (the default for one release, then planned to be refuse: registered, flagged tree:unbound, bound to its commit only) or "refuse"
	// (DG-UNBOUND, 400).
	UnboundTree string `json:"unboundTree"`
	// DelegatePersons are principal globs ("user:<login>") a person named by a delegate must match
	// (CLEARANCE_DELEGATE_PERSON_ALLOWED). A person who signs in themselves passes the OIDC allowlist
	// (CLEARANCE_OIDC_ALLOWED_USERS) in the authenticator; a delegate's named person never meets it, so this is the same
	// door for them. Empty: any user:<name> the delegate says (the behaviour before this existed).
	DelegatePersons []string `json:"delegatePersons"`
	// ExtraVias are surface names a write may claim beside gate.Vias (CLEARANCE_VIAS_EXTRA): the deployment's portal.
	ExtraVias []string `json:"extraVias"`
	// Fresh is how recent a person's sign-in must be per action (CLEARANCE_FRESH_AUTH_*; zero values: no requirement).
	Fresh Freshness `json:"fresh"`
}

// verifierApp matches the principals of a pipeline in an app's cicd namespace: <ns>/<sa> (in-cluster) and
// <cluster>/<ns>/<sa> (a foreign cluster's workload, authn.KindForeignWorkload). Persons (user:), GitHub Actions
// (github:) and any other name are not matched.
var verifierApp = regexp.MustCompile(`^(?:[^/]+/)?app-([^/]+)-cicd/[^/]+$`)

// Unbound-tree modes (Config.UnboundTree).
const (
	UnboundFlag   = "flag"
	UnboundRefuse = "refuse"
)

// Owners says who owns an app (a group ref) when the check does not: on Hangar, the Backstage Component's
// spec.owner. "" when unknown.
type Owners interface {
	OwnerOf(ctx context.Context, app string) string
}

// Directory is a person's groups (inbox.Directory).
type Directory interface {
	Groups(ctx context.Context, person string) []string
}

// NotVerifier is provenance.NotVerifier raised by the gate (403, {"error": ...}).
type NotVerifier struct{ Message string }

func (e *NotVerifier) Error() string { return e.Message }

// Service is the deployment gate on a store: one store.Atomic per operation (the change row and its deploy.*
// records commit together) and one operation at a time (Gateway.lock).
type Service struct {
	Config    Config
	Policy    Policy // the baseline; DefaultPolicy() unless the deployment says otherwise
	Store     store.Store
	Clock     func() time.Time
	Writer    evidence.Writer // who the deploy.* records name as provider; zero: evidence.Core("")
	Owners    Owners          // nil: the outside group stands in
	Directory Directory       // nil: nobody is in any group
	Tools     review.Registry
	Parse     definitions.Parser
	// OnAnswered is called (non-blocking, after the commit) when a waiting GitHub deployment got its answer: the
	// GitHub App's delivery poke.
	OnAnswered []func()
	// OnOutcome is called (after the commit, never inside the transaction) with a change's id and the seq of the
	// deploy.outcome record just written for it: the attestation signer's trigger (C-2). nil: none.
	OnOutcome func(changeID string, seq int64)
	// Tokens issues the clearance token on deploy.clear (C-1); nil: no tokens (a deployment without a signing key).
	Tokens *Tokens
	// ProviderOf is the registered provider (CLEARANCE_PROVIDERS) that a principal is, if it is one. The outcome of a
	// terraform-plan change is written by the core on the caller's behalf (POST /v1/clearances/{id}/outcome), and
	// names that provider, so a Terraform CI's records say terraform-ci and not clearance. nil, or a principal that is
	// no provider: the core's own name.
	ProviderOf func(principal string) (evidence.Provider, bool)
	// Evidence is the evidence ledger's outage knob (C-3): while it says to hold, a tier 3 change whose
	// approvals are all in waits instead of clearing (SettleEvidence clears it when the ledger recovers).
	// nil: no ledger, nothing waits.
	Evidence EvidenceGate

	mu     sync.Mutex
	notify Notifier
}

// Watch is the gate's Notifier.Watch: a channel closed when change id is next written.
func (s *Service) Watch(id string) (<-chan struct{}, func(), error) { return s.notify.Watch(id) }

// NewService is a Service with the baseline policy (and the configured trusted registries).
func NewService(cfg Config, st store.Store, clock func() time.Time) *Service {
	p := DefaultPolicy()
	p.TrustedRegistries = append([]string(nil), cfg.TrustedRegistries...)
	return &Service{Config: cfg, Policy: p, Store: st, Clock: clock}
}

func (s *Service) now() time.Time { return s.Clock().UTC().Truncate(time.Microsecond) }

// op runs fn under the gate's lock in one transaction; fn's result error is returned after the commit (a refusal
// that follows a write, such as an expiry found while clearing, still commits the write).
func (s *Service) op(ctx context.Context, fn func(tx store.Tx, w *writer) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result, failed error
	var answered int
	var touched map[string]string
	err := s.Store.Atomic(ctx, func(tx store.Tx) error {
		w := &writer{ctx: ctx, tx: tx, now: s.now(), wr: s.Writer.OrCore(), svc: s}
		result = fn(tx, w)
		if w.fail != nil {
			// The operation says its refusal leaves nothing behind (Register): roll the whole transaction back.
			failed = w.fail
			return w.fail
		}
		w.signFeeds() // the touched clusters' grant feeds, in this transaction
		if w.err != nil {
			return w.err
		}
		answered, touched = w.answered, w.touched
		return nil
	})
	if failed != nil && errors.Is(err, failed) {
		return failed
	}
	if err != nil {
		return fmt.Errorf("gate: %w", err)
	}
	s.notify.notify(touched)
	if answered > 0 {
		for _, poke := range s.OnAnswered {
			poke()
		}
	}
	return result
}

// writer collects a gate operation's writes inside its transaction; the first store error aborts it.
type writer struct {
	ctx      context.Context
	tx       store.Tx
	now      time.Time
	err      error
	answered int
	wr       evidence.Writer
	svc      *Service
	touched  map[string]string // change id -> cluster, of every change or token written
	// fail, when set by the operation, rolls the whole transaction back and is returned as it is (op otherwise commits what
	// fn wrote when fn returns an error: an expiry found while clearing, a refused clear's record).
	fail error
}

func (w *writer) put(c *Change) {
	if w.err != nil {
		return
	}
	c.View()
	raw, err := json.Marshal(c)
	if err != nil {
		w.err = err
		return
	}
	w.touch(c.ID, c.Cluster)
	w.err = w.tx.PutChange(w.ctx, store.Change{ID: c.ID, App: c.App, Env: c.Env, State: c.State, Repo: c.Repo,
		Head: c.Head, PR: int(c.PR), ExpiresAt: c.ExpiresAt.Time, Record: raw})
}

func (w *writer) append(ev store.Event) store.Record {
	if w.err != nil {
		return nil
	}
	rec, err := w.tx.Append(w.ctx, ev, w.wr)
	if err != nil {
		w.err = err
	}
	return rec
}

// record is Gateway._gate_record. extra are fields beside the record's own (approvals, cleared_by, token).
func (w *writer) record(principal string, via *string, tool string, c *Change, decision string, rule *string, result string, args any, extra ...map[string]any) store.Record {
	if via != nil {
		result += " via " + *via
	}
	ev := store.Event{
		"ts": pycompat.ISO(w.now), "task_id": strOrNil(c.TaskID), "session": nil, "parent": nil, "principal": principal,
		"agent": strOrNil(c.Agent), "tool": tool, "tier": nil, "decision": decision, "rule": strOrNil(rule),
		"target": c.TargetOf(), "args_sha256": pycompat.ArgsDigest(args), "result": result, "app": c.App,
		"boundary": "deployment", "change": c.Summary(), "subject": c.recordSubject(), "policy": c.PolicyGroup(),
	}
	for _, x := range extra {
		for k, v := range x {
			ev[k] = v
		}
	}
	// The classes are the core's own computation from the diff it holds, so they are verified; a change registered
	// before I-1 has none stored and gets them computed from what it stores, under the baseline.
	stampClass(ev, c, w.svc.Policy)
	return w.recordVerified([]string{"operational_class", "class_mapping"}, func() store.Record { return w.append(ev) })
}

func (w *writer) settle(c *Change) {
	w.answered += AnswerDeployments(c, w.now)
}

func strOrNil(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func load(ctx context.Context, r store.Reader, id string) (*Change, error) {
	row, err := r.Change(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return FromRecord(row.Record)
}

func loadAll(rows []store.Change, err error) ([]*Change, error) {
	if err != nil {
		return nil, err
	}
	out := make([]*Change, 0, len(rows))
	for _, row := range rows {
		c, err := FromRecord(row.Record)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	// ORDER BY record->>'created_at' (pg.py): isoformat strings, compared as text.
	sort.SliceStable(out, func(i, j int) bool {
		return pycompat.Isoformat(out[i].CreatedAt.Time) < pycompat.Isoformat(out[j].CreatedAt.Time)
	})
	return out, nil
}

func (s *Service) gateOn() error {
	if s.Config.Off {
		return gerr("DG-OFF", "this Clearance keeps no changes (the deployment gate is off)", "", 404)
	}
	return nil
}

// Registered is register_change's answer: the change's view.
type Registered = Change

// Register is Gateway.register_change: the clearance-gate check registers (or re-evaluates) a change. The caller
// must be a verifier. Idempotent by (repo, pr, head): a holding change is re-evaluated with the new checks, a
// decided one returned as it stands; a new head on the same PR supersedes the heads still holding. body is the
// decoded JSON (numbers as json.Number). Errors: *NotVerifier, *BadChange, *Error.
func (s *Service) Register(ctx context.Context, p authn.Principal, body any) (*Change, error) {
	if !pycompat.MatchAny(p.ID, s.Config.Verifiers) {
		return nil, &NotVerifier{p.ID + " is not a verifier"}
	}
	if err := s.gateOn(); err != nil {
		return nil, err
	}
	req, err := ParseRequest(body)
	if err != nil {
		return nil, err
	}
	if !req.Protected {
		// Clearance decides protection from its own list (Config.Protected); a caller cannot opt a change out.
		return nil, gerr("DG-PROTECTED", "protected: false is refused: Clearance decides which environments it protects",
			"Drop the field; a change to an environment the deployment does not protect is cleared at tier 0 (unprotected).", 400)
	}
	req.Protected = s.ProtectsApp(ctx, req.Cluster, req.App, req.Env)
	if s.Config.UnboundTree == UnboundRefuse && req.Kind() != KindTerraformPlan && Unbound(req.TreeDigest) {
		return nil, gerr("DG-UNBOUND", "treeDigest is a placeholder, not the digest of the rendered tree",
			"Send the manifest-tree digest of what will be applied (`clearance register` computes it; docs/gate.md, The manifest-tree digest).", 400)
	}
	if m := verifierApp.FindStringSubmatch(p.ID); m != nil && !s.Config.VerifierAppBindingOff && m[1] != req.App && treeKeyOfReq(req) != "" {
		// A verifier running in app-<app>-cicd registers manifest-tree changes for <app> only (terraform plans and
		// definition releases have no tree record; a placeholder tree has one per head), so a verifier cannot add names to another app's trees.
		return nil, gerr("DG-VERIFIER-APP", fmt.Sprintf("%s may register changes for %s only, not %s", p.ID, m[1], req.App),
			"Register from the app's own pipeline (CLEARANCE_VERIFIER_APP_BINDING=off turns this check off).", 403)
	}
	if bound, ok := p.Claims["repository"].(string); ok {
		// A workflow's OIDC token registers changes for its own repository only (`clearance register`).
		if req.Repo != lower(bound) {
			return nil, gerr("DG-REPO", fmt.Sprintf("%s may register changes for %s only, not %s", p.ID, bound, req.Repo),
				"Register from a workflow in the repository the change deploys.", 403)
		}
	}
	if req.Owner == "" && s.Owners != nil {
		req.Owner = s.Owners.OwnerOf(ctx, req.App)
	}
	if req.Owner == "" {
		req.Owner = vocab.Get().OwnerFallback
		if len(s.Policy.OutsideGroups) > 0 {
			req.Owner = s.Policy.OutsideGroups[0]
		}
	}
	var out *Change
	err = s.op(ctx, func(tx store.Tx, w *writer) (rerr error) {
		// A registration is all or nothing: any error it returns rolls everything back (nothing superseded, no record).
		defer func() {
			if rerr != nil {
				w.fail = rerr
			}
		}()
		if c, err := s.clearedByTree(ctx, tx, req); err != nil {
			return err
		} else if c != nil {
			out = c
			return nil
		}
		// The people behind the change, before any state moves: the tree's record (grow-only, outlives every change on
		// the tree) takes this registration's proposer and set, or the registration is refused whole (DG-SOURCE-LIMIT).
		tree, err := s.unionTree(ctx, tx, req)
		if err != nil {
			return err
		}
		existing, err := load(ctx, tx, req.ID())
		if err != nil {
			return err
		}
		if existing != nil {
			// A re-registration adds its proposer and set to the change's, never removes (the change's snapshot of the tree's).
			changed, err := s.applyPeople(w, existing, req, tree, p.ID, false)
			if err != nil {
				return err
			}
			if changed && existing.State != StateHolding {
				w.put(existing)
			}
		}
		if err := tree.save(ctx, tx, w.now); err != nil {
			return err
		}
		if existing != nil && existing.State != StateHolding {
			out = existing
			return nil
		}
		var c Classification
		var cerr error
		if !req.Protected {
			c = unprotected(req, s.Policy)
		} else {
			var problems []review.Problem
			if req.Definition != nil {
				problems = s.definitionProblems(req)
			}
			c, cerr = Classify(req, s.Policy, s.Tools, problems)
		}
		var ge *Error
		if errors.As(cerr, &ge) {
			// A clearance.yaml that loosens the baseline: the change is denied, not the file ignored.
			ch := existing
			if ch == nil {
				ch = Open(req, Classification{3, []Reason{{"clearance.yaml", "policy:loosens", 3}}, "deny", &ge.Rule, ge.Message, nil, s.Policy}, w.now, p.ID)
				ch.State = ""
				w.opened(ch, StateDenied)
			} else {
				w.move(ch, StateDenied, "", nil)
			}
			now := PyTime{w.now}
			ch.DenyReason, ch.DeniedBy, ch.DecidedAt, ch.UpdatedAt = strp(ge.Message), strp("policy"), &now, now
			w.put(ch)
			if existing == nil {
				w.record(p.ID, nil, "deploy.request", ch, "allow", nil, fmt.Sprintf("tier %d: denied (%s)", ch.Tier, ge.Rule), body)
			}
			w.record("policy", nil, "deploy.deny", ch, "deny", &ge.Rule, ge.Message, map[string]any{"rule": ge.Rule})
			out = ch
			return nil
		} else if cerr != nil {
			return cerr
		}
		now := PyTime{w.now}
		to := map[string]string{"deny": StateDenied, "clear": StateCleared, "hold": StateHolding}[c.Decision]
		var ch *Change
		if existing == nil {
			olds, err := loadAll(tx.ChangesForPR(ctx, req.Repo, int(req.PR)))
			if err != nil {
				return err
			}
			for _, old := range olds {
				// A new head supersedes the heads still holding, and takes the clearance (and the token) of a
				// cleared older head: on the same pull request, or, for a pushed commit (pr 0), for the same app,
				// environment and cluster.
				if old.Head == req.Head || !(req.PR != 0 || (old.App == req.App && old.Env == req.Env && old.Cluster == req.Cluster)) {
					continue
				}
				if old.State != StateHolding && old.State != StateCleared {
					continue
				}
				w.move(old, StateSuperseded, "superseded by "+pycompat.Truncate(req.Head, 7), map[string]any{"by": req.Head})
				old.SupersededBy, old.DecidedAt, old.UpdatedAt = strp(req.Head), &now, now
				w.settle(old)
				w.put(old)
				w.record("policy", nil, "deploy.expire", old, "allow", nil, "superseded by "+pycompat.Truncate(req.Head, 7), map[string]any{"by": req.Head})
			}
			ch = Open(req, c, w.now, p.ID)
			if _, err := s.applyPeople(w, ch, req, tree, p.ID, true); err != nil {
				return err
			}
			ch.State = ""
			w.opened(ch, to)
			w.record(p.ID, nil, "deploy.request", ch, "allow", nil, c.Why, body, map[string]any{"change": ch.recordChange()})
		} else {
			ch = existing
			ch.Checks, ch.Tier, ch.Reasons, ch.UpdatedAt = copyChecks(req.Checks), c.Tier, append([]Reason(nil), c.Reasons...), now
			ch.Requirement, ch.Owner, ch.Protected, ch.Outage = c.Requirement, req.Owner, req.Protected, c.Policy.OutageFor(c.Tier)
			ch.Admission = copyAdmission(req.Admission)
			ch.PolicyRef, ch.PolicyVersion, ch.RepoPolicyDigest = policyRefOf(req), c.Policy.Version, c.Policy.RepoPolicyDigest
			if to != StateHolding {
				w.move(ch, to, "", nil)
			}
		}
		switch c.Decision {
		case "deny":
			ch.DenyReason, ch.DeniedBy, ch.DecidedAt = strp(c.Why), strp("policy"), &now
			w.record("policy", nil, "deploy.deny", ch, "deny", c.Rule, c.Why, map[string]any{"rule": strOrNil(c.Rule)})
		case "clear":
			ch.ClearedBy, ch.DecidedAt = strp("policy"), &now
			nonce, err := w.issue(ch, "")
			if err != nil {
				return err
			}
			w.record("policy", nil, "deploy.clear", ch, "allow", nil, c.Why, map[string]any{"tier": c.Tier}, clearedFields(ch, nonce))
		}
		w.settle(ch)
		w.put(ch)
		out = ch
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out.View(), nil
}

// clearedByTree is G-ARGO-4's lookup: a registration without a pull request (pr 0: Argo CD syncs the merge commit
// on main, which is no PR head) for a bound manifest tree answers the live cleared change for the same app,
// environment, cluster, repository and tree, if there is one, and registers nothing. The tree is what a grant binds to, so the
// commit and the PR the change was cleared under do not matter. Otherwise nil: the registration is evaluated as a
// new change (an uncovered tree is held for people unless its checks and tier let policy clear it).
func (s *Service) clearedByTree(ctx context.Context, r store.Reader, req ChangeRequest) (*Change, error) {
	if req.PR != 0 || req.Kind() != KindManifestTree || Unbound(req.TreeDigest) {
		return nil, nil
	}
	cleared, err := loadAll(r.ChangesCleared(ctx, req.App, req.Env))
	if err != nil {
		return nil, err
	}
	now := s.now()
	for i := len(cleared) - 1; i >= 0; i-- { // newest first
		c := cleared[i]
		if (c.Subject == nil || c.Subject.Kind == KindManifestTree) && c.Cluster == req.Cluster && c.Repo == req.Repo && bareHex(c.TreeDigest) == bareHex(req.TreeDigest) &&
			c.ExpiresAt.After(now) {
			return c.View(), nil
		}
	}
	return nil, nil
}

func (s *Service) definitionProblems(req ChangeRequest) []review.Problem {
	newDoc := req.Definition["new"]
	if newDoc == nil {
		return nil
	}
	name, _ := req.Definition["name"].(string)
	o := review.Options{Name: &name, Models: s.Config.Models, ImageAllow: s.Config.ImageAllow}
	if req.Owner != "" {
		o.Owner = strp(req.Owner)
	}
	if p, ok := req.Definition["path"].(string); ok {
		o.Path = &p
	}
	return review.Validate(newDoc, s.Tools, s.Parse, o)
}

// identity is who approved, at their identity provider: the subject and issuer of the ID token they signed in
// with, or, through a delegate, the person as the delegate named them and the delegate as the issuer.
type identity struct{ sub, iss, sid string }

// UnattestedIssuer is the iss of a person whose principal carries no issuer (an authenticator that does not say,
// such as `clearance core --insecure-dev-auth`).
const UnattestedIssuer = "unattested"

// person is Gateway._person through _gate_person: a person signed in themselves, or a delegate naming one.
func (s *Service) person(ctx context.Context, p authn.Principal, onBehalfOf string) (string, *string, map[string]bool, identity, error) {
	person, via := p.ID, (*string)(nil)
	var who identity
	if onBehalfOf != "" {
		if !pycompat.MatchAny(p.ID, s.Config.Delegates) {
			return "", nil, nil, who, gerr("DG-DELEGATE", p.ID+" may not act for a person", "", 403)
		}
		if len(onBehalfOf) < 5 || onBehalfOf[:5] != "user:" || pycompat.Len(onBehalfOf) > 200 {
			return "", nil, nil, who, gerr("DG-PERSON", "on-behalf-of must name a person (user:<name>)", "", 400)
		}
		if len(s.Config.DelegatePersons) > 0 && !pycompat.MatchAny(onBehalfOf, s.Config.DelegatePersons) {
			return "", nil, nil, who, gerr("DG-PERSON-ALLOWED", onBehalfOf+" is not allowed to act through a delegate on this Clearance",
				"The person is outside CLEARANCE_DELEGATE_PERSON_ALLOWED.", 403)
		}
		person, via = onBehalfOf, strp(p.ID)
		who = identity{sub: onBehalfOf, iss: "delegate:" + p.ID}
	} else if !p.IsPerson() {
		return "", nil, nil, who, gerr("DG-PERSON", p.ID+" is not a person", "", 403)
	} else {
		who = identity{sub: p.ID, iss: UnattestedIssuer}
		if v, ok := p.Claims["sub"].(string); ok && v != "" {
			who.sub = v
		}
		if v, ok := p.Claims["iss"].(string); ok && v != "" {
			who.iss = v
		}
		if v, ok := p.Claims["sid"].(string); ok {
			who.sid = v
		}
	}
	groups := map[string]bool{}
	if s.Directory != nil {
		for _, g := range s.Directory.Groups(ctx, person) {
			groups[g] = true
		}
	}
	return person, via, groups, who, nil
}

// Decided is clear_change's and deny_change's answer: the change's view and the record's seq.
type Decided struct {
	*Change
	AuditSeq any `json:"audit_seq"`
}

// MarshalJSON writes the change's view with audit_seq last ({**c.view(now), "audit_seq": seq}).
func (d Decided) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(d.Change)
	if err != nil {
		return nil, err
	}
	seq, err := json.Marshal(d.AuditSeq)
	if err != nil {
		return nil, err
	}
	return append(append(raw[:len(raw)-1], []byte(`,"audit_seq":`)...), append(seq, '}')...), nil
}

// Clear is Gateway.clear_change: one approval in the role the person qualifies for; the change is cleared when the
// requirement is met. Recorded as deploy.clear naming person and delegate.
func (s *Service) Clear(ctx context.Context, p authn.Principal, changeID, onBehalfOf string) (Decided, error) {
	if err := s.gateOn(); err != nil {
		return Decided{}, err
	}
	var out Decided
	err := s.op(ctx, func(tx store.Tx, w *writer) error {
		c, err := load(ctx, tx, changeID)
		if err != nil {
			return err
		}
		if c == nil {
			return gerr("DG-UNKNOWN", "no such change", "", 404)
		}
		if onBehalfOf == "" && !p.IsPerson() {
			return automationRefusal(p.ID, "a "+p.Kind+" principal")
		}
		person, via, groups, who, err := s.person(ctx, p, onBehalfOf)
		if err != nil {
			return err
		}
		if err := s.checkFresh(ctx, p, onBehalfOf, clearAction(c.Tier)); err != nil {
			return err
		}
		if c.State == StateHolding && !w.now.Before(c.ExpiresAt.Time) {
			s.expire(w, c)
			return gerr("DG-STATE", "this change has expired; a new push registers it again", "", 409)
		}
		if err := checkApproverKind(onBehalfOf, person, who); err != nil {
			return err
		}
		// The people as they are now, and the approvals that still count under them.
		if err := s.recheckPeople(ctx, tx, w, c); err != nil {
			return err
		}
		role, err := RoleFor(person, groups, c)
		if err != nil {
			var ge *Error
			if errors.As(err, &ge) && ge.Rule == "DG-PROPOSER" {
				// A refused clear is a record (who tried, which role excluded them), bounded per change.
				w.refused(c, person, via, ge)
			}
			return err
		}
		if err := checkApproverDistinct(c, person, who, sessionDigest(who.iss, who.sid), onBehalfOf != ""); err != nil {
			return err
		}
		now := PyTime{w.now}
		c.Approvals = append(c.Approvals, Approval{person, via, role, pycompat.ISO(w.now), who.sub, who.iss, KindPerson, sessionDigest(who.iss, who.sid), ""})
		c.UpdatedAt = now
		req := c.RequirementObj()
		done := req != nil && req.Satisfied(c.Approvals)
		nonce := ""
		var waiting string
		if done {
			if waiting = s.evidenceHold(ctx, c); waiting != "" {
				done = false
				if c.EvidenceWait == nil {
					c.EvidenceWait = &EvidenceWait{Since: pycompat.ISO(w.now)}
				}
				c.EvidenceWait.Assurance, c.EvidenceWait.Reason = AssuranceWaiting, waiting
			}
		}
		if done {
			c.EvidenceWait = nil
			w.move(c, StateCleared, "", nil)
			c.ClearedBy, c.DecidedAt = strp("people"), &now
			w.settle(c)
			if nonce, err = w.issue(c, ""); err != nil {
				return err
			}
		}
		w.put(c)
		result := "cleared as " + role
		if done {
			result += " (requirement met)"
		} else if waiting != "" {
			result += " (requirement met; waiting, the evidence cannot be checkpointed: " + waiting + ")"
		} else {
			result += fmt.Sprintf(" (%d of the people needed)", len(c.Approvals))
		}
		extra := clearedFields(c, nonce)
		withSurface(ctx, extra)
		if r := metaFrom(ctx).Reason; r != "" {
			extra["reason"] = r
		}
		if waiting != "" {
			extra["evidence"] = map[string]any{"assurance": AssuranceWaiting, "detail": waiting}
		}
		extra["change"] = c.recordChange() // the set this clear was checked against (change.people.digest)
		rec := w.record(person, via, "deploy.clear", c, "allow", nil, result, map[string]any{"role": role}, extra)
		out = Decided{c.View(), recordSeq(rec)}
		return nil
	})
	return out, err
}

// Deny is Gateway.deny_change: a person who could clear a holding change denies it, with a reason.
func (s *Service) Deny(ctx context.Context, p authn.Principal, changeID string, reason any, onBehalfOf string) (Decided, error) {
	if err := s.gateOn(); err != nil {
		return Decided{}, err
	}
	var out Decided
	err := s.op(ctx, func(tx store.Tx, w *writer) error {
		c, err := load(ctx, tx, changeID)
		if err != nil {
			return err
		}
		if c == nil {
			return gerr("DG-UNKNOWN", "no such change", "", 404)
		}
		person, via, groups, _, err := s.person(ctx, p, onBehalfOf)
		if err != nil {
			return err
		}
		text, err := CheckReason(reason)
		if err != nil {
			return err
		}
		if c.State != StateHolding {
			return gerr("DG-STATE", "this change is "+c.State, "", 409)
		}
		req := c.RequirementObj()
		eligible := false
		if req != nil {
			eligible = groups[req.OwnerGroup] || pycompat.MatchAny(person, s.Config.Admins)
			for _, g := range req.OutsideGroups {
				eligible = eligible || groups[g]
			}
		}
		if !eligible {
			return gerr("DG-FORBIDDEN", person+" may not decide this change", "Only the owner group, the outside group or a platform admin may.", 403)
		}
		now := PyTime{w.now}
		w.move(c, StateDenied, "", nil)
		c.DenyReason, c.DeniedBy, c.DecidedAt, c.UpdatedAt = &text, &person, &now, now
		w.settle(c)
		w.put(c)
		extra := map[string]any{}
		withSurface(ctx, extra)
		rec := w.record(person, via, "deploy.deny", c, "deny", strp("DG-DENIED"), text, map[string]any{"reason": text}, extra)
		out = Decided{c.View(), recordSeq(rec)}
		return nil
	})
	return out, err
}

func (s *Service) expire(w *writer, c *Change) {
	now := PyTime{w.now}
	w.move(c, StateExpired, "", nil)
	c.DecidedAt, c.UpdatedAt = &now, now
	w.settle(c)
	w.put(c)
	w.record("policy", nil, "deploy.expire", c, "allow", nil, "not cleared within "+s.ttlWords(c),
		map[string]any{"expires_at": pycompat.ISO(c.ExpiresAt.Time)})
}

// Expire is Gateway.expire_changes: holding changes past their TTL expire, each a deploy.expire record. The ids
// expired, in created order.
func (s *Service) Expire(ctx context.Context) ([]string, error) {
	if s.Config.Off {
		return nil, nil
	}
	var done []string
	err := s.op(ctx, func(tx store.Tx, w *writer) error {
		hold, err := loadAll(tx.ChangesHolding(ctx))
		if err != nil {
			return err
		}
		for _, c := range hold {
			if c.State == StateHolding && !w.now.Before(c.ExpiresAt.Time) {
				s.expire(w, c)
				done = append(done, c.ID)
			}
		}
		return nil
	})
	return done, err
}

// recordSeq is the stored record's seq as a JSON number.
func recordSeq(rec store.Record) any {
	if rec == nil {
		return nil
	}
	return rec["seq"]
}

// SeqInt is a record's seq as an integer (any of the number types a store may return).
func SeqInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case float64:
		return int64(x), true
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	}
	return 0, false
}

func lower(s string) string { return strings.ToLower(s) }

// PolicyView is Gateway.gate_policy_view.
func (s *Service) PolicyView() PolicyView { return s.Policy.View() }

// treeKey is what "the same tree" means for the people rule, as clearedByTree keys it: a manifest tree of the same app,
// environment, cluster and repository with the same bound tree digest, whatever its pull request or head. A change
// whose tree is a placeholder has a record of its own per head ("unbound@<head>"), so its people still count in its
// target's window (targetOf). "" for a terraform plan or a definition release, whose people stay with the change.
func treeKey(app, env, cluster, repo, digest, head string, manifest bool) string {
	if !manifest {
		return ""
	}
	if Unbound(digest) {
		return targetKey(app, env, cluster, repo) + "|unbound@" + head
	}
	return targetKey(app, env, cluster, repo) + "|" + bareHex(digest)
}

// targetKey is the target a tree belongs to: the app's environment on a cluster, from a repository.
func targetKey(app, env, cluster, repo string) string {
	return app + "|" + env + "|" + cluster + "|" + repo
}

func treeKeyOfReq(r ChangeRequest) string {
	return treeKey(r.App, r.Env, r.Cluster, r.Repo, r.TreeDigest, r.Head, r.Kind() == KindManifestTree)
}

func treeKeyOf(c *Change) string {
	return treeKey(c.App, c.Env, c.Cluster, c.Repo, c.TreeDigest, c.Head, c.Subject == nil || c.Subject.Kind == KindManifestTree)
}

// treeState is the tree's record as read and as it will be written.
type treeState struct {
	key    string
	target string
	rec    TreeRecord
	grew   bool
}

func (t *treeState) save(ctx context.Context, tx store.Tx, now time.Time) error {
	if t.key == "" || !t.grew {
		return nil
	}
	raw, err := json.Marshal(t.rec)
	if err != nil {
		return err
	}
	return tx.PutTreePeople(ctx, store.TreePeople{Key: t.key, Target: t.target, UpdatedAt: now, HasSource: !t.rec.noPeopleOfItsOwn(), Record: raw})
}

func readTree(ctx context.Context, r store.Reader, key string) (TreeRecord, error) {
	row, err := r.TreePeople(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return TreeRecord{}, nil
	}
	if err != nil {
		return TreeRecord{}, err
	}
	var rec TreeRecord
	if err := json.Unmarshal(row.Record, &rec); err != nil {
		return TreeRecord{}, fmt.Errorf("gate: tree people %s: %w", key, err)
	}
	return rec, nil
}

// unionTree reads the request's tree record (one primary-key read) and adds the request's people to it, refusing the
// registration before anything is written when a role would pass MaxTreePeople. A request with no tree key has none.
func (s *Service) unionTree(ctx context.Context, r store.Reader, req ChangeRequest) (*treeState, error) {
	t := &treeState{key: treeKeyOfReq(req), target: targetKey(req.App, req.Env, req.Cluster, req.Repo)}
	if t.key == "" {
		return t, nil
	}
	rec, err := readTree(ctx, r, t.key)
	if err != nil {
		return nil, err
	}
	t.rec, t.grew, err = rec.union(requestPeople(req))
	return t, err
}

// recheckPeople is what a clear stands on: the people behind the change as they are now, and the approvals that still
// count under them. It gives the change the tree's record as it is (a registration since the change's last one may have
// added people); when the change has no people of its own (its tree's record holds no author, merger or promoter; proposers do not
// count), every other people record of its target written or grown within its hold window is behind it
// too (the plugin's pr 0 change for a tree that is not the pull request's), a read bounded at MaxTargetRecords: past it
// the clear is refused (DG-PEOPLE-WINDOW). Then each approval from a person now behind the change is set aside (kept in
// the history, not counted, with a record saying why). It persists what it changed.
func (s *Service) recheckPeople(ctx context.Context, tx store.Tx, w *writer, c *Change) error {
	key := treeKeyOf(c)
	if key == "" {
		return s.setAside(w, c, false)
	}
	rec, err := readTree(ctx, tx, key)
	if err != nil {
		return err
	}
	added, err := c.absorb(rec.people())
	if err != nil {
		return err
	}
	changed := len(added) > 0
	if rec.noPeopleOfItsOwn() {
		since := w.now.Add(-holdWindow(c))
		rows, err := tx.TreePeopleForTarget(ctx, targetKey(c.App, c.Env, c.Cluster, c.Repo), since, MaxTargetRecords+1)
		if err != nil {
			return err
		}
		if len(rows) > MaxTargetRecords {
			return gerr("DG-PEOPLE-WINDOW", fmt.Sprintf("this target has more than %d recent people records, so who may clear cannot be settled; use break-glass", MaxTargetRecords),
				"Nobody can clear it through the gate until older changes lapse; break-glass (not source-aware, at most 4 hours) is the path.", 409)
		}
		for _, row := range rows {
			if row.Key == key {
				continue
			}
			var other TreeRecord
			if err := json.Unmarshal(row.Record, &other); err != nil {
				return fmt.Errorf("gate: tree people %s: %w", row.Key, err)
			}
			a, err := c.absorb(other.people())
			if err != nil {
				return err
			}
			changed = changed || len(a) > 0
		}
	}
	return s.setAside(w, c, changed)
}

// holdWindow is how long a change holds: its own TTL (the hold window the target's recent records are read over).
func holdWindow(c *Change) time.Duration {
	if d := c.ExpiresAt.Sub(c.CreatedAt.Time); d > 0 {
		return d
	}
	return 7 * 24 * time.Hour
}

// setAside marks each approval from a person now behind c, and persists c when it (or the people) changed.
func (s *Service) setAside(w *writer, c *Change, changed bool) error {
	for i := range c.Approvals {
		a := &c.Approvals[i]
		if a.SetAside != "" {
			continue
		}
		if roles := rolesBehind(a.Person, c); len(roles) > 0 {
			a.SetAside = a.Person + " is " + strings.Join(roles, " and ") + " of this change since they approved"
			changed = true
			w.note(c, "policy", "people: approval of "+a.Person+" set aside: "+a.SetAside)
		}
	}
	if changed {
		w.put(c)
	}
	return nil
}

// applyPeople gives ch the tree's people (or, with no tree key, this request's) and records a re-registration that
// omitted names the change has (only when it sent a set: a verifier that sends none gets today's behaviour). It only
// adds. It reports whether ch changed.
func (s *Service) applyPeople(w *writer, ch *Change, req ChangeRequest, tree *treeState, principal string, fresh bool) (bool, error) {
	changed := false
	if !fresh && req.Source != nil {
		if n := ch.omitted(req); n > 0 && ch.PeopleNotes < MaxPeopleNotes {
			changed = true
			w.note(ch, principal, fmt.Sprintf("people: the registration omitted %d source name(s) the change has; kept (the set only grows)", n))
		}
	}
	add := requestPeople(req)
	if tree.key != "" {
		add = tree.rec.people()
	}
	added, err := ch.absorb(add)
	if err != nil {
		return false, err
	}
	if len(added) > 0 {
		changed = true
		if !fresh {
			w.note(ch, principal, "people: added "+strings.Join(added, ", "))
		}
	}
	return changed, nil
}

// note records a growth of (or an omission from) a change's people, as deploy.people, bounded per change.
func (w *writer) note(c *Change, principal, result string) {
	if c.PeopleNotes >= MaxPeopleNotes {
		return
	}
	c.PeopleNotes++
	w.record(principal, nil, "deploy.people", c, "allow", nil, result, map[string]any{"change": c.recordChange()})
}

// refused records a clear the people rule refused, as deploy.refuse (decision deny, rule DG-PROPOSER), bounded per
// change and apart from the people notes, so refusals cannot use up the budget that records a shrink attempt; the
// packet reads deploy.request, deploy.clear and deploy.deny, so this is not mistaken for a state.
func (w *writer) refused(c *Change, person string, via *string, ge *Error) {
	if c.RefusalNotes >= MaxPeopleNotes {
		return
	}
	c.RefusalNotes++
	w.record(person, via, "deploy.refuse", c, "deny", strp(ge.Rule), ge.Message, map[string]any{"rule": ge.Rule}, map[string]any{"change": c.recordChange()})
	w.put(c)
}
