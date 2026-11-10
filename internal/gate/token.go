package gate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// Tokens is how the gate issues clearance tokens (C-1): the signer, the issuer name verifiers check, and each
// token's life. A token is re-issued (same nonce, new iat and exp) before it expires while its change stays
// cleared, up to the change's horizon: as long after it was cleared as the change could have held (the policy's
// TTL, 7 days by default). Past the horizon, or once a new head supersedes the change, the token is revoked and
// the change must be registered again (a new head) to deploy.
type Tokens struct {
	Signer token.Signer
	Issuer string
	TTL    time.Duration
}

// Defaults for Tokens.
const (
	DefaultTokenTTL    = 15 * time.Minute
	DefaultTokenIssuer = "clearance"
	// MaxTokenTTL is the longest TTL a deployment may set (token.MaxLifetime).
	MaxTokenTTL = token.MaxLifetime
	// RefreshBatch caps the tokens one Refresh re-issues.
	RefreshBatch = 500
)

func (t *Tokens) ttl() time.Duration {
	if t.TTL <= 0 {
		return DefaultTokenTTL
	}
	return min(t.TTL, MaxTokenTTL)
}

func (t *Tokens) issuer() string {
	if t.Issuer == "" {
		return DefaultTokenIssuer
	}
	return t.Issuer
}

// due is when a token must be re-issued: half its life before it expires.
func (t *Tokens) due(now time.Time) time.Time { return now.Add(t.ttl() / 2) }

// NewNonce is 128 random bits, base64url.
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// horizon is the last moment c's token may be valid: decided_at plus the hold it was given.
func horizon(c *Change) time.Time {
	if c.DecidedAt == nil {
		return time.Time{}
	}
	return c.DecidedAt.Time.Add(c.ExpiresAt.Time.Sub(c.CreatedAt.Time))
}

// ProvenanceLevel is the evidence schema's provenance level for a change: an agent's PR the agent gates confirmed
// is confirmed-agent, any other agent PR probable-agent; a person's PR the gates found no agent in is
// confirmed-human; anything else unknown.
func ProvenanceLevel(c *Change) string {
	check := c.Checks["provenance"]
	switch {
	case c.ProposerKind == "agent" && check == "confirmed":
		return "confirmed-agent"
	case c.ProposerKind == "agent":
		return "probable-agent"
	case c.ProposerKind == "person" && check == "not-agent":
		return "confirmed-human"
	}
	return "unknown"
}

// approval is a person's approval as the token and the deploy.* records name it. An approval recorded before C-1
// carries no identity: the person stands in as sub, with UnattestedIssuer.
func (a Approval) claim() token.Approval {
	out := token.Approval{Sub: a.Sub, Iss: a.Iss, Person: a.Person, Role: a.Role, At: a.At, Kind: a.Kind}
	if a.Via != nil {
		out.Via = *a.Via
	}
	if out.Sub == "" {
		out.Sub = a.Person
	}
	if out.Iss == "" {
		out.Iss = UnattestedIssuer
	}
	return out
}

// Claims are the token claims for a cleared change, valid from now to exp.
func (t *Tokens) Claims(c *Change, nonce string, now, exp time.Time) token.Claims {
	images := []string{}
	objects := make([]token.Object, 0, len(c.Objects))
	for _, o := range c.Objects {
		for _, im := range o.Images {
			if !slices.Contains(images, im) {
				images = append(images, im)
			}
		}
		objects = append(objects, token.Object{APIVersion: o.APIVersion, Kind: o.Kind, Namespace: o.Namespace,
			Name: o.Name, Rendered: o.Digest, Changed: o.Op != "" && o.Op != "unchanged", Op: o.Op})
	}
	sort.Strings(images)
	approvals := make([]token.Approval, 0, len(c.Approvals))
	for _, a := range c.Approvals {
		approvals = append(approvals, a.claim())
	}
	clearedBy := "policy"
	if c.ClearedBy != nil && *c.ClearedBy != "" {
		clearedBy = *c.ClearedBy
	}
	decided := ""
	if c.DecidedAt != nil {
		decided = pycompat.Isoformat(c.DecidedAt.Time)
	}
	pol := c.PolicyClaim() // the deploy.* record's policy group, so the token attests what the record says
	prov := token.Provenance{Level: ProvenanceLevel(c), Check: c.Checks["provenance"], Proposer: c.Proposer,
		ProposerKind: c.ProposerKind}
	if c.Agent != nil {
		prov.Agent = *c.Agent
	}
	if c.TaskID != nil {
		prov.TaskID = *c.TaskID
	}
	// The token binds what the change binds: a saved plan by its digest (kind terraform-plan, plan_digest), else
	// the tree root (manifest-tree; a definition release binds to its tree digest the same way).
	subj := token.Subjects{Kind: KindManifestTree, Repo: c.Repo, PR: c.PR, Commit: c.Head, Base: c.Base,
		TreeRoot: c.TreeDigest, Images: images}
	if c.Subject != nil && c.Subject.Kind == KindTerraformPlan {
		subj.Kind, subj.TreeRoot, subj.PlanDigest = KindTerraformPlan, "", c.Subject.PlanDigest
	}
	return token.Claims{
		Type: token.Type, Issuer: t.issuer(), Subject: c.ID, IssuedAt: now.Unix(), Expires: exp.Unix(), Nonce: nonce,
		Clearance: token.Clearance{ID: c.ID, ClearedBy: clearedBy, DecidedAt: decided},
		Subjects:  subj,
		Objects:   objects, Target: token.Target{Cluster: c.Cluster, Env: c.Env, App: c.App}, Tier: c.Tier,
		Policy: pol, Provenance: prov, Approvals: approvals,
	}
}

// mint signs c's token for nonce at now; ok is false when c is past its horizon (no token can be issued).
func (t *Tokens) mint(ctx context.Context, c *Change, nonce string, now time.Time) (store.Token, bool, error) {
	exp := now.Add(t.ttl())
	// An applied, superseded change's token is kept live while its objects are (see move), which no horizon bounds:
	// the horizon is how long a change may wait to be applied.
	if hz := horizon(c); hz.Before(exp) && c.State != StateSuperseded {
		exp = hz
	}
	// NumericDate is whole seconds: a token that would expire within its first second is not worth issuing.
	if exp.Unix() <= now.Unix() {
		return store.Token{}, false, nil
	}
	tok, err := token.Issue(ctx, t.Signer, t.Claims(c, nonce, now, exp))
	if err != nil {
		return store.Token{}, false, err
	}
	env, err := json.Marshal(tok.Envelope)
	if err != nil {
		return store.Token{}, false, err
	}
	return store.Token{ChangeID: c.ID, Cluster: c.Cluster, Nonce: nonce, KeyID: tok.KeyID,
		IssuedAt: time.Unix(tok.Claims.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(tok.Claims.Expires, 0).UTC(),
		Envelope: env, JWT: tok.JWT}, true, nil
}

// issue is the token for a change just cleared: a fresh nonce (or the one given), signed in the clearing
// transaction. A signing failure fails the operation (the clear rolls back), so a change is never cleared without
// its token. "" and no error when the gate issues no tokens.
func (w *writer) issue(c *Change, nonce string) (string, error) {
	if w.err != nil || w.svc == nil || w.svc.Tokens == nil {
		return "", nil
	}
	if nonce == "" {
		n, err := NewNonce()
		if err != nil {
			return "", err
		}
		nonce = n
	}
	row, ok, err := w.svc.Tokens.mint(w.ctx, c, nonce, w.now)
	if err != nil {
		w.err = fmt.Errorf("gate: issuing the clearance token: %w", err) // rolls the clear back
		return "", w.err
	}
	if !ok {
		return "", nil
	}
	if err := w.tx.PutToken(w.ctx, row); err != nil {
		w.err = err
		return "", err
	}
	w.touch(row.ChangeID, row.Cluster)
	return nonce, nil
}

// revoke revokes c's live token because it left cleared (why: "superseded by <head>", "exception: drift"),
// recorded as deploy.revoke with extra beside the token's nonce. Only move calls it: a token is live only while
// its change is cleared.
func (w *writer) revoke(c *Change, why string, extra map[string]any) {
	if w.err != nil {
		return
	}
	tk, err := w.tx.Token(w.ctx, c.ID)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		w.err = err
		return
	}
	if tk.RevokedAt != nil {
		return
	}
	at := w.now
	tk.RevokedAt = &at
	if w.err = w.tx.PutToken(w.ctx, tk); w.err != nil {
		return
	}
	args := map[string]any{"token": tk.Nonce}
	for k, v := range extra {
		args[k] = v
	}
	w.touch(tk.ChangeID, tk.Cluster)
	w.record("policy", nil, "deploy.revoke", c, "allow", nil, "token revoked: "+why, args, map[string]any{"token": tk.Nonce})
}

// clearedFields are what a deploy.clear (and a deploy.request or deploy.answer on a cleared change) records about
// who cleared it: the approvals, each naming the person at their identity provider and the delegate it came
// through, cleared_by ("policy" when no person was needed), and the token's nonce when one was issued.
func clearedFields(c *Change, nonce string) map[string]any {
	approvals := make([]any, 0, len(c.Approvals))
	for _, a := range c.Approvals {
		cl := a.claim()
		m := map[string]any{"sub": cl.Sub, "iss": cl.Iss, "person": cl.Person, "role": cl.Role, "at": cl.At}
		if cl.Via != "" {
			m["via"] = cl.Via
		}
		if cl.Kind != "" {
			m["kind"] = cl.Kind
		}
		approvals = append(approvals, m)
	}
	out := map[string]any{"approvals": approvals, "cleared_by": strOrNil(c.ClearedBy)}
	if nonce != "" {
		out["token"] = nonce
	}
	return out
}

// Refresh re-issues the tokens due (half their life left, or signed by a key the core no longer uses) with the
// same nonce, and revokes those whose change is no longer cleared or is past its horizon. It records nothing:
// the decision was recorded when the change was cleared. The number re-issued and revoked.
func (s *Service) Refresh(ctx context.Context) (reissued, revoked int, err error) {
	if s.Tokens == nil || s.Config.Off {
		return 0, 0, nil
	}
	err = s.op(ctx, func(tx store.Tx, w *writer) error {
		due, err := tx.TokensDue(ctx, s.Tokens.due(w.now), s.Tokens.Signer.KeyID(), RefreshBatch)
		if err != nil {
			w.err = err
			return err
		}
		for _, tk := range due {
			n, err := s.refreshOne(tx, w, tk)
			if err != nil {
				w.err = err // nothing of this pass commits
				return err
			}
			if n {
				reissued++
			} else {
				revoked++
			}
		}
		return nil
	})
	return reissued, revoked, err
}

// refreshOne re-issues tk (true) or revokes it (false).
func (s *Service) refreshOne(tx store.Tx, w *writer, tk store.Token) (bool, error) {
	w.touch(tk.ChangeID, tk.Cluster)
	c, err := load(w.ctx, tx, tk.ChangeID)
	if err != nil {
		return false, err
	}
	if c != nil && (c.State == StateCleared || (c.State == StateSuperseded && applied(c))) {
		row, ok, err := s.Tokens.mint(w.ctx, c, tk.Nonce, w.now)
		if err != nil {
			return false, fmt.Errorf("gate: re-issuing the clearance token: %w", err)
		}
		if ok {
			return true, tx.PutToken(w.ctx, row)
		}
	}
	at := w.now
	tk.RevokedAt = &at
	return false, tx.PutToken(w.ctx, tk)
}

// Clearance is a change and its live token (nil when it has none: not cleared, revoked, lapsed, or a gate that
// issues no tokens), for GET /v1/clearances/{id} on the core. It reads without the gate's lock; only a token due
// for refresh takes it, to re-issue the token first, so the answer is never a token about to expire.
func (s *Service) Clearance(ctx context.Context, id string) (*Change, *store.Token, error) {
	if err := s.gateOn(); err != nil {
		return nil, nil, err
	}
	c, err := load(ctx, s.Store, id)
	if err != nil {
		return nil, nil, fmt.Errorf("gate: %w", err)
	}
	if c == nil {
		return nil, nil, gerr("DG-UNKNOWN", "no such change", "", 404)
	}
	if s.Tokens == nil {
		return c.View(), nil, nil
	}
	tk, err := s.Store.Token(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return c.View(), nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("gate: %w", err)
	}
	now := s.now()
	if tk.RevokedAt == nil && (tk.ExpiresAt.Before(s.Tokens.due(now)) || tk.KeyID != s.Tokens.Signer.KeyID()) {
		err := s.op(ctx, func(tx store.Tx, w *writer) error {
			cur, err := tx.Token(ctx, id) // re-read under the lock: another read may have refreshed it
			if err != nil {
				w.err = err
				return err
			}
			if cur.RevokedAt == nil && (cur.ExpiresAt.Before(s.Tokens.due(w.now)) || cur.KeyID != s.Tokens.Signer.KeyID()) {
				if _, err := s.refreshOne(tx, w, cur); err != nil {
					w.err = err
					return err
				}
			}
			if c, err = load(ctx, tx, id); err != nil {
				w.err = err
				return err
			}
			tk, err = tx.Token(ctx, id)
			w.err = err
			return err
		})
		if err != nil {
			return nil, nil, err
		}
	}
	// A superseded change's token that stays in the grant feed (it was applied) is no clearance: not served.
	if tk.RevokedAt != nil || !now.Before(tk.ExpiresAt) || c.State != StateCleared {
		return c.View(), nil, nil
	}
	return c.View(), &tk, nil
}

// CheckNonce is the core's replay check (token.NonceChecker): the token's nonce must be the live one its clearance
// holds now, unrevoked, on a change still cleared. A token from before a new head, or from an earlier clearance
// of the same change, is a replay.
func (s *Service) CheckNonce(ctx context.Context, c *token.Claims) error {
	tk, err := s.Store.Token(ctx, c.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("%w: the clearance has no token", token.ErrReplay)
	}
	if err != nil {
		return err
	}
	if tk.RevokedAt != nil || tk.Nonce != c.Nonce {
		return token.ErrReplay
	}
	ch, err := load(ctx, s.Store, c.Subject)
	if err != nil {
		return err
	}
	if ch == nil || ch.State != StateCleared {
		return fmt.Errorf("%w: the change is not cleared", token.ErrReplay)
	}
	return nil
}

// TokenView is a clearance token as the core and clearance-api answer it: both encodings, its nonce, the key that
// signed it and its validity.
type TokenView struct {
	Nonce     string         `json:"nonce"`
	KeyID     string         `json:"key_id"`
	IssuedAt  string         `json:"issued_at"`
	ExpiresAt string         `json:"expires_at"`
	DSSE      token.Envelope `json:"dsse"`
	JWT       string         `json:"jwt"`
}

// ViewToken is tk as a TokenView.
func ViewToken(tk store.Token) (*TokenView, error) {
	var env token.Envelope
	if err := json.Unmarshal(tk.Envelope, &env); err != nil {
		return nil, fmt.Errorf("gate: stored token envelope: %w", err)
	}
	return &TokenView{Nonce: tk.Nonce, KeyID: tk.KeyID, IssuedAt: tk.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt: tk.ExpiresAt.UTC().Format(time.RFC3339), DSSE: env, JWT: tk.JWT}, nil
}

// ClearanceAnswer is GET /v1/clearances/{id} on the core: the change's state and what it is bound to, and its live
// token (null when it has none).
type ClearanceAnswer struct {
	ID         string  `json:"id"`
	State      string  `json:"state"`
	App        string  `json:"app"`
	Env        string  `json:"env"`
	Cluster    string  `json:"cluster"`
	Repo       string  `json:"repo"`
	PR         int64   `json:"pr"`
	Head       string  `json:"head"`
	TreeDigest string  `json:"tree_digest"`
	Tier       int     `json:"tier"`
	ClearedBy  *string `json:"cleared_by"`
	TaskID     *string `json:"task_id"`
	ExpiresAt  PyTime  `json:"expires_at"`
	// Outcome is what the deploy reported for the change (null before one did): the deploy.outcome record's seq
	// and hash, whether it applied, the digest, and the release it names (G-ARGO-6).
	Outcome *Outcome   `json:"outcome"`
	Token   *TokenView `json:"token"`
}

// Answer is the ClearanceAnswer for c and its live token.
func Answer(c *Change, tk *store.Token) (ClearanceAnswer, error) {
	a := ClearanceAnswer{ID: c.ID, State: c.State, App: c.App, Env: c.Env, Cluster: c.Cluster, Repo: c.Repo, PR: c.PR,
		Head: c.Head, TreeDigest: c.TreeDigest, Tier: c.Tier, ClearedBy: c.ClearedBy, TaskID: c.TaskID,
		ExpiresAt: c.ExpiresAt, Outcome: c.Outcome}
	if tk != nil {
		v, err := ViewToken(*tk)
		if err != nil {
			return a, err
		}
		a.Token = v
	}
	return a, nil
}
