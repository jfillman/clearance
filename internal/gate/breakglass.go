package gate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
)

// Break-glass (C-6): an admin (CLEARANCE_ADMINS), or a delegate naming one, opens a window on one protected
// environment for a bounded time, with a reason. The window is recorded (breakglass.open) and committed before the
// route answers, so the record precedes every change it covers: nothing in Clearance applies a change, and a
// provider that honours break-glass (the Argo agent's marker, G-ARGO-3) reads the open windows from the core
// (GET /v1/breakglass). Break-glass clears nothing: changes made in the window are still exceptions when a provider
// sees them, and each deploy.exception and deploy.degraded inside it carries the window's id (breakglass). When the
// TTL ends (or an admin closes it early) the core reconciles the window: a breakglass.close record lists what the
// record store knows changed in it, from the chain, and says what it cannot know.
const (
	ToolBreakglassOpen  = "breakglass.open"
	ToolBreakglassClose = "breakglass.close"

	BreakglassOpen   = "open"
	BreakglassClosed = "closed"

	// MaxBreakglassTTL is the longest window any deployment may allow; MinBreakglassTTL the shortest.
	MaxBreakglassTTL = 4 * time.Hour
	MinBreakglassTTL = time.Minute
	// MaxBreakglassListed caps the records a breakglass.close lists (the count is always complete up to
	// MaxBreakglassScan).
	MaxBreakglassListed = 200
	// MaxBreakglassScan caps the records reconciliation reads after the window opened.
	MaxBreakglassScan = 100000
	// MaxBreakglassBody caps POST /v1/breakglass.
	MaxBreakglassBody = 16 << 10
)

// BreakglassLimitation is what a breakglass.close cannot know, recorded with every one.
const BreakglassLimitation = "Lists only what a provider reported to Clearance in the window (deployment-boundary " +
	"exceptions, outage reports, outcomes and clearances for this cluster and environment). A change made directly " +
	"(kubectl, a cloud console, a script) appears only if an exception detector watches this environment and " +
	"reported it; a report that arrived after the window closed is not listed."

// Breakglass is a break-glass window, the row's record and the API's answer.
type Breakglass struct {
	ID         string     `json:"id"`
	State      string     `json:"state"`
	Person     string     `json:"person"`
	Via        *string    `json:"via"`
	Sub        string     `json:"sub"`
	Iss        string     `json:"iss"`
	Reason     string     `json:"reason"`
	Cluster    string     `json:"cluster"`
	Env        string     `json:"env"`
	App        *string    `json:"app"`
	TTLSeconds int64      `json:"ttl_seconds"`
	OpenedAt   time.Time  `json:"opened_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	OpenSeq    int64      `json:"open_seq"`
	ClosedAt   *time.Time `json:"closed_at"`
	ClosedBy   *string    `json:"closed_by"`
	CloseSeq   *int64     `json:"close_seq"`
	// Reported is how many records the record store holds for the window (set when it closes).
	Reported *int `json:"reported"`
}

// BreakglassRequest is POST /v1/breakglass's body: why, for how long (a Go duration), and where.
type BreakglassRequest struct {
	Reason  string  `json:"reason" contract:"required"`
	TTL     string  `json:"ttl" contract:"required"`
	Cluster string  `json:"cluster" contract:"required"`
	Env     string  `json:"env" contract:"required"`
	App     *string `json:"app,omitempty"`
}

func (s *Service) maxBreakglassTTL() time.Duration {
	if d := s.Config.BreakglassMaxTTL; d > 0 && d < MaxBreakglassTTL {
		return d
	}
	return MaxBreakglassTTL
}

func newBreakglassID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "bg-" + hex.EncodeToString(b), nil
}

func (b *Breakglass) row() (store.Breakglass, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return store.Breakglass{}, err
	}
	return store.Breakglass{ID: b.ID, Cluster: b.Cluster, Env: b.Env, State: b.State, ExpiresAt: b.ExpiresAt, Record: raw}, nil
}

func fromRow(r store.Breakglass) (*Breakglass, error) {
	var b Breakglass
	if err := json.Unmarshal(r.Record, &b); err != nil {
		return nil, fmt.Errorf("gate: break-glass record: %w", err)
	}
	return &b, nil
}

// openWindow is the open window on cluster and env at now (nil when none). With app nil any window there counts
// (the one-window-per-environment check); with app set only a window for the whole environment or for that app
// does (tagging a report, as inWindow scopes the close).
func openWindow(ctx context.Context, r store.Reader, cluster, env string, app *string, now time.Time) (*Breakglass, error) {
	rows, err := r.BreakglassOpen(ctx)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Cluster != cluster || row.Env != env || !now.Before(row.ExpiresAt) {
			continue
		}
		b, err := fromRow(row)
		if err != nil {
			return nil, err
		}
		if app == nil || b.App == nil || *b.App == *app {
			return b, nil
		}
	}
	return nil, nil
}

// admin is the person behind p (themselves, or the person a delegate names) when they are an admin.
func (s *Service) admin(ctx context.Context, p authn.Principal, onBehalfOf string) (string, *string, identity, error) {
	person, via, _, who, err := s.person(ctx, p, onBehalfOf)
	if err != nil {
		return "", nil, who, err
	}
	if !pycompat.MatchAny(person, s.Config.Admins) {
		return "", nil, who, gerr("DG-BREAKGLASS", person+" is not a Clearance admin (CLEARANCE_ADMINS)",
			"Only an admin, or a delegate naming one, may break glass.", 403)
	}
	return person, via, who, nil
}

// glassWriter seals break-glass records: the core, with the window and the reconciliation verified (the core
// computed them), and the initiator verified when the admin signed in themselves.
func (w *writer) glassWriter(via *string) evidence.Writer {
	wr := w.wr
	v := maps.Clone(evidence.GatewayVerified)
	for _, k := range []string{"breakglass", "window", "changes", "reported", "truncated", "limitations"} {
		v[k] = true
	}
	if via == nil {
		v["initiator"] = true
	}
	wr.Verified = v
	return wr
}

// OpenBreakglass is POST /v1/breakglass: an admin opens a window. It is recorded (breakglass.open) in the same
// transaction as the row, and the answer comes only after both commit. Errors: *Error (DG-BREAKGLASS 403,
// DG-BREAKGLASS-TTL and DG-BREAKGLASS-SCOPE 400, DG-BREAKGLASS-OPEN 409, DG-REASON 400, DG-DELEGATE, DG-PERSON).
func (s *Service) OpenBreakglass(ctx context.Context, p authn.Principal, req BreakglassRequest, onBehalfOf string) (*Breakglass, error) {
	if err := s.gateOn(); err != nil {
		return nil, err
	}
	person, via, who, err := s.admin(ctx, p, onBehalfOf)
	if err != nil {
		return nil, err
	}
	reason, err := CheckReason(req.Reason)
	if err != nil {
		return nil, err
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil || ttl < MinBreakglassTTL || ttl > s.maxBreakglassTTL() {
		return nil, gerr("DG-BREAKGLASS-TTL", fmt.Sprintf("ttl is a Go duration from %s to %s", MinBreakglassTTL, s.maxBreakglassTTL()),
			"Break glass for as short a time as the fix needs; open another window if it runs out.", 400)
	}
	ttl = ttl.Truncate(time.Second)
	if !nameRx.MatchString(req.Cluster) || !nameRx.MatchString(req.Env) || (req.App != nil && !nameRx.MatchString(*req.App)) {
		return nil, gerr("DG-BREAKGLASS-SCOPE", "cluster, env (and app) are names", "", 400)
	}
	if !s.Protects(req.Cluster, req.Env) {
		return nil, gerr("DG-BREAKGLASS-SCOPE", req.Cluster+"/"+req.Env+" is not a protected environment: there is no glass to break",
			"", 400)
	}
	var out *Breakglass
	err = s.op(ctx, func(tx store.Tx, w *writer) error {
		cur, err := openWindow(ctx, tx, req.Cluster, req.Env, nil, w.now)
		if err != nil {
			return err
		}
		if cur != nil {
			return gerr("DG-BREAKGLASS-OPEN", fmt.Sprintf("break-glass %s is already open on %s/%s until %s", cur.ID, cur.Cluster,
				cur.Env, evidence.ISO(cur.ExpiresAt)), "Close it first, or work inside it.", 409)
		}
		id, err := newBreakglassID()
		if err != nil {
			return err
		}
		b := &Breakglass{ID: id, State: BreakglassOpen, Person: person, Via: via, Sub: who.sub, Iss: who.iss, Reason: reason,
			Cluster: req.Cluster, Env: req.Env, App: req.App, TTLSeconds: int64(ttl / time.Second), OpenedAt: w.now,
			ExpiresAt: w.now.Add(ttl)}
		result := fmt.Sprintf("break-glass opened on %s/%s for %s", b.Cluster, b.Env, ttl)
		if via != nil {
			result += " via " + *via
		}
		target := b.Cluster + "/" + b.Env
		rec := w.appendWith(store.Event{
			"ts": evidence.ISO(w.now), "task_id": nil, "session": nil, "parent": nil, "principal": person,
			"agent": nil, "tool": ToolBreakglassOpen, "tier": nil, "decision": "allow", "rule": nil, "target": target,
			"args_sha256": pycompat.ArgsDigest(map[string]any{"reason": reason, "ttl": req.TTL, "cluster": req.Cluster,
				"env": req.Env, "app": strOrNil(req.App)}),
			"result": result, "app": strOrNil(req.App), "boundary": "deployment", "reason": reason,
			"initiator": map[string]any{"sub": who.sub, "iss": who.iss},
			"breakglass": map[string]any{"id": b.ID, "cluster": b.Cluster, "env": b.Env, "app": strOrNil(b.App),
				"ttl_seconds": json.Number(fmt.Sprint(b.TTLSeconds)), "expires_at": evidence.ISO(b.ExpiresAt)},
			"destination": map[string]any{"cluster": b.Cluster, "environment": b.Env},
		}, w.glassWriter(via))
		if w.err != nil {
			return w.err
		}
		b.OpenSeq, _ = SeqInt(rec["seq"])
		w.putGlass(b)
		out = b
		return w.err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (w *writer) appendWith(ev store.Event, wr evidence.Writer) store.Record {
	if w.err != nil {
		return nil
	}
	rec, err := w.tx.Append(w.ctx, ev, wr)
	if err != nil {
		w.err = err
	}
	return rec
}

func (w *writer) putGlass(b *Breakglass) {
	if w.err != nil {
		return
	}
	row, err := b.row()
	if err != nil {
		w.err = err
		return
	}
	w.err = w.tx.PutBreakglass(w.ctx, row)
}

// CloseBreakglass closes a window early: an admin (or a delegate naming one). It is reconciled at once.
func (s *Service) CloseBreakglass(ctx context.Context, p authn.Principal, id, onBehalfOf string) (*Breakglass, error) {
	if err := s.gateOn(); err != nil {
		return nil, err
	}
	person, via, _, err := s.admin(ctx, p, onBehalfOf)
	if err != nil {
		return nil, err
	}
	var out *Breakglass
	err = s.op(ctx, func(tx store.Tx, w *writer) error {
		row, err := tx.Breakglass(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return gerr("DG-UNKNOWN", "no such break-glass window", "", 404)
		}
		if err != nil {
			return err
		}
		b, err := fromRow(row)
		if err != nil {
			return err
		}
		if b.State != BreakglassOpen {
			return gerr("DG-STATE", "this break-glass window is already closed", "", 409)
		}
		by := person
		if via != nil {
			by += " via " + *via
		}
		s.reconcile(w, b, by, person, via)
		out = b
		return w.err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReconcileBreakglass closes the windows whose TTL has passed, each with its breakglass.close record. The ids
// closed.
func (s *Service) ReconcileBreakglass(ctx context.Context) ([]string, error) {
	if s.Config.Off {
		return nil, nil
	}
	var done []string
	err := s.op(ctx, func(tx store.Tx, w *writer) error {
		rows, err := tx.BreakglassOpen(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if w.now.Before(row.ExpiresAt) {
				continue
			}
			b, err := fromRow(row)
			if err != nil {
				return err
			}
			s.reconcile(w, b, "ttl", "policy", nil)
			if w.err != nil {
				return w.err
			}
			done = append(done, b.ID)
		}
		return nil
	})
	return done, err
}

// OpenBreakglassWindows are the windows open now, for cluster ("" for every cluster): what a provider honours.
func (s *Service) OpenBreakglassWindows(ctx context.Context, cluster string) ([]*Breakglass, error) {
	if err := s.gateOn(); err != nil {
		return nil, err
	}
	rows, err := s.Store.BreakglassOpen(ctx)
	if err != nil {
		return nil, fmt.Errorf("gate: %w", err)
	}
	now := s.now()
	out := []*Breakglass{}
	for _, row := range rows {
		if (cluster == "" || row.Cluster == cluster) && now.Before(row.ExpiresAt) {
			b, err := fromRow(row)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		}
	}
	return out, nil
}

// windowTools are the deployment records reconciliation lists.
var windowTools = map[string]bool{KindException: true, KindDegraded: true, "deploy.outcome": true, "deploy.clear": true}

// inWindow says whether a record is about b's environment (and app, when b names one).
func inWindow(r store.Record, b *Breakglass) bool {
	if r["boundary"] != "deployment" || !windowTools[fmt.Sprint(r["tool"])] {
		return false
	}
	cluster, env := "", ""
	if d, ok := r["destination"].(map[string]any); ok {
		cluster, _ = d["cluster"].(string)
		env, _ = d["environment"].(string)
	}
	if c, ok := r["change"].(map[string]any); ok && cluster == "" {
		cluster, _ = c["cluster"].(string)
		env, _ = c["env"].(string)
	}
	if cluster != b.Cluster || env != b.Env {
		return false
	}
	return b.App == nil || r["app"] == *b.App
}

// reconcile closes b now: it reads the records written since the window opened and writes breakglass.close
// listing the ones about its environment. by is "ttl" or the admin who closed it (and the delegate), principal
// the record's principal ("policy" for the TTL).
func (s *Service) reconcile(w *writer, b *Breakglass, by, principal string, via *string) {
	if w.err != nil {
		return
	}
	var listed []any
	count, exceptions, scanned, truncated := 0, 0, 0, false
	for from := b.OpenSeq + 1; ; {
		recs, err := w.tx.Records(w.ctx, from, 1000)
		if err != nil {
			w.err = err
			return
		}
		for _, r := range recs {
			scanned++
			if !inWindow(r, b) {
				continue
			}
			count++
			if r["tool"] == KindException || r["tool"] == KindDegraded {
				exceptions++
			}
			if len(listed) < MaxBreakglassListed {
				item := map[string]any{"seq": r["seq"], "tool": r["tool"], "target": r["target"], "ts": r["ts"]}
				if x, ok := r["exception"].(map[string]any); ok {
					item["kind"] = x["kind"]
				}
				listed = append(listed, item)
			} else {
				truncated = true
			}
		}
		if len(recs) < 1000 {
			break
		}
		if scanned >= MaxBreakglassScan {
			truncated = true
			break
		}
		from += int64(len(recs))
	}
	if listed == nil {
		listed = []any{}
	}
	closedAt := w.now
	if by == "ttl" && b.ExpiresAt.Before(closedAt) {
		closedAt = b.ExpiresAt // the window ended at its TTL; reconciliation may run a little later
	}
	result := fmt.Sprintf("break-glass %s closed (%s): %d records in the window, %d of them exceptions", b.ID, by, count, exceptions)
	rec := w.appendWith(store.Event{
		"ts": evidence.ISO(w.now), "task_id": nil, "session": nil, "parent": nil, "principal": principal,
		"agent": nil, "tool": ToolBreakglassClose, "tier": nil, "decision": "allow", "rule": nil,
		"target": b.Cluster + "/" + b.Env, "args_sha256": pycompat.ArgsDigest(map[string]any{"id": b.ID, "by": by}),
		"result": result, "app": strOrNil(b.App), "boundary": "deployment",
		"breakglass": map[string]any{"id": b.ID, "cluster": b.Cluster, "env": b.Env, "app": strOrNil(b.App),
			"opened_by": b.Person, "open_seq": json.Number(fmt.Sprint(b.OpenSeq)), "closed_by": by},
		"window":  map[string]any{"from": evidence.ISO(b.OpenedAt), "to": evidence.ISO(closedAt)},
		"changes": listed, "reported": json.Number(fmt.Sprint(count)), "truncated": truncated,
		"limitations": BreakglassLimitation,
		"destination": map[string]any{"cluster": b.Cluster, "environment": b.Env},
	}, w.glassWriter(via))
	if w.err != nil {
		return
	}
	seq, _ := SeqInt(rec["seq"])
	b.State, b.ClosedAt, b.ClosedBy, b.CloseSeq, b.Reported = BreakglassClosed, &closedAt, &by, &seq, &count
	w.putGlass(b)
}
