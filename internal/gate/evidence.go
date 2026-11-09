package gate

import (
	"context"

	"github.com/jfillman/clearance/internal/store"
)

// EvidenceGate is the evidence ledger's outage knob as the gate sees it (C-3, internal/ledger.Service).
type EvidenceGate interface {
	// Hold reports whether evidence cannot be checkpointed right now and a tier 3 change must wait, and why. It
	// answers false when the deployment turned the wait off.
	Hold(ctx context.Context) (hold bool, why string)
}

// evidenceHold is why c must wait for evidence to be checkpointed, or "" when it need not: a tier 3 change, a
// ledger, and a ledger that says to hold.
func (s *Service) evidenceHold(ctx context.Context, c *Change) string {
	if s.Evidence == nil || c.Tier < 3 {
		return ""
	}
	if hold, why := s.Evidence.Hold(ctx); hold {
		if why == "" {
			why = "the evidence ledger cannot checkpoint"
		}
		return why
	}
	return ""
}

// SettleEvidence clears the tier 3 changes that were waiting for evidence to be checkpointed (EvidenceWait), once the
// ledger can checkpoint again. Each is a deploy.clear record by policy, and issues its token like any clearance. The
// ids settled; none while the ledger still says to hold.
func (s *Service) SettleEvidence(ctx context.Context) ([]string, error) {
	if s.Config.Off || s.Evidence == nil {
		return nil, nil
	}
	if hold, _ := s.Evidence.Hold(ctx); hold {
		return nil, nil
	}
	var done []string
	err := s.op(ctx, func(tx store.Tx, w *writer) error {
		hold, err := loadAll(tx.ChangesHolding(ctx))
		if err != nil {
			return err
		}
		for _, c := range hold {
			if c.State != StateHolding || c.EvidenceWait == nil || !w.now.Before(c.ExpiresAt.Time) {
				continue
			}
			if req := c.RequirementObj(); req == nil || !req.Satisfied(c.Approvals) {
				continue
			}
			now := PyTime{w.now}
			c.EvidenceWait = nil
			w.move(c, StateCleared, "", nil)
			c.ClearedBy, c.DecidedAt, c.UpdatedAt = strp("people"), &now, now
			w.settle(c)
			nonce, err := w.issue(c, "")
			if err != nil {
				return err
			}
			w.put(c)
			w.record("policy", nil, "deploy.clear", c, "allow", nil,
				"cleared (requirement met while the evidence could not be checkpointed; the ledger recovered)", map[string]any{"role": "evidence"}, clearedFields(c, nonce))
			done = append(done, c.ID)
		}
		return nil
	})
	return done, err
}
