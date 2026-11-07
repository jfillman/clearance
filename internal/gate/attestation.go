package gate

import (
	"context"
	"fmt"

	"github.com/jfillman/clearance/internal/store"
)

// KindAttestation is the record that carries a change attestation's envelope digest (C-2): the chain says when the
// core signed what, and the digest ties the stored bundle to that record.
const KindAttestation = "deploy.attestation"

// RecordAttestation stores the change's attestation and appends deploy.attestation, with the envelope digest and the
// Rekor index, in one transaction. a.ChangeID, Digest, Backend, Bundle and OutcomeSeq are the signer's; RecordSeq and
// CreatedAt are set here. A change that already has one keeps it (the first attestation stands): the existing row is
// returned and nothing is written. Errors: *Error DG-UNKNOWN (404) for a change the core does not hold.
func (s *Service) RecordAttestation(ctx context.Context, a store.Attestation) (store.Attestation, error) {
	if err := s.gateOn(); err != nil {
		return a, err
	}
	var out store.Attestation
	err := s.op(ctx, func(tx store.Tx, w *writer) error {
		c, err := load(ctx, tx, a.ChangeID)
		if err != nil {
			return err
		}
		if c == nil {
			return gerr("DG-UNKNOWN", "no such change", "", 404)
		}
		if have, err := tx.Attestation(ctx, a.ChangeID); err == nil {
			out = have
			return nil
		}
		fields := map[string]any{"digest": a.Digest, "backend": a.Backend, "outcome_seq": a.OutcomeSeq}
		if a.RekorLogIndex != nil {
			fields["rekor_log_index"] = *a.RekorLogIndex
		}
		if a.RekorUUID != "" {
			fields["rekor_uuid"] = a.RekorUUID
		}
		if a.KeyID != "" {
			fields["key_id"] = a.KeyID
		}
		result := fmt.Sprintf("attested deploy.outcome seq %d: %s (%s)", a.OutcomeSeq, a.Digest, a.Backend)
		rec := w.record("policy", nil, KindAttestation, c, "allow", nil, result, map[string]any{"digest": a.Digest},
			map[string]any{"attestation": fields})
		if w.err != nil {
			return w.err
		}
		seq, ok := SeqInt(recordSeq(rec))
		if !ok {
			return fmt.Errorf("gate: the %s record has no seq", KindAttestation)
		}
		a.RecordSeq, a.CreatedAt = seq, w.now
		if err := tx.PutAttestation(ctx, a); err != nil {
			return err
		}
		out = a
		return nil
	})
	return out, err
}
