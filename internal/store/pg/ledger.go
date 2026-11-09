package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/store"
)

var _ store.Ledger = (*Store)(nil)

const ledgerCols = "SELECT origin, size, root, note, at FROM clearance_ledger_checkpoints"

func scanLedger(row pgx.Row) (store.LedgerCheckpoint, error) {
	var cp store.LedgerCheckpoint
	err := row.Scan(&cp.Origin, &cp.Size, &cp.Root, &cp.Note, &cp.At)
	if errors.Is(err, pgx.ErrNoRows) {
		return cp, store.ErrNotFound
	}
	if err != nil {
		return cp, fmt.Errorf("pg: %w", err)
	}
	cp.At = cp.At.UTC()
	return cp, nil
}

// LedgerCheckpoint is the latest witnessed checkpoint of the evidence ledger (store.ErrNotFound when none).
func (r *Reader) LedgerCheckpoint(ctx context.Context) (store.LedgerCheckpoint, error) {
	ctx, cancel := deadline(ctx, r.opt)
	defer cancel()
	return scanLedger(r.pool.QueryRow(ctx, ledgerCols+" ORDER BY size DESC LIMIT 1"))
}

// PutLedgerCheckpoint records cp and marks the records under it checkpointed, in one transaction. It writes
// through the pool, not the writer connection: it touches the assurance column and the checkpoint table, never the
// chain's rows, so it does not need the chain lock the writer connection holds (the writer holds it for the life of
// the process, and this is that process).
func (s *Store) PutLedgerCheckpoint(ctx context.Context, cp store.LedgerCheckpoint) error {
	ctx, cancel := deadline(ctx, s.opt)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg: %w", err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // a no-op after Commit
	var chain int64
	if err := tx.QueryRow(ctx, "SELECT COALESCE(max(seq) + 1, 0) FROM clearance_evidence").Scan(&chain); err != nil {
		return fmt.Errorf("pg: %w", err)
	}
	var held *store.LedgerCheckpoint
	if h, err := scanLedger(tx.QueryRow(ctx, ledgerCols+" ORDER BY size DESC LIMIT 1 FOR UPDATE")); err == nil {
		held = &h
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := store.CheckLedgerCheckpoint(held, cp, chain); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO clearance_ledger_checkpoints (size, origin, root, note, at)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (size) DO NOTHING`, cp.Size, cp.Origin, cp.Root, cp.Note, cp.At); err != nil {
		return fmt.Errorf("pg: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE clearance_evidence SET assurance = 'checkpointed'
		WHERE seq < $1 AND assurance = 'recorded-not-checkpointed'`, cp.Size); err != nil {
		return fmt.Errorf("pg: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pg: commit: %w", err)
	}
	return nil
}
