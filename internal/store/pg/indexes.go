package pg

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// MapIndexes are the partial indexes behind clearance-api's GET /v1/map (api/mapstore.go spells each predicate as its
// index does). A record's jsonb is TOASTed (about 2 KB compressed), so every record a statement has to look at costs a
// fetch and a decompress: each index holds only the rows its statement wants, in the order it wants them.
//
// They are not in Schema. On a chain of millions of records an index takes minutes to build, and the core must not be
// down for that (it is the deploy gate's only writer), nor may the build block its writes. So the core builds them
// after it has started, in the background, with CREATE INDEX CONCURRENTLY (which takes no lock that stops a write). Until an
// index exists the Map is as slow as it was without it.
var MapIndexes = []struct{ Name, DDL string }{
	{"clearance_evidence_gate", `CREATE INDEX CONCURRENTLY IF NOT EXISTS clearance_evidence_gate ON clearance_evidence ((record->>'ts'))
  WHERE record->>'tool' IN ('deploy.request', 'deploy.clear', 'deploy.deny', 'deploy.expire', 'deploy.outcome', 'deploy.exception', 'deploy.degraded')
     OR (record->>'boundary' = 'runtime' AND record ? 'policy' AND NOT (record ? 'outcome_of'))`},
	{"clearance_evidence_health", `CREATE INDEX CONCURRENTLY IF NOT EXISTS clearance_evidence_health ON clearance_evidence ((record->>'scope'), seq)
  WHERE record->>'tool' = 'observation.health'`},
	{"clearance_evidence_obs_ts", `CREATE INDEX CONCURRENTLY IF NOT EXISTS clearance_evidence_obs_ts ON clearance_evidence ((record->>'scope'), (record->>'ts'))
  WHERE record->>'tool' IN ('observation', 'assessment')`},
}

// indexBuildTimeout bounds one index build (its own bound, not the statement timeout).
const indexBuildTimeout = 2 * time.Hour

type indexBuild struct {
	mu     sync.Mutex // one build at a time: a build in progress looks INVALID to another
	cancel context.CancelFunc
	done   chan struct{}
}

// startIndexBuild builds MapIndexes in the background, once, from Open. A failure is logged and retried at the next start.
func (s *Store) startIndexBuild() {
	ctx, cancel := context.WithCancel(context.Background())
	s.build.cancel, s.build.done = cancel, make(chan struct{})
	go func() {
		defer close(s.build.done)
		_ = s.BuildIndexes(ctx) // logged per index; never fatal
	}()
}

// stopIndexBuild cancels a build in progress (leaving an INVALID index for the next start to drop) and waits for it.
func (s *Store) stopIndexBuild() {
	if s.build.cancel == nil {
		return
	}
	s.build.cancel()
	select {
	case <-s.build.done:
	case <-time.After(5 * time.Second):
	}
}

// BuildIndexes builds the MapIndexes one at a time, each on its own connection with no statement timeout. An index
// a build interrupted left INVALID (pg_index.indisvalid false: IF NOT EXISTS would skip it for ever) is dropped
// and rebuilt. It logs each index's start, finish and duration, goes on past a failure and returns the failures.
func (s *Store) BuildIndexes(ctx context.Context) error {
	s.build.mu.Lock()
	defer s.build.mu.Unlock()
	var errs []error
	for _, ix := range MapIndexes {
		if ctx.Err() != nil {
			return errors.Join(append(errs, ctx.Err())...)
		}
		if err := s.buildIndex(ctx, ix.Name, ix.DDL); err != nil {
			if ctx.Err() != nil {
				s.opt.Logger.Info("clearance index build interrupted (the core is stopping); it is checked at the next start", "index", ix.Name)
				return errors.Join(append(errs, err)...)
			}
			s.opt.Logger.Error("clearance index build failed; retried at the next start", "index", ix.Name, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", ix.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Store) buildIndex(ctx context.Context, name, ddl string) error {
	cctx, cancel := context.WithTimeout(ctx, indexBuildTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(cctx, s.cfg.Copy())
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(cctx, "SET statement_timeout = 0; SET lock_timeout = 0; SET idle_in_transaction_session_timeout = 0"); err != nil {
		return err
	}
	var valid *bool
	if err := conn.QueryRow(cctx, "SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid = to_regclass($1)", name).Scan(&valid); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if valid != nil && *valid {
		return nil
	}
	if valid != nil {
		s.opt.Logger.Warn("clearance index is invalid (an earlier build was interrupted): dropping it to rebuild", "index", name)
		if _, err := conn.Exec(cctx, "DROP INDEX CONCURRENTLY IF EXISTS "+name); err != nil {
			return err
		}
	}
	start := time.Now()
	s.opt.Logger.Info("clearance index build started", "index", name)
	if _, err := conn.Exec(cctx, ddl); err != nil {
		return err
	}
	s.opt.Logger.Info("clearance index build finished", "index", name, "duration", time.Since(start).String())
	return nil
}
