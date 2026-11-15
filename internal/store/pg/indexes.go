package pg

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
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
	{"clearance_evidence_health_core", `CREATE INDEX CONCURRENTLY IF NOT EXISTS clearance_evidence_health_core ON clearance_evidence ((record->>'scope'), seq)
  WHERE record->>'tool' = 'observation.health' AND record->'provider'->>'name' = 'clearance'`},
	{"clearance_evidence_health_ok", `CREATE INDEX CONCURRENTLY IF NOT EXISTS clearance_evidence_health_ok ON clearance_evidence ((record->>'scope'), (COALESCE(record->'source'->>'name', '')), seq)
  WHERE record->>'tool' = 'observation.health' AND COALESCE(record->'provider'->>'name', '') <> 'clearance' AND record->'health'->>'state' = 'healthy'`},
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

// indexPoll is how often a build waits for another backend's build of the same index to finish.
var indexPoll = 5 * time.Second

func (s *Store) buildIndex(ctx context.Context, name, ddl string) error {
	cctx, cancel := context.WithTimeout(ctx, indexBuildTimeout)
	defer cancel()
	cc := s.cfg.Copy()
	// A cancelled context must stop the build on the server, not only on our side. pgx's default handler only sets a past
	// deadline on the socket and closes it, which leaves the backend building as a ghost until it next looks at the
	// socket (for CREATE INDEX CONCURRENTLY, possibly minutes); this one also sends a CancelRequest, which aborts the
	// build at once and leaves an INVALID index for the next start.
	cc.Config.BuildContextWatcherHandler = func(c *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.CancelRequestContextWatcherHandler{Conn: c, DeadlineDelay: 3 * time.Second}
	}
	conn, err := pgx.ConnectConfig(cctx, cc)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(cctx, "SET statement_timeout = 0; SET lock_timeout = 0; SET idle_in_transaction_session_timeout = 0"); err != nil {
		return err
	}
	warned := false
	for {
		var valid *bool
		if err := conn.QueryRow(cctx, "SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid = to_regclass($1)", name).Scan(&valid); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if valid != nil && *valid {
			return nil
		}
		if valid == nil {
			break
		}
		// INVALID: an interrupted build, or one still running in a backend that outlived its core (a killed pod's
		// connection is noticed late). Dropping an index a live backend is building throws its work away, so wait for it.
		var live int
		if err := conn.QueryRow(cctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()
			AND state = 'active' AND query LIKE '%CREATE INDEX CONCURRENTLY%' AND query LIKE '%EXISTS ' || $1::text || ' ON %'`, name).Scan(&live); err != nil {
			return err
		}
		if live == 0 {
			s.opt.Logger.Warn("clearance index rebuilt from zero; previous build did not finish (a start loop shorter than a build never completes it)", "index", name)
			if _, err := conn.Exec(cctx, "DROP INDEX CONCURRENTLY IF EXISTS "+name); err != nil {
				return err
			}
			break
		}
		if !warned {
			s.opt.Logger.Warn("clearance index is being built by another backend (an earlier core's build still running); waiting for it", "index", name)
			warned = true
		}
		select {
		case <-cctx.Done():
			return cctx.Err()
		case <-time.After(indexPoll):
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
