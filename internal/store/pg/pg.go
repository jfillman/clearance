// Package pg is store.Store on Postgres (pgx/v5), ported from clearance pg.py for the tables the core keeps:
// clearance_evidence, clearance_changes and clearance_definitions. The others in pg.py's SCHEMA belong to the
// gateway (sessions, artifacts, inbox, events, holds, results) and are left alone.
//
// One writer. Open takes the session-level advisory lock store.LockKey on a dedicated connection and keeps it for
// the life of the Store; every write transaction runs on that connection, so a write cannot happen without the
// lock. Reads outside a transaction go through one pgxpool per process. On open the chain is verified from genesis,
// streamed in batches (pg.py's PgAuditLog loaded the whole chain at once), and its head read back: a row edited,
// deleted or reordered stops the core from starting instead of being extended.
//
// OpenReader is the read-only mode for clearance-api and `clearance chain verify --dsn`: no lock, no migration,
// every session default_transaction_read_only.
//
// Every statement runs under the server's statement_timeout and a context deadline (Options.CallTimeout when
// the caller's context has none).
package pg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
)

// Schema is pg.py's SCHEMA for the core's tables, verbatim, plus the Go core's own (clearance_tokens and
// clearance_signing_keys, C-1; clearance_feeds and the App installations' index, C-10; clearance_breakglass and the
// exceptions index behind clearance-api's GET /v1/exceptions, C-6; clearance_ledger_checkpoints, C-3: the witnessed checkpoints of the evidence ledger; clearance_evidence_cost, A-4: the records
// clearance-api's counts by=cost sums, model-call outcomes with usage and run.finish with cost): CREATE ... IF NOT
// EXISTS only, so migrate never alters or drops what is there.
const Schema = `
CREATE TABLE IF NOT EXISTS clearance_evidence (
  seq        bigint PRIMARY KEY,
  hash       text   NOT NULL UNIQUE,
  prev_hash  text   NOT NULL,
  record     jsonb  NOT NULL,
  assurance  text   NOT NULL DEFAULT 'recorded-not-checkpointed'
             CHECK (assurance IN ('checkpointed', 'recorded-not-checkpointed', 'not-recorded')),
  written_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_evidence_receipt ON clearance_evidence
  ((record->'effect'->>'repo'), (record->'effect'->>'pr')) WHERE record ? 'effect';
CREATE INDEX IF NOT EXISTS clearance_evidence_cost ON clearance_evidence (seq)
  WHERE record ? 'usage' OR record ? 'cost';
CREATE TABLE IF NOT EXISTS clearance_changes (
  id         text        PRIMARY KEY,
  app        text        NOT NULL,
  env        text        NOT NULL,
  state      text        NOT NULL,
  repo       text        NOT NULL,
  pr         integer     NOT NULL,
  head       text        NOT NULL,
  expires_at timestamptz NOT NULL,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_changes_pr ON clearance_changes (repo, pr);
CREATE INDEX IF NOT EXISTS clearance_changes_state ON clearance_changes (state, expires_at);
CREATE INDEX IF NOT EXISTS clearance_changes_app ON clearance_changes (app, env, updated_at DESC);
CREATE TABLE IF NOT EXISTS clearance_definitions (
  name       text        NOT NULL,
  state      text        NOT NULL,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (name, state)
);
CREATE TABLE IF NOT EXISTS clearance_tokens (
  change_id  text        PRIMARY KEY,
  cluster    text        NOT NULL,
  nonce      text        NOT NULL,
  key_id     text        NOT NULL,
  issued_at  timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  envelope   jsonb       NOT NULL,
  jwt        text        NOT NULL
);
CREATE INDEX IF NOT EXISTS clearance_tokens_feed ON clearance_tokens (cluster, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS clearance_tokens_due ON clearance_tokens (expires_at) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS clearance_signing_keys (
  key_id     text        PRIMARY KEY,
  jwk        jsonb       NOT NULL,
  created_at timestamptz NOT NULL,
  retired_at timestamptz
);
CREATE TABLE IF NOT EXISTS clearance_attestations (
  change_id       text        PRIMARY KEY,
  digest          text        NOT NULL,
  backend         text        NOT NULL,
  key_id          text        NOT NULL,
  rekor_log_index bigint,
  rekor_uuid      text        NOT NULL,
  outcome_seq     bigint      NOT NULL,
  record_seq      bigint      NOT NULL,
  created_at      timestamptz NOT NULL,
  bundle          jsonb       NOT NULL
);
CREATE TABLE IF NOT EXISTS clearance_feeds (
  cluster    text        PRIMARY KEY,
  seq        bigint      NOT NULL,
  key_id     text        NOT NULL,
  issued_at  timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  envelope   jsonb       NOT NULL,
  tokens     jsonb       NOT NULL
);
CREATE INDEX IF NOT EXISTS clearance_evidence_app ON clearance_evidence ((record->>'principal'), seq)
  WHERE record->>'principal' LIKE 'app:%';
CREATE TABLE IF NOT EXISTS clearance_breakglass (
  id         text        PRIMARY KEY,
  cluster    text        NOT NULL,
  env        text        NOT NULL,
  state      text        NOT NULL CHECK (state IN ('open', 'closed')),
  expires_at timestamptz NOT NULL,
  record     jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS clearance_breakglass_open ON clearance_breakglass (expires_at) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS clearance_evidence_exceptions ON clearance_evidence (seq)
  WHERE record->>'tool' IN ('deploy.exception', 'deploy.degraded', 'breakglass.open', 'breakglass.close')
     OR record->>'coverage' = 'coverage-unavailable';
CREATE TABLE IF NOT EXISTS clearance_ledger_checkpoints (
  size   bigint      PRIMARY KEY,
  origin text        NOT NULL,
  root   text        NOT NULL,
  note   bytea       NOT NULL,
  at     timestamptz NOT NULL
);
`

// Options tune a store; the zero value is the defaults.
type Options struct {
	StatementTimeout time.Duration // server-side statement_timeout on every connection (default 5s)
	CallTimeout      time.Duration // deadline for a call whose context has none (default 10s)
	VerifyBatch      int           // records per batch when verifying the chain (default 1000)
	MaxConns         int32         // pool size (default pgxpool's)
	Logger           *slog.Logger  // default slog.Default()
}

func (o Options) withDefaults() Options {
	if o.StatementTimeout <= 0 {
		o.StatementTimeout = 5 * time.Second
	}
	if o.CallTimeout <= 0 {
		o.CallTimeout = 10 * time.Second
	}
	if o.VerifyBatch <= 0 {
		o.VerifyBatch = 1000
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

// ErrWriterLost is returned when the writer connection (and with it the lock) dropped and could not be retaken.
var ErrWriterLost = errors.New("pg: the writer connection and its lock were lost")

// ErrRoundTrip is returned by Append when the record Postgres stored does not hash to what was written: the
// row is rolled back with the transaction.
var ErrRoundTrip = errors.New("pg: stored record does not hash as written")

// ErrTxDone is returned by a Tx used after its Atomic returned.
var ErrTxDone = errors.New("pg: transaction is finished")

// querier is what reads need: the pool, a pooled connection or a transaction.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Reader is the read-only store: store.Reader on the pool.
type Reader struct {
	pool *pgxpool.Pool
	opt  Options
}

var _ store.Reader = (*Reader)(nil)

func poolConfig(dsn string, opt Options, readOnly bool) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pg: dsn: %w", err) // pgx's message does not carry the password
	}
	rp := cfg.ConnConfig.RuntimeParams
	rp["statement_timeout"] = strconv.FormatInt(opt.StatementTimeout.Milliseconds(), 10)
	rp["idle_in_transaction_session_timeout"] = strconv.FormatInt((6 * opt.StatementTimeout).Milliseconds(), 10)
	if rp["application_name"] == "" {
		rp["application_name"] = "clearance"
	}
	if readOnly {
		rp["default_transaction_read_only"] = "on"
	}
	if opt.MaxConns > 0 {
		cfg.MaxConns = opt.MaxConns
	}
	return cfg, nil
}

// OpenReader opens the read-only store. It neither locks nor migrates, and does not verify the chain (Verify does).
func OpenReader(ctx context.Context, dsn string, opt Options) (*Reader, error) {
	opt = opt.withDefaults()
	cfg, err := poolConfig(dsn, opt, true)
	if err != nil {
		return nil, err
	}
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg: %w", err)
	}
	return &Reader{pool: pool, opt: opt}, nil
}

// Close closes the pool.
func (r *Reader) Close() { r.pool.Close() }

func deadline(ctx context.Context, opt Options) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, opt.CallTimeout)
}

// Store is the writable store.
type Store struct {
	*Reader
	cfg *pgx.ConnConfig

	mu     sync.Mutex // one Atomic at a time; guards conn and stale
	conn   *pgx.Conn  // holds the advisory lock; every write runs here
	stale  bool       // a commit failed without a known outcome: re-read the head before the next write
	closed bool

	headMu    sync.RWMutex
	committed evidence.Checkpoint
}

var _ store.Store = (*Store)(nil)

// Open opens the writer: takes the lock (store.ErrWriterLocked if another writer has it), migrates, verifies
// the chain from genesis and reads its head.
func Open(ctx context.Context, dsn string, opt Options) (*Store, error) {
	opt = opt.withDefaults()
	cfg, err := poolConfig(dsn, opt, false)
	if err != nil {
		return nil, err
	}
	s := &Store{Reader: &Reader{opt: opt}, cfg: cfg.ConnConfig.Copy()}
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	cctx, cancel := deadline(ctx, opt)
	defer cancel()
	if _, err := s.conn.Exec(cctx, Schema); err != nil {
		s.conn.Close(context.Background())
		return nil, fmt.Errorf("pg: migrate: %w", err)
	}
	if s.pool, err = pgxpool.NewWithConfig(cctx, cfg); err != nil {
		s.conn.Close(context.Background())
		return nil, fmt.Errorf("pg: %w", err)
	}
	cp, err := verifyStream(ctx, s.conn, evidence.Start, s.opt, nil)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.committed = cp
	opt.Logger.Info("clearance store open", "records", cp.Count, "head", cp.Head)
	return s, nil
}

// lock connects the writer connection and takes the advisory lock on it.
func (s *Store) lock(ctx context.Context) error {
	ctx, cancel := deadline(ctx, s.opt)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, s.cfg.Copy())
	if err != nil {
		return fmt.Errorf("pg: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", store.LockKey).Scan(&ok); err != nil {
		conn.Close(context.Background())
		return fmt.Errorf("pg: lock: %w", err)
	}
	if !ok {
		conn.Close(context.Background())
		return store.ErrWriterLocked
	}
	s.conn = conn
	return nil
}

// Close releases the lock (by closing its connection) and the pool.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.conn.Close(ctx)
		cancel()
	}
	if s.pool != nil {
		s.pool.Close()
	}
}

// Verify streams the chain from genesis in batches and returns its checkpoint, or a *evidence.BadRecord. each,
// if not nil, sees every verified record's seq and hash (for checking an anchor as the chain goes by).
func (r *Reader) Verify(ctx context.Context, each func(seq int64, hash string)) (evidence.Checkpoint, error) {
	return verifyStream(ctx, r.pool, evidence.Start, r.opt, each)
}

// verifyStream verifies clearance_evidence from checkpoint from onward, opt.VerifyBatch rows at a time by keyset
// on seq. Beyond the record itself (every audit.py verify check) it requires the seq, hash and prev_hash columns
// to agree with the record.
func verifyStream(ctx context.Context, q querier, from evidence.Checkpoint, opt Options, each func(seq int64, hash string)) (evidence.Checkpoint, error) {
	batch := opt.VerifyBatch
	v := evidence.Resume(from)
	for {
		n, err := func() (int, error) {
			cctx, cancel := deadline(ctx, opt)
			defer cancel()
			at := v.Checkpoint().Count
			rows, err := q.Query(cctx, "SELECT seq, hash, prev_hash, record::text FROM clearance_evidence WHERE seq >= $1 ORDER BY seq LIMIT $2", at, batch)
			if err != nil {
				return 0, fmt.Errorf("pg: read chain: %w", err)
			}
			defer rows.Close()
			n := 0
			for rows.Next() {
				var seq int64
				var hash, prev, text string
				if err := rows.Scan(&seq, &hash, &prev, &text); err != nil {
					return n, fmt.Errorf("pg: read chain: %w", err)
				}
				i := v.Checkpoint().Count
				bad := func(why string) error { return &evidence.BadRecord{Seq: i, Reason: why} }
				if seq != i {
					return n, bad(fmt.Sprintf("row seq %d where %d was expected (a row is missing)", seq, i))
				}
				val, err := canon.Parse([]byte(text))
				if err != nil {
					return n, bad("record does not parse: " + err.Error())
				}
				rec, ok := val.(map[string]any)
				if !ok {
					return n, bad("record is not an object")
				}
				if err := v.Add(rec); err != nil {
					return n, err
				}
				if hash != v.Checkpoint().Head || prev != rec["prev_hash"] {
					return n, bad("the hash or prev_hash column disagrees with the record")
				}
				if each != nil {
					each(seq, hash)
				}
				n++
			}
			return n, rows.Err()
		}()
		if err != nil {
			return v.Checkpoint(), err
		}
		if n < batch {
			return v.Checkpoint(), nil
		}
	}
}

// Atomic runs fn in one transaction on the writer connection.
func (s *Store) Atomic(ctx context.Context, fn func(tx store.Tx) error) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("pg: store closed")
	}
	ctx, cancel := deadline(ctx, s.opt)
	defer cancel()
	if err := s.ensureWriter(ctx); err != nil {
		return err
	}
	pgtx, err := s.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg: begin: %w", err)
	}
	t := &tx{s: s, tx: pgtx, head: s.committedHead()}
	defer func() {
		t.mu.Lock()
		t.done = true
		t.mu.Unlock()
		if p := recover(); p != nil {
			s.rollback(pgtx)
			panic(p)
		}
	}()
	if err := fn(t); err != nil {
		s.rollback(pgtx)
		return err // the in-memory head was never moved: t.head is the transaction's own
	}
	if err := pgtx.Commit(ctx); err != nil {
		// The commit may or may not have reached the server: re-read the head before the next write.
		s.stale = true
		return fmt.Errorf("pg: commit: %w", err)
	}
	s.headMu.Lock()
	s.committed = t.head
	s.headMu.Unlock()
	return nil
}

func (s *Store) rollback(t pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), s.opt.StatementTimeout)
	defer cancel()
	if err := t.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		s.stale = true // the connection is suspect; ensureWriter checks it
	}
}

func (s *Store) committedHead() evidence.Checkpoint {
	s.headMu.RLock()
	defer s.headMu.RUnlock()
	return s.committed
}

// ensureWriter makes sure the writer connection is alive and holds the lock, and after a reconnect or an
// uncertain commit re-verifies the chain from the last head known to be committed. Called with s.mu held.
func (s *Store) ensureWriter(ctx context.Context) error {
	if s.conn.IsClosed() {
		s.opt.Logger.Warn("clearance store: writer connection lost; reconnecting and retaking the lock")
		if err := s.lock(ctx); err != nil {
			return fmt.Errorf("%w: %w", ErrWriterLost, err)
		}
		s.stale = true
	}
	if !s.stale {
		return nil
	}
	cp, err := verifyStream(ctx, s.conn, s.committedHead(), s.opt, nil)
	if err != nil {
		return err
	}
	s.headMu.Lock()
	s.committed = cp
	s.headMu.Unlock()
	s.stale = false
	return nil
}

// tx is a write transaction on the writer connection.
type tx struct {
	s    *Store
	tx   pgx.Tx
	mu   sync.Mutex
	done bool
	head evidence.Checkpoint
}

func (t *tx) lock() error {
	t.mu.Lock()
	if t.done {
		t.mu.Unlock()
		return ErrTxDone
	}
	return nil
}

func (t *tx) Append(ctx context.Context, event store.Event, w evidence.Writer) (store.Record, error) {
	if err := t.lock(); err != nil {
		return nil, err
	}
	defer t.mu.Unlock()
	rec, full, err := evidence.Seal(t.head, event, w)
	if err != nil {
		return nil, err
	}
	hash := rec["hash"].(string)
	ctx, cancel := deadline(ctx, t.s.opt)
	defer cancel()
	var back string
	if err := t.tx.QueryRow(ctx,
		"INSERT INTO clearance_evidence (seq, hash, prev_hash, record) VALUES ($1, $2, $3, $4) RETURNING record::text",
		t.head.Count, hash, t.head.Head, string(full)).Scan(&back); err != nil {
		return nil, fmt.Errorf("pg: append: %w", err)
	}
	// "The record column stores exactly what was hashed": prove it on the way in, so jsonb's normalisation
	// can never leave a row the next Open refuses.
	if err := evidence.Resume(t.head).Add(mustObject(back)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoundTrip, err)
	}
	t.head = evidence.Checkpoint{Count: t.head.Count + 1, Head: hash}
	return rec, nil
}

func mustObject(text string) map[string]any {
	v, err := canon.Parse([]byte(text))
	if err != nil {
		return map[string]any{}
	}
	m, _ := v.(map[string]any)
	return m
}

func (t *tx) PutChange(ctx context.Context, c store.Change) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	ctx, cancel := deadline(ctx, t.s.opt)
	defer cancel()
	_, err := t.tx.Exec(ctx, "INSERT INTO clearance_changes (id, app, env, state, repo, pr, head, expires_at, record) "+
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, "+
		"expires_at = EXCLUDED.expires_at, record = EXCLUDED.record, updated_at = now()",
		c.ID, c.App, c.Env, c.State, c.Repo, c.PR, c.Head, c.ExpiresAt, string(c.Record))
	if err != nil {
		return fmt.Errorf("pg: put change: %w", err)
	}
	return nil
}

func (t *tx) ReplaceDefinitions(ctx context.Context, defs []store.Definition) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	ctx, cancel := deadline(ctx, t.s.opt)
	defer cancel()
	if _, err := t.tx.Exec(ctx, "DELETE FROM clearance_definitions"); err != nil {
		return fmt.Errorf("pg: replace definitions: %w", err)
	}
	for _, d := range defs {
		if _, err := t.tx.Exec(ctx, "INSERT INTO clearance_definitions (name, state, record) VALUES ($1, $2, $3)",
			d.Name, d.State, string(d.Record)); err != nil {
			return fmt.Errorf("pg: replace definitions: %w", err)
		}
	}
	return nil
}

func (t *tx) PutToken(ctx context.Context, tk store.Token) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	ctx, cancel := deadline(ctx, t.s.opt)
	defer cancel()
	_, err := t.tx.Exec(ctx, "INSERT INTO clearance_tokens (change_id, cluster, nonce, key_id, issued_at, expires_at, "+
		"revoked_at, envelope, jwt) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (change_id) DO UPDATE SET "+
		"cluster = EXCLUDED.cluster, nonce = EXCLUDED.nonce, key_id = EXCLUDED.key_id, issued_at = EXCLUDED.issued_at, "+
		"expires_at = EXCLUDED.expires_at, revoked_at = EXCLUDED.revoked_at, envelope = EXCLUDED.envelope, jwt = EXCLUDED.jwt",
		tk.ChangeID, tk.Cluster, tk.Nonce, tk.KeyID, tk.IssuedAt, tk.ExpiresAt, tk.RevokedAt, string(tk.Envelope), tk.JWT)
	if err != nil {
		return fmt.Errorf("pg: put token: %w", err)
	}
	return nil
}

func (t *tx) PutBreakglass(ctx context.Context, b store.Breakglass) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	ctx, cancel := deadline(ctx, t.s.opt)
	defer cancel()
	_, err := t.tx.Exec(ctx, "INSERT INTO clearance_breakglass (id, cluster, env, state, expires_at, record) "+
		"VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, "+
		"expires_at = EXCLUDED.expires_at, record = EXCLUDED.record, updated_at = now()",
		b.ID, b.Cluster, b.Env, b.State, b.ExpiresAt, string(b.Record))
	if err != nil {
		return fmt.Errorf("pg: put break-glass window: %w", err)
	}
	return nil
}

func (t *tx) PutAttestation(ctx context.Context, a store.Attestation) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	ctx, cancel := deadline(ctx, t.s.opt)
	defer cancel()
	_, err := t.tx.Exec(ctx, "INSERT INTO clearance_attestations (change_id, digest, backend, key_id, rekor_log_index, "+
		"rekor_uuid, outcome_seq, record_seq, created_at, bundle) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) "+
		"ON CONFLICT (change_id) DO UPDATE SET digest = EXCLUDED.digest, backend = EXCLUDED.backend, "+
		"key_id = EXCLUDED.key_id, rekor_log_index = EXCLUDED.rekor_log_index, rekor_uuid = EXCLUDED.rekor_uuid, "+
		"outcome_seq = EXCLUDED.outcome_seq, record_seq = EXCLUDED.record_seq, created_at = EXCLUDED.created_at, "+
		"bundle = EXCLUDED.bundle",
		a.ChangeID, a.Digest, a.Backend, a.KeyID, a.RekorLogIndex, a.RekorUUID, a.OutcomeSeq, a.RecordSeq, a.CreatedAt,
		string(a.Bundle))
	if err != nil {
		return fmt.Errorf("pg: put attestation: %w", err)
	}
	return nil
}

func (t *tx) PutFeed(ctx context.Context, f store.Feed) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	ctx, cancel := deadline(ctx, t.s.opt)
	defer cancel()
	_, err := t.tx.Exec(ctx, "INSERT INTO clearance_feeds (cluster, seq, key_id, issued_at, expires_at, envelope, tokens) "+
		"VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (cluster) DO UPDATE SET seq = EXCLUDED.seq, "+
		"key_id = EXCLUDED.key_id, issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at, "+
		"envelope = EXCLUDED.envelope, tokens = EXCLUDED.tokens",
		f.Cluster, f.Seq, f.KeyID, f.IssuedAt, f.ExpiresAt, string(f.Envelope), string(f.Tokens))
	if err != nil {
		return fmt.Errorf("pg: put feed: %w", err)
	}
	return nil
}

func (t *tx) UseSigningKey(ctx context.Context, k store.SigningKey, now time.Time) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.mu.Unlock()
	ctx, cancel := deadline(ctx, t.s.opt)
	defer cancel()
	if _, err := t.tx.Exec(ctx, "UPDATE clearance_signing_keys SET retired_at = $2 WHERE key_id <> $1 AND retired_at IS NULL",
		k.KeyID, now); err != nil {
		return fmt.Errorf("pg: use signing key: %w", err)
	}
	if _, err := t.tx.Exec(ctx, "INSERT INTO clearance_signing_keys (key_id, jwk, created_at) VALUES ($1, $2, $3) "+
		"ON CONFLICT (key_id) DO UPDATE SET retired_at = NULL", k.KeyID, string(k.JWK), now); err != nil {
		return fmt.Errorf("pg: use signing key: %w", err)
	}
	return nil
}

// Reads in a transaction see its own writes.

func (t *tx) q() (querier, func(), error) {
	if err := t.lock(); err != nil {
		return nil, nil, err
	}
	return t.tx, t.mu.Unlock, nil
}

func (t *tx) Head(ctx context.Context) (int64, string, error) {
	if err := t.lock(); err != nil {
		return 0, "", err
	}
	defer t.mu.Unlock()
	return t.head.Count - 1, t.head.Head, nil
}

func (t *tx) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return records(ctx, q, t.s.opt, from, limit)
}

func (t *tx) Receipts(ctx context.Context, repo string, pr int, tools []string) ([]store.Record, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return receipts(ctx, q, t.s.opt, repo, pr, tools)
}

func (t *tx) Assurance(ctx context.Context, seq int64) (string, error) {
	q, done, err := t.q()
	if err != nil {
		return "", err
	}
	defer done()
	return assurance(ctx, q, t.s.opt, seq)
}

func (t *tx) Change(ctx context.Context, id string) (store.Change, error) {
	q, done, err := t.q()
	if err != nil {
		return store.Change{}, err
	}
	defer done()
	return change(ctx, q, t.s.opt, id)
}

func (t *tx) ChangesForPR(ctx context.Context, repo string, pr int) ([]store.Change, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return changes(ctx, q, t.s.opt, "repo = $1 AND pr = $2", nil, repo, pr)
}

func (t *tx) ChangesForHead(ctx context.Context, repo, head string) ([]store.Change, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return changes(ctx, q, t.s.opt, "repo = $1 AND head = $2", nil, repo, head)
}

func (t *tx) ChangesCleared(ctx context.Context, app, env string) ([]store.Change, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return changes(ctx, q, t.s.opt, "app = $1 AND env = $2 AND state = 'cleared'", nil, app, env)
}

func (t *tx) ChangesHolding(ctx context.Context) ([]store.Change, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return changes(ctx, q, t.s.opt, "state = 'holding'", nil)
}

func (t *tx) ChangesUndelivered(ctx context.Context) ([]store.Change, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return changes(ctx, q, t.s.opt, undeliveredWhere, store.Undelivered)
}

func (t *tx) Definitions(ctx context.Context) ([]store.Definition, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return definitions(ctx, q, t.s.opt)
}

// Head outside a transaction: the writer's committed head.
func (s *Store) Head(ctx context.Context) (int64, string, error) {
	cp := s.committedHead()
	return cp.Count - 1, cp.Head, nil
}

// The Reader's methods, on the pool.

// Head reads the last row (the read-only store has no in-memory head).
func (r *Reader) Head(ctx context.Context) (int64, string, error) {
	ctx, cancel := deadline(ctx, r.opt)
	defer cancel()
	var seq int64
	var hash string
	err := r.pool.QueryRow(ctx, "SELECT seq, hash FROM clearance_evidence ORDER BY seq DESC LIMIT 1").Scan(&seq, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return -1, evidence.Genesis, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("pg: head: %w", err)
	}
	return seq, hash, nil
}

func (r *Reader) Records(ctx context.Context, from int64, limit int) ([]store.Record, error) {
	return records(ctx, r.pool, r.opt, from, limit)
}

func (r *Reader) Receipts(ctx context.Context, repo string, pr int, tools []string) ([]store.Record, error) {
	return receipts(ctx, r.pool, r.opt, repo, pr, tools)
}

func (r *Reader) Assurance(ctx context.Context, seq int64) (string, error) {
	return assurance(ctx, r.pool, r.opt, seq)
}

func (r *Reader) Change(ctx context.Context, id string) (store.Change, error) {
	return change(ctx, r.pool, r.opt, id)
}

func (r *Reader) ChangesForPR(ctx context.Context, repo string, pr int) ([]store.Change, error) {
	return changes(ctx, r.pool, r.opt, "repo = $1 AND pr = $2", nil, repo, pr)
}

func (r *Reader) ChangesForHead(ctx context.Context, repo, head string) ([]store.Change, error) {
	return changes(ctx, r.pool, r.opt, "repo = $1 AND head = $2", nil, repo, head)
}

func (r *Reader) ChangesCleared(ctx context.Context, app, env string) ([]store.Change, error) {
	return changes(ctx, r.pool, r.opt, "app = $1 AND env = $2 AND state = 'cleared'", nil, app, env)
}

func (r *Reader) ChangesHolding(ctx context.Context) ([]store.Change, error) {
	return changes(ctx, r.pool, r.opt, "state = 'holding'", nil)
}

func (r *Reader) ChangesUndelivered(ctx context.Context) ([]store.Change, error) {
	return changes(ctx, r.pool, r.opt, undeliveredWhere, store.Undelivered)
}

func (r *Reader) Definitions(ctx context.Context) ([]store.Definition, error) {
	return definitions(ctx, r.pool, r.opt)
}

func (r *Reader) Token(ctx context.Context, changeID string) (store.Token, error) {
	return tokenOne(ctx, r.pool, r.opt, changeID)
}

func (r *Reader) TokensDue(ctx context.Context, due time.Time, keyID string, limit int) ([]store.Token, error) {
	return tokensDue(ctx, r.pool, r.opt, due, keyID, limit)
}

func (r *Reader) SigningKeys(ctx context.Context, since time.Time) ([]store.SigningKey, error) {
	return signingKeys(ctx, r.pool, r.opt, since)
}

func (t *tx) Token(ctx context.Context, changeID string) (store.Token, error) {
	q, done, err := t.q()
	if err != nil {
		return store.Token{}, err
	}
	defer done()
	return tokenOne(ctx, q, t.s.opt, changeID)
}

func (t *tx) TokensDue(ctx context.Context, due time.Time, keyID string, limit int) ([]store.Token, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return tokensDue(ctx, q, t.s.opt, due, keyID, limit)
}

func (t *tx) SigningKeys(ctx context.Context, since time.Time) ([]store.SigningKey, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return signingKeys(ctx, q, t.s.opt, since)
}

func (r *Reader) LiveTokens(ctx context.Context, cluster string, now time.Time, limit int) ([]store.Token, error) {
	return liveTokens(ctx, r.pool, r.opt, cluster, now, limit)
}

func (r *Reader) Attestation(ctx context.Context, changeID string) (store.Attestation, error) {
	return attestationOne(ctx, r.pool, r.opt, changeID)
}

func (t *tx) Attestation(ctx context.Context, changeID string) (store.Attestation, error) {
	q, done, err := t.q()
	if err != nil {
		return store.Attestation{}, err
	}
	defer done()
	return attestationOne(ctx, q, t.s.opt, changeID)
}

func (r *Reader) Feed(ctx context.Context, cluster string) (store.Feed, error) {
	return feedOne(ctx, r.pool, r.opt, cluster)
}

func (r *Reader) FeedClusters(ctx context.Context) ([]string, error) {
	return feedClusters(ctx, r.pool, r.opt)
}

func (t *tx) LiveTokens(ctx context.Context, cluster string, now time.Time, limit int) ([]store.Token, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return liveTokens(ctx, q, t.s.opt, cluster, now, limit)
}

func (t *tx) Feed(ctx context.Context, cluster string) (store.Feed, error) {
	q, done, err := t.q()
	if err != nil {
		return store.Feed{}, err
	}
	defer done()
	return feedOne(ctx, q, t.s.opt, cluster)
}

func (t *tx) FeedClusters(ctx context.Context) ([]string, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return feedClusters(ctx, q, t.s.opt)
}

// liveTokens reads clearance_tokens_feed (cluster, expires_at) WHERE revoked_at IS NULL.
func liveTokens(ctx context.Context, q querier, opt Options, cluster string, now time.Time, limit int) ([]store.Token, error) {
	if limit <= 0 {
		limit = MaxRecords
	}
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	rows, err := q.Query(ctx, "SELECT "+TokenCols+" FROM clearance_tokens WHERE cluster = $1 AND revoked_at IS NULL "+
		`AND expires_at > $2 ORDER BY change_id COLLATE "C" LIMIT $3`, cluster, now, limit)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	defer rows.Close()
	out := []store.Token{}
	for rows.Next() {
		tk, err := ScanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out = append(out, tk)
	}
	return out, rows.Err()
}

// AttestationCols are clearance_attestations' columns in ScanAttestation's order.
const AttestationCols = "change_id, digest, backend, key_id, rekor_log_index, rekor_uuid, outcome_seq, record_seq, created_at, bundle::text"

// ScanAttestation scans one row of AttestationCols.
func ScanAttestation(row pgx.Row) (store.Attestation, error) {
	var a store.Attestation
	var bundle string
	if err := row.Scan(&a.ChangeID, &a.Digest, &a.Backend, &a.KeyID, &a.RekorLogIndex, &a.RekorUUID, &a.OutcomeSeq,
		&a.RecordSeq, &a.CreatedAt, &bundle); err != nil {
		return a, err
	}
	a.Bundle = []byte(bundle)
	a.CreatedAt = a.CreatedAt.UTC()
	return a, nil
}

func attestationOne(ctx context.Context, q querier, opt Options, changeID string) (store.Attestation, error) {
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	a, err := ScanAttestation(q.QueryRow(ctx, "SELECT "+AttestationCols+" FROM clearance_attestations WHERE change_id = $1", changeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Attestation{}, store.ErrNotFound
	}
	if err != nil {
		return store.Attestation{}, fmt.Errorf("pg: %w", err)
	}
	return a, nil
}

// FeedCols are clearance_feeds' columns in ScanFeed's order.
const FeedCols = "cluster, seq, key_id, issued_at, expires_at, envelope::text, tokens::text"

// ScanFeed scans one row of FeedCols.
func ScanFeed(row pgx.Row) (store.Feed, error) {
	var f store.Feed
	var env, toks string
	if err := row.Scan(&f.Cluster, &f.Seq, &f.KeyID, &f.IssuedAt, &f.ExpiresAt, &env, &toks); err != nil {
		return f, err
	}
	f.Envelope, f.Tokens = []byte(env), []byte(toks)
	f.IssuedAt, f.ExpiresAt = f.IssuedAt.UTC(), f.ExpiresAt.UTC()
	return f, nil
}

func feedOne(ctx context.Context, q querier, opt Options, cluster string) (store.Feed, error) {
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	f, err := ScanFeed(q.QueryRow(ctx, "SELECT "+FeedCols+" FROM clearance_feeds WHERE cluster = $1", cluster))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Feed{}, store.ErrNotFound
	}
	if err != nil {
		return store.Feed{}, fmt.Errorf("pg: %w", err)
	}
	return f, nil
}

func feedClusters(ctx context.Context, q querier, opt Options) ([]string, error) {
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	rows, err := q.Query(ctx, "SELECT cluster FROM (SELECT cluster FROM clearance_tokens WHERE cluster <> '' UNION "+
		`SELECT cluster FROM clearance_feeds) u ORDER BY cluster COLLATE "C"`)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// TokenCols are clearance_tokens' columns in ScanToken's order.
const TokenCols = "change_id, cluster, nonce, key_id, issued_at, expires_at, revoked_at, envelope::text, jwt"

// ScanToken scans one row of TokenCols.
func ScanToken(row pgx.Row) (store.Token, error) {
	var tk store.Token
	var env string
	if err := row.Scan(&tk.ChangeID, &tk.Cluster, &tk.Nonce, &tk.KeyID, &tk.IssuedAt, &tk.ExpiresAt, &tk.RevokedAt, &env, &tk.JWT); err != nil {
		return tk, err
	}
	tk.Envelope = []byte(env)
	tk.IssuedAt, tk.ExpiresAt = tk.IssuedAt.UTC(), tk.ExpiresAt.UTC()
	if tk.RevokedAt != nil {
		at := tk.RevokedAt.UTC()
		tk.RevokedAt = &at
	}
	return tk, nil
}

func tokenOne(ctx context.Context, q querier, opt Options, id string) (store.Token, error) {
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	tk, err := ScanToken(q.QueryRow(ctx, "SELECT "+TokenCols+" FROM clearance_tokens WHERE change_id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Token{}, store.ErrNotFound
	}
	if err != nil {
		return store.Token{}, fmt.Errorf("pg: %w", err)
	}
	return tk, nil
}

func tokensDue(ctx context.Context, q querier, opt Options, due time.Time, keyID string, limit int) ([]store.Token, error) {
	if limit <= 0 {
		limit = MaxRecords
	}
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	rows, err := q.Query(ctx, "SELECT "+TokenCols+" FROM clearance_tokens WHERE revoked_at IS NULL AND "+
		`(expires_at < $1 OR key_id <> $2) ORDER BY expires_at, change_id COLLATE "C" LIMIT $3`, due, keyID, limit)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	defer rows.Close()
	out := []store.Token{}
	for rows.Next() {
		tk, err := ScanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		out = append(out, tk)
	}
	return out, rows.Err()
}

func signingKeys(ctx context.Context, q querier, opt Options, since time.Time) ([]store.SigningKey, error) {
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	rows, err := q.Query(ctx, "SELECT key_id, jwk::text, created_at, retired_at FROM clearance_signing_keys "+
		`WHERE retired_at IS NULL OR retired_at > $1 ORDER BY created_at DESC, key_id COLLATE "C"`, since)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	defer rows.Close()
	out := []store.SigningKey{}
	for rows.Next() {
		var k store.SigningKey
		var jwk string
		if err := rows.Scan(&k.KeyID, &jwk, &k.CreatedAt, &k.RetiredAt); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		k.JWK, k.CreatedAt = []byte(jwk), k.CreatedAt.UTC()
		if k.RetiredAt != nil {
			at := k.RetiredAt.UTC()
			k.RetiredAt = &at
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// MaxRecords caps one Records call.
const MaxRecords = 10000

func records(ctx context.Context, q querier, opt Options, from int64, limit int) ([]store.Record, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("store: limit %d", limit)
	}
	limit = min(limit, MaxRecords)
	return recordRows(ctx, q, opt, "SELECT record::text FROM clearance_evidence WHERE seq >= $1 ORDER BY seq LIMIT $2", from, limit)
}

// receipts uses clearance_evidence_receipt: the partial index's predicate (record ? 'effect') and its two
// expressions, exactly as the index spells them.
func receipts(ctx context.Context, q querier, opt Options, repo string, pr int, tools []string) ([]store.Record, error) {
	return recordRows(ctx, q, opt, "SELECT record::text FROM clearance_evidence WHERE record ? 'effect' "+
		"AND (record->'effect'->>'repo') = $1 AND (record->'effect'->>'pr') = $2 AND record->>'tool' = ANY($3) ORDER BY seq",
		repo, strconv.Itoa(pr), tools)
}

func recordRows(ctx context.Context, q querier, opt Options, sql string, args ...any) ([]store.Record, error) {
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	defer rows.Close()
	out := []store.Record{}
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		v, err := canon.Parse([]byte(text))
		if err != nil {
			return nil, fmt.Errorf("pg: stored record: %w", err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("pg: stored record is not an object")
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func assurance(ctx context.Context, q querier, opt Options, seq int64) (string, error) {
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	var a string
	err := q.QueryRow(ctx, "SELECT assurance FROM clearance_evidence WHERE seq = $1", seq).Scan(&a)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", store.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("pg: %w", err)
	}
	return a, nil
}

const changeCols = "SELECT id, app, env, state, repo, pr, head, expires_at, record::text FROM clearance_changes"

// undeliveredWhere is pg.py's containment test; store.Undelivered then applies its Python filter.
const undeliveredWhere = `record->'deployments' @> '[{"delivered": false}]'::jsonb`

func change(ctx context.Context, q querier, opt Options, id string) (store.Change, error) {
	cs, err := changes(ctx, q, opt, "id = $1", nil, id)
	if err != nil {
		return store.Change{}, err
	}
	if len(cs) == 0 {
		return store.Change{}, store.ErrNotFound
	}
	return cs[0], nil
}

// changes reads clearance_changes rows matching where, in pg.py's order (record->>'created_at'), id breaking ties.
func changes(ctx context.Context, q querier, opt Options, where string, keep func(store.Change) bool, args ...any) ([]store.Change, error) {
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	rows, err := q.Query(ctx, changeCols+" WHERE "+where+` ORDER BY record->>'created_at' COLLATE "C", id COLLATE "C"`, args...)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	defer rows.Close()
	out := []store.Change{}
	for rows.Next() {
		var c store.Change
		var pr int32
		var rec string
		if err := rows.Scan(&c.ID, &c.App, &c.Env, &c.State, &c.Repo, &pr, &c.Head, &c.ExpiresAt, &rec); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		c.PR, c.Record = int(pr), []byte(rec)
		if keep == nil || keep(c) {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

func definitions(ctx context.Context, q querier, opt Options) ([]store.Definition, error) {
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	rows, err := q.Query(ctx, `SELECT name, state, record::text FROM clearance_definitions ORDER BY state COLLATE "C", name COLLATE "C"`)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	defer rows.Close()
	out := []store.Definition{}
	for rows.Next() {
		var d store.Definition
		var rec string
		if err := rows.Scan(&d.Name, &d.State, &rec); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		d.Record = []byte(rec)
		out = append(out, d)
	}
	return out, rows.Err()
}

// BreakglassCols are clearance_breakglass's columns, in Breakglass's order.
const BreakglassCols = "id, cluster, env, state, expires_at, record::text"

func breakglassRows(ctx context.Context, q querier, opt Options, where string, args ...any) ([]store.Breakglass, error) {
	ctx, cancel := deadline(ctx, opt)
	defer cancel()
	rows, err := q.Query(ctx, "SELECT "+BreakglassCols+" FROM clearance_breakglass WHERE "+where+
		` ORDER BY expires_at, id COLLATE "C"`, args...)
	if err != nil {
		return nil, fmt.Errorf("pg: %w", err)
	}
	defer rows.Close()
	out := []store.Breakglass{}
	for rows.Next() {
		var b store.Breakglass
		var rec string
		if err := rows.Scan(&b.ID, &b.Cluster, &b.Env, &b.State, &b.ExpiresAt, &rec); err != nil {
			return nil, fmt.Errorf("pg: %w", err)
		}
		b.ExpiresAt, b.Record = b.ExpiresAt.UTC(), []byte(rec)
		out = append(out, b)
	}
	return out, rows.Err()
}

func breakglassOne(ctx context.Context, q querier, opt Options, id string) (store.Breakglass, error) {
	bs, err := breakglassRows(ctx, q, opt, "id = $1", id)
	if err != nil {
		return store.Breakglass{}, err
	}
	if len(bs) == 0 {
		return store.Breakglass{}, store.ErrNotFound
	}
	return bs[0], nil
}

func (r *Reader) Breakglass(ctx context.Context, id string) (store.Breakglass, error) {
	return breakglassOne(ctx, r.pool, r.opt, id)
}

func (r *Reader) BreakglassOpen(ctx context.Context) ([]store.Breakglass, error) {
	return breakglassRows(ctx, r.pool, r.opt, "state = 'open'")
}

func (t *tx) Breakglass(ctx context.Context, id string) (store.Breakglass, error) {
	q, done, err := t.q()
	if err != nil {
		return store.Breakglass{}, err
	}
	defer done()
	return breakglassOne(ctx, q, t.s.opt, id)
}

func (t *tx) BreakglassOpen(ctx context.Context) ([]store.Breakglass, error) {
	q, done, err := t.q()
	if err != nil {
		return nil, err
	}
	defer done()
	return breakglassRows(ctx, q, t.s.opt, "state = 'open'")
}
