package slack

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PG is the Store in Postgres. It uses its own tables (clearance_slack_*) and, in a deployment, its own role: the
// evidence tables are the core's and this service has no grant on them.
type PG struct{ Pool *pgxpool.Pool }

// OpenPG connects to dsn.
func OpenPG(ctx context.Context, dsn string) (*PG, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("slack: the DSN does not parse")
	}
	cfg.MaxConns = 4
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return &PG{Pool: p}, nil
}

// Close releases the pool.
func (s *PG) Close() { s.Pool.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS clearance_slack_links (
  team text NOT NULL, slack_user text NOT NULL,
  issuer text NOT NULL, subject text NOT NULL, person text NOT NULL,
  auth_time bigint NOT NULL DEFAULT 0,
  linked_at timestamptz NOT NULL, verified_at timestamptz NOT NULL,
  dm boolean NOT NULL DEFAULT true,
  PRIMARY KEY (team, slack_user)
);
CREATE INDEX IF NOT EXISTS clearance_slack_links_person ON clearance_slack_links (person);
CREATE TABLE IF NOT EXISTS clearance_slack_messages (
  change_id text NOT NULL, dest text NOT NULL,
  channel text NOT NULL, ts text NOT NULL, link text NOT NULL DEFAULT '',
  rendered text NOT NULL DEFAULT '', state_key text NOT NULL DEFAULT '', ref text NOT NULL DEFAULT '', open boolean NOT NULL DEFAULT true,
  PRIMARY KEY (change_id, dest)
);
CREATE INDEX IF NOT EXISTS clearance_slack_messages_open ON clearance_slack_messages (change_id) WHERE open;
CREATE TABLE IF NOT EXISTS clearance_slack_kv (k text PRIMARY KEY, v text NOT NULL);
`

func (s *PG) Migrate(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, schema)
	return err
}

func (s *PG) GetLink(ctx context.Context, team, user string) (*Link, error) {
	var l Link
	err := s.Pool.QueryRow(ctx, `SELECT team, slack_user, issuer, subject, person, auth_time, linked_at, verified_at, dm
		FROM clearance_slack_links WHERE team=$1 AND slack_user=$2`, team, user).
		Scan(&l.Team, &l.User, &l.Issuer, &l.Subject, &l.Person, &l.AuthTime, &l.LinkedAt, &l.VerifiedAt, &l.DM)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &l, err
}

func (s *PG) PutLink(ctx context.Context, l Link) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO clearance_slack_links (team, slack_user, issuer, subject, person, auth_time, linked_at, verified_at, dm)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (team, slack_user) DO UPDATE SET issuer=$3, subject=$4, person=$5, auth_time=$6, linked_at=$7, verified_at=$8, dm=$9`,
		l.Team, l.User, l.Issuer, l.Subject, l.Person, l.AuthTime, l.LinkedAt.UTC(), l.VerifiedAt.UTC(), l.DM)
	return err
}

func (s *PG) DeleteLink(ctx context.Context, team, user string) (bool, error) {
	t, err := s.Pool.Exec(ctx, `DELETE FROM clearance_slack_links WHERE team=$1 AND slack_user=$2`, team, user)
	return t.RowsAffected() > 0, err
}

func (s *PG) ListLinks(ctx context.Context) ([]Link, error) {
	rows, err := s.Pool.Query(ctx, `SELECT team, slack_user, issuer, subject, person, auth_time, linked_at, verified_at, dm
		FROM clearance_slack_links ORDER BY team, slack_user`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		var l Link
		if err := rows.Scan(&l.Team, &l.User, &l.Issuer, &l.Subject, &l.Person, &l.AuthTime, &l.LinkedAt, &l.VerifiedAt, &l.DM); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *PG) SetDM(ctx context.Context, team, user string, on bool) error {
	t, err := s.Pool.Exec(ctx, `UPDATE clearance_slack_links SET dm=$3 WHERE team=$1 AND slack_user=$2`, team, user, on)
	if err == nil && t.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *PG) Messages(ctx context.Context, id string) ([]Message, error) {
	return s.messages(ctx, `WHERE change_id=$1 ORDER BY dest`, id)
}

func (s *PG) OpenMessages(ctx context.Context) ([]Message, error) {
	return s.messages(ctx, `WHERE open ORDER BY change_id, dest`)
}

func (s *PG) messages(ctx context.Context, where string, args ...any) ([]Message, error) {
	rows, err := s.Pool.Query(ctx, `SELECT change_id, dest, channel, ts, link, rendered, state_key, ref, open FROM clearance_slack_messages `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ChangeID, &m.Dest, &m.Channel, &m.TS, &m.Link, &m.Rendered, &m.StateKey, &m.Ref, &m.Open); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PG) PutMessage(ctx context.Context, m Message) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO clearance_slack_messages (change_id, dest, channel, ts, link, rendered, state_key, ref, open)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (change_id, dest) DO UPDATE SET channel=$3, ts=$4, link=$5, rendered=$6, state_key=$7, ref=$8, open=$9`,
		m.ChangeID, m.Dest, m.Channel, m.TS, m.Link, m.Rendered, m.StateKey, m.Ref, m.Open)
	return err
}

func (s *PG) KV(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.Pool.QueryRow(ctx, `SELECT v FROM clearance_slack_kv WHERE k=$1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (s *PG) SetKV(ctx context.Context, key, value string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO clearance_slack_kv (k, v) VALUES ($1,$2) ON CONFLICT (k) DO UPDATE SET v=$2`, key, value)
	return err
}
