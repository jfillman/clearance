package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Query runs one statement on the read-only pool, under the store's deadline (Options.CallTimeout when ctx has
// none) and the server's statement_timeout: clearance-api's own reads (internal/api). The caller closes rows and
// then calls done. Every session of an OpenReader pool is default_transaction_read_only, so a write is refused by
// Postgres whatever the role allows.
func (r *Reader) Query(ctx context.Context, sql string, args ...any) (rows pgx.Rows, done func(), err error) {
	ctx, cancel := deadline(ctx, r.opt)
	rows, err = r.pool.Query(ctx, sql, args...)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("pg: %w", err)
	}
	return rows, cancel, nil
}
