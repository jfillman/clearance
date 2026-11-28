package store

import (
	"context"
	"time"
)

// AppliedMigration is one row of a database's clearance_schema table (N-6a).
type AppliedMigration struct {
	Version     int       `json:"version"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"` // "expand" or "contract"
	Release     string    `json:"release"`
	MinCore     string    `json:"min_core"`
	AppliedAt   time.Time `json:"applied_at"`
	CoreVersion string    `json:"applied_by_core,omitempty"`
	// Adopted: the database already had this migration's shape (built by a core before N-6), so it was recorded and no DDL ran.
	Adopted bool `json:"adopted,omitempty"`
}

// SchemaInfo is what a database's schema says about itself: the data the version guard (N-6b), `clearance upgrade
// check`, GET /v1/version and doctor (N-3) read.
type SchemaInfo struct {
	Version int `json:"version"`
	// MinCore is the oldest core that can run on this schema: the highest min_core of any applied migration.
	MinCore string `json:"min_core"`
	// NoRollback: a contract migration has raised MinCore, so a core older than it refuses to start.
	NoRollback bool               `json:"no_rollback"`
	Migrations []AppliedMigration `json:"migrations"`
}

// SchemaReporter is implemented by a Store that keeps a versioned schema (the Postgres store). The memory store has none.
type SchemaReporter interface {
	SchemaInfo(ctx context.Context) (SchemaInfo, error)
}
