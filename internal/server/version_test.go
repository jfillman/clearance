package server_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/store/pg"
)

func versioned(t *testing.T, dsn string) *fixture {
	t.Helper()
	cfg := config(t, dsn)
	cfg.Version = "v0.58.0"
	return newFixture(t, cfg)
}

func TestVersionAnswersTheCompatTable(t *testing.T) {
	f := versioned(t, "")
	f.do("GET", "/v1/version", "", nil).want(t, 401, "")
	a := f.do("GET", "/v1/version", "anyone", nil).want(t, 200, "")
	if a.body["core"] != "v0.58.0" {
		t.Fatalf("core: %v", a.body["core"])
	}
	if _, ok := a.body["schema"]; ok {
		t.Fatalf("the in-memory store has no schema: %v", a.body["schema"])
	}
	c := a.body["compat"].(map[string]any)
	rows := c["releases"].([]any)
	last := rows[len(rows)-1].(map[string]any)
	if last["core"] != "0.58.0" || last["providers"].(map[string]any)["argocd-agent"] == nil {
		t.Fatalf("the table: %v", last)
	}
}

func TestVersionAnswersThePostgresSchema(t *testing.T) {
	f := versioned(t, pgDSN(t))
	a := f.do("GET", "/v1/version", "anyone", nil).want(t, 200, "")
	s := a.body["schema"].(map[string]any)
	if s["version"] != float64(1) || s["min_core"] != "0.0.0" || s["no_rollback"] != false {
		t.Fatalf("schema: %v", s)
	}
	if ms := s["migrations"].([]any); len(ms) != 1 || ms[0].(map[string]any)["name"] != "baseline" {
		t.Fatalf("migrations: %v", ms)
	}
}

func TestAProviderOutsideTheRangeIsRefusedWithTheCode(t *testing.T) {
	f := versioned(t, "")
	get := func(header string) answer {
		req, _ := http.NewRequest("GET", f.srv.URL+"/v1/version", nil)
		req.Header.Set("Authorization", "Bearer anyone")
		if header != "" {
			req.Header.Set("Clearance-Provider", header)
		}
		return f.send(req)
	}
	// Negative: older than the table's minimum for argocd-agent.
	a := get("argocd-agent/0.50.0").want(t, http.StatusPreconditionFailed, "argocd-agent 0.50.0 is older than 0.57.0")
	if a.body["code"] != "provider_version_unsupported" {
		t.Fatalf("code: %v", a.body)
	}
	// Positive: in range, with a v prefix, a later patch, and an unlisted program.
	for _, h := range []string{"argocd-agent/0.57.0", "observe-k8s/v0.58.1", "observe-aws/0.58.0", "someone-else/0.0.1", "argocd-agent/dev", ""} {
		get(h).want(t, 200, "")
	}
	// A refusal is before the route: the evaluate route refuses it too.
	req, _ := http.NewRequest("POST", f.srv.URL+"/v1/records", nil)
	req.Header.Set("Authorization", "Bearer anyone")
	req.Header.Set("Clearance-Provider", "observe-k8s/0.1.0")
	f.send(req).want(t, http.StatusPreconditionFailed, "")
}

// A core one version older than the schema's min_core refuses to start, with the named code, through the whole core's
// build (core.Build on Postgres); a core that meets it starts.
func TestACoreOlderThanTheSchemaRefusesToBuild(t *testing.T) {
	dsn := pgDSN(t)
	first := versioned(t, dsn) // 0.58.0 creates the schema
	first.core.Close()
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	// What a later release's contract migration leaves behind.
	if _, err := conn.Exec(context.Background(), `INSERT INTO clearance_schema (version, name, kind, release, min_core, checksum, core)
VALUES (2, 'drop-x', 'contract', '0.59.0', '0.59.0', 'x', '0.59.0')`); err != nil {
		t.Fatal(err)
	}
	cfg := config(t, dsn)
	cfg.Version = "0.58.0"
	_, err = core.Build(context.Background(), cfg, nil, quiet)
	if !errors.Is(err, pg.ErrCoreTooOld) || !strings.Contains(err.Error(), "schema_requires_newer_core:") {
		t.Fatalf("a 0.58.0 core on a schema that needs 0.59.0: %v", err)
	}
	cfg.Version = "0.59.0"
	c, err := core.Build(context.Background(), cfg, nil, quiet)
	if err != nil {
		t.Fatalf("a 0.59.0 core: %v", err)
	}
	c.Close()
}
