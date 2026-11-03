package traefikhub_test

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
)

func TestMain(m *testing.M) { os.Exit(vocabtest.Main(m)) }

// hub is the principal the adapter authenticates as in these tests (DevAuthenticator: the token is the principal).
const hub = "traefik-hub-system/clearance-federate"

type coreFixture struct {
	core   *core.Core
	srv    *httptest.Server
	client *client.Client
}

func newCore(t *testing.T) *coreFixture {
	t.Helper()
	ps, err := server.ParseProviders(`[{"name": "traefik-hub", "version": "3.21.0", "principals": ["traefik-hub-system/*"],
  "kinds": ["federated.decision"]},
 {"name": "autopilot-gateway", "version": "0.4.1", "principals": ["autopilot-system/clearance"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	cfg := core.Config{Memory: true, Version: "test", Providers: ps, Auth: core.DevAuthenticator(), MaxClockSkew: -1,
		AgentLogins: []string{vocabtest.AgentLogin}}
	c, err := core.Build(context.Background(), cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	srv := httptest.NewServer(c.Server.Handler())
	t.Cleanup(srv.Close)
	f := &coreFixture{core: c, srv: srv}
	f.client = f.clientAs(t, hub, "traefik-hub")
	return f
}

func (f *coreFixture) clientAs(t *testing.T, principal, provider string) *client.Client {
	t.Helper()
	c, err := client.New(client.Options{BaseURL: f.srv.URL, Token: client.StaticToken(principal), Provider: provider,
		Retries: -1, BreakerThreshold: -1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *coreFixture) records(t *testing.T) []map[string]any {
	t.Helper()
	recs, err := f.core.Store.Records(context.Background(), 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]map[string]any, len(recs))
	for i, r := range recs {
		out[i] = r
	}
	return out
}

func (f *coreFixture) verify(recs []map[string]any) (bool, int64) { return evidence.Verify(recs) }
