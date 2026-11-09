package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/ledger"
)

// ledgerFiles writes a throwaway log key and a witness policy naming url; the keys are made here, not real.
func ledgerFiles(t *testing.T, witnessURL string, witness http.Handler) map[string]string {
	t.Helper()
	dir := t.TempDir()
	skey, vkey, _, err := ledger.GenerateKey("core-test-ledger")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "log.key")
	if err := ledger.WriteKeyFile(keyFile, skey); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(keyFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("the key file is %v", st.Mode())
	}
	wskey, _, wcosig, err := ledger.GenerateKey("core-test-witness")
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy")
	if err := os.WriteFile(policy, []byte(fmt.Sprintf("witness w %s %s\nquorum w\n", wcosig, witnessURL)), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = wskey
	_ = vkey
	return map[string]string{"CLEARANCE_LEDGER_DIR": filepath.Join(dir, "ledger"), "CLEARANCE_LEDGER_KEY_FILE": keyFile,
		"CLEARANCE_LEDGER_WITNESS_POLICY_FILE": policy}
}

func TestLedgerIsOffUnlessConfigured(t *testing.T) {
	cfg, err := FromEnv(env(map[string]string{"CLEARANCE_DSN": "postgres://x"}))
	if err != nil || cfg.Ledger != nil {
		t.Fatalf("%+v %v", cfg.Ledger, err)
	}
	for _, bad := range []map[string]string{
		{"CLEARANCE_LEDGER_TIER3_WAIT": "false"}, // a setting without the volume: the ledger would silently stay off
		{"CLEARANCE_LEDGER_KEY_FILE": "/k"},      // likewise
		{"CLEARANCE_LEDGER_DIR": "/ledger"},      // the volume without a key and a witness
		{"CLEARANCE_LEDGER_DIR": "/l", "CLEARANCE_LEDGER_KEY_FILE": "/nonexistent", "CLEARANCE_LEDGER_WITNESS_POLICY_FILE": "/p"},
	} {
		if _, err := FromEnv(env(bad)); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	files := ledgerFiles(t, "http://witness.invalid", nil)
	cfg, err = FromEnv(env(files))
	if err != nil || cfg.Ledger == nil || !cfg.Ledger.Tier3Wait {
		t.Fatalf("%+v %v", cfg.Ledger, err)
	}
	files["CLEARANCE_LEDGER_TIER3_WAIT"] = "false"
	files["CLEARANCE_LEDGER_CHECKPOINT_INTERVAL"] = "30s"
	if cfg, err = FromEnv(env(files)); err != nil || cfg.Ledger.Tier3Wait || cfg.Ledger.Log.CheckpointInterval != 30*time.Second {
		t.Fatalf("%+v %v", cfg.Ledger, err)
	}
	files["CLEARANCE_LEDGER_CHECKPOINT_INTERVAL"] = "1ms"
	if _, err := FromEnv(env(files)); err == nil {
		t.Fatal("accepted a 1ms checkpoint interval")
	}
}

func readyz(t *testing.T, c *Core) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	c.Server.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != 200 {
		t.Fatalf("%d %s %v", rec.Code, rec.Body, err)
	}
	return out
}

func TestReadyzReportsTheLedgerOnlyWhenItIsOn(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	off, err := Build(context.Background(), Config{Memory: true, Auth: DevAuthenticator()}, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer off.Close()
	if _, ok := readyz(t, off)["ledger"]; ok || off.Ledger != nil || off.Gate.Evidence != nil {
		t.Fatal("a core without a ledger reports one")
	}

	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	lcfg, err := ledger.FromEnv(env(ledgerFiles(t, srv.URL, nil)))
	if err != nil {
		t.Fatal(err)
	}
	on, err := Build(context.Background(), Config{Memory: true, Auth: DevAuthenticator(), Ledger: lcfg}, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer on.Close()
	l, ok := readyz(t, on)["ledger"].(map[string]any)
	if !ok || l["enabled"] != true || l["tier3_wait"] != true || l["state"] != ledger.StateCurrent || on.Gate.Evidence == nil {
		t.Fatalf("%v", l)
	}
}
