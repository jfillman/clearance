package verify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/statement"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/verify"
)

// A statement is read from a file anyone can hand a reviewer, and the status beside it from a URL anyone can serve: whatever
// they hold, the verifier returns a seven-check report and never panics, and never exit 0, because an arbitrary file is
// neither a statement signed by the issuer's key nor a status. (The valid case is exercised by the server tests: a fuzzer
// cannot sign.)
func FuzzVerifyStatement(f *testing.F) {
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Add([]byte(`not json`), []byte(``))
	f.Add([]byte(`{"payloadType":"application/vnd.clearance.statement.v1+json","payload":"e30=","signatures":[{"keyid":"k","sig":"AA=="}]}`), []byte(`x`))
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	s, _ := token.NewKeySigner(k)
	keys := token.KeySet{s.KeyID(): s.Public()}
	dir, pktDir := f.TempDir(), f.TempDir()
	f.Fuzz(func(t *testing.T, raw, status []byte) {
		p := filepath.Join(dir, "s.json")
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Skip()
		}
		for _, so := range []verify.StatementOptions{
			{},
			{Keys: keys, Issuer: "i", PacketDir: pktDir, Status: status, Options: verify.Options{LogKeys: raw, WitnessPolicy: raw, Now: time.Now}},
			{Keys: keys, PacketFiles: map[string][]byte{"packet.json": raw, "evidence/records.jsonl": raw, "MANIFEST.json": raw}, Live: &verify.Live{State: statement.StateValid, AsOf: time.Now()}},
		} {
			rep := verify.VerifyStatementFile(p, so)
			if rep == nil || len(rep.Checks) == 0 {
				t.Fatalf("no report for %q", raw)
			}
			if rep.ExitCode() == 0 {
				t.Fatalf("an arbitrary file verified: %q", raw)
			}
		}
		// The envelope itself, as bytes, and the status check alone.
		_ = verify.VerifyStatement(raw, "x", verify.StatementOptions{Keys: keys, Status: status})
		_ = verify.CheckCurrent("st-00000000000000000000000000000000", verify.StatementOptions{Keys: keys, Status: raw})
	})
}
