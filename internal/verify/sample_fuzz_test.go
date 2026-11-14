package verify_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfillman/clearance/internal/verify"
)

// A sample document is read from a file anyone can hand an auditor: whatever it holds, the verifier returns a report and
// never panics, and a document that is not a whole, consistent sample is never a pass.
func FuzzVerifySample(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"schema":"clearance.packet-sample/v1","method":"clearance.sample-select/v1","packet":{"id":"pk-00000000000000000000000000000000","digest":"0000000000000000000000000000000000000000000000000000000000000000"},"params":{"n":1,"seed":"","seed_source":"default","stratify":"none"},"checkpoint":{"origin":"o","size":3,"root":"00","note":"x"},"population":{"count":1,"cleared":1,"eligible":1,"sha256":"","changes":[{"change":"c","clear_seq":1,"eligible":true,"month":"2026-10"}]},"selected":[{"change":"c","seq":1,"record":{"seq":1,"hash":"00"},"proof":{"seq":1}}],"recorded":{"seq":5,"hash":"0000000000000000000000000000000000000000000000000000000000000000"}}`))
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, raw []byte) {
		p := filepath.Join(dir, "s.json")
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Skip()
		}
		if rep := verify.VerifySample(p, "", verify.Options{}); rep.ExitCode() == 0 {
			t.Fatalf("an arbitrary file verified: %q", raw)
		}
	})
}
