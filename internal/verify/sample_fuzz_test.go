package verify_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jfillman/clearance/internal/verify"
)

// A sample document is read from a file anyone can hand an auditor: whatever it holds, the verifier returns a report and
// never panics. It is run both ways a caller can run it, bare, and with a packet directory (one that holds nothing) and the
// input itself as the supplied core record, so the packet and record-comparison paths are fed hostile bytes too; neither is
// ever exit 0, because an arbitrary file is not a sample, a packet and a record that agree. (The valid case is exercised by
// the server tests: a fuzzer cannot assemble a document that verifies.)
func FuzzVerifySample(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"schema":"clearance.packet-sample/v1","method":"clearance.sample-select/v1","packet":{"id":"pk-00000000000000000000000000000000","digest":"0000000000000000000000000000000000000000000000000000000000000000"},"params":{"n":1,"seed":"","seed_source":"default","stratify":"none"},"checkpoint":{"origin":"o","size":3,"root":"00","note":"x"},"population":{"count":1,"cleared":1,"eligible":1,"sha256":"","changes":[{"change":"c","clear_seq":1,"eligible":true,"month":"2026-10"}]},"selected":[{"change":"c","seq":1,"record":{"seq":1,"hash":"00"},"proof":{"seq":1}}],"recorded":{"seq":5,"hash":"0000000000000000000000000000000000000000000000000000000000000000"}}`))
	dir, pktDir := f.TempDir(), f.TempDir()
	f.Fuzz(func(t *testing.T, raw []byte) {
		p := filepath.Join(dir, "s.json")
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Skip()
		}
		for _, c := range []struct {
			pkt  string
			opts verify.Options
		}{{"", verify.Options{}}, {pktDir, verify.Options{SampleRecord: raw, SampleRecordSrc: "fuzz", LogKeys: raw, WitnessPolicy: raw}}} {
			rep := verify.VerifySample(p, c.pkt, c.opts)
			if rep == nil || len(rep.Checks) == 0 {
				t.Fatalf("no report for %q", raw)
			}
			if rep.ExitCode() == 0 {
				t.Fatalf("an arbitrary file verified: %q", raw)
			}
		}
	})
}
