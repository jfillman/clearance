package ledger

import (
	"net/http"
	"testing"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// FuzzWitnessRequest: whatever a client sends the witness, it never panics and never cosigns what no trusted log
// signed (the log key here signs nothing the fuzzer can reach).
func FuzzWitnessRequest(f *testing.F) {
	skey, _, _, _ := GenerateKey("fuzz-log")
	_, v, _ := f_note.NewEd25519SignerVerifier(skey)
	wkey, _, _, _ := GenerateKey("fuzz-witness")
	ws, _ := f_note.NewSignerForCosignatureV1(wkey)
	w, err := NewWitness(ws, []note.Verifier{v}, "")
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte("old 0\n\nfuzz-log\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— fuzz-log AAAAAAAA\n"))
	f.Add([]byte("old 5\nAAAA\n\n"))
	f.Add([]byte("\n\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if _, status, _ := w.add(body); status == http.StatusOK {
			t.Fatalf("cosigned %q", body)
		}
	})
}
