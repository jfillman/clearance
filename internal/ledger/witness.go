package ledger

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

// MaxWitnessBody bounds a request to the witness: a checkpoint, a consistency proof (at most 64 hashes) and a
// few lines.
const MaxWitnessBody = 16 << 10

// Witness is a C2SP tlog-witness: for every log it knows, it holds the latest checkpoint it cosigned and
// cosigns a new one only when it is consistent with that one. It is the party that makes a truncation or a
// rewrite of the log refusable: the log's own key alone cannot sign a smaller or a forked tree past it.
//
// The wire protocol is the add-checkpoint request Tessera's witness client sends (POST, body "old <size>", the
// consistency proof one base64 hash per line, a blank line, the signed checkpoint) and its answers: 200 with the
// cosignature line; 409 with the witness's size (text/x.tlog.size) when the client's idea of it is wrong; 404 for
// an unknown log; 403 when no known log signature verifies; 400 when the old size is larger than the checkpoint;
// 422 when the proof does not verify.
type Witness struct {
	signer note.Signer
	logs   map[string][]note.Verifier // by origin
	path   string                     // the state file; "" keeps the state in memory (tests)

	mu    sync.Mutex
	state map[string]witnessed
}

type witnessed struct {
	Size uint64 `json:"size"`
	Root string `json:"root"` // base64, as in the checkpoint
}

// NewWitness is a witness that cosigns as signer and knows the logs whose checkpoint signatures verify under
// logs (grouped by the origin each verifier's name gives). statePath is a file the latest cosigned checkpoint of
// every log is kept in, written atomically; "" keeps it in memory. A log with several verifiers (a key rotation
// in progress) is trusted under any of them.
func NewWitness(signer note.Signer, logs []note.Verifier, statePath string) (*Witness, error) {
	if signer == nil {
		return nil, errors.New("ledger: the witness has no signing key")
	}
	if len(logs) == 0 {
		return nil, errors.New("ledger: the witness knows no log")
	}
	w := &Witness{signer: signer, logs: map[string][]note.Verifier{}, path: statePath, state: map[string]witnessed{}}
	for _, v := range logs {
		w.logs[v.Name()] = append(w.logs[v.Name()], v)
	}
	if statePath != "" {
		raw, err := os.ReadFile(statePath)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf("ledger: reading the witness state: %w", err)
		default:
			if err := json.Unmarshal(raw, &w.state); err != nil {
				return nil, fmt.Errorf("ledger: the witness state %s is not valid: %w", statePath, err)
			}
		}
	}
	return w, nil
}

// Name is the witness's key name.
func (w *Witness) Name() string { return w.signer.Name() }

// Size is the size of the latest checkpoint the witness cosigned for origin (0 when none).
func (w *Witness) Size(origin string) uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state[origin].Size
}

// ServeHTTP answers GET /healthz and POST add-checkpoint (any other path).
func (w *Witness) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz") {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "ok\n")
		return
	}
	if r.Method != http.MethodPost {
		rw.Header().Set("Allow", "POST")
		http.Error(rw, "POST an add-checkpoint request", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, MaxWitnessBody))
	if err != nil {
		http.Error(rw, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	sig, status, msg := w.add(body)
	switch {
	case status == http.StatusOK:
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = rw.Write(sig)
	case status == http.StatusConflict && strings.HasPrefix(msg, "size:"):
		rw.Header().Set("Content-Type", "text/x.tlog.size")
		rw.WriteHeader(status)
		_, _ = io.WriteString(rw, strings.TrimPrefix(msg, "size:")+"\n")
	default:
		http.Error(rw, msg, status)
	}
}

// add is the protocol: the cosignature line, or a status and message.
func (w *Witness) add(body []byte) (sig []byte, status int, msg string) {
	head, cp, ok := bytes.Cut(body, []byte("\n\n"))
	if !ok {
		return nil, http.StatusBadRequest, "no blank line between the request's header and its checkpoint"
	}
	lines := strings.Split(string(head), "\n")
	if len(lines) > 1+64 || !strings.HasPrefix(lines[0], "old ") {
		return nil, http.StatusBadRequest, `the request starts with "old <size>" and carries at most 64 proof hashes`
	}
	old, err := strconv.ParseUint(strings.TrimPrefix(lines[0], "old "), 10, 64)
	if err != nil {
		return nil, http.StatusBadRequest, "old size is not a number"
	}
	var hashes [][]byte
	for _, l := range lines[1:] {
		h, err := base64.StdEncoding.DecodeString(l)
		if err != nil || len(h) != 32 {
			return nil, http.StatusBadRequest, "a proof line is not a base64 SHA-256 hash"
		}
		hashes = append(hashes, h)
	}
	var parsed f_log.Checkpoint
	if _, err := parsed.Unmarshal(cp); err != nil {
		return nil, http.StatusBadRequest, "the checkpoint is malformed: " + err.Error()
	}
	vs, known := w.logs[parsed.Origin]
	if !known {
		return nil, http.StatusNotFound, "unknown log " + strconv.Quote(parsed.Origin)
	}
	n, err := note.Open(cp, note.VerifierList(vs...))
	if err != nil {
		return nil, http.StatusForbidden, "no signature of a key this witness trusts for the log verifies"
	}
	if len(parsed.Hash) != 32 {
		return nil, http.StatusBadRequest, "the root hash is not 32 bytes"
	}
	root := base64.StdEncoding.EncodeToString(parsed.Hash)

	w.mu.Lock()
	defer w.mu.Unlock()
	have := w.state[parsed.Origin]
	switch {
	case old > parsed.Size:
		return nil, http.StatusBadRequest, "old size is larger than the checkpoint's"
	case old != have.Size:
		// The client's idea of this witness's state is wrong; tell it the size so it can send the right proof.
		return nil, http.StatusConflict, fmt.Sprintf("size:%d", have.Size)
	case parsed.Size == have.Size && root != have.Root:
		return nil, http.StatusConflict, "a different tree of the size this witness already cosigned"
	case parsed.Size > have.Size && have.Size > 0:
		oldRoot, err := base64.StdEncoding.DecodeString(have.Root)
		if err != nil {
			return nil, http.StatusInternalServerError, "the witness state is damaged"
		}
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, have.Size, parsed.Size, hashes, oldRoot, parsed.Hash); err != nil {
			return nil, http.StatusUnprocessableEntity, "the consistency proof does not verify: " + err.Error()
		}
	}
	signed, err := note.Sign(&note.Note{Text: n.Text}, w.signer)
	if err != nil {
		return nil, http.StatusInternalServerError, "signing failed"
	}
	_, cosig, ok := bytes.Cut(signed, []byte("\n\n"))
	if !ok {
		return nil, http.StatusInternalServerError, "signing failed"
	}
	if parsed.Size != have.Size || have.Root == "" {
		next := w.state[parsed.Origin]
		w.state[parsed.Origin] = witnessed{Size: parsed.Size, Root: root}
		if err := w.save(); err != nil {
			// Never cosign what could not be remembered: a witness that forgets can be rolled back.
			if next.Root == "" && next.Size == 0 {
				delete(w.state, parsed.Origin)
			} else {
				w.state[parsed.Origin] = next
			}
			return nil, http.StatusInternalServerError, "the witness could not record its state"
		}
	}
	return cosig, http.StatusOK, ""
}

func (w *Witness) save() error {
	if w.path == "" {
		return nil
	}
	raw, err := json.Marshal(w.state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(w.path), ".witness-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), w.path)
}
