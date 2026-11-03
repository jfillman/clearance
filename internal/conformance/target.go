package conformance

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Applied is one thing the fake target received.
type Applied struct {
	Seq    int64     `json:"seq"`
	ID     string    `json:"id"`
	SHA256 string    `json:"sha256"`
	At     time.Time `json:"at"`
}

// Target is the fake target: an HTTP server that records what was applied and the digest of what it received. It
// computes the digest itself, so an assertion on it does not rest on what the provider says it applied.
type Target struct {
	bearer string
	now    func() time.Time

	mu      sync.Mutex
	applied []Applied
}

// NewTarget is a target that accepts applies carrying bearer.
func NewTarget(bearer string, now func() time.Time) *Target {
	if now == nil {
		now = time.Now
	}
	return &Target{bearer: bearer, now: now}
}

// Handler serves POST /v1/apply.
func (t *Target) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PathTargetApply, t.apply)
	return mux
}

func (t *Target) apply(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(t.bearer)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "the target's bearer is required"})
		return
	}
	var body TargetApply
	if err := StrictDecode(r.Body, MaxTargetBody, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !ValidID(body.ID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is an apply id"})
		return
	}
	sum := sha256.Sum256([]byte(body.Content))
	t.mu.Lock()
	a := Applied{Seq: int64(len(t.applied)), ID: body.ID, SHA256: hex.EncodeToString(sum[:]), At: t.now()}
	t.applied = append(t.applied, a)
	t.mu.Unlock()
	writeJSON(w, http.StatusOK, TargetReceipt{Seq: a.Seq, SHA256: a.SHA256})
}

// For is what the target received for apply id, in order.
func (t *Target) For(id string) []Applied {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Applied
	for _, a := range t.applied {
		if a.ID == id {
			out = append(out, a)
		}
	}
	return out
}

// All is everything the target received.
func (t *Target) All() []Applied {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Applied(nil), t.applied...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
