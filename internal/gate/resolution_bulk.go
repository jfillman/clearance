package gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/httpjson"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/vocab"
)

// Bulk resolution: one person resolves up to MaxBulkResolutions observations or exceptions in one call. Each item gets
// a resolution record of its own, exactly as POST /v1/observations/{seq}/resolution would write it (naming the person,
// append-only, about that seq), and every record of the call carries the same resolution.batch {id, size}. Never one
// record for many. All the records are written in one transaction.
const (
	// MaxBulkResolutions caps the items of one call.
	MaxBulkResolutions = 200
	// MaxBulkResolutionBody caps POST /v1/observations/resolutions.
	MaxBulkResolutionBody = 64 << 10
	// resolutionScanPage is how many records are read per page when looking for the newest resolutions.
	resolutionScanPage = 1000
)

// BulkResolutionRequest is POST /v1/observations/resolutions's body: the single route's {state, cause?, note?} for
// each of items.
type BulkResolutionRequest struct {
	// Items are the seqs of the observations or gate exceptions to resolve (1 to 200; a seq named twice is resolved once).
	Items []int64 `json:"items" contract:"required"`
	// State is reverted, ratified, declared-break-glass or still-live (observe.ResolutionStates).
	State string `json:"state" contract:"required"`
	// Cause is one of observe.RevertCauses, and only for state reverted.
	Cause *string `json:"cause,omitempty"`
	// Note is free text (at most 4 KiB), the same on every record.
	Note *string `json:"note,omitempty"`
}

// BulkResolutionRecorded is one resolution the call wrote.
type BulkResolutionRecorded struct {
	// Seq is the observation or exception resolved; RecordSeq the resolution record written about it.
	Seq       int64  `json:"seq"`
	RecordSeq int64  `json:"record_seq"`
	Scope     string `json:"scope"`
}

// BulkResolutionSkipped is an item the call did not resolve, and why.
type BulkResolutionSkipped struct {
	Seq    int64  `json:"seq"`
	Reason string `json:"reason"`
}

// BulkResolutionFailed is an item whose record was refused.
type BulkResolutionFailed struct {
	Seq   int64  `json:"seq"`
	Error string `json:"error"`
}

// BulkResolutionResult is the answer: the batch id every record carries, and the outcome of each item.
type BulkResolutionResult struct {
	Batch    string                   `json:"batch"`
	State    string                   `json:"state"`
	Cause    *string                  `json:"cause"`
	Note     *string                  `json:"note"`
	By       string                   `json:"by"`
	Via      *string                  `json:"via"`
	TS       string                   `json:"ts"`
	Recorded []BulkResolutionRecorded `json:"recorded"`
	Skipped  []BulkResolutionSkipped  `json:"skipped"`
	Failed   []BulkResolutionFailed   `json:"failed"`
}

func batchID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "bulk-" + hex.EncodeToString(b[:]), nil
}

// SetResolutions is POST /v1/observations/resolutions. Errors: *Error (DG-PERSON, DG-DELEGATE, DG-RESOLUTION 403 for a
// person who is not an admin, 400 for no items, more than MaxBulkResolutions, or a state or cause outside the
// vocabulary). An item that is not an observation or a resolvable exception, or whose newest resolution already says
// the same, is skipped with the reason; the rest are recorded in one transaction.
func (s *Service) SetResolutions(ctx context.Context, p authn.Principal, req BulkResolutionRequest, onBehalfOf string) (*BulkResolutionResult, error) {
	if err := s.gateOn(); err != nil {
		return nil, err
	}
	person, via, who, err := s.admin(ctx, p, onBehalfOf, "DG-RESOLUTION", "Only an admin, or a delegate naming one, may set a resolution.")
	if err != nil {
		return nil, err
	}
	if n := len(req.Items); n == 0 || n > MaxBulkResolutions {
		return nil, &Error{Rule: "DG-RESOLUTION", Status: http.StatusBadRequest,
			Message: "items is the seqs to resolve: at least 1 and at most " + strconv.Itoa(MaxBulkResolutions),
			Hint:    "Send larger selections as several calls."}
	}
	for _, it := range req.Items {
		if it < 0 {
			return nil, &Error{Rule: "DG-RESOLUTION", Status: http.StatusBadRequest, Message: "items are the seqs of observations"}
		}
	}
	res := map[string]any{"state": req.State, "by": person}
	if req.Cause != nil {
		res["cause"] = *req.Cause
	}
	if req.Note != nil {
		res["note"] = *req.Note
	}
	id, err := batchID()
	if err != nil {
		return nil, err
	}
	out := &BulkResolutionResult{Batch: id, State: req.State, Cause: req.Cause, Note: req.Note, By: person, Via: via,
		Recorded: []BulkResolutionRecorded{}, Skipped: []BulkResolutionSkipped{}, Failed: []BulkResolutionFailed{}}
	err = s.op(ctx, func(tx store.Tx, w *writer) error {
		out.TS = evidence.ISO(w.now)
		// Validate the vocabulary once, up front: it is the same for every item, so a bad state or cause refuses the call.
		if _, err := resolutionEvent(w, "scope", "observation", 0, person, who, cloneRes(res), req.State); err != nil {
			return err
		}
		type plan struct {
			seq         int64
			scope, what string
		}
		var todo []plan
		seen := map[int64]bool{}
		for _, seq := range req.Items {
			if seen[seq] {
				out.Skipped = append(out.Skipped, BulkResolutionSkipped{Seq: seq, Reason: "named twice in the call"})
				continue
			}
			seen[seq] = true
			scope, what, err := resolutionTarget(ctx, tx, seq)
			if err != nil {
				var ge *Error
				if errors.As(err, &ge) {
					out.Skipped = append(out.Skipped, BulkResolutionSkipped{Seq: seq, Reason: ge.Message})
					continue
				}
				return err
			}
			todo = append(todo, plan{seq, scope, what})
		}
		newest, err := newestResolutions(ctx, tx, seen)
		if err != nil {
			return err
		}
		var write []plan
		for _, pl := range todo {
			if r, ok := newest[pl.seq]; ok && sameResolution(r, req) {
				out.Skipped = append(out.Skipped, BulkResolutionSkipped{Seq: pl.seq, Reason: "its newest resolution already says this"})
				continue
			}
			write = append(write, pl)
		}
		for _, pl := range write {
			r := cloneRes(res)
			r["batch"] = map[string]any{"id": id, "size": json.Number(strconv.Itoa(len(write)))}
			ev, err := resolutionEvent(w, pl.scope, pl.what, pl.seq, person, who, r, req.State)
			if err != nil {
				out.Failed = append(out.Failed, BulkResolutionFailed{Seq: pl.seq, Error: err.Error()})
				continue
			}
			rec := w.appendResolution(ev, via)
			if w.err != nil {
				return w.err
			}
			rseq, _ := SeqInt(rec["seq"])
			out.Recorded = append(out.Recorded, BulkResolutionRecorded{Seq: pl.seq, RecordSeq: rseq, Scope: pl.scope})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func cloneRes(m map[string]any) map[string]any {
	c := make(map[string]any, len(m)+1)
	for k, v := range m {
		c[k] = v
	}
	return c
}

// newestResolutions reads the chain from the lowest wanted seq to its head and returns, for each wanted seq, the newest
// resolution record about it.
func newestResolutions(ctx context.Context, tx store.Reader, want map[int64]bool) (map[int64]store.Record, error) {
	out := map[int64]store.Record{}
	if len(want) == 0 {
		return out, nil
	}
	from := int64(-1)
	for s := range want {
		if from < 0 || s < from {
			from = s
		}
	}
	for {
		rs, err := tx.Records(ctx, from, resolutionScanPage)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			seq, _ := SeqInt(r["seq"])
			from = seq + 1
			if r["tool"] != evidence.KindResolution {
				continue
			}
			ab, _ := r["about"].(map[string]any)
			n, ok := ab["seq"].(json.Number)
			if !ok {
				continue
			}
			a, err := n.Int64()
			if err == nil && want[a] {
				out[a] = r // in seq order: the last one wins
			}
		}
		if len(rs) < resolutionScanPage {
			return out, nil
		}
	}
}

// sameResolution: the record already says what the request would write (state, cause and note).
func sameResolution(r store.Record, req BulkResolutionRequest) bool {
	res, _ := r["resolution"].(map[string]any)
	str := func(k string) string { s, _ := res[k].(string); return s }
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return str("state") == req.State && str("cause") == deref(req.Cause) && str("note") == deref(req.Note)
}

func (h *Handler) setResolutions(w http.ResponseWriter, r *http.Request) {
	p, ok := authn.From(r.Context())
	if !ok {
		httpjson.Write(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token is required"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBulkResolutionBody+1))
	if err != nil {
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": "the body could not be read"})
		return
	}
	if len(raw) > MaxBulkResolutionBody {
		httpjson.Write(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large"})
		return
	}
	var req BulkResolutionRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		msg := "the body is {items: [seq...], state, cause?, note?}"
		if err != nil {
			msg += ": " + err.Error()
		}
		httpjson.Write(w, http.StatusBadRequest, map[string]any{"error": msg})
		return
	}
	out, err := h.Svc.SetResolutions(r.Context(), p, req, r.Header.Get(vocab.Get().OnBehalfOfHeader))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpjson.Write(w, http.StatusOK, out)
}
