// Package evidence is the hash-chained evidence record, ported from clearance audit.py: the envelope a record
// carries (schema, boundary, coverage, the verified/claimed field tags, seq, prev_hash, hash) and the chain rule
// that links each record to the one before it.
//
// A record's hash is SHA-256 over canon.Canonical of the record without "hash"; its prev_hash is the hash of the
// record before it (Genesis for seq 0); seq counts from 0 with no gaps. That proves consistency, not
// completeness: truncating the tail leaves a valid chain, which is what VerifyAgainst and an anchored
// Checkpoint are for.
package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/canon"
)

// Genesis is the prev_hash of record 0.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Schema names the record shape (audit.py EVIDENCE_SCHEMA).
const Schema = "clearance.evidence/v0-draft"

// Verified are the fields Clearance establishes itself for a runtime decision; every other event field is
// claimed (audit.py VERIFIED).
var Verified = set("ts", "task_id", "session", "parent", "principal", "agent", "tool", "tier", "decision", "rule",
	"target", "args_sha256", "result", "effect", "app")

// Envelope are the fields the chain adds; an event may set only coverage and boundary of them (audit.py ENVELOPE).
var Envelope = set("seq", "schema", "boundary", "coverage", "verified", "claimed", "prev_hash", "hash")

func set(ks ...string) map[string]bool {
	m := make(map[string]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

// ErrEnvelopeField is returned by Seal for an event that sets an envelope field other than coverage or boundary.
var ErrEnvelopeField = errors.New("evidence: event sets an envelope field")

// ErrNotStorable is returned by Seal for an event Postgres jsonb would not store as it was hashed (so the chain
// would break when read back): a non-finite float, a float whose repr has a positive exponent (|x| >= 1e16; jsonb
// prints it as an integer), a negative zero float (jsonb has none), or a string holding U+0000 (jsonb refuses it).
// The Python core accepted these and broke its own chain on the next start; Go refuses them up front.
var ErrNotStorable = errors.New("evidence: event would not survive Postgres jsonb unchanged")

// Fields is audit.py evidence(event): the envelope for an event, without seq, prev_hash and hash.
func Fields(event map[string]any) map[string]any {
	fields := make([]string, 0, len(event))
	for k := range event {
		if !Envelope[k] {
			fields = append(fields, k)
		}
	}
	sort.Strings(fields) // code point order, as Python's sorted() on str
	verified, claimed := []any{}, []any{}
	for _, k := range fields {
		if Verified[k] {
			verified = append(verified, k)
		} else {
			claimed = append(claimed, k)
		}
	}
	boundary, ok := event["boundary"]
	if !ok {
		boundary = "runtime"
	}
	coverage, ok := event["coverage"]
	if !ok {
		coverage = "authorized-and-verified"
	}
	return map[string]any{"schema": Schema, "boundary": boundary, "coverage": coverage, "verified": verified, "claimed": claimed}
}

// Checkpoint is a chain's length and head hash (audit.py Checkpoint).
type Checkpoint struct {
	Count int64  `json:"count"`
	Head  string `json:"head"`
}

// Start is the checkpoint of an empty chain.
var Start = Checkpoint{Count: 0, Head: Genesis}

// Seal makes event the record after head: {"seq": head.Count, **event, **Fields(event), "prev_hash": head.Head}
// plus its hash, as audit.py AuditLog.append does. It returns the record (freshly decoded from the hashed bytes)
// and its canonical JSON with the hash, which is what a store keeps. event is not modified.
func Seal(head Checkpoint, event map[string]any) (map[string]any, []byte, error) {
	var bad []string
	for k := range event {
		if Envelope[k] && k != "coverage" && k != "boundary" {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return nil, nil, fmt.Errorf("%w: event must not set %v", ErrEnvelopeField, bad)
	}
	rec := make(map[string]any, len(event)+8)
	rec["seq"] = json.Number(fmt.Sprint(head.Count))
	for k, v := range event {
		rec[k] = v
	}
	for k, v := range Fields(event) {
		rec[k] = v
	}
	rec["prev_hash"] = head.Head
	body, err := canon.Canonical(rec)
	if err != nil {
		return nil, nil, err
	}
	// The stored record is the parse of the hashed bytes, so a store hands back exactly what was hashed (and in
	// the value types Parse yields), whatever Go types the event carried.
	parsed, err := canon.Parse(body)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotStorable, err) // NaN or Infinity
	}
	out := parsed.(map[string]any)
	if err := storable(out); err != nil {
		return nil, nil, err
	}
	out["hash"] = canon.SHA256Hex(body)
	full, err := canon.Canonical(out)
	if err != nil {
		return nil, nil, err
	}
	return out, full, nil
}

// storable walks a parsed record for values jsonb would change (ErrNotStorable).
func storable(v any) error {
	switch x := v.(type) {
	case string:
		if strings.IndexByte(x, 0) >= 0 {
			return fmt.Errorf("%w: string holds U+0000", ErrNotStorable)
		}
	case json.Number:
		if !canon.IsFloatLiteral(string(x)) {
			return nil
		}
		f, _ := x.Float64()
		switch {
		case f == 0 && math.Signbit(f):
			return fmt.Errorf("%w: negative zero", ErrNotStorable)
		case math.Abs(f) >= 1e16:
			return fmt.Errorf("%w: float %s prints with an exponent jsonb drops", ErrNotStorable, x)
		}
	case []any:
		for _, e := range x {
			if err := storable(e); err != nil {
				return err
			}
		}
	case map[string]any:
		for k, e := range x {
			if err := storable(k); err != nil {
				return err
			}
			if err := storable(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// BadRecord says which record broke the chain and why.
type BadRecord struct {
	Seq    int64 // the index of the first bad record (audit.py verify's "bad")
	Reason string
}

func (e *BadRecord) Error() string {
	return fmt.Sprintf("evidence: chain broken at record %d: %s", e.Seq, e.Reason)
}

// Verifier checks a chain one record at a time, so a store can stream it from genesis without holding it.
type Verifier struct{ at Checkpoint }

// NewVerifier starts at genesis.
func NewVerifier() *Verifier { return &Verifier{at: Start} }

// Resume continues from a chain prefix already verified (or anchored) as cp.
func Resume(cp Checkpoint) *Verifier { return &Verifier{at: cp} }

// Checkpoint is the count and head of what has been verified so far.
func (v *Verifier) Checkpoint() Checkpoint { return v.at }

// Add checks the next record and returns a *BadRecord if it is not the chain's next link.
//
// seq must be the JSON integer equal to the record's index. (Python compares with ==, so a seq of 1.0 or true
// would pass there; Go accepts only the integer, which every writer has produced.)
func (v *Verifier) Add(r map[string]any) error {
	i := v.at.Count
	bad := func(format string, a ...any) error { return &BadRecord{Seq: i, Reason: fmt.Sprintf(format, a...)} }
	if !seqIs(r["seq"], i) {
		return bad("seq is %v, want %d", r["seq"], i)
	}
	if p, ok := r["prev_hash"].(string); !ok || p != v.at.Head {
		return bad("prev_hash does not name the previous record's hash")
	}
	h, ok := r["hash"].(string)
	if !ok {
		return bad("no hash")
	}
	body := make(map[string]any, len(r))
	for k, x := range r {
		if k != "hash" {
			body[k] = x
		}
	}
	c, err := canon.Canonical(body)
	if err != nil {
		return bad("not canonicalizable: %v", err)
	}
	if canon.SHA256Hex(c) != h {
		return bad("hash does not match the record")
	}
	v.at = Checkpoint{Count: i + 1, Head: h}
	return nil
}

func seqIs(x any, i int64) bool {
	switch s := x.(type) {
	case json.Number:
		return !canon.IsFloatLiteral(string(s)) && string(s) == fmt.Sprint(i)
	case int64:
		return s == i
	case int:
		return int64(s) == i
	}
	return false
}

// Verify is audit.py verify: (true, -1) for a good chain, else (false, index of the first bad record).
func Verify(records []map[string]any) (ok bool, bad int64) {
	v := NewVerifier()
	for _, r := range records {
		if err := v.Add(r); err != nil {
			return false, err.(*BadRecord).Seq
		}
	}
	return true, -1
}

// VerifyAgainst is audit.py verify_against: a chain checked against a checkpoint anchored earlier and elsewhere.
// An anchor of count 0 must name Genesis (Python would index records[-1] there).
func VerifyAgainst(records []map[string]any, anchored Checkpoint) (bool, string) {
	ok, bad := Verify(records)
	if !ok {
		return false, fmt.Sprintf("chain broken at record %d", bad)
	}
	return Anchored(int64(len(records)), func(i int64) string { h, _ := records[i]["hash"].(string); return h }, anchored)
}

// Anchored is VerifyAgainst's anchor test on an already verified chain of count records, where hashAt(i) is
// record i's hash; streaming callers record the hash at anchored.Count-1 as they pass it.
func Anchored(count int64, hashAt func(int64) string, anchored Checkpoint) (bool, string) {
	if count < anchored.Count {
		return false, fmt.Sprintf("truncated: %d records, anchored %d", count, anchored.Count)
	}
	head := Genesis
	if anchored.Count > 0 {
		head = hashAt(anchored.Count - 1)
	}
	if head != anchored.Head {
		return false, "history rewritten: anchored head does not match"
	}
	return true, "ok"
}

// ISO is the one timestamp format records use (audit.py iso).
func ISO(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }
