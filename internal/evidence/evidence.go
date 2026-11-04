// Package evidence is the hash-chained evidence record, clearance.evidence/v1 (schemas/evidence.schema.json,
// docs/evidence.md), ported from clearance audit.py and kept byte for byte with it: the same event sealed by the
// same Writer after the same head is the same record in both languages (testdata/python_chain.py checks it).
//
// This package is the one place the Go core builds a record's envelope: schema, boundary, coverage, provider,
// subject, intent (redacted unless the writer opts in), the verified/claimed field tags, seq, prev_hash and hash.
// Every Go writer (store/memory, store/pg, and through them the decision, record and gate routes) seals here.
//
// A record's hash is SHA-256 over canon.Canonical of the record without "hash"; its prev_hash is the hash of the
// record before it (Genesis for seq 0); seq counts from 0 with no gaps. The rule is the same for every schema
// version, so a chain of v0-draft rows extended with v1 records verifies as one chain. That proves consistency,
// not completeness: truncating the tail leaves a valid chain, which is what VerifyAgainst and an anchored
// Checkpoint are for. The assurance state is kept beside a record, never inside the hash.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jfillman/clearance/internal/vocab"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/canon"
)

// Genesis is the prev_hash of record 0.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Schema names the record shape writers emit (audit.py EVIDENCE_SCHEMA).
const Schema = "clearance.evidence/v1"

// SchemaV0 is the draft shape of the rows written before the freeze (hangar-dev seq 0-611). They stay as written;
// Project gives a reader their v1 shape.
const SchemaV0 = "clearance.evidence/v0-draft"

// The v1 enumerations (audit.py BOUNDARIES, COVERAGE, ASSURANCE, SUBJECT_KINDS, INTENT_CAPTURE).
var (
	Boundaries    = []string{"runtime", "deployment"}
	Coverage      = []string{"authorized-and-verified", "observed-not-attributed", "out-of-band-detected", "coverage-unavailable"}
	Assurance     = []string{"checkpointed", "recorded-not-checkpointed", "not-recorded"}
	SubjectKinds  = []string{"tool-call", "manifest-tree", "terraform-plan", "definition", "model-call"}
	IntentCapture = []string{"redacted", "full"}
)

// Verified are the fields the Python gateway establishes itself for a runtime decision, the v0-draft set
// (audit.py VERIFIED).
var Verified = set("ts", "task_id", "session", "parent", "principal", "agent", "tool", "tier", "decision", "rule",
	"target", "args_sha256", "result", "effect", "app")

// GatewayVerified is Verified plus provider, which a writer sets from its own registration (audit.py
// GATEWAY_VERIFIED). It is the default Writer.Verified: the core's own decision records.
var GatewayVerified = union(Verified, set("provider"))

// ProviderVerified is for a registered provider's own records (POST /v1/records, R-1d): the core verifies who sent
// them and nothing else they say (audit.py PROVIDER_VERIFIED).
var ProviderVerified = set("provider")

// Envelope are the chain's own fields, never tagged (audit.py ENVELOPE).
var Envelope = set("seq", "schema", "boundary", "coverage", "verified", "claimed", "prev_hash", "hash")

// Reserved are the fields an event may not set: the envelope but boundary and coverage, and provider (audit.py
// RESERVED).
var Reserved = set("seq", "schema", "verified", "claimed", "prev_hash", "hash", "provider")

// Annotations are what a reader adds beside a stored record: never stored, never hashed (audit.py ANNOTATIONS).
var Annotations = set("assurance", "projected")

// MaxIntent caps an event's intent text, in UTF-8 bytes.
const MaxIntent = 64 << 10

// V0Provider is the provider a v0-draft row is projected with: the deployment's (vocab, CLEARANCE_V0_PROVIDER),
// since a v0-draft row names none.
func V0Provider() Provider {
	v := vocab.Get()
	return Provider{Name: v.V0ProviderName, Version: v.V0ProviderVersion}
}

func set(ks ...string) map[string]bool {
	m := make(map[string]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

func union(a, b map[string]bool) map[string]bool {
	m := make(map[string]bool, len(a)+len(b))
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	return m
}

func in(list []string, v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ErrEnvelopeField is returned by Seal for an event that sets a Reserved field.
var ErrEnvelopeField = errors.New("evidence: event sets an envelope field")

// ErrInvalid is returned by Seal for an event or Writer the v1 envelope does not accept: a boundary, coverage,
// subject, intent or provider outside the schema.
var ErrInvalid = errors.New("evidence: not a v1 record")

// ErrNotStorable is returned by Seal for an event Postgres jsonb would not store as it was hashed (so the chain
// would break when read back): a non-finite float, a float whose repr has a positive exponent (|x| >= 1e16; jsonb
// prints it as an integer), a negative zero float (jsonb has none), or a string holding U+0000 (jsonb refuses it).
// The Python core accepted these and broke its own chain on the next start; Go refuses them up front.
var ErrNotStorable = errors.New("evidence: event would not survive Postgres jsonb unchanged")

// Provider is the registered provider a record names: who wrote it, at what version.
type Provider struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (p Provider) value() map[string]any { return map[string]any{"name": p.Name, "version": p.Version} }

// Writer is how a writer seals its events (audit.py Writer). R-1d builds one per call: the core's own decision
// records use the core's provider and GatewayVerified; a registered provider's records use that provider (from
// CLEARANCE_PROVIDERS, after it authenticated) and ProviderVerified.
type Writer struct {
	Provider Provider
	// IntentCapture is "redacted" (the default, also for "") or "full", where the deployment opts in.
	IntentCapture string
	// Verified are the fields this writer establishes itself; nil means GatewayVerified. Every other field is
	// claimed.
	Verified map[string]bool
}

var (
	providerName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	digestAlg    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,31}$`)
	hex64        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex40        = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func (w Writer) check() (capture string, verified map[string]bool, err error) {
	if !providerName.MatchString(w.Provider.Name) {
		return "", nil, fmt.Errorf("%w: provider name %q is not a lowercase name", ErrInvalid, w.Provider.Name)
	}
	if n := utf8.RuneCountInString(w.Provider.Version); n == 0 || n > 64 {
		return "", nil, fmt.Errorf("%w: provider version is 1 to 64 characters", ErrInvalid)
	}
	capture = w.IntentCapture
	if capture == "" {
		capture = "redacted"
	}
	if !in(IntentCapture, capture) {
		return "", nil, fmt.Errorf("%w: intent capture is one of %v", ErrInvalid, IntentCapture)
	}
	verified = w.Verified
	if verified == nil {
		verified = GatewayVerified
	}
	return capture, verified, nil
}

func isHex(v any, re *regexp.Regexp) bool {
	s, ok := v.(string)
	return ok && re.MatchString(s)
}

// DeriveSubject is what a record is about when its writer did not say, and the fields it came from (audit.py
// derive_subject): a gate record's change (its rendered tree, and the commit), an agent definition the gateway
// loaded (the digest of its pin), or the call itself (the tool and the digest of its arguments). A deployment
// record with no tree has none (nil). r holds Parse's value types.
//
// A model call (tool model.call, since revision 3) is a model-call subject named by its target, the model alias it
// asked for, with the digest of its arguments. That is for records written from revision 3 on: Project derives a
// v0-draft row's subject as it always did (deriveSubject with v0), so no served projection of a stored row changes.
func DeriveSubject(r map[string]any) (subject map[string]any, sources []string) {
	return deriveSubject(r, false)
}

func deriveSubject(r map[string]any, v0 bool) (subject map[string]any, sources []string) {
	if ch, ok := r["change"].(map[string]any); ok && isHex(ch["tree"], hex64) && ch["tree"] != Genesis {
		d := map[string]any{"sha256": ch["tree"]}
		if isHex(ch["head"], hex40) {
			d["gitCommit"] = ch["head"]
		}
		s := map[string]any{"kind": "manifest-tree", "digests": d}
		app, ok1 := ch["app"].(string)
		env, ok2 := ch["env"].(string)
		if ok1 && ok2 {
			s["name"] = app + "/" + env
		}
		return s, []string{"change"}
	}
	if b, ok := r["boundary"]; ok && b != "runtime" {
		return nil, nil
	}
	tool, ok := r["tool"].(string)
	if !ok || tool == "" || !isHex(r["args_sha256"], hex64) {
		return nil, nil
	}
	a := r["args_sha256"]
	if strings.HasPrefix(tool, "definition.") {
		name := tool
		if t, ok := r["target"].(string); ok && t != "" {
			name = t
		}
		return map[string]any{"kind": "definition", "name": name, "digests": map[string]any{"sha256": a}},
			[]string{"tool", "target", "args_sha256"}
	}
	if tool == "model.call" && !v0 {
		if t, ok := r["target"].(string); ok && t != "" {
			return map[string]any{"kind": "model-call", "name": t, "digests": map[string]any{"sha256": a}},
				[]string{"tool", "target", "args_sha256"}
		}
	}
	return map[string]any{"kind": "tool-call", "name": tool, "digests": map[string]any{"sha256": a}},
		[]string{"tool", "args_sha256"}
}

// checkSubject is audit.py check_subject: null, or {kind, digests[, name]}.
func checkSubject(v any) error {
	if v == nil {
		return nil
	}
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrInvalid, why) }
	s, ok := v.(map[string]any)
	if !ok {
		return bad("subject is {kind, digests[, name]}")
	}
	_, hasKind := s["kind"]
	_, hasDigests := s["digests"]
	for k := range s {
		if k != "kind" && k != "name" && k != "digests" {
			return bad("subject is {kind, digests[, name]}")
		}
	}
	if !hasKind || !hasDigests {
		return bad("subject is {kind, digests[, name]}")
	}
	if !in(SubjectKinds, s["kind"]) {
		return bad(fmt.Sprintf("subject kind is one of %v", SubjectKinds))
	}
	if n, ok := s["name"]; ok {
		ns, ok := n.(string)
		if c := utf8.RuneCountInString(ns); !ok || c == 0 || c > 1024 {
			return bad("subject name is a non-empty string")
		}
	}
	d, ok := s["digests"].(map[string]any)
	if !ok || len(d) == 0 || len(d) > 16 {
		return bad("subject digests is a non-empty object")
	}
	for k, x := range d {
		xs, ok := x.(string)
		if c := utf8.RuneCountInString(xs); !digestAlg.MatchString(k) || !ok || c == 0 || c > 256 {
			return bad(fmt.Sprintf("subject digest %q is not an algorithm name with a string value", k))
		}
	}
	return nil
}

// intentOf is audit.py intent_of: redacted keeps only the text's digest; full keeps the text.
func intentOf(v any, capture string) (map[string]any, error) {
	text, ok := v.(string)
	if !ok || len(text) > MaxIntent {
		return nil, fmt.Errorf("%w: intent is a string of at most %d bytes", ErrInvalid, MaxIntent)
	}
	sum := sha256.Sum256([]byte(text))
	out := map[string]any{"capture": capture, "sha256": hex.EncodeToString(sum[:])}
	if capture == "full" {
		out["text"] = text
	}
	return out, nil
}

// Fields is audit.py evidence(event, writer): the v1 envelope Seal adds to an event (and the intent it replaces),
// without seq, prev_hash and hash. event holds Parse's value types (Seal normalizes it first).
func Fields(event map[string]any, w Writer) (map[string]any, error) {
	var bad []string
	for k := range event {
		if Reserved[k] {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return nil, fmt.Errorf("%w: event must not set %v", ErrEnvelopeField, bad)
	}
	capture, verified, err := w.check()
	if err != nil {
		return nil, err
	}
	boundary, ok := event["boundary"]
	if !ok {
		boundary = "runtime"
	}
	coverage, ok := event["coverage"]
	if !ok {
		coverage = "authorized-and-verified"
	}
	if !in(Boundaries, boundary) {
		return nil, fmt.Errorf("%w: boundary is one of %v", ErrInvalid, Boundaries)
	}
	if !in(Coverage, coverage) {
		return nil, fmt.Errorf("%w: coverage is one of %v", ErrInvalid, Coverage)
	}
	var subject any
	var subjectVerified bool
	if s, ok := event["subject"]; ok {
		if err := checkSubject(s); err != nil {
			return nil, err
		}
		subject, subjectVerified = s, verified["subject"]
	} else {
		s, sources := DeriveSubject(event)
		if s != nil {
			subject = s
		}
		subjectVerified = true
		for _, k := range sources {
			subjectVerified = subjectVerified && verified[k]
		}
	}
	env := map[string]any{"schema": Schema, "boundary": boundary, "coverage": coverage,
		"provider": w.Provider.value(), "subject": subject}
	if t, ok := event["intent"]; ok {
		it, err := intentOf(t, capture)
		if err != nil {
			return nil, err
		}
		env["intent"] = it
	}
	fields := make([]string, 0, len(event)+2)
	seen := map[string]bool{}
	for _, k := range append(keys(event), "provider", "subject") {
		if !Envelope[k] && !seen[k] {
			seen[k] = true
			fields = append(fields, k)
		}
	}
	sort.Strings(fields) // code point order, as Python's sorted() on str
	vs, cs := []any{}, []any{}
	for _, k := range fields {
		tag := verified[k]
		if k == "subject" {
			tag = subjectVerified
		}
		if tag {
			vs = append(vs, k)
		} else {
			cs = append(cs, k)
		}
	}
	env["verified"], env["claimed"] = vs, cs
	return env, nil
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Checkpoint is a chain's length and head hash (audit.py Checkpoint).
type Checkpoint struct {
	Count int64  `json:"count"`
	Head  string `json:"head"`
}

// Start is the checkpoint of an empty chain.
var Start = Checkpoint{Count: 0, Head: Genesis}

// Seal makes event the record after head: {"seq": head.Count, **event, **Fields(event, w), "prev_hash":
// head.Head} plus its hash, as audit.py seal does. It returns the record (freshly decoded from the hashed bytes)
// and its canonical JSON with the hash, which is what a store keeps. event is not modified; it may hold any Go
// values canon.Canonical accepts.
func Seal(head Checkpoint, event map[string]any, w Writer) (map[string]any, []byte, error) {
	for k := range event { // before normalizing, so the error names the field whatever its value
		if Reserved[k] {
			_, err := Fields(map[string]any{k: nil}, w)
			return nil, nil, err
		}
	}
	// Normalize the event to Parse's value types, so the envelope reads it as Python's json.loads would.
	raw, err := canon.Canonical(event)
	if err != nil {
		return nil, nil, err
	}
	ev, err := canon.Parse(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotStorable, err) // NaN or Infinity
	}
	evm := ev.(map[string]any)
	env, err := Fields(evm, w)
	if err != nil {
		return nil, nil, err
	}
	rec := make(map[string]any, len(evm)+10)
	rec["seq"] = json.Number(fmt.Sprint(head.Count))
	for k, v := range evm {
		rec[k] = v
	}
	for k, v := range env {
		rec[k] = v
	}
	rec["prev_hash"] = head.Head
	body, err := canon.Canonical(rec)
	if err != nil {
		return nil, nil, err
	}
	// The stored record is the parse of the hashed bytes, so a store hands back exactly what was hashed (and in
	// the value types Parse yields).
	parsed, err := canon.Parse(body)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotStorable, err)
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

// Project is a stored record as a reader sees it, in the v1 shape whatever it was written as (audit.py project):
// a v0-draft row is left as written and gains provider (V0Provider) and subject (DeriveSubject), named in
// "projected" because the hash does not cover them; a v1 record gains "projected": []. r is not modified.
// clearance-api serves every record through it (R-2's Go port must too).
func Project(r map[string]any) map[string]any {
	out := make(map[string]any, len(r)+3)
	for k, v := range r {
		out[k] = v
	}
	added := []any{}
	if r["schema"] == SchemaV0 {
		if _, ok := out["provider"]; !ok {
			out["provider"] = V0Provider().value()
			added = append(added, "provider")
		}
		if _, ok := out["subject"]; !ok {
			s, _ := deriveSubject(r, true)
			if s != nil {
				out["subject"] = s
			} else {
				out["subject"] = nil
			}
			added = append(added, "subject")
		}
	}
	out["projected"] = added
	return out
}

// Stored is Project's inverse for a hash check: the record without the read-side annotations and projected
// fields (audit.py stored).
func Stored(r map[string]any) map[string]any {
	drop := map[string]bool{}
	for k := range Annotations {
		drop[k] = true
	}
	if p, ok := r["projected"].([]any); ok {
		for _, k := range p {
			if s, ok := k.(string); ok {
				drop[s] = true
			}
		}
	}
	out := make(map[string]any, len(r))
	for k, v := range r {
		if !drop[k] {
			out[k] = v
		}
	}
	return out
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

// CoreProviderName is the provider name the Go core writes its own records as (decisions, deploy.*, provenance
// verdicts, definition.*).
const CoreProviderName = "clearance"

// Core is the Writer for the core's own records at a build version; a zero Writer in a service means Core with
// version "unversioned" (tests, and a build without -ldflags).
func Core(version string) Writer {
	if version == "" {
		version = "unversioned"
	}
	return Writer{Provider: Provider{Name: CoreProviderName, Version: version}}
}

// OrCore is w, or Core("") when w names no provider.
func (w Writer) OrCore() Writer {
	if w.Provider.Name == "" {
		return Core("")
	}
	return w
}
