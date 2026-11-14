package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	f_log "github.com/transparency-dev/formats/log"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/ledger"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/sampling"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// The sampling call (P-2): GET /v1/packets/{id}/sample?n=&seed=&stratify=. A recipient holding a packet credential draws a
// sample of the packet's cleared changes, each with its clear record and an inclusion proof against the packet's
// checkpoint, and the population it was drawn from. It reuses P-1's credential, scope model, hourly caps, refusal rules and
// record-before-serve ordering: the sampling is the packet.sample record, written before a byte is served, and asking for the
// same sample again is served from that record and writes nothing.

// ToolPacketSample is the record kind of a sampling (an allowed one and a refusal).
const ToolPacketSample = "packet.sample"

const (
	// MaxSamplesPerDelivery is how many distinct samples (distinct n, seed or stratify) one delivery may draw, ever. Each is a
	// record; past it the call is 429 and writes nothing. Asking for a sample already drawn does not count.
	MaxSamplesPerDelivery = 20
	// maxSampleQuery caps the raw query string the route reads.
	maxSampleQuery = 256
	// samplerCacheSize is how many packets' sampling frames the core keeps in memory.
	samplerCacheSize = 4
)

// RuleSampleLimit is the answer to a delivery that has drawn MaxSamplesPerDelivery distinct samples.
const RuleSampleLimit = "PK-SAMPLE-LIMIT"

// sampleFrame is a packet read once for sampling: its population, its carried clear records and its proofs, every one
// checked by the core before any is served. A packet is immutable, so the frame is too.
type sampleFrame struct {
	digest  string
	ref     sampling.PacketRef
	cp      sampling.Checkpoint
	rows    []sampling.Row
	popSHA  string
	count   [3]int // all, cleared, eligible
	records map[int64]json.RawMessage
	proofs  map[int64]sampling.Proof
	tiers   map[int64]*int64
	months  map[int64]string
}

type samplers struct {
	mu   sync.Mutex
	byID map[string]*sampleFrame
}

func (c *samplers) get(id, digest string) *sampleFrame {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f := c.byID[id]; f != nil && f.digest == digest {
		return f
	}
	return nil
}

func (c *samplers) put(id string, f *sampleFrame) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byID == nil || len(c.byID) >= samplerCacheSize {
		c.byID = map[string]*sampleFrame{}
	}
	c.byID[id] = f
}

// sampleRecorded is a sampling the chain already holds.
type sampleRecorded struct {
	seq    int64
	hash   string
	sha256 string
}

// sampleIndex is the samplings the chain holds, by (packet, delivery, n, seed, stratify), and how many each delivery has
// drawn. Read once and then kept by the one writer (the caller holds sampleMu).
type sampleIndex struct {
	by       map[string]sampleRecorded
	delivery map[string]int
}

func sampleKey(packetID, delivery string, n int, seed, stratify string) string {
	return strings.Join([]string{packetID, delivery, strconv.Itoa(n), seed, stratify}, "\x00")
}

func (s *Server) sampleIdx(ctx context.Context) (*sampleIndex, error) {
	if s.sampled != nil {
		return s.sampled, nil
	}
	idx := &sampleIndex{by: map[string]sampleRecorded{}, delivery: map[string]int{}}
	const page = 5000
	for from := int64(0); ; {
		recs, err := s.opt.Store.Records(ctx, from, page)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if r["tool"] != ToolPacketSample || r["decision"] != "allow" {
				continue
			}
			pk, _ := r["packet"].(map[string]any)
			dl, _ := r["delivery"].(map[string]any)
			sm, _ := r["sample"].(map[string]any)
			n, err := strconv.Atoi(fmt.Sprint(sm["n"]))
			if err != nil {
				continue
			}
			seq, _ := gate.SeqInt(r["seq"])
			k := sampleKey(fmt.Sprint(pk["id"]), fmt.Sprint(dl["id"]), n, fmt.Sprint(sm["seed_input"]), fmt.Sprint(sm["stratify"]))
			if _, ok := idx.by[k]; !ok {
				idx.by[k] = sampleRecorded{seq: seq, hash: fmt.Sprint(r["hash"]), sha256: fmt.Sprint(sm["sample_sha256"])}
				idx.delivery[fmt.Sprint(dl["id"])]++
			}
		}
		if len(recs) < page {
			break
		}
		last, _ := gate.SeqInt(recs[len(recs)-1]["seq"])
		from = last + 1
	}
	s.sampled = idx
	return idx, nil
}

// sampleParams validates the query before anything else happens: only n, seed and stratify, each once, each in range.
func sampleParams(r *http.Request) (p sampling.Params, seedInput string, msg string) {
	if len(r.URL.RawQuery) > maxSampleQuery {
		return p, "", fmt.Sprintf("the query is over %d bytes", maxSampleQuery)
	}
	q := r.URL.Query()
	for k, vs := range q {
		if (k != "n" && k != "seed" && k != "stratify") || len(vs) != 1 {
			return p, "", "the query parameters are n, seed and stratify, each at most once"
		}
	}
	p.N = sampling.DefaultN
	if v := q.Get("n"); q.Has("n") {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > sampling.MaxN || strconv.Itoa(n) != v {
			return p, "", fmt.Sprintf("n is a whole number from 1 to %d", sampling.MaxN)
		}
		p.N = n
	}
	p.Stratify = sampling.StratifyNone
	if q.Has("stratify") {
		if p.Stratify = q.Get("stratify"); !sampling.ValidStratify(p.Stratify) {
			return p, "", "stratify is " + sampling.StratifyNone + " or " + sampling.StratifyTierMonth
		}
	}
	p.SeedSource = sampling.SeedDefault
	if q.Has("seed") {
		seedInput = q.Get("seed")
		if !sampling.ValidSeed(seedInput) {
			return p, "", fmt.Sprintf("seed is 1 to %d letters, digits, dots, underscores or hyphens", sampling.MaxSeedLen)
		}
		p.SeedSource = sampling.SeedSupplied
	}
	p.Seed = seedInput
	return p, seedInput, ""
}

// buildFrame reads a packet's population, its carried records and its proofs, and checks them all: every record hashes to
// the hash it states, every proof verifies against the checkpoint root and names the record's hash, and the checkpoint the
// packet describes is the one its files carry. A packet that does not check is not sampled.
func buildFrame(b *packet.Bundle) (*sampleFrame, error) {
	file := func(name string) ([]byte, error) {
		raw, ok := b.Files[name]
		if !ok {
			return nil, fmt.Errorf("the packet carries no %s", name)
		}
		return raw, nil
	}
	pj, err := file("packet.json")
	if err != nil {
		return nil, err
	}
	var pk struct {
		Schema string `json:"schema"`
		Header struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"header"`
		Changes      []sampling.Change `json:"changes"`
		Verification struct {
			Ledger struct {
				State  string `json:"state"`
				Origin string `json:"origin"`
				Size   int64  `json:"size"`
				Root   string `json:"root"`
			} `json:"ledger"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(pj, &pk); err != nil || pk.Schema != packet.Schema {
		return nil, errors.New("packet.json is not a packet")
	}
	l := pk.Verification.Ledger
	if l.State != "checkpointed" || l.Size < 1 || l.Origin == "" || !sampling.IsHex64(l.Root) {
		return nil, errNoCheckpoint
	}
	note, err := file(packet.FileCheckpoint)
	if err != nil {
		return nil, err
	}
	i := bytes.LastIndex(note, []byte("\n\n— "))
	var stated f_log.Checkpoint
	if i < 0 {
		return nil, errors.New("the checkpoint file is not a signed note")
	}
	if _, err := stated.Unmarshal(note[:i+1]); err != nil || stated.Origin != l.Origin || int64(stated.Size) != l.Size || hex.EncodeToString(stated.Hash) != l.Root {
		return nil, errors.New("the checkpoint file is not the checkpoint packet.json describes")
	}
	root, _ := hex.DecodeString(l.Root)
	pr, err := file(packet.FileProofs)
	if err != nil {
		return nil, err
	}
	var pd struct {
		Origin   string           `json:"origin"`
		TreeSize int64            `json:"tree_size"`
		Root     string           `json:"root"`
		Proofs   []sampling.Proof `json:"proofs"`
	}
	if err := json.Unmarshal(pr, &pd); err != nil || pd.Origin != l.Origin || pd.TreeSize != l.Size || pd.Root != l.Root {
		return nil, errors.New("the proofs are not for the checkpoint packet.json describes")
	}
	rj, err := file(packet.FileRecords)
	if err != nil {
		return nil, err
	}
	f := &sampleFrame{digest: b.Digest, records: map[int64]json.RawMessage{}, proofs: map[int64]sampling.Proof{}, tiers: map[int64]*int64{}, months: map[int64]string{}}
	hashes := map[int64]string{}
	for _, ln := range bytes.Split(bytes.TrimRight(rj, "\n"), []byte("\n")) {
		v, err := canon.Parse(ln)
		m, ok := v.(map[string]any)
		if err != nil || !ok {
			return nil, errors.New("a carried record is not JSON")
		}
		n, ok := m["seq"].(json.Number)
		seq, err := n.Int64()
		stated, _ := m["hash"].(string)
		if !ok || err != nil || !sampling.IsHex64(stated) {
			return nil, errors.New("a carried record has no seq or hash")
		}
		delete(m, "hash")
		c, err := canon.Canonical(m)
		if err != nil || canon.SHA256Hex(c) != stated {
			return nil, fmt.Errorf("carried record %d does not hash to the hash it states", seq)
		}
		if _, dup := hashes[seq]; dup {
			return nil, fmt.Errorf("carried record %d appears twice", seq)
		}
		hashes[seq] = stated
		f.records[seq] = bytes.Clone(ln)
	}
	for _, p := range pd.Proofs {
		h, ok := hashes[p.Seq]
		if !ok || p.Seq >= l.Size || p.TreeSize != l.Size || p.Hash != h {
			return nil, fmt.Errorf("the proof of record %d is not for a carried record under the checkpoint", p.Seq)
		}
		if _, dup := f.proofs[p.Seq]; dup {
			return nil, fmt.Errorf("record %d has two proofs", p.Seq)
		}
		path := make([][]byte, len(p.Path))
		for j, hx := range p.Path {
			if path[j], err = hex.DecodeString(hx); err != nil || len(path[j]) != 32 {
				return nil, fmt.Errorf("the proof of record %d holds a hash that is not a SHA-256", p.Seq)
			}
		}
		entry, _ := hex.DecodeString(h)
		if err := ledger.VerifyInclusion(p.Seq, l.Size, entry, path, root); err != nil {
			return nil, fmt.Errorf("the proof of record %d does not verify under the checkpoint", p.Seq)
		}
		f.proofs[p.Seq] = p
	}
	rows, err := sampling.Population(pk.Changes, func(seq int64) bool { _, ok := f.proofs[seq]; return ok })
	if err != nil {
		return nil, err
	}
	// The record at a clear seq must be the change's deploy.clear: a sample of anything else is not a sample of cleared changes.
	for i := range rows {
		r := &rows[i]
		if !r.Eligible {
			continue
		}
		var m struct {
			Tool   string `json:"tool"`
			Change struct {
				ID string `json:"id"`
			} `json:"change"`
		}
		if err := json.Unmarshal(f.records[*r.ClearSeq], &m); err != nil || m.Tool != "deploy.clear" || m.Change.ID != r.Change {
			return nil, fmt.Errorf("record %d is not the clearing record of change %s", *r.ClearSeq, r.Change)
		}
		f.tiers[*r.ClearSeq], f.months[*r.ClearSeq] = r.Tier, r.Month
	}
	f.rows = rows
	if f.popSHA, err = sampling.PopulationSHA256(rows); err != nil {
		return nil, err
	}
	f.count[0], f.count[1], f.count[2] = sampling.Counts(rows)
	f.ref = sampling.PacketRef{ID: b.ID, Digest: b.Digest, From: pk.Header.From, To: pk.Header.To}
	f.cp = sampling.Checkpoint{Origin: l.Origin, Size: l.Size, Root: l.Root, Note: string(note)}
	if k, ok := b.Files[packet.FileLogKeys]; ok {
		f.cp.LogKeys = string(k)
	}
	if p, ok := b.Files[packet.FilePolicy]; ok {
		f.cp.WitnessPolicy = string(p)
	}
	return f, nil
}

var errNoCheckpoint = errors.New("this packet stood on no witnessed ledger checkpoint, so no record of it has an inclusion proof")

func (f *sampleFrame) document(claims *token.AccessClaims, p sampling.Params) (*sampling.Document, error) {
	if p.N > f.count[2] {
		return nil, fmt.Errorf("n is %d and the packet has %d changes that can be sampled", p.N, f.count[2])
	}
	eff := sampling.EffectiveSeed(f.digest, p.Seed)
	seqs, strata, err := sampling.Select(f.rows, eff, p.N, p.Stratify)
	if err != nil {
		return nil, err
	}
	d := &sampling.Document{Schema: sampling.Schema, Method: sampling.Method, Packet: f.ref, Delivery: claims.Subject, Recipient: claims.Recipient,
		Params: p, EffectiveSeed: hex.EncodeToString(eff), Checkpoint: f.cp, Strata: strata,
		Population: sampling.PopulationDoc{Count: f.count[0], Cleared: f.count[1], Eligible: f.count[2], SHA256: f.popSHA, Changes: f.rows}}
	byseq := map[int64]string{}
	for _, r := range f.rows {
		if r.ClearSeq != nil {
			byseq[*r.ClearSeq] = r.Change
		}
	}
	for _, seq := range seqs {
		d.Selected = append(d.Selected, sampling.Item{Change: byseq[seq], Seq: seq, Tier: f.tiers[seq], Month: f.months[seq], Record: f.records[seq], Proof: f.proofs[seq]})
	}
	return d, nil
}

func (s *Server) sampleEvent(c *token.AccessClaims, id, decision, rule, result string, now time.Time, sm map[string]any) store.Event {
	var ru any
	if rule != "" {
		ru = rule
	}
	ev := store.Event{"ts": pycompat.ISO(now), "task_id": nil, "session": nil, "parent": nil, "principal": "recipient:" + c.Recipient,
		"agent": nil, "tool": ToolPacketSample, "tier": nil, "decision": decision, "rule": ru, "target": "packet:" + id,
		"args_sha256": c.Digest, "boundary": "deployment", "result": result,
		"packet": map[string]any{"id": id}, "delivery": map[string]any{"id": c.Subject, "recipient": c.Recipient, "packet": c.Packet}}
	if sm != nil {
		ev["sample"] = sm
	}
	return ev
}

// getSample is GET /v1/packets/{id}/sample. The order is P-1's: the path id and the query are validated first (nothing
// reaches a record or an answer unchecked), then the credential's signature (anything the core did not sign is a bare 401
// and writes nothing), then every refusal is a record with its rule, then the caps, and an allowed sample is a record
// written before a byte is served.
func (s *Server) getSample(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if !packet.ValidID(id) {
		writeError(w, http.StatusNotFound, "no such packet")
		return
	}
	params, seedInput, msg := sampleParams(r)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	claims, ok := s.credentialClaims(w, r)
	if !ok {
		return
	}
	now := s.opt.Clock()
	rule, msg, status := "", "", 0
	switch {
	case id != claims.Packet:
		rule, msg, status = RulePacketScope, "this credential opens packet "+claims.Packet+", not "+id, http.StatusForbidden
	case !slices.Contains(claims.Scope, packet.PartSummary) || !slices.Contains(claims.Scope, packet.PartEvidence):
		rule, msg, status = RulePacketScope, "a sample needs both parts of the packet (the population is in the summary, the records and proofs in the evidence); this credential's scope is "+strings.Join(claims.Scope, ", "), http.StatusForbidden
	case now.Before(time.Unix(claims.NotBefore, 0)):
		rule, msg, status = RulePacketNotYet, "this credential is not good until "+pycompat.ISO(time.Unix(claims.NotBefore, 0)), http.StatusForbidden
	case !now.Before(time.Unix(claims.Expires, 0)):
		rule, msg, status = RulePacketExpired, "this credential expired at "+pycompat.ISO(time.Unix(claims.Expires, 0))+": ask the subscriber for a new delivery", http.StatusUnauthorized
	case recipient(s.opt.Providers, claims.Recipient) == nil:
		rule, msg, status = RulePacketRecipient, claims.Recipient+" is no longer a registered recipient", http.StatusForbidden
	}
	if rule != "" {
		s.refuseSample(w, r, claims, id, rule, msg, status, now)
		return
	}
	if !s.reads.allow("a|"+claims.Subject, now, s.readLimit()) {
		w.Header().Set("Retry-After", "3600")
		writeJSON(w, http.StatusTooManyRequests, PacketError{Error: "this delivery has been read " + strconv.Itoa(s.readLimit()) + " times this hour: try again later"})
		return
	}
	b, rule, msg, status, fail := s.loadBundle(w, r, id, claims.Digest)
	if fail {
		return
	}
	if rule != "" {
		s.refuseSample(w, r, claims, id, rule, msg, status, now)
		return
	}
	frame := s.samplerFor(b)
	if frame == nil {
		writeError(w, http.StatusConflict, errNoCheckpoint.Error()+", or the stored packet does not check: nothing was sampled")
		return
	}
	doc, err := frame.document(claims, params)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sha, err := doc.SHA256()
	if err != nil {
		s.log.ErrorContext(ctx, "sample: the sample could not be hashed", "packet", id, "error", err.Error())
		writeError(w, http.StatusServiceUnavailable, "the sample could not be built")
		return
	}
	// One writer at a time: the check for a sample already drawn and the record that would be its first are one step. The
	// lock is not held while the answer is written.
	rec, created, status, msg, rule := s.recordSampling(ctx, claims, id, doc, params, seedInput, sha, now)
	if status != 0 {
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "3600")
			writeJSON(w, status, PacketError{Error: msg, Rule: rule})
			return
		}
		writeError(w, status, msg)
		return
	}
	doc.Recorded = rec
	s.serveSample(w, doc, created)
}

// recordSampling finds the record that already holds this sampling or writes it (one record, before anything is served).
// A non-zero status is the refusal to answer with.
func (s *Server) recordSampling(ctx context.Context, claims *token.AccessClaims, id string, doc *sampling.Document, params sampling.Params, seedInput, sha string, now time.Time) (rec *sampling.Recorded, created bool, status int, msg, rule string) {
	s.sampleMu.Lock()
	defer s.sampleMu.Unlock()
	idx, err := s.sampleIdx(ctx)
	if err != nil {
		return nil, false, http.StatusServiceUnavailable, "the store could not be read", ""
	}
	k := sampleKey(id, claims.Subject, params.N, seedInput, params.Stratify)
	if have, ok := idx.by[k]; ok {
		if have.sha256 != sha {
			// The chain holds a sampling under these parameters that is not this sample: serve nothing rather than a sample
			// the record does not describe.
			s.log.ErrorContext(ctx, "sample: the recorded sampling is not the sample drawn now", "packet", id, "seq", have.seq)
			return nil, false, http.StatusServiceUnavailable, "the recorded sampling does not match the sample: it was not served", ""
		}
		return &sampling.Recorded{Seq: have.seq, Hash: have.hash}, false, 0, "", ""
	}
	if idx.delivery[claims.Subject] >= MaxSamplesPerDelivery {
		return nil, false, http.StatusTooManyRequests, fmt.Sprintf("this delivery has drawn %d samples: ask the subscriber for a new delivery", MaxSamplesPerDelivery), RuleSampleLimit
	}
	selected := make([]any, len(doc.Selected))
	for i, it := range doc.Selected {
		selected[i] = json.Number(strconv.FormatInt(it.Seq, 10))
	}
	sm := map[string]any{"id": sampling.HexID(sha), "n": json.Number(strconv.Itoa(params.N)), "seed_input": seedInput, "seed_source": params.SeedSource,
		"stratify": params.Stratify, "effective_seed": doc.EffectiveSeed, "method": sampling.Method, "sample_sha256": sha, "population_sha256": doc.Population.SHA256,
		"population": json.Number(strconv.Itoa(doc.Population.Count)), "eligible": json.Number(strconv.Itoa(doc.Population.Eligible)),
		"checkpoint_size": json.Number(strconv.FormatInt(doc.Checkpoint.Size, 10)), "selected": selected}
	// Recorded before a byte is served: a sampling that could not be recorded is not made.
	var r store.Record
	err = s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		var err error
		r, err = tx.Append(ctx, s.sampleEvent(claims, id, "allow", "", fmt.Sprintf("packet %s sampled by %s (%d of %d eligible, %s)", id, claims.Recipient, params.N, doc.Population.Eligible, params.Stratify), now, sm), s.coreWriter(packetVerified))
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "sample: the sampling could not be recorded", "packet", id, "error", err.Error())
		return nil, false, http.StatusServiceUnavailable, "the sampling could not be recorded, so it was not served", ""
	}
	seq, _ := gate.SeqInt(r["seq"])
	h := fmt.Sprint(r["hash"])
	idx.by[k] = sampleRecorded{seq: seq, hash: h, sha256: sha}
	idx.delivery[claims.Subject]++
	return &sampling.Recorded{Seq: seq, Hash: h}, true, 0, "", ""
}

func (s *Server) serveSample(w http.ResponseWriter, doc *sampling.Document, created bool) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		writeError(w, http.StatusServiceUnavailable, "the sample could not be encoded")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Clearance-Packet-Digest", doc.Packet.Digest)
	w.Header().Set("X-Clearance-Sample-Created", strconv.FormatBool(created))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// samplerFor is the packet's checked sampling frame, built once and cached, or nil when the packet cannot be sampled.
func (s *Server) samplerFor(b *packet.Bundle) *sampleFrame {
	if f := s.samplers.get(b.ID, b.Digest); f != nil {
		return f
	}
	f, err := buildFrame(b)
	if err != nil {
		s.log.Warn("sample: a packet cannot be sampled", "packet", b.ID, "reason", err.Error())
		return nil
	}
	s.samplers.put(b.ID, f)
	return f
}

// refuseSample records a refusal of a credential the core signed, then answers it, as a refused read is (the same cap:
// a flood of refusals of one delivery is recorded up to maxRefusalRecords an hour, across both routes).
func (s *Server) refuseSample(w http.ResponseWriter, r *http.Request, c *token.AccessClaims, id, rule, msg string, status int, now time.Time) {
	ctx := r.Context()
	if !s.refused.allow("r|"+c.Subject, now, maxRefusalRecords) {
		w.Header().Set("Retry-After", "3600")
		writeJSON(w, http.StatusTooManyRequests, PacketError{Error: "this delivery has been refused " + strconv.Itoa(maxRefusalRecords) + " times this hour: " + msg, Rule: rule})
		return
	}
	err := s.opt.Store.Atomic(ctx, func(tx store.Tx) error {
		_, err := tx.Append(ctx, s.sampleEvent(c, id, "deny", rule, "refused: "+msg, now, nil), s.coreWriter(packetVerified))
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "sample: a refusal could not be recorded", "packet", id, "rule", rule, "error", err.Error())
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="clearance-packet", error="invalid_token"`)
	}
	writeJSON(w, status, PacketError{Error: msg, Rule: rule})
}
