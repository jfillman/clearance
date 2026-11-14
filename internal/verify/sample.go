package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/sampling"
)

// VerifySample checks a sample document (`GET /v1/packets/{id}/sample`, P-2) offline, the way Verify checks a packet.
// packetDir, when not empty, is the packet the sample was drawn from, which the sample is then checked against.
//
// Every check is on data the file carries or on the packet; nothing is asked of Clearance. What fails, not passes with a
// note: a record that does not hash to the hash it states; a record with no proof, or a proof that does not verify under
// the checkpoint; a checkpoint that does not verify under the log keys; fewer or more records than n says; a record that
// is not a clearing record of an eligible change of the population; a population that does not hash to the digest it
// states; a selection that is not the one the rule draws from the stated seed; and, against the packet, a different packet
// digest, population, checkpoint or record.
func VerifySample(file, packetDir string, opts Options) *Report {
	rep := &Report{Packet: file}
	c := &ctx{opts: opts, rep: rep, mem: map[string][]byte{}}
	doc := c.loadSample(file)
	if doc == nil {
		return rep
	}
	// The sample's own copy of the checkpoint, keys and proofs, as the files the packet's checks read.
	proofs := struct {
		Schema   string           `json:"schema"`
		Origin   string           `json:"origin"`
		TreeSize int64            `json:"tree_size"`
		Root     string           `json:"root"`
		Proofs   []sampling.Proof `json:"proofs"`
	}{"clearance.packet-proofs/v1", doc.Checkpoint.Origin, doc.Checkpoint.Size, doc.Checkpoint.Root, nil}
	for _, it := range doc.Selected {
		proofs.Proofs = append(proofs.Proofs, it.Proof)
	}
	pj, _ := json.Marshal(proofs)
	c.mem[fileProofs], c.mem[fileCheckpoint] = pj, []byte(doc.Checkpoint.Note)
	c.mem[fileLogKeys], c.mem[filePolicy] = []byte(doc.Checkpoint.LogKeys), []byte(doc.Checkpoint.WitnessPolicy)
	c.sampleRecords(doc)
	src := func(supplied bool, from, packetFile string) string {
		switch {
		case supplied:
			return "supplied by you (" + from + ")"
		case c.exists(packetFile):
			return "TAKEN FROM THE SAMPLE (a copy of the packet's): proves nothing about who the log is"
		}
		return "none"
	}
	rep.Inputs = []Input{
		{"log keys", src(len(opts.LogKeys) > 0, opts.LogKeysSrc, fileLogKeys)},
		{"witness policy", src(len(opts.WitnessPolicy) > 0, opts.WitnessPolicySrc, filePolicy)},
	}
	c.ledgerCheck()
	c.samplePopulation(doc)
	c.sampleSelection(doc)
	c.samplePacket(doc, packetDir)
	c.sampleRecordCheck(doc)
	rep.note("What exit 0 proves: the records and proofs are under the checkpoint (as far as the log keys and witness policy you supplied vouch for it), the population is the packet's, the selection is the one the rule draws from that population and the seed, and the core's own packet.sample record, read from the core, names this draw. What it does not prove: that the review of these records was right; that the seed was chosen after the packet's digest was fixed (that is for whoever agreed the seed); or, without --sample-record, that the core ever drew this sample.")
	return rep
}

// loadSample reads and parses the sample document. A file it cannot read or that is not a sample document is a failed
// check and a nil result.
func (c *ctx) loadSample(file string) *sampling.Document {
	chk := Check{Name: "sample: document"}
	f, err := os.Open(file)
	if err != nil {
		chk.Status, chk.Detail = Fail, err.Error()
		c.rep.add(chk)
		return nil
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, sampling.MaxDocument+1))
	if err != nil || len(raw) > sampling.MaxDocument {
		chk.Status, chk.Detail = Fail, fmt.Sprintf("cannot be read, or is over %d bytes", sampling.MaxDocument)
		c.rep.add(chk)
		return nil
	}
	var d sampling.Document
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&d); err != nil || dec.More() {
		chk.Status, chk.Detail = Fail, "is not a sample document (JSON of clearance.packet-sample/v1)"
		c.rep.add(chk)
		return nil
	}
	var bad []string
	if d.Schema != sampling.Schema || d.Method != sampling.Method {
		bad = append(bad, fmt.Sprintf("schema %q and method %q: this verifier reads %s drawn by %s", d.Schema, d.Method, sampling.Schema, sampling.Method))
	}
	if !sampling.IsHex64(d.Packet.Digest) || d.Packet.ID != "pk-"+d.Packet.Digest[:min(32, len(d.Packet.Digest))] {
		bad = append(bad, "the packet id is not derived from the packet digest")
	}
	if d.Recorded == nil || d.Recorded.Seq < 0 || !sampling.IsHex64(d.Recorded.Hash) || len(d.Recorded.Record) == 0 {
		bad = append(bad, "the sample carries no sampling record (packet.sample): a sample the core did not record is not one it drew")
	}
	if len(bad) > 0 {
		chk.Status, chk.Detail, chk.Findings = Fail, fmt.Sprintf("%d problem(s)", len(bad)), bad
		c.rep.add(chk)
		return nil
	}
	chk.Status, chk.Detail = Pass, fmt.Sprintf("%s of packet %s for %s, drawn by %s", sampling.Schema, d.Packet.ID, d.Recipient, sampling.Method)
	c.rep.add(chk)
	return &d
}

// sampleRecords recomputes every sampled record's hash and puts the records where the ledger checks look for them.
func (c *ctx) sampleRecords(d *sampling.Document) {
	chk := Check{Name: "sample: records hash to what they state"}
	var bad []string
	seen := map[int64]bool{}
	for i, it := range d.Selected {
		r, problem := parseRecordLine(i+1, it.Record)
		if problem != "" {
			bad = append(bad, fmt.Sprintf("sampled change %s: %s", it.Change, problem))
			if r.line == 0 {
				continue
			}
		}
		switch {
		case r.seq != it.Seq:
			bad = append(bad, fmt.Sprintf("sampled change %s: the record is seq %d, the item says %d", it.Change, r.seq, it.Seq))
		case seen[r.seq]:
			bad = append(bad, fmt.Sprintf("seq %d is sampled twice", r.seq))
		}
		seen[r.seq] = true
		c.recs = append(c.recs, r)
	}
	if len(d.Selected) == 0 {
		bad = append(bad, "the sample carries no record")
	}
	if len(bad) > 0 {
		chk.Status, chk.Detail, chk.Findings = Fail, fmt.Sprintf("%d problem(s) in %d records", len(bad), len(d.Selected)), bad
	} else {
		chk.Status, chk.Detail = Pass, fmt.Sprintf("%d records, every hash recomputes from the original", len(d.Selected))
	}
	c.rep.add(chk)
}

// samplePopulation checks the population as printed: its figures, its digest and that each row is coherent. It cannot
// check the population is the packet's: that is samplePacket, with the packet.
func (c *ctx) samplePopulation(d *sampling.Document) {
	chk := Check{Name: "sample: the population printed with it"}
	p := d.Population
	var bad []string
	all, cleared, eligible := sampling.Counts(p.Changes)
	if all != p.Count || cleared != p.Cleared || eligible != p.Eligible {
		bad = append(bad, fmt.Sprintf("it states %d changes, %d cleared, %d eligible; the rows are %d, %d and %d", p.Count, p.Cleared, p.Eligible, all, cleared, eligible))
	}
	if sha, err := sampling.PopulationSHA256(p.Changes); err != nil || sha != p.SHA256 {
		bad = append(bad, "the rows do not hash to the population digest it states")
	}
	if want := sampling.ClearedExcluded(p.Changes); !reflect.DeepEqual(want, nonNil(p.ClearedExcluded)) {
		bad = append(bad, fmt.Sprintf("it states cleared-but-excluded counts %v; the rows give %v", p.ClearedExcluded, want))
	}
	seenID, seenSeq := map[string]bool{}, map[int64]bool{}
	for i, r := range p.Changes {
		switch {
		case r.Change == "" || seenID[r.Change]:
			bad = append(bad, fmt.Sprintf("row %d: change id %q is empty or repeated", i+1, r.Change))
		case i > 0 && p.Changes[i-1].Change >= r.Change:
			bad = append(bad, fmt.Sprintf("row %d (%s): rows are not in change-id order", i+1, r.Change))
		}
		seenID[r.Change] = true
		if r.ClearSeq != nil {
			if *r.ClearSeq < 0 || seenSeq[*r.ClearSeq] {
				bad = append(bad, fmt.Sprintf("row %d (%s): clear record %d is invalid or another row's", i+1, r.Change, *r.ClearSeq))
			}
			seenSeq[*r.ClearSeq] = true
		}
		switch {
		case r.Eligible && (r.ClearSeq == nil || r.Excluded != "" || r.Month == ""):
			bad = append(bad, fmt.Sprintf("row %d (%s): eligible with no clear record, a month, or with an exclusion", i+1, r.Change))
		case r.Eligible && *r.ClearSeq >= d.Checkpoint.Size:
			bad = append(bad, fmt.Sprintf("row %d (%s): eligible, and its clear record %d is past the checkpoint (%d records): it cannot have an inclusion proof", i+1, r.Change, *r.ClearSeq, d.Checkpoint.Size))
		case !r.Eligible && !slices.Contains([]string{sampling.ExcludedNotCleared, sampling.ExcludedNoProof, sampling.ExcludedTimestamp}, r.Excluded):
			bad = append(bad, fmt.Sprintf("row %d (%s): not eligible and gives no recognised reason (%q)", i+1, r.Change, r.Excluded))
		}
	}
	if len(bad) > 0 {
		chk.Status, chk.Detail, chk.Findings = Fail, fmt.Sprintf("%d problem(s)", len(bad)), bad
	} else {
		chk.Status, chk.Detail = Pass, fmt.Sprintf("%d changes, %d cleared, %d in the frame (eligible): the rows hash to the digest it states", all, cleared, eligible)
		if ex := sampling.ClearedExcluded(p.Changes); len(ex) > 0 {
			chk.Detail += fmt.Sprintf("; cleared and excluded from the frame: %s", exclusionWords(ex))
			if n := ex[sampling.ExcludedNoProof]; n > 0 {
				chk.Findings = append(chk.Findings, fmt.Sprintf("%d cleared change(s) have no inclusion proof (cleared after the checkpoint) and could not be sampled: the sample is of the %d eligible changes, not of every cleared change", n, eligible))
			}
		}
	}
	c.rep.add(chk)
}

// sampleSelection redraws the sample from the population and the seed and requires it to be the one carried.
func (c *ctx) sampleSelection(d *sampling.Document) {
	chk := Check{Name: "sample: the selection is the one the rule draws"}
	var bad []string
	pr := d.Params
	if !sampling.ValidSeed(pr.Seed) {
		bad = append(bad, "the seed is missing or not a valid seed: a sample is always drawn with a seed the caller chose")
	}
	eff := sampling.EffectiveSeed(d.Packet.Digest, pr.Seed)
	if hex.EncodeToString(eff) != d.EffectiveSeed {
		bad = append(bad, "the effective seed is not the SHA-256 of the packet digest and the seed the rule names")
	}
	if pr.N != len(d.Selected) {
		bad = append(bad, fmt.Sprintf("n is %d and the sample carries %d records: records are missing or added", pr.N, len(d.Selected)))
	}
	if len(bad) == 0 {
		seqs, strata, err := sampling.Select(d.Population.Changes, eff, pr.N, pr.Stratify)
		switch {
		case err != nil:
			bad = append(bad, "the population cannot be sampled as stated: "+err.Error())
		default:
			got := make([]int64, len(d.Selected))
			for i, it := range d.Selected {
				got[i] = it.Seq
			}
			if !slices.Equal(seqs, got) {
				bad = append(bad, fmt.Sprintf("the rule draws clear records %v from this population and seed; the sample carries %v", seqs, got))
			}
			if !reflect.DeepEqual(emptyStrata(strata), emptyStrata(d.Strata)) {
				bad = append(bad, "the strata the rule draws are not the strata stated")
			}
		}
	}
	byseq := map[int64]sampling.Row{}
	for _, r := range d.Population.Changes {
		if r.Eligible && r.ClearSeq != nil {
			byseq[*r.ClearSeq] = r
		}
	}
	bySeq := map[int64]rec{}
	for _, r := range c.recs {
		bySeq[r.seq] = r
	}
	for _, it := range d.Selected {
		row, ok := byseq[it.Seq]
		switch {
		case !ok:
			bad = append(bad, fmt.Sprintf("seq %d is not the clear record of an eligible change of the population: a record outside the scope was sampled", it.Seq))
			continue
		case row.Change != it.Change || !reflect.DeepEqual(row.Tier, it.Tier) || row.Month != it.Month:
			bad = append(bad, fmt.Sprintf("seq %d: the item names change %s, tier and month that are not the population row's", it.Seq, it.Change))
		}
		if r, ok := bySeq[it.Seq]; ok {
			ch, _ := r.m["change"].(map[string]any)
			if r.m["tool"] != "deploy.clear" || ch["id"] != row.Change {
				bad = append(bad, fmt.Sprintf("seq %d is not the deploy.clear record of change %s", it.Seq, row.Change))
			}
		}
	}
	if len(bad) > 0 {
		chk.Status, chk.Detail, chk.Findings = Fail, fmt.Sprintf("%d problem(s)", len(bad)), bad
	} else {
		chk.Status, chk.Detail = Pass, fmt.Sprintf("%d of %d eligible changes, %s, seed %q: redrawn from the population, the same records, each the clearing record of its change", pr.N, d.Population.Eligible, pr.Stratify, pr.Seed)
	}
	c.rep.add(chk)
}

func emptyStrata(s []sampling.Stratum) []sampling.Stratum {
	if len(s) == 0 {
		return nil
	}
	return s
}

// samplePacket checks the sample against the packet it says it was drawn from: the digest, the checkpoint, the population
// and each sampled record. Without the packet it says so as NOT CHECKED, which is not a pass.
func (c *ctx) samplePacket(d *sampling.Document, dir string) {
	chk := Check{Name: "sample: against the packet it was drawn from"}
	if dir == "" {
		chk.Status = NotChecked
		chk.Detail = "no --packet was given: the packet digest, the population and the checkpoint are as the sample states them, and nothing here shows they are the packet's"
		c.rep.add(chk)
		return
	}
	pc := &ctx{dir: dir, opts: c.opts, rep: c.rep}
	pc.manifestCheck()
	var bad []string
	man, err := pc.read(fileManifest)
	if err != nil {
		c.rep.add(Check{Name: chk.Name, Status: Fail, Detail: err.Error()})
		return
	}
	if sha := sha256Hex(man); sha != d.Packet.Digest {
		bad = append(bad, fmt.Sprintf("the packet's MANIFEST.json hashes to %s; the sample says it is of %s", short8(sha), short8(d.Packet.Digest)))
	}
	var pk struct {
		Schema string `json:"schema"`
		Header struct {
			Chain struct {
				Count int64 `json:"count"`
			} `json:"chain"`
		} `json:"header"`
		Changes      []sampling.Change `json:"changes"`
		Verification struct {
			Ledger struct {
				Origin string `json:"origin"`
				Size   int64  `json:"size"`
				Root   string `json:"root"`
			} `json:"ledger"`
		} `json:"verification"`
	}
	if raw, err := pc.read(filePacket); err != nil {
		bad = append(bad, "the packet's packet.json cannot be read: "+err.Error())
	} else if err := json.Unmarshal(raw, &pk); err != nil || pk.Schema != "clearance.packet/v1" {
		bad = append(bad, "the packet's packet.json is not a packet")
	}
	if l := pk.Verification.Ledger; l.Origin != d.Checkpoint.Origin || l.Size != d.Checkpoint.Size || l.Root != d.Checkpoint.Root {
		bad = append(bad, "the sample's checkpoint is not the checkpoint the packet stood on")
	}
	if d.Recorded != nil && d.Recorded.Seq < pk.Header.Chain.Count {
		bad = append(bad, fmt.Sprintf("the sampling record is %d and the packet read a chain of %d records: it was written before the packet existed", d.Recorded.Seq, pk.Header.Chain.Count))
	}
	// The packet's own carried records and proofs: the population is rebuilt from them, as the core rebuilt it.
	carried := map[int64][]byte{}
	if raw, err := pc.read(fileRecords); err == nil {
		for i, ln := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
			if r, problem := parseRecordLine(i+1, ln); problem == "" {
				carried[r.seq] = ln
			}
		}
	}
	proved := map[int64]bool{}
	if raw, err := pc.read(fileProofs); err == nil {
		var pd proofsDoc
		if json.Unmarshal(raw, &pd) == nil {
			for _, e := range pd.Proofs {
				if _, ok := carried[e.Seq]; ok {
					proved[e.Seq] = true
				}
			}
		}
	}
	rows, err := sampling.Population(pk.Changes, func(seq int64) bool { return proved[seq] })
	switch {
	case err != nil:
		bad = append(bad, "the packet's changes cannot be a population: "+err.Error())
	case !reflect.DeepEqual(rows, d.Population.Changes):
		bad = append(bad, "the population in the sample is not the population of the packet's changes: a change was left out, added or altered")
	}
	for _, it := range d.Selected {
		line, ok := carried[it.Seq]
		if !ok {
			bad = append(bad, fmt.Sprintf("seq %d is not a record the packet carries", it.Seq))
			continue
		}
		if !sameJSON(line, it.Record) {
			bad = append(bad, fmt.Sprintf("seq %d: the sampled record is not the record the packet carries", it.Seq))
		}
	}
	if len(bad) > 0 {
		chk.Status, chk.Detail, chk.Findings = Fail, fmt.Sprintf("%d problem(s)", len(bad)), bad
	} else {
		chk.Status, chk.Detail = Pass, fmt.Sprintf("packet %s (%s): the digest, the checkpoint and the whole population are the packet's, and each sampled record is the one it carries", d.Packet.ID, filepath.Base(dir))
	}
	c.rep.add(chk)
}

// sameJSON says whether two JSON values are equal as the chain's canonical JSON.
func sameJSON(a, b []byte) bool {
	ca, err1 := canonOf(a)
	cb, err2 := canonOf(b)
	return err1 == nil && err2 == nil && bytes.Equal(ca, cb)
}

func canonOf(raw []byte) ([]byte, error) {
	v, err := canon.Parse(raw)
	if err != nil {
		return nil, err
	}
	return canon.Canonical(v)
}

// sampleUsage is the part of the usage text about samples.
var sampleUsage = strings.TrimSpace(`
usage: clearance verify --sample <file> [--packet <packet-dir>] [--sample-record <file>] [flags]

Checks a sample of a packet's cleared changes (the answer of GET /v1/packets/{id}/sample) offline: every record's hash,
every inclusion proof against the checkpoint, the checkpoint's signatures, the population's digest, and that the sample is
the one the rule draws from the population and the seed. With --packet it also checks the sample against the packet it was
drawn from. Exit codes are the packet's: 0 verified, 1 failed, 2 nothing failed but something could not be established.`)

// sampleRecordCheck is the check that the core drew this sample. The packet.sample record is written after the checkpoint the
// proofs are under, so nothing in the sample proves the core wrote it, and a document anyone can assemble offline (the rule is
// public) carries a record anyone can make up. What can show it is the record as the core serves it, which the caller reads from
// the core and gives with --sample-record: GET /v1/evidence/{seq} on the core, for the seq the sample names. Without it the
// check is NOT CHECKED, never a pass.
func (c *ctx) sampleRecordCheck(d *sampling.Document) {
	chk := Check{Name: "sample: the core's packet.sample record"}
	own := checkSamplingRecord(d, d.Recorded.Record)
	if len(own) > 0 {
		chk.Status, chk.Detail, chk.Findings = Fail, "the record the sample carries is not the record of this draw", own
		c.rep.add(chk)
		return
	}
	if len(c.opts.SampleRecord) == 0 {
		chk.Status = NotChecked
		chk.Detail = fmt.Sprintf("no --sample-record was given: the record the sample carries (seq %d) is consistent with the draw, and nothing here shows the core wrote it. "+
			"Read record %d from the core (GET /v1/evidence/%d, or ask the subscriber) and pass it with --sample-record", d.Recorded.Seq, d.Recorded.Seq, d.Recorded.Seq)
		c.rep.add(chk)
		return
	}
	bad := checkSamplingRecord(d, c.opts.SampleRecord)
	if !sameJSON(c.opts.SampleRecord, d.Recorded.Record) {
		bad = append(bad, "the record you supplied is not the record the sample carries")
	}
	if len(bad) > 0 {
		chk.Status, chk.Detail, chk.Findings = Fail, fmt.Sprintf("%d problem(s)", len(bad)), bad
		c.rep.add(chk)
		return
	}
	chk.Status = Pass
	chk.Detail = fmt.Sprintf("record %d (%s), supplied by you (%s), is the core's packet.sample record of this draw: same packet, delivery, seed, population digest and records", d.Recorded.Seq, short8(d.Recorded.Hash), c.opts.SampleRecordSrc)
	c.rep.add(chk)
}

// checkSamplingRecord says what is wrong with raw as the packet.sample record of d: its hash, its seq, what kind of record it
// is and that the draw it states is d's.
func checkSamplingRecord(d *sampling.Document, raw []byte) []string {
	r, problem := parseRecordLine(1, raw)
	if problem != "" {
		return []string{"the record does not hash to the hash it states, or is not a record"}
	}
	var bad []string
	if r.seq != d.Recorded.Seq || r.computed != d.Recorded.Hash {
		bad = append(bad, fmt.Sprintf("it is record %d (%s); the sample names record %d (%s)", r.seq, short8(r.computed), d.Recorded.Seq, short8(d.Recorded.Hash)))
	}
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }
	sub := func(k string) map[string]any { m, _ := r.m[k].(map[string]any); return m }
	pk, dl, sm := sub("packet"), sub("delivery"), sub("sample")
	if r.m["tool"] != "packet.sample" || r.m["decision"] != "allow" {
		bad = append(bad, "it is not an allowed packet.sample record")
	}
	if str(pk, "id") != d.Packet.ID || str(dl, "id") != d.Delivery || str(dl, "recipient") != d.Recipient {
		bad = append(bad, "it is a sampling of another packet, delivery or recipient")
	}
	if str(sm, "method") != d.Method || str(sm, "population_sha256") != d.Population.SHA256 || str(sm, "effective_seed") != d.EffectiveSeed ||
		str(sm, "seed") != d.Params.Seed || str(sm, "stratify") != d.Params.Stratify {
		bad = append(bad, "its method, population digest, seed or stratification are not the sample's")
	}
	if n, ok := intOf(sm["n"]); !ok || n != int64(d.Params.N) {
		bad = append(bad, "its n is not the sample's")
	}
	sel, _ := sm["selected"].([]any)
	if len(sel) != len(d.Selected) {
		bad = append(bad, "it names a different number of sampled records")
	} else {
		for i, v := range sel {
			if n, ok := intOf(v); !ok || n != d.Selected[i].Seq {
				bad = append(bad, "it names other sampled records than the sample carries")
				break
			}
		}
	}
	return bad
}

func nonNil(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

func exclusionWords(m map[string]int) string {
	var out []string
	for _, k := range sortedKeys(m) {
		out = append(out, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(out, ", ")
}
