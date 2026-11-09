package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jfillman/clearance/internal/canon"
)

// rec is one carried record: the line it is on, its seq, the hash it states and the hash it recomputes to.
type rec struct {
	line     int
	seq      int64
	stated   string
	computed string
	prev     string
	m        map[string]any
}

// recordsCheck recomputes every carried record's hash from its original (drop "hash", canonicalize, SHA-256) and
// checks the prev_hash links where seqs are adjacent. A line whose hash does not recompute is named; so is the
// record on either side of a broken link.
func (c *ctx) recordsCheck() {
	chk := Check{Name: "records: hashes and chain links"}
	raw, err := c.read(fileRecords)
	if err != nil {
		chk.Status, chk.Detail = Fail, fileRecords+" cannot be read: "+err.Error()
		c.rep.add(chk)
		return
	}
	var bad []string
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(raw) == 0 {
		lines = nil
	}
	for i, ln := range lines {
		n := i + 1
		v, err := canon.Parse(ln)
		m, ok := v.(map[string]any)
		if err != nil || !ok {
			bad = append(bad, fmt.Sprintf("line %d: not a record (%v)", n, errOr(err, "not an object")))
			continue
		}
		seq, ok := intOf(m["seq"])
		stated, _ := m["hash"].(string)
		prev, _ := m["prev_hash"].(string)
		if !ok || len(stated) != 64 {
			bad = append(bad, fmt.Sprintf("line %d: no seq or no 64-hex hash", n))
			continue
		}
		delete(m, "hash")
		cb, err := canon.Canonical(m)
		if err != nil {
			bad = append(bad, fmt.Sprintf("line %d (seq %d): cannot be canonicalized: %v", n, seq, err))
			continue
		}
		r := rec{line: n, seq: seq, stated: stated, computed: canon.SHA256Hex(cb), prev: prev, m: m}
		if r.computed != r.stated {
			bad = append(bad, fmt.Sprintf("line %d (seq %d): ALTERED. It states hash %s and its content hashes to %s", n, seq, short8(stated), short8(r.computed)))
		}
		c.recs = append(c.recs, r)
	}
	for i := 1; i < len(c.recs); i++ {
		a, b := c.recs[i-1], c.recs[i]
		switch {
		case b.seq <= a.seq:
			bad = append(bad, fmt.Sprintf("line %d (seq %d) does not come after seq %d: records are out of order or repeated", b.line, b.seq, a.seq))
		case b.seq == a.seq+1 && b.prev != a.computed:
			bad = append(bad, fmt.Sprintf("seq %d (line %d): its prev_hash is not the hash of seq %d (line %d): seq %d or seq %d was altered or replaced", b.seq, b.line, a.seq, a.line, a.seq, b.seq))
		}
	}
	if p := c.pk; p != nil && len(c.recs) > 0 {
		last := c.recs[len(c.recs)-1]
		if p.Header.Chain.Count > 0 && last.seq == p.Header.Chain.Count-1 && last.computed != p.Header.Chain.Head {
			bad = append(bad, fmt.Sprintf("seq %d is the last record of the chain and does not hash to the head the packet states (%s)", last.seq, short8(p.Header.Chain.Head)))
		}
	}
	if len(c.recs) == 0 && len(bad) == 0 {
		bad = append(bad, "the packet carries no records")
	}
	chk.Findings = bad
	if len(bad) > 0 {
		chk.Status, chk.Detail = Fail, fmt.Sprintf("%d problem(s) in %d records", len(bad), len(c.recs))
	} else {
		chk.Status, chk.Detail = Pass, fmt.Sprintf("%d records, every hash recomputes from the original, adjacent seqs are linked", len(c.recs))
	}
	c.rep.add(chk)
}

func errOr(err error, s string) string {
	if err != nil {
		return err.Error()
	}
	return s
}

func intOf(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case int64:
		return n, true
	}
	return 0, false
}

func unhex32(s string) ([]byte, bool) {
	b, err := hex.DecodeString(s)
	return b, err == nil && len(b) == 32
}
