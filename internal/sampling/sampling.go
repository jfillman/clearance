// Package sampling is the sampling call's selection and its document (P-2): the one definition of how a sample is drawn
// from a packet's population, shared by the core that draws it and the offline verifier that redraws it. It imports
// nothing of the core (no store, no packet builder), so the verifier can stay installable alone.
//
// The selection is a function of public inputs only: the packet's population, the packet's digest, the seed the caller
// gave (or none), the size and the stratification. Anyone holding those redraws the same sample, byte for byte.
//
//	effective seed = SHA-256("clearance.sample-seed/v1" 0x00 packet digest (hex) 0x00 seed)   (the seed is required)
//	key(record)    = SHA-256(effective seed || big-endian 64-bit seq of the record's clear record)
//
// Uniform: the n eligible changes with the smallest keys. Stratified (tier-month): the eligible changes are grouped by
// (tier, month of the change's first record); each group gets floor(n * size / eligible) places, the places left over
// go one each to the groups with the largest remainders (ties: the earlier group), and each group takes the changes
// with the smallest keys. The sample is listed in clear-record order.
package sampling

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jfillman/clearance/internal/canon"
)

// Names and limits.
const (
	// Schema names the sample document; Method the selection rule (a change to either is a new name).
	Schema = "clearance.packet-sample/v1"
	Method = "clearance.sample-select/v1"
	// SeedMethod prefixes the effective-seed derivation.
	SeedMethod = "clearance.sample-seed/v1"

	StratifyNone      = "none"
	StratifyTierMonth = "tier-month"

	// DefaultN is the sample size when none is asked for; MaxN the largest a call may ask for; MaxSeedLen the longest seed.
	DefaultN   = 25
	MaxN       = 100
	MaxSeedLen = 64

	// MaxDocument caps a sample document a reader will parse.
	MaxDocument = 32 << 20
)

// ValidSeed says whether s is a seed a caller may give: 1 to MaxSeedLen of letters, digits, dot, underscore and hyphen.
func ValidSeed(s string) bool {
	if s == "" || len(s) > MaxSeedLen {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// ValidStratify says whether s is a stratification.
func ValidStratify(s string) bool { return s == StratifyNone || s == StratifyTierMonth }

// EffectiveSeed binds the caller's seed to the packet, so a seed chosen for one packet means nothing for another. The seed
// is always the caller's: there is no default, because any default is a function of the packet alone and so something the
// party who builds the packet can grind for.
func EffectiveSeed(packetDigest, seed string) []byte {
	h := sha256.New()
	h.Write([]byte(SeedMethod))
	h.Write([]byte{0})
	h.Write([]byte(packetDigest))
	h.Write([]byte{0})
	h.Write([]byte(seed))
	return h.Sum(nil)
}

func key(eff []byte, seq int64) [32]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(seq))
	h := sha256.New()
	h.Write(eff)
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Change is the part of a packet.json change the population reads.
type Change struct {
	ID            string `json:"id"`
	App           string `json:"app"`
	Env           string `json:"env"`
	Tier          *int64 `json:"tier"`
	State         string `json:"state"`
	FirstTS       string `json:"first_ts"`
	Clear         *int64 `json:"clear_seq"`
	ClearVerified bool   `json:"clear_verified"`
}

// Exclusion reasons: why a change in the population is not in the sampling frame.
const (
	ExcludedNotCleared = "not-cleared"
	ExcludedNoProof    = "no-inclusion-proof"
	ExcludedTimestamp  = "unreadable-timestamp"
)

// Row is one change of the population as the sample prints it.
type Row struct {
	Change        string `json:"change"`
	App           string `json:"app"`
	Env           string `json:"env"`
	Tier          *int64 `json:"tier"`
	Month         string `json:"month"`
	State         string `json:"state"`
	ClearSeq      *int64 `json:"clear_seq"`
	ClearVerified bool   `json:"clear_verified"`
	// Eligible: the change has a clear record that is carried by the packet and has an inclusion proof under its checkpoint.
	// Only eligible changes can be sampled; Excluded says why a change is not.
	Eligible bool   `json:"eligible"`
	Excluded string `json:"excluded,omitempty"`
}

// Population is every change of the packet, one row each, ordered by change id. have says whether the record at a seq is
// carried by the packet and has a verified inclusion proof. It refuses a population it cannot key: a repeated change id
// or a clear record claimed by two changes.
func Population(changes []Change, have func(seq int64) bool) ([]Row, error) {
	rows := make([]Row, 0, len(changes))
	seenID, seenSeq := map[string]bool{}, map[int64]bool{}
	for _, c := range changes {
		if c.ID == "" || seenID[c.ID] {
			return nil, fmt.Errorf("sampling: change id %q is empty or repeated", c.ID)
		}
		seenID[c.ID] = true
		r := Row{Change: c.ID, App: c.App, Env: c.Env, Tier: c.Tier, State: c.State, ClearSeq: c.Clear, ClearVerified: c.ClearVerified}
		if t, err := time.Parse(time.RFC3339, c.FirstTS); err == nil {
			r.Month = t.UTC().Format("2006-01")
		}
		switch {
		case c.Clear == nil:
			r.Excluded = ExcludedNotCleared
		case *c.Clear < 0 || seenSeq[*c.Clear]:
			return nil, fmt.Errorf("sampling: change %s names clear record %d, which is invalid or another change's", c.ID, *c.Clear)
		case r.Month == "":
			seenSeq[*c.Clear] = true
			r.Excluded = ExcludedTimestamp
		case !have(*c.Clear):
			seenSeq[*c.Clear] = true
			r.Excluded = ExcludedNoProof
		default:
			seenSeq[*c.Clear] = true
			r.Eligible = true
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Change < rows[j].Change })
	return rows, nil
}

// CanonicalSHA256 is the hex SHA-256 of v's canonical JSON (the evidence chain's canonical form).
func CanonicalSHA256(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	parsed, err := canon.Parse(raw)
	if err != nil {
		return "", err
	}
	c, err := canon.Canonical(parsed)
	if err != nil {
		return "", err
	}
	return canon.SHA256Hex(c), nil
}

// PopulationSHA256 commits to the population: the canonical JSON of its rows.
func PopulationSHA256(rows []Row) (string, error) { return CanonicalSHA256(rows) }

// Counts are the population's three figures: every change, those with a clear record, and those that can be sampled.
func Counts(rows []Row) (all, cleared, eligible int) {
	for _, r := range rows {
		all++
		if r.ClearSeq != nil {
			cleared++
		}
		if r.Eligible {
			eligible++
		}
	}
	return
}

// Stratum is one group of a stratified sample: the eligible changes of one tier in one month, and how many were drawn.
type Stratum struct {
	Tier       *int64 `json:"tier"`
	Month      string `json:"month"`
	Population int    `json:"population"`
	Sample     int    `json:"sample"`
}

func tierNum(t *int64) int64 {
	if t == nil {
		return -1
	}
	return *t
}

// Select draws n of the eligible rows: the clear-record seqs of the sample in ascending order and, when stratified, the
// strata. It fails on an n outside 1..the eligible count, an unknown stratification, or rows it cannot key.
func Select(rows []Row, eff []byte, n int, stratify string) ([]int64, []Stratum, error) {
	if !ValidStratify(stratify) {
		return nil, nil, fmt.Errorf("sampling: stratify is %s or %s", StratifyNone, StratifyTierMonth)
	}
	var frame []Row
	seen := map[int64]bool{}
	for _, r := range rows {
		if !r.Eligible {
			continue
		}
		if r.ClearSeq == nil || seen[*r.ClearSeq] {
			return nil, nil, errors.New("sampling: an eligible change has no clear record, or two share one")
		}
		seen[*r.ClearSeq] = true
		frame = append(frame, r)
	}
	if n < 1 || n > len(frame) {
		return nil, nil, fmt.Errorf("sampling: n is %d and %d changes are eligible", n, len(frame))
	}
	pick := func(group []Row, k int) []int64 {
		type kv struct {
			k   [32]byte
			seq int64
		}
		ks := make([]kv, len(group))
		for i, r := range group {
			ks[i] = kv{key(eff, *r.ClearSeq), *r.ClearSeq}
		}
		sort.Slice(ks, func(i, j int) bool {
			if c := bytes.Compare(ks[i].k[:], ks[j].k[:]); c != 0 {
				return c < 0
			}
			return ks[i].seq < ks[j].seq
		})
		out := make([]int64, k)
		for i := range out {
			out[i] = ks[i].seq
		}
		return out
	}
	var out []int64
	var strata []Stratum
	if stratify == StratifyNone {
		out = pick(frame, n)
	} else {
		type gk struct {
			tier  int64
			month string
		}
		groups := map[gk][]Row{}
		tiers := map[gk]*int64{}
		for _, r := range frame {
			k := gk{tierNum(r.Tier), r.Month}
			groups[k] = append(groups[k], r)
			tiers[k] = r.Tier
		}
		order := make([]gk, 0, len(groups))
		for k := range groups {
			order = append(order, k)
		}
		sort.Slice(order, func(i, j int) bool {
			if order[i].tier != order[j].tier {
				return order[i].tier < order[j].tier
			}
			return order[i].month < order[j].month
		})
		alloc := make([]int, len(order))
		rem := make([]int, len(order))
		given := 0
		for i, k := range order {
			num := n * len(groups[k])
			alloc[i], rem[i] = num/len(frame), num%len(frame)
			given += alloc[i]
		}
		idx := make([]int, len(order))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool { return rem[idx[a]] > rem[idx[b]] })
		for left, j := n-given, 0; left > 0 && j < len(idx); left, j = left-1, j+1 {
			alloc[idx[j]]++
		}
		for i, k := range order {
			if alloc[i] > 0 {
				out = append(out, pick(groups[k], alloc[i])...)
			}
			strata = append(strata, Stratum{Tier: tiers[k], Month: k.month, Population: len(groups[k]), Sample: alloc[i]})
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	}
	if stratify == StratifyNone {
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	}
	return out, strata, nil
}

// The sample document.

// PacketRef names the packet the sample is of.
type PacketRef struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	From   string `json:"from"`
	To     string `json:"to"`
}

// Params are what the caller asked for. The seed is the caller's: the auditor chooses it after the packet's digest is fixed.
type Params struct {
	N        int    `json:"n"`
	Seed     string `json:"seed"`
	Stratify string `json:"stratify"`
}

// Checkpoint is the ledger checkpoint every proof is against, with the note and the keys it is checked under (the
// packet's own copies: a verifier prefers keys it was given).
type Checkpoint struct {
	Origin        string `json:"origin"`
	Size          int64  `json:"size"`
	Root          string `json:"root"`
	Note          string `json:"note"`
	LogKeys       string `json:"log_keys,omitempty"`
	WitnessPolicy string `json:"witness_policy,omitempty"`
}

// PopulationDoc is the population printed with the sample.
type PopulationDoc struct {
	Count    int    `json:"count"`
	Cleared  int    `json:"cleared"`
	Eligible int    `json:"eligible"`
	SHA256   string `json:"sha256"`
	// ClearedExcluded counts the cleared changes that are not in the frame, by reason (no-inclusion-proof,
	// unreadable-timestamp): changes that were cleared and could not be sampled.
	ClearedExcluded map[string]int `json:"cleared_excluded"`
	Changes         []Row          `json:"changes"`
}

// ClearedExcluded counts the cleared changes of the population that are not eligible, by reason. Never nil.
func ClearedExcluded(rows []Row) map[string]int {
	out := map[string]int{}
	for _, r := range rows {
		if r.ClearSeq != nil && !r.Eligible {
			out[r.Excluded]++
		}
	}
	return out
}

// Proof is one record's inclusion proof (the packet's own entry shape).
type Proof struct {
	Seq      int64    `json:"seq"`
	Hash     string   `json:"hash"`
	LeafHash string   `json:"leaf_hash"`
	Path     []string `json:"path"`
	TreeSize int64    `json:"tree_size"`
}

// Item is one sampled change: its clear record, as the packet carries it, and the proof of that record.
type Item struct {
	Change string          `json:"change"`
	Seq    int64           `json:"seq"`
	Tier   *int64          `json:"tier"`
	Month  string          `json:"month"`
	Record json.RawMessage `json:"record"`
	Proof  Proof           `json:"proof"`
}

// Recorded is the ledger record the core wrote for the sampling (packet.sample), written before the sample was served,
// with the record itself as the core stored it. It is after the checkpoint the proofs are against, so nothing in the
// document proves the core wrote it: the verifier checks the copy here is consistent with the draw, and compares it with
// a copy the caller got from the core itself (`clearance verify --sample-record`).
type Recorded struct {
	Seq    int64           `json:"seq"`
	Hash   string          `json:"hash"`
	Record json.RawMessage `json:"record"`
}

// Document is the sample as served and as `clearance verify --sample` reads it.
type Document struct {
	Schema        string        `json:"schema"`
	Method        string        `json:"method"`
	Packet        PacketRef     `json:"packet"`
	Delivery      string        `json:"delivery"`
	Recipient     string        `json:"recipient"`
	Params        Params        `json:"params"`
	EffectiveSeed string        `json:"effective_seed"`
	Checkpoint    Checkpoint    `json:"checkpoint"`
	Population    PopulationDoc `json:"population"`
	Strata        []Stratum     `json:"strata,omitempty"`
	Selected      []Item        `json:"selected"`
	Recorded      *Recorded     `json:"recorded,omitempty"`
}

// SHA256 is the document's content address: the canonical JSON of everything but Recorded (which names a record that
// holds this hash).
func (d Document) SHA256() (string, error) {
	d.Recorded = nil
	return CanonicalSHA256(d)
}

// HexID is the sample's id: sm- and the first 32 hex digits of its SHA-256.
func HexID(sha string) string {
	if len(sha) < 32 {
		return ""
	}
	return "sm-" + sha[:32]
}

// IsHex64 says whether s is 64 lowercase hex digits.
func IsHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == string(bytes.ToLower([]byte(s)))
}
