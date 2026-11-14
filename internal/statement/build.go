package statement

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/receipt"
)

//go:embed data/questionnaire.json
var questionnaireJSON []byte

// QuestionnaireJSON is the mapping data as shipped (data/questionnaire.json), beside the control mappings: a framework
// or questionnaire line is data, and adding one is editing this file.
func QuestionnaireJSON() []byte { return slices.Clone(questionnaireJSON) }

type questionnaire struct {
	Version  string         `json:"version"`
	Standard []MappingEntry `json:"standard"`
	Insurer  []MappingEntry `json:"insurer"`
}

func mappingFor(profile string) (string, []MappingEntry, error) {
	var q questionnaire
	if err := json.Unmarshal(questionnaireJSON, &q); err != nil {
		return "", nil, fmt.Errorf("the questionnaire mapping data does not parse: %w", err)
	}
	if profile == ProfileInsurer {
		return q.Version, q.Insurer, nil
	}
	return q.Version, q.Standard, nil
}

// ExceptionClasses are the packet's exception classes, in print order (internal/packet.ExceptionClasses). Every one is
// always listed, even at zero.
var ExceptionClasses = []string{"out-of-band", "break-glass", "attempted-refused", "monitoring-protection", "degraded-mode-auto-clear",
	"invalidated-token", "provider-correlation-failure"}

// critical is the tier a change needs two independent approvers at: tier 3 holds for one owner and one outside person
// (docs/gate.md).
const critical = 3

// view is the part of packet.json a statement is derived from: its own small copy of the shape, tolerant of added fields,
// as the verifier's packetDoc is.
type view struct {
	Schema string `json:"schema"`
	Header struct {
		From   string   `json:"from"`
		To     string   `json:"to"`
		Scopes []string `json:"observation_scopes"`
	} `json:"header"`
	Coverage struct {
		Total      int     `json:"total_records"`
		ByCoverage []Count `json:"by_coverage"`
		Degraded   []struct {
			Kind    string `json:"kind"`
			Scope   string `json:"scope"`
			From    string `json:"from"`
			To      string `json:"to"`
			Seconds int64  `json:"seconds"`
		} `json:"degraded_windows"`
		Scopes []struct {
			Scope     string `json:"scope"`
			Collector bool   `json:"collector"`
			Statement struct {
				State   string `json:"state"`
				Clean   bool   `json:"clean"`
				Cleared struct {
					Count int `json:"count"`
				} `json:"cleared_and_verified"`
				Seen struct {
					Count int `json:"count"`
				} `json:"seen_not_cleared"`
				Blind struct {
					Seconds int64 `json:"seconds"`
				} `json:"could_not_see"`
			} `json:"statement"`
		} `json:"observation_health"`
		WindowVerified bool `json:"window_verified"`
	} `json:"coverage_statement"`
	Changes []struct {
		ID    string `json:"id"`
		Tier  *int64 `json:"tier"`
		Clear *int64 `json:"clear_seq"`
		Agent string `json:"agent"`
	} `json:"changes"`
	Human []struct {
		Change    string `json:"change"`
		Tier      *int64 `json:"tier"`
		Approvers []struct {
			Sub  string `json:"sub"`
			Iss  string `json:"iss"`
			Kind string `json:"kind"`
		} `json:"approvers"`
	} `json:"human_cleared_changes"`
	Exceptions struct {
		ByClass []Count `json:"by_class"`
		Rows    []struct {
			Class      string `json:"class"`
			Seq        int64  `json:"seq"`
			Resolution string `json:"resolution"`
		} `json:"rows"`
	} `json:"exceptions"`
	Acceptances struct {
		Receipts []struct {
			Verdict string `json:"verdict"`
		} `json:"receipts"`
	} `json:"acceptances"`
	Verification struct {
		Ledger struct {
			State           string `json:"state"`
			Origin          string `json:"origin"`
			Size            int64  `json:"size"`
			Root            string `json:"root"`
			Checkpointed    int    `json:"records_checkpointed"`
			NotCheckpointed int    `json:"records_not_checkpointed"`
		} `json:"ledger"`
	} `json:"verification"`
}

// Derived is everything a statement says that comes from the packet, as Summarize computes it.
type Derived struct {
	Period     Period
	Observed   int
	Checkpoint *CheckpointRef
	Cited      Cited
	Summary    Summary
	Insurer    *Insurer
	// ExceptionSeqs are the records the exception rows cite: not in a statement (they are recipient detail), but what the
	// verifier checks the packet carries.
	ExceptionSeqs []int64
}

// Summarize derives a statement's counts from a packet's packet.json and records: the one function the issuer builds a
// statement with and the verifier recomputes it with. Counts that the packet states are used only after they are
// compared with each other (the by-class list with its rows); a packet that disagrees with itself is an error, not a
// statement.
func Summarize(packetJSON, recordsJSONL []byte, profile string) (*Derived, error) {
	if len(packetJSON) > MaxPacketJSON {
		return nil, errors.New("packet.json is too large")
	}
	var p view
	if err := json.NewDecoder(bytes.NewReader(packetJSON)).Decode(&p); err != nil {
		return nil, errors.New("packet.json is not readable")
	}
	if p.Schema != "clearance.packet/v1" {
		return nil, fmt.Errorf("packet.json schema is %q", p.Schema)
	}
	from, e1 := time.Parse(time.RFC3339, p.Header.From)
	to, e2 := time.Parse(time.RFC3339, p.Header.To)
	if e1 != nil || e2 != nil || !to.After(from) {
		return nil, errors.New("the packet's period is not two RFC 3339 times")
	}
	if len(p.Coverage.Scopes) > MaxScopes {
		return nil, fmt.Errorf("the packet has more than %d observed scopes", MaxScopes)
	}
	recs, err := RecordsOf(recordsJSONL)
	if err != nil {
		return nil, err
	}
	d := &Derived{Period: Period{From: p.Header.From, To: p.Header.To}, Observed: len(p.Coverage.Scopes), Cited: CitedOf(recs)}
	l := p.Verification.Ledger
	if l.State == "checkpointed" {
		d.Checkpoint = &CheckpointRef{OriginSHA256: canon.SHA256Hex([]byte(l.Origin)), Size: l.Size, Root: l.Root}
	}
	s := &d.Summary
	s.TotalRecords = p.Coverage.Total
	byCov := map[string]int{}
	for _, c := range p.Coverage.ByCoverage {
		byCov[c.State] += c.Count
	}
	for _, st := range coverageStates() {
		s.ByCoverage = append(s.ByCoverage, Count{State: st, Count: byCov[st]})
		delete(byCov, st)
	}
	if len(byCov) > 0 {
		return nil, errors.New("the packet counts a coverage state this statement does not know: a state left out would read as none")
	}
	s.Ledger = Ledger{State: l.State, Checkpointed: l.Checkpointed, NotCheckpointed: l.NotCheckpointed}

	// Exceptions: every class listed, tallied from the rows and checked against the packet's own by-class list.
	tally := map[string]int{}
	for _, r := range p.Exceptions.Rows {
		if !slices.Contains(ExceptionClasses, r.Class) {
			return nil, errors.New("the packet has an exception class this statement does not know")
		}
		tally[r.Class]++
		d.ExceptionSeqs = append(d.ExceptionSeqs, r.Seq)
	}
	stated := map[string]int{}
	for _, c := range p.Exceptions.ByClass {
		stated[c.State] += c.Count
	}
	for c := range stated {
		if !slices.Contains(ExceptionClasses, c) {
			return nil, errors.New("the packet's exceptions by class name a class this statement does not know")
		}
	}
	var unresolved []Unresolved
	for _, c := range ExceptionClasses {
		if stated[c] != tally[c] {
			return nil, errors.New("the packet's exceptions by class are not its exception rows")
		}
		s.Exceptions.ByClass = append(s.Exceptions.ByClass, Count{State: c, Count: tally[c]})
	}
	for _, r := range p.Exceptions.Rows {
		if disp := dispositionOf(r.Resolution); disp != "" {
			unresolved = append(unresolved, Unresolved{Class: r.Class, Disposition: disp})
		}
	}
	s.Exceptions.Total, s.Exceptions.Unresolved = len(p.Exceptions.Rows), len(unresolved)

	// Health: by position. The scope names stay in the packet.
	h := &s.Health
	h.WindowVerified = p.Coverage.WindowVerified
	h.Scopes = []ScopeHealth{}
	index := map[string]int{}
	period := to.Sub(from).Seconds()
	var tele []TelemetryShare
	for i, sc := range p.Coverage.Scopes {
		index[sc.Scope] = i + 1
		st := sc.Statement
		state := st.State
		if !sc.Collector {
			state = "blind"
		}
		h.Scopes = append(h.Scopes, ScopeHealth{Index: i + 1, Collector: sc.Collector, State: state, Clean: st.Clean && sc.Collector,
			Cleared: st.Cleared.Count, Seen: st.Seen.Count, BlindSeconds: st.Blind.Seconds})
		h.BlindSeconds += st.Blind.Seconds
		share := 0
		if sc.Collector && period > 0 {
			vis := max(0, period-float64(st.Blind.Seconds))
			share = int(vis * 1000 / period)
		}
		tele = append(tele, TelemetryShare{Index: i + 1, PerMille: min(share, 1000)})
	}
	h.BlindWindows = []BlindWindow{}
	for _, w := range p.Coverage.Degraded {
		if len(h.BlindWindows) >= MaxBlindWindows {
			h.BlindWindowsCut = true
			break
		}
		h.BlindWindows = append(h.BlindWindows, BlindWindow{Kind: w.Kind, Index: index[w.Scope], From: w.From, To: w.To, Seconds: w.Seconds})
	}

	// Receipts, by verdict, every verdict listed.
	rv := map[string]int{}
	for _, r := range p.Acceptances.Receipts {
		rv[r.Verdict]++
	}
	for _, v := range receipt.Verdicts {
		s.Receipts.ByVerdict = append(s.Receipts.ByVerdict, Count{State: v, Count: rv[v]})
		delete(rv, v)
	}
	if len(rv) > 0 {
		return nil, errors.New("the packet carries a receipt with a verdict this statement does not know")
	}
	s.Receipts.Count = len(p.Acceptances.Receipts)

	if profile == ProfileInsurer {
		d.Insurer = insurerOf(&p, unresolved, tele)
	}
	return d, nil
}

// dispositionOf is the recorded disposition of an exception that is still unresolved, "" for one that is resolved. Only
// the packet's own fixed phrases map to a word: free text never reaches a statement.
func dispositionOf(resolution string) string {
	switch {
	case resolution == "" || resolution == "none recorded":
		return "none-recorded"
	case resolution == "still-live":
		return "still-live"
	case strings.HasPrefix(resolution, "token revoked; no later clearance"):
		return "revoked-not-recleared"
	}
	return ""
}

func insurerOf(p *view, unresolved []Unresolved, tele []TelemetryShare) *Insurer {
	in := &Insurer{Unresolved: unresolved, Telemetry: tele}
	if in.Unresolved == nil {
		in.Unresolved = []Unresolved{}
	}
	if in.Telemetry == nil {
		in.Telemetry = []TelemetryShare{}
	}
	crit := map[string]bool{}
	for _, c := range p.Changes {
		if c.Tier != nil && *c.Tier == critical && c.Clear != nil {
			crit[c.ID] = true
		}
		if c.Agent != "" {
			in.AgentChanges++
		}
	}
	in.Changes = len(p.Changes)
	in.CriticalChanges = len(crit)
	seen := map[string]bool{}
	for _, h := range p.Human {
		if h.Tier == nil || *h.Tier != critical || !crit[h.Change] || seen[h.Change] {
			continue
		}
		people := map[string]bool{}
		ok := len(h.Approvers) >= 2
		for _, a := range h.Approvers {
			ok = ok && a.Kind == "person"
			people[a.Iss+"\x00"+a.Sub] = true
		}
		if ok && len(people) == len(h.Approvers) {
			seen[h.Change] = true
			in.WithTwoApprovers++
		}
	}
	if in.CriticalChanges > 0 {
		v := in.WithTwoApprovers * 1000 / in.CriticalChanges
		in.SharePerMille = &v
	}
	if in.Changes > 0 {
		v := in.AgentChanges * 1000 / in.Changes
		in.AgentSharePerMille = &v
	}
	return in
}

// Input is what Build is given.
type Input struct {
	ID, Issuer, IssuedAt                           string
	Profile, ScopeLabel, PolicyVersion, Supersedes string
	IndependentWitnesses                           []string
	PacketID, PacketDigest                         string
	PacketJSON, RecordsJSONL                       []byte
}

// Build cuts a statement from a packet. It refuses a statement the invariants forbid: the scope is the only choice, so
// there is no input that leaves a total, a coverage state, an exception class or the unreconciled count out, and a
// period the feeds could not see is printed whatever the subscriber would prefer.
func Build(in Input) (*Document, error) {
	if in.Profile == "" {
		in.Profile = ProfileStandard
	}
	if in.Profile != ProfileStandard && in.Profile != ProfileInsurer {
		return nil, fmt.Errorf("profile is %s or %s", ProfileStandard, ProfileInsurer)
	}
	if !ValidLabel(in.ScopeLabel) {
		return nil, fmt.Errorf("scope is 1 to %d letters, digits, spaces and . , : / ( ) & + -", MaxLabel)
	}
	if !ValidPolicyVersion(in.PolicyVersion) {
		return nil, fmt.Errorf("policy_version is 1 to %d letters, digits, dots, underscores and hyphens", MaxPolicyVersion)
	}
	der, err := Summarize(in.PacketJSON, in.RecordsJSONL, in.Profile)
	if err != nil {
		return nil, err
	}
	ver, mp, err := mappingFor(in.Profile)
	if err != nil {
		return nil, err
	}
	own := slices.Clone(in.IndependentWitnesses)
	slices.Sort(own)
	own = slices.Compact(own)
	if own == nil {
		own = []string{}
	}
	d := &Document{Type: Schema, ID: in.ID, Issuer: in.Issuer, IssuedAt: in.IssuedAt, Profile: in.Profile, Period: der.Period,
		Scope: Scope{Label: in.ScopeLabel, Observed: der.Observed}, PolicyVersion: in.PolicyVersion,
		Packet: PacketRef{ID: in.PacketID, Digest: in.PacketDigest}, Checkpoint: der.Checkpoint, Cited: der.Cited, Summary: der.Summary,
		Insurer: der.Insurer, Witness: Witness{Independent: own}, Mapping: mp, MappingVer: ver, Supersedes: in.Supersedes}
	if err := d.Check(); err != nil {
		return nil, err
	}
	return d, nil
}

// SameDerived reports what in d no longer matches the packet it names: "" when everything the packet derives is the
// same. It is the verifier's recomputation (check 5 and 6), by the issuer's own function.
func SameDerived(d *Document, der *Derived) []string {
	var bad []string
	eq := func(what string, a, b any) {
		x, _ := canonOf(a)
		y, _ := canonOf(b)
		if !bytes.Equal(x, y) {
			bad = append(bad, what)
		}
	}
	eq("period", d.Period, der.Period)
	eq("observed scopes", d.Scope.Observed, der.Observed)
	eq("checkpoint", d.Checkpoint, der.Checkpoint)
	eq("cited records", d.Cited, der.Cited)
	eq("total records", d.Summary.TotalRecords, der.Summary.TotalRecords)
	eq("counts by coverage state", d.Summary.ByCoverage, der.Summary.ByCoverage)
	eq("exceptions by class and unresolved", d.Summary.Exceptions, der.Summary.Exceptions)
	eq("observation health", d.Summary.Health, der.Summary.Health)
	eq("the packet's verification result", d.Summary.Ledger, der.Summary.Ledger)
	eq("receipts", d.Summary.Receipts, der.Summary.Receipts)
	eq("insurer figures", d.Insurer, der.Insurer)
	return bad
}
