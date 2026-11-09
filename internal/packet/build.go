package packet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// MaxWindow is the longest window one packet speaks for.
const MaxWindow = 366 * 24 * time.Hour

// ProofEntry is the inclusion proof of one carried record in the witnessed checkpoint.
type ProofEntry struct {
	Seq      int64    `json:"seq"`
	Hash     string   `json:"hash"`      // the record's hash: the ledger entry
	LeafHash string   `json:"leaf_hash"` // RFC 6962 leaf hash of the entry
	Path     []string `json:"path"`      // the audit path, hex, leaf to root
	TreeSize int64    `json:"tree_size"`
}

// Result is a packet and everything beside it that goes in the directory.
type Result struct {
	Packet *Packet
	// Records are the stored records the packet carries in full, in seq order (no assurance: the bytes that were
	// hashed, plus "hash"), and Carried says why each is there.
	Records []Record
	Window  map[int64]bool
	// Proofs is one inclusion proof for each carried record under the checkpoint.
	Proofs []ProofEntry
	// Checkpoint, LogKeys and WitnessPolicy are the ledger material copied into the packet ("" when none).
	Checkpoint, LogKeys, WitnessPolicy []byte
	// Bundles are the Sigstore bundles of the changes' attestations by change id.
	Bundles  map[string][]byte
	Mappings []Mapping
}

// ErrNoMapping is returned for a mapping the build does not carry.
var ErrNoMapping = errors.New("packet: no such mapping")

func (p *Params) normalize() error {
	if p.Now.IsZero() {
		p.Now = time.Now()
	}
	p.Now = p.Now.UTC()
	if p.To.IsZero() || p.To.After(p.Now) {
		p.To = p.Now
	}
	p.To = p.To.UTC().Truncate(time.Second)
	if p.From.IsZero() {
		p.From = p.To.Add(-30 * 24 * time.Hour)
	}
	p.From = p.From.UTC().Truncate(time.Second)
	switch {
	case !p.From.Before(p.To):
		return errors.New("packet: from must be before to")
	case p.To.Sub(p.From) > MaxWindow:
		return errors.New("packet: the window is at most 366 days")
	}
	switch p.View {
	case "":
		p.View = ViewPacket
	case ViewPacket, ViewFreeze, ViewIncident:
	default:
		return fmt.Errorf("packet: view is %s, %s or %s", ViewPacket, ViewFreeze, ViewIncident)
	}
	return nil
}

var sectionsByView = map[string][]string{
	ViewPacket: {"header", "coverage_statement", "control_assertions", "changes", "human_cleared_changes", "ai_identities",
		"exceptions", "policy_changes", "verification", "acceptances"},
	ViewFreeze:   {"header", "coverage_statement", "changes", "exceptions", "acceptances", "verification"},
	ViewIncident: {"header", "coverage_statement", "changes", "ai_identities", "exceptions", "policy_changes", "acceptances", "verification"},
}

// Build reads the chain through r and makes the packet p asks for.
func Build(ctx context.Context, r store.Reader, p Params) (*Result, error) {
	if err := p.normalize(); err != nil {
		return nil, err
	}
	maps, err := SelectMappings(p.Mappings)
	if err != nil {
		return nil, err
	}
	c, err := readChain(ctx, r)
	if err != nil {
		return nil, err
	}
	ls, err := readLedger(ctx, r, c, p)
	if err != nil {
		return nil, err
	}
	b := &builder{p: p, c: c, ls: ls, r: r}
	return b.build(ctx, maps)
}

type builder struct {
	p  Params
	c  *chain
	ls *ledgerState
	r  store.Reader

	from, to string // ISO bounds, compared with a record's ts as text, as the api does
	inWin    map[int64]bool
	sel      []Record // the records the sections speak for: in the window, in the filter
	scopes   []string

	// assessments and resolutions by the seq they are about, latest wins
	assessed, resolved map[int64]Record
	changes            []Change
	byChange           map[string]*Change
	exceptions         []Exception
	statements         []ScopeState
	extra              map[int64]bool // records outside the window's range the sections read
	proofErr           error
}

func (b *builder) ts(r Record) string { return str(r, "ts") }

func (b *builder) inWindow(r Record) bool {
	t := b.ts(r)
	return t >= b.from && t < b.to
}

func isObserved(tool string) bool {
	for _, k := range evidence.ObservedKinds {
		if k == tool {
			return true
		}
	}
	return false
}

// place is the destination a record names: its cluster (or workspace) and environment.
func place(r Record) (cluster, env string) {
	d := obj(r, "destination")
	if w := obj(d, "workspace"); w != nil {
		return str(w, "backend") + "/" + str(w, "key") + "#" + str(w, "name"), str(w, "name")
	}
	cluster, env = str(d, "cluster"), str(d, "environment")
	if ch := obj(r, "change"); ch != nil {
		if cluster == "" {
			cluster = str(ch, "cluster")
		}
		if env == "" {
			env = str(ch, "env")
		}
	}
	if bg := obj(r, "breakglass"); bg != nil {
		if cluster == "" {
			cluster = str(bg, "cluster")
		}
		if env == "" {
			env = str(bg, "env")
		}
	}
	return
}

// gateMatch applies the view's app, env and cluster scoping to a gate record. A runtime record (no app, no
// destination) never matches a scoped view: it is not about that place.
func (b *builder) gateMatch(r Record) bool {
	f := b.p
	if f.App == "" && f.Env == "" && f.Cluster == "" {
		return true
	}
	cluster, env := place(r)
	app := str(r, "app")
	if app == "" {
		app = str(obj(r, "change"), "app")
	}
	if f.App != "" && app != f.App {
		return false
	}
	if f.Env != "" && env != f.Env {
		return false
	}
	if f.Cluster != "" && cluster != f.Cluster {
		return false
	}
	return true
}

func (b *builder) scopeWanted(sc string) bool {
	if len(b.p.Scopes) == 0 {
		return true
	}
	for _, s := range b.p.Scopes {
		if s == sc {
			return true
		}
	}
	return false
}

func (b *builder) build(ctx context.Context, maps []Mapping) (*Result, error) {
	p := b.p
	b.from, b.to = evidence.ISO(p.From), evidence.ISO(p.To)
	b.inWin, b.extra = map[int64]bool{}, map[int64]bool{}
	b.assessed, b.resolved = map[int64]Record{}, map[int64]Record{}
	scopeSeen := map[string]bool{}
	lo, hi := int64(-1), int64(-1)
	for _, r := range b.c.records {
		seq := seqOf(r)
		tool := str(r, "tool")
		if isObserved(tool) {
			if sc := str(r, "scope"); sc != "" && b.ts(r) < b.to {
				scopeSeen[sc] = true
			}
			if a, ok := observe.About(r); ok {
				m := b.assessed
				if tool == evidence.KindResolution {
					m = b.resolved
				}
				if tool == evidence.KindAssessment || tool == evidence.KindResolution {
					if old, have := m[a]; !have || seqOf(old) < seq {
						m[a] = r
					}
				}
			}
		}
		if !b.inWindow(r) {
			continue
		}
		b.inWin[seq] = true
		if lo < 0 {
			lo = seq
		}
		hi = seq
		// A record is in the packet's counts when it is in the filter: observation kinds by scope, the rest by place.
		if isObserved(tool) {
			if !b.scopeWanted(str(r, "scope")) {
				continue
			}
		} else if !b.gateMatch(r) {
			continue
		}
		b.sel = append(b.sel, r)
	}
	if len(p.Scopes) > 0 {
		b.scopes = append(b.scopes, p.Scopes...)
	} else {
		b.scopes = sortedKeys(scopeSeen)
	}
	sort.Strings(b.scopes)

	pk := &Packet{Schema: Schema}
	b.header(pk, lo, hi, maps)
	b.coverage(pk)
	b.changesSection(pk)
	b.humanCleared(pk)
	b.aiIdentities(pk)
	b.exceptionsSection(pk)
	b.policySection(pk)
	b.acceptances(pk)
	res := &Result{Packet: pk, Window: b.inWin, Mappings: maps, Bundles: map[string][]byte{}}
	pk.Assertions = b.evaluate(pk, maps)
	b.carry(ctx, res, lo, hi)
	b.verification(ctx, pk, res)
	b.trim(pk)
	if b.proofErr != nil {
		return nil, fmt.Errorf("packet: an inclusion proof does not verify: %w", b.proofErr)
	}
	return res, nil
}

func (b *builder) header(pk *Packet, lo, hi int64, maps []Mapping) {
	p := b.p
	h := Header{View: p.View, Title: p.Title, GeneratedAt: evidence.ISO(p.Now), Producer: "clearance " + p.Version,
		From: b.from, To: b.to, Scopes: b.scopes, Filter: Filter{App: p.App, Env: p.Env, Cluster: p.Cluster},
		Sections: sectionsByView[p.View],
		Chain:    ChainRef{Count: b.c.head.Count, Head: b.c.head.Head, Verified: true, FirstSeq: lo, LastSeq: hi, Window: len(b.inWin)}}
	if h.Scopes == nil {
		h.Scopes = []string{}
	}
	for _, m := range maps {
		h.Mappings = append(h.Mappings, m.Key())
	}
	pk.Header = h
}

// assurance of a record as the packet counts it.
func (b *builder) assurance(r Record) string { return b.ls.assurance(seqOf(r)) }

func (b *builder) coverage(pk *Packet) {
	cv := Coverage{Total: len(b.sel)}
	by := map[string]int{}
	ass := map[string]int{}
	mx := map[string]*MatrixRow{}
	order := append([]string(nil), evidence.Coverage...)
	for _, r := range b.sel {
		cov := str(r, "coverage")
		if cov == "" {
			cov = evidence.CoverageAuthorizedAndVerified
		}
		a := b.assurance(r)
		by[cov]++
		ass[a]++
		row := mx[cov]
		if row == nil {
			row = &MatrixRow{Coverage: cov}
			mx[cov] = row
			if !contains(order, cov) {
				order = append(order, cov)
			}
		}
		row.Total++
		switch a {
		case store.AssuranceCheckpointed:
			row.Checkpoint++
		case store.AssuranceRecorded:
			row.Recorded++
		default:
			row.NotRecorded++
		}
	}
	// Every coverage state and every assurance state is listed, at zero too: a state left out would read as "none".
	for _, s := range order {
		cv.ByCoverage = append(cv.ByCoverage, Count{s, by[s]})
		if mx[s] == nil {
			mx[s] = &MatrixRow{Coverage: s}
		}
		cv.Matrix = append(cv.Matrix, *mx[s])
	}
	for _, s := range evidence.Assurance {
		cv.ByAssurance = append(cv.ByAssurance, Count{s, ass[s]})
	}
	// Observation scopes.
	cv.Scopes = []ScopeState{}
	for _, sc := range b.scopes {
		in := observe.Input{Scope: sc, Window: observe.Window{From: b.p.From, To: b.p.To}}
		for _, r := range b.c.records {
			if str(r, "scope") != sc || !isObserved(str(r, "tool")) {
				continue
			}
			t := b.ts(r)
			switch str(r, "tool") {
			case evidence.KindObservation:
				if t >= b.from && t < b.to {
					in.Observations = append(in.Observations, r)
				}
			case evidence.KindAssessment:
				in.Assessments = append(in.Assessments, r)
			case evidence.KindResolution:
				in.Resolutions = append(in.Resolutions, r)
			case evidence.KindHealth:
				if t < b.to {
					in.Health = append(in.Health, r)
				}
			case evidence.KindAuditGap:
				if t >= b.from && t < b.to {
					in.Gaps = append(in.Gaps, r)
				}
			}
		}
		st := observe.Build(in, b.p.Now)
		ss := ScopeState{Scope: sc, Collector: len(st.Health.Sources) > 0, Statement: st, Text: st.Text}
		if !ss.Collector {
			ss.Text = fmt.Sprintf("Scope %s, %s to %s: blind. No collector has reported health for this scope, so nothing seen or unseen in it can be stated; "+
				"an empty list for it is not a clean one.", sc, st.From, st.To)
		}
		cv.Scopes = append(cv.Scopes, ss)
	}
	b.statements = cv.Scopes
	cv.WindowVerified = len(cv.Scopes) > 0
	for _, s := range cv.Scopes {
		if !s.Collector || s.Statement.State != observe.Healthy || s.Statement.Truncated {
			cv.WindowVerified = false
		}
	}
	cv.Degraded = b.degraded(cv.Scopes)
	cv.Text = coverageWords(cv, b)
	pk.Coverage = cv
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (b *builder) degraded(scopes []ScopeState) []Degraded {
	out := []Degraded{}
	for _, r := range b.sel {
		switch str(r, "tool") {
		case gate.KindDegraded:
			o := obj(r, "outage")
			from, to := str(o, "from"), str(o, "to")
			d := Degraded{Kind: "core-outage", From: from, To: to, Seq: ptr(seqOf(r)), Reason: "a provider reported what it did while the core was unreachable"}
			if f, e1 := time.Parse(time.RFC3339, from); e1 == nil {
				if t, e2 := time.Parse(time.RFC3339, to); e2 == nil {
					d.Seconds = int64(t.Sub(f).Seconds())
				}
			}
			out = append(out, d)
		case gate.ToolBreakglassClose:
			w := obj(r, "window")
			bg := obj(r, "breakglass")
			d := Degraded{Kind: "break-glass", From: str(w, "from"), To: str(w, "to"), Seq: ptr(seqOf(r)),
				Reason: "break-glass " + str(bg, "id") + " on " + str(r, "target") + ": changes in it were not cleared first"}
			if f, e1 := time.Parse(time.RFC3339, d.From); e1 == nil {
				if t, e2 := time.Parse(time.RFC3339, d.To); e2 == nil {
					d.Seconds = int64(t.Sub(f).Seconds())
				}
			}
			out = append(out, d)
		}
	}
	for _, s := range scopes {
		for _, g := range s.Statement.Blind.Segments {
			kind := "feed-blind"
			if g.State == observe.Degraded {
				kind = "feed-degraded"
			}
			out = append(out, Degraded{Kind: kind, Scope: s.Scope, Source: g.Source, From: g.From, To: g.To, Seconds: g.Seconds,
				Reason: g.Reason, Seq: g.Seq})
		}
	}
	return out
}

func coverageWords(cv Coverage, b *builder) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d records in the window", cv.Total)
	for _, c := range cv.ByCoverage {
		fmt.Fprintf(&sb, "; %s %d", c.State, c.Count)
	}
	sb.WriteString(". ")
	switch {
	case len(cv.Scopes) == 0:
		sb.WriteString("No observation scope was named or seen: no collector reported, so observation coverage is blind for this window.")
	case cv.WindowVerified:
		sb.WriteString("Every observed scope had a healthy feed for the whole window.")
	default:
		var bad []string
		for _, s := range cv.Scopes {
			if !s.Collector || s.Statement.State != observe.Healthy || s.Statement.Truncated {
				state := s.Statement.State
				if !s.Collector {
					state = observe.Blind + " (no collector)"
				}
				bad = append(bad, s.Scope+" "+state)
			}
		}
		sb.WriteString("Coverage was NOT verified for this window: " + strings.Join(bad, ", ") + ".")
	}
	return sb.String()
}

// ---- changes ---------------------------------------------------------------------------------------------------

var changeTools = map[string]bool{"deploy.request": true, "deploy.clear": true, "deploy.deny": true, "deploy.expire": true,
	"deploy.revoke": true, "deploy.outcome": true, "deploy.exception": true, "deploy.attestation": true, "deploy.answer": true,
	"deploy.go": true, gate.KindDegraded: true}

func changeKey(r Record) string {
	ch := obj(r, "change")
	if id := str(ch, "id"); id != "" {
		return id
	}
	if t := str(ch, "tree"); t != "" {
		return fmt.Sprintf("%s/%s@%s", str(r, "app"), str(ch, "env"), cut(t, 12))
	}
	return fmt.Sprintf("seq-%d", seqOf(r))
}

func subjectOf(r Record) *Subject {
	s := obj(r, "subject")
	if s == nil {
		return nil
	}
	dg := obj(s, "digests")
	return &Subject{Kind: str(s, "kind"), Name: str(s, "name"), SHA256: str(dg, "sha256"), GitCommit: str(dg, "gitCommit"), VariableSet: str(dg, "variableSet")}
}

func reporterOf(r Record) Reporter {
	p := obj(r, "provider")
	rep := Reporter{Name: str(p, "name"), Version: str(p, "version"), Conformance: str(p, "conformance")}
	return rep
}

func healthOf(v any) string {
	switch h := v.(type) {
	case string:
		return h
	case map[string]any:
		for _, k := range []string{"state", "status", "result"} {
			if s := str(h, k); s != "" {
				return s
			}
		}
	}
	return ""
}

func (b *builder) changesSection(pk *Packet) {
	b.byChange = map[string]*Change{}
	var order []string
	for _, r := range b.sel {
		tool := str(r, "tool")
		if !changeTools[tool] || str(r, "boundary") != "deployment" {
			continue
		}
		if (tool == gate.KindException || tool == gate.KindDegraded) && str(obj(r, "change"), "id") == "" {
			continue // a report about no registered change is an exception row, not a change
		}
		key := changeKey(r)
		c := b.byChange[key]
		if c == nil {
			cluster, env := place(r)
			ch := obj(r, "change")
			if env == "" {
				env = str(ch, "env")
			}
			c = &Change{ID: key, App: str(r, "app"), Env: env, Place: cluster, State: "holding", FirstTS: b.ts(r)}
			if c.App == "" {
				c.App = str(ch, "app")
			}
			b.byChange[key] = c
			order = append(order, key)
		}
		c.Seqs = append(c.Seqs, seqOf(r))
		if c.Subject == nil {
			c.Subject = subjectOf(r)
		}
		if t := i64p(obj(r, "change")["tier"]); t != nil {
			c.Tier = t
		}
		if oc := opClass(r); len(oc) > 0 {
			c.OperationalClass, c.ClassMapping = oc, str(r, "class_mapping")
		}
		if a := str(r, "agent"); a != "" && c.Agent == "" {
			c.Agent = a
		}
		switch tool {
		case "deploy.request":
			c.Request = ptr(seqOf(r))
			if str(r, "decision") == "deny" {
				c.State = "denied"
			}
		case "deploy.clear":
			c.Clear, c.State = ptr(seqOf(r)), "cleared"
			if cb := str(r, "cleared_by"); cb != "" {
				c.ClearedBy = cb
			}
			c.ClearVerified = verifiedField(r, "decision") && verifiedField(r, "tier")
		case "deploy.deny":
			c.State = "denied"
		case "deploy.expire", "deploy.revoke":
			// A token revoked or lapsed after the change was applied does not undo what the outcome says.
			if c.State == "holding" || c.State == "cleared" {
				c.State = map[string]string{"deploy.expire": "expired", "deploy.revoke": "revoked"}[tool]
			}
		case gate.KindException:
			c.State = "exception"
			c.Exceptions = append(c.Exceptions, seqOf(r))
		case "deploy.outcome":
			o := b.outcomeOf(r)
			fail := o.Applied != nil && !*o.Applied || o.Error != "" || failedHealth(o.Health)
			if o.Rollback == nil && c.Outcome != nil {
				o.Rollback = c.Outcome.Rollback // a rollback reported earlier stands until another says otherwise
			}
			c.Outcome = o
			c.Failed = c.Failed || fail // once failed, always listed as failed, whatever came after
			switch {
			case fail:
				c.State = "failed"
			case o.Applied != nil && *o.Applied && c.Failed:
				c.State = "rolled-back"
			case o.Applied != nil && *o.Applied:
				c.State = "applied"
			}
			if c.Subject == nil {
				c.Subject = subjectOf(r)
			}
		case "deploy.attestation":
			at := obj(r, "attestation")
			c.Attestation = &Attestation{Seq: seqOf(r), Digest: str(at, "digest"), Backend: str(at, "backend"), RekorLogIndex: i64p(at["rekor_log_index"])}
		}
	}
	pk.Changes = []Change{}
	for _, k := range order {
		pk.Changes = append(pk.Changes, *b.byChange[k])
		b.changes = append(b.changes, *b.byChange[k])
	}
	for i := range pk.Changes {
		b.byChange[pk.Changes[i].ID] = &pk.Changes[i]
	}
}

func failedHealth(h string) bool {
	switch strings.ToLower(h) {
	case "degraded", "failed", "unhealthy", "missing", "error", "fail":
		return true
	}
	return false
}

func (b *builder) outcomeOf(r Record) *Outcome {
	oc := obj(r, "outcome")
	o := &Outcome{Seq: seqOf(r), TS: b.ts(r), Applied: boolp(oc["applied"]), Reporter: reporterOf(r), Health: healthOf(oc["health"]),
		Error: short(oc["error"], 200)}
	if m := boolp(r["matched"]); m != nil && verifiedField(r, "matched") {
		o.Matched, o.Verified = m, true
	} else if m := boolp(oc["matched"]); m != nil {
		o.Matched = m
	}
	if ds, ok := oc["digests"].(map[string]any); ok {
		for _, k := range sortedKeys(ds) {
			if s, ok := ds[k].(string); ok {
				o.Digest = s
				break
			}
		}
	}
	if o.Digest == "" {
		o.Digest = str(oc, "digest")
	}
	if rb := obj(oc, "rollback"); rb != nil {
		o.Rollback = &Rollback{Available: boolp(rb["available"]), Used: boolp(rb["used"]), To: str(rb, "to")}
	}
	if o.Reporter.Name == "" {
		o.Reporter.Name = "clearance"
	}
	return o
}

// ---- human-cleared ---------------------------------------------------------------------------------------------

func (b *builder) humanCleared(pk *Packet) {
	pk.HumanCleared = []HumanChange{}
	for _, r := range b.sel {
		if str(r, "tool") != "deploy.clear" {
			continue
		}
		l, _ := r["approvals"].([]any)
		if len(l) == 0 {
			continue
		}
		hc := HumanChange{Change: changeKey(r), App: str(r, "app"), Env: str(obj(r, "change"), "env"), Tier: i64p(obj(r, "change")["tier"]), ClearSeq: seqOf(r)}
		var as []token.Approval
		for _, x := range l {
			m, _ := x.(map[string]any)
			hc.Approvers = append(hc.Approvers, Approver{Person: str(m, "person"), Sub: str(m, "sub"), Iss: str(m, "iss"), Role: str(m, "role"),
				Via: str(m, "via"), At: str(m, "at"), Kind: str(m, "kind")})
			as = append(as, token.Approval{Sub: str(m, "sub"), Iss: str(m, "iss"), Person: str(m, "person"), Via: str(m, "via"),
				Role: str(m, "role"), At: str(m, "at"), Kind: str(m, "kind")})
		}
		hc.Statement = token.ApproversStatement(as)
		hc.Printed = hc.Statement
		if hc.Printed == "" {
			hc.Printed = "approvers: not provable from the records (an approval has no recorded kind, or two share a subject)"
		}
		pk.HumanCleared = append(pk.HumanCleared, hc)
	}
}

// ---- AI identities ---------------------------------------------------------------------------------------------

func (b *builder) aiIdentities(pk *Packet) {
	type acc struct {
		AIIdentity
	}
	m := map[string]*acc{}
	for _, r := range b.sel {
		ag := str(r, "agent")
		if ag == "" || isObserved(str(r, "tool")) {
			continue
		}
		a := m[ag]
		if a == nil {
			a = &acc{AIIdentity{Agent: ag, FirstTS: b.ts(r), LastTS: b.ts(r)}}
			m[ag] = a
		}
		a.Records++
		switch str(r, "decision") {
		case "allow":
			a.Allowed++
		case "deny":
			a.Denied++
		}
		a.Principals = addUnique(a.Principals, str(r, "principal"))
		a.ModelVersions = addUnique(a.ModelVersions, str(r, "model_version"))
		if str(r, "boundary") == "deployment" {
			a.Changes = addUnique(a.Changes, changeKey(r))
		}
		a.Provenance = addUnique(a.Provenance, str(obj(r, "provenance"), "level"))
		if t := b.ts(r); t < a.FirstTS {
			a.FirstTS = t
		} else if t > a.LastTS {
			a.LastTS = t
		}
	}
	pk.AIIdentities = []AIIdentity{}
	for _, k := range sortedKeys(m) {
		pk.AIIdentities = append(pk.AIIdentities, m[k].AIIdentity)
	}
}

// ---- policy ----------------------------------------------------------------------------------------------------

func (b *builder) policySection(pk *Packet) {
	pk.Policy = []PolicyEvent{}
	lastRef, lastVer := "", ""
	for _, r := range b.sel {
		tool := str(r, "tool")
		switch {
		case strings.HasPrefix(tool, "definition."):
			pk.Policy = append(pk.Policy, PolicyEvent{Seq: seqOf(r), TS: b.ts(r), Kind: tool, Name: str(obj(r, "subject"), "name"),
				Digest: str(obj(r, "subject"), "sha256"), Detail: short(r["result"], 160)})
		case str(r, "boundary") == "deployment":
			pol := obj(r, "policy")
			if pol == nil {
				continue
			}
			ref, ver := str(pol, "ref"), str(pol, "version")
			if ref == "" && ver == "" || ref == lastRef && ver == lastVer {
				continue
			}
			k := "policy-in-force"
			pk.Policy = append(pk.Policy, PolicyEvent{Seq: seqOf(r), TS: b.ts(r), Kind: k, Ref: ref, Version: ver,
				Detail: "first record under this policy in the window"})
			lastRef, lastVer = ref, ver
		}
	}
}

// ---- acceptances -----------------------------------------------------------------------------------------------

// NoReceipts is what the Acceptances section says until package P-1 records receipts.
const NoReceipts = "No acceptance receipts have been recorded for this packet or for earlier ones. Receipts are the signed " +
	"acceptances assurance recipients return (package P-1); none exist yet, and nothing here is inferred from the chain."

func (b *builder) acceptances(pk *Packet) {
	pk.Acceptances = Acceptances{Status: "none-recorded", Statement: NoReceipts, Receipts: []Receipt{}}
	if len(b.p.Receipts) > 0 {
		pk.Acceptances = Acceptances{Status: "recorded", Receipts: b.p.Receipts,
			Statement: fmt.Sprintf("%d acceptance receipts recorded for earlier packets.", len(b.p.Receipts))}
	}
}

// trim drops the sections a view does not carry (the coverage statement and the verification never go).
func (b *builder) timeline(pk *Packet) {
	if pk.Header.View != ViewIncident {
		return
	}
	for _, r := range b.sel {
		tool := str(r, "tool")
		if !changeTools[tool] && !strings.HasPrefix(tool, "breakglass.") && !isObserved(tool) {
			continue
		}
		if tool == evidence.KindHealth {
			continue
		}
		d := short(r["result"], 120)
		if d == "" {
			d = strings.TrimSpace(str(r, "app") + " " + str(r, "target"))
		}
		pk.Timeline = append(pk.Timeline, TimelineEntry{TS: b.ts(r), Seq: seqOf(r), Kind: tool, Detail: d})
	}
	sort.SliceStable(pk.Timeline, func(i, j int) bool {
		if pk.Timeline[i].TS != pk.Timeline[j].TS {
			return pk.Timeline[i].TS < pk.Timeline[j].TS
		}
		return pk.Timeline[i].Seq < pk.Timeline[j].Seq
	})
}

func (b *builder) trim(pk *Packet) {
	b.timeline(pk)
	keep := map[string]bool{}
	for _, s := range pk.Header.Sections {
		keep[s] = true
	}
	if !keep["control_assertions"] {
		pk.Assertions = []Control{}
	}
	if !keep["human_cleared_changes"] {
		pk.HumanCleared = []HumanChange{}
	}
	if !keep["ai_identities"] {
		pk.AIIdentities = []AIIdentity{}
	}
	if !keep["policy_changes"] {
		pk.Policy = []PolicyEvent{}
	}
}

var _ = json.Number("")
