package observe

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
)

// Record is a stored evidence record as read.
type Record = map[string]any

// Window is the period a coverage statement speaks for, [From, To).
type Window struct{ From, To time.Time }

// Segment is a stretch of a window one source was in one state.
type Segment struct {
	Source  string `json:"source"`
	State   string `json:"state"`
	From    string `json:"from"`
	To      string `json:"to"`
	Seconds int64  `json:"seconds"`
	// Reason: reported (a health record says so), stale (no health record came when one was due) or never-seen (the
	// first health record is later than the window's start, or there is none).
	Reason string `json:"reason"`
	// Seq is the health record behind a reported segment, or the last one before a stale one (null: none).
	Seq *int64 `json:"seq"`
}

// SourceHealth is one source's health at the end of the window.
type SourceHealth struct {
	Source string `json:"source"`
	// State is the worst state the source was in at any moment of the window: healthy only if it was healthy all through.
	State string `json:"state"`
	// Now is the state at the window's end: the last record's, or blind once it is stale.
	Now      string   `json:"now"`
	LastSeq  *int64   `json:"last_seq"`
	LastTS   *string  `json:"last_ts"`
	Stale    bool     `json:"stale"`
	Failed   []string `json:"failed_checks"`
	Blind    int64    `json:"blind_seconds"`
	Degraded int64    `json:"degraded_seconds"`
}

// Item is one observation in the statement.
type Item struct {
	Seq        int64   `json:"seq"`
	TS         string  `json:"ts"`
	Source     string  `json:"source"`
	API        string  `json:"api,omitempty"`
	Resource   string  `json:"resource,omitempty"`
	Succeeded  *bool   `json:"succeeded,omitempty"`
	Coverage   string  `json:"coverage"`
	Tier       *int64  `json:"tier"`
	Assessment *int64  `json:"assessment"`
	Resolution *string `json:"resolution"`
	Cause      *string `json:"cause"`
	Monitoring bool    `json:"monitoring_protection,omitempty"`
	// CompletenessSupported: the observation claimed completeness and its feed's health supported it when it arrived.
	CompletenessSupported *bool `json:"completeness_supported,omitempty"`
}

// Part is one of the statement's first two parts.
type Part struct {
	Count      int            `json:"count"`
	ByCoverage map[string]int `json:"by_coverage"`
	Items      []Item         `json:"items"`
	// Truncated: Items is the first MaxItems of Count.
	Truncated bool `json:"truncated"`
}

// Statement is what a window of a scope can say: what was cleared and verified, what was seen and not cleared, what
// could not be seen, and the health of the feeds the other two rest on. Clean is true only when nothing was seen
// uncleared AND every feed was healthy for the whole window: a window with no healthy health record is never clean.
type Statement struct {
	Scope string `json:"scope"`
	From  string `json:"from"`
	To    string `json:"to"`
	// State is the worst state of any source in the window: healthy, degraded or blind (blind when no source has a
	// health record at all).
	State     string      `json:"state"`
	Clean     bool        `json:"clean"`
	Cleared   Part        `json:"cleared_and_verified"`
	Seen      Part        `json:"seen_not_cleared"`
	Blind     CouldNotSee `json:"could_not_see"`
	Health    Health      `json:"health"`
	Truncated bool        `json:"truncated"`
	// Text is the statement in words, the form the packet prints.
	Text string `json:"text"`
}

// CouldNotSee is the third part: the stretches no feed was healthy for, and the audit gaps recorded.
type CouldNotSee struct {
	Seconds  int64     `json:"seconds"`
	Segments []Segment `json:"segments"`
	Gaps     []Gap     `json:"audit_gaps"`
}

// Gap is an observation.audit-gap record in the window.
type Gap struct {
	Seq    int64  `json:"seq"`
	TS     string `json:"ts"`
	Source string `json:"source"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}

// Health is the health summary.
type Health struct {
	Sources []SourceHealth `json:"sources"`
}

// MaxItems caps each part's Items.
const MaxItems = 200

// Input is the records a statement is built from: the scope's observation-kind records (any order). Health must
// hold, per source, the health records in the window and the last one before it.
type Input struct {
	Scope        string
	Window       Window
	Observations []Record
	Assessments  []Record
	Resolutions  []Record
	Health       []Record
	Gaps         []Record
	Truncated    bool
}

func seqOf(r Record) int64 {
	switch n := r["seq"].(type) {
	case json.Number:
		i, _ := n.Int64()
		return i
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return -1
}

func intOf(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}

func sub(r Record, k string) map[string]any { m, _ := r[k].(map[string]any); return m }
func s(m map[string]any, k string) string   { v, _ := m[k].(string); return v }

func tsOf(r Record) time.Time {
	t, _ := time.Parse(time.RFC3339, s(r, "ts"))
	return t
}

func iso(t time.Time) string { return evidence.ISO(t) }

type hrec struct {
	seq      int64
	ts       time.Time
	state    string
	interval time.Duration
	failed   []string
}

func hrecs(rs []Record) map[string][]hrec {
	out := map[string][]hrec{}
	for _, r := range rs {
		h := sub(r, "health")
		src := s(sub(r, "source"), "name")
		if h == nil || src == "" {
			continue
		}
		iv := DefaultCadence
		if n, ok := intOf(h["interval_seconds"]); ok && n > 0 {
			iv = time.Duration(n) * time.Second
		}
		x := hrec{seq: seqOf(r), ts: tsOf(r), state: s(h, "state"), interval: iv}
		if cs, ok := h["checks"].([]any); ok {
			for _, c := range cs {
				if m, ok := c.(map[string]any); ok && m["ok"] == false {
					x.failed = append(x.failed, s(m, "name"))
				}
			}
		}
		out[src] = append(out[src], x)
	}
	for _, l := range out {
		sort.Slice(l, func(i, j int) bool { return l[i].seq < l[j].seq })
	}
	return out
}

// Timeline is one source's states over w: each health record holds from its time until the next record or until
// twice its reporting interval passes with no new one, and the time between is blind (stale). Before the first record
// the source is blind (never seen). A source the window knows of but with no health record is blind throughout.
func Timeline(source string, recs []hrec, w Window, now time.Time) []Segment {
	var out []Segment
	add := func(state, reason string, from, to time.Time, seq *int64) {
		if from.Before(w.From) {
			from = w.From
		}
		if to.After(w.To) {
			to = w.To
		}
		if !to.After(from) {
			return
		}
		if n := len(out); n > 0 && out[n-1].State == state && out[n-1].Reason == reason && out[n-1].To == iso(from) {
			out[n-1].To, out[n-1].Seconds = iso(to), out[n-1].Seconds+int64(to.Sub(from).Seconds())
			return
		}
		out = append(out, Segment{Source: source, State: state, Reason: reason, From: iso(from), To: iso(to),
			Seconds: int64(to.Sub(from).Seconds()), Seq: seq})
	}
	if len(recs) == 0 {
		add(Blind, "never-seen", w.From, w.To, nil)
		return out
	}
	add(Blind, "never-seen", w.From, recs[0].ts, nil)
	for i, r := range recs {
		r := r
		end := w.To
		if i+1 < len(recs) {
			end = recs[i+1].ts
		}
		hold := r.ts.Add(2 * r.interval)
		if hold.After(end) {
			hold = end
		}
		seq := r.seq
		add(r.state, "reported", r.ts, hold, &seq)
		add(Blind, "stale", hold, end, &seq)
	}
	return out
}

func rank(state string) int {
	switch state {
	case Healthy:
		return 0
	case Degraded:
		return 1
	}
	return 2
}

func worse(a, b string) string {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Build assembles the statement for in.Scope over in.Window at now.
func Build(in Input, now time.Time) Statement {
	w := in.Window
	if w.To.After(now) { // a window cannot speak for the future
		w.To = now
	}
	st := Statement{Scope: in.Scope, From: iso(w.From), To: iso(w.To), Truncated: in.Truncated}
	empty := func() Part { return Part{ByCoverage: map[string]int{}, Items: []Item{}} }
	st.Cleared, st.Seen = empty(), empty()

	latest := func(rs []Record) map[int64]Record { // about.seq -> its latest record
		m := map[int64]Record{}
		for _, r := range rs {
			a, ok := About(r)
			if !ok {
				continue
			}
			if p, have := m[a]; !have || seqOf(p) < seqOf(r) {
				m[a] = r
			}
		}
		return m
	}
	assessed, resolved := latest(in.Assessments), latest(in.Resolutions)

	sources := map[string]bool{}
	sort.Slice(in.Observations, func(i, j int) bool { return seqOf(in.Observations[i]) < seqOf(in.Observations[j]) })
	for _, o := range in.Observations {
		seq := seqOf(o)
		it := Item{Seq: seq, TS: s(o, "ts"), Source: s(sub(o, "source"), "name"), Coverage: "unassessed"}
		sources[it.Source] = true
		ac, rs := sub(o, "action"), sub(o, "resource")
		it.API = s(ac, "api")
		if b, ok := ac["succeeded"].(bool); ok {
			it.Succeeded = &b
		}
		if rs != nil {
			it.Resource = s(rs, "kind")
			if n := s(rs, "name"); n != "" {
				it.Resource += "/" + n
			} else if id := s(rs, "id"); id != "" {
				it.Resource += "/" + id
			}
		}
		if t, ok := intOf(o["tier"]); ok {
			it.Tier = &t
		}
		it.Monitoring = it.Tier != nil && *it.Tier == 3 && o["tier"] != nil && isMonitoring(o)
		if b, ok := o["completeness_supported"].(bool); ok {
			it.CompletenessSupported = &b
		}
		if a, ok := assessed[seq]; ok {
			it.Coverage = s(a, "coverage")
			aseq := seqOf(a)
			it.Assessment = &aseq
			if t, ok := intOf(a["tier"]); ok && !it.Monitoring {
				it.Tier = &t
			}
		}
		if r, ok := resolved[seq]; ok {
			rr := sub(r, "resolution")
			state := s(rr, "state")
			it.Resolution = &state
			if c := s(rr, "cause"); c != "" {
				it.Cause = &c
			}
		}
		part := &st.Seen
		if it.Coverage == evidence.CoverageAuthorizedAndVerified && !it.Monitoring {
			part = &st.Cleared
		}
		part.Count++
		part.ByCoverage[it.Coverage]++
		if len(part.Items) < MaxItems {
			part.Items = append(part.Items, it)
		} else {
			part.Truncated = true
		}
	}

	hr := hrecs(in.Health)
	for src := range hr {
		sources[src] = true
	}
	srcNames := make([]string, 0, len(sources))
	for k := range sources {
		srcNames = append(srcNames, k)
	}
	sort.Strings(srcNames)
	st.Blind.Segments, st.Blind.Gaps, st.Health.Sources = []Segment{}, []Gap{}, []SourceHealth{}
	st.State = Healthy
	if len(srcNames) == 0 {
		// Nothing is known of this scope's feeds: a window with no health record is blind, never clean.
		st.Blind.Segments = append(st.Blind.Segments, Segment{Source: "", State: Blind, Reason: "never-seen",
			From: st.From, To: st.To, Seconds: int64(w.To.Sub(w.From).Seconds())})
		st.State = Blind
	}
	for _, src := range srcNames {
		segs := Timeline(src, hr[src], w, now)
		sh := SourceHealth{Source: src, State: Healthy, Now: Blind, Failed: []string{}}
		for _, g := range segs {
			sh.State = worse(sh.State, g.State)
			switch g.State {
			case Blind:
				sh.Blind += g.Seconds
			case Degraded:
				sh.Degraded += g.Seconds
			}
			if g.State != Healthy {
				st.Blind.Segments = append(st.Blind.Segments, g)
			}
		}
		if sh.State == Healthy && len(segs) == 0 {
			sh.State = Blind // a window of no length says nothing
		}
		if l := hr[src]; len(l) > 0 {
			last := l[len(l)-1]
			seq, ts := last.seq, iso(last.ts)
			sh.LastSeq, sh.LastTS = &seq, &ts
			sh.Stale = !w.To.Before(last.ts.Add(2 * last.interval))
			sh.Now = last.state
			if sh.Stale {
				sh.Now = Blind
			}
			if sh.Now != Healthy && len(last.failed) > 0 {
				sh.Failed = last.failed
			}
		}
		st.State = worse(st.State, sh.State)
		st.Health.Sources = append(st.Health.Sources, sh)
	}
	for _, g := range st.Blind.Segments {
		st.Blind.Seconds += g.Seconds
	}
	for _, g := range in.Gaps {
		gp := sub(g, "gap")
		st.Blind.Gaps = append(st.Blind.Gaps, Gap{Seq: seqOf(g), TS: s(g, "ts"), Source: s(sub(g, "source"), "name"),
			State: s(gp, "state"), Reason: s(gp, "reason")})
	}
	st.Clean = st.State == Healthy && st.Seen.Count == 0 && !st.Truncated
	st.Text = words(st)
	return st
}

func isMonitoring(o Record) bool {
	// the core verified the tier of an operation on monitoring: it lists tier among the verified fields
	vs, _ := o["verified"].([]any)
	for _, v := range vs {
		if v == "tier" {
			return true
		}
	}
	return false
}

func words(st Statement) string {
	var b []byte
	line := func(f string, a ...any) { b = append(b, []byte(fmtf(f, a...)+"\n")...) }
	line("Scope %s, %s to %s: feed %s.", st.Scope, st.From, st.To, st.State)
	line("Cleared and verified: %d.", st.Cleared.Count)
	line("Seen, not cleared: %d.", st.Seen.Count)
	switch {
	case st.State == Healthy && st.Seen.Count == 0:
		line("No exceptions, and every feed was healthy for the whole window.")
	case st.State == Healthy:
		line("Every feed was healthy for the whole window; the exceptions above are all there is.")
	default:
		line("Could not see: %d seconds with a feed %s or degraded. This window is %s; an empty exceptions list is not a clean one.",
			st.Blind.Seconds, Blind, st.State)
	}
	return string(b)
}
