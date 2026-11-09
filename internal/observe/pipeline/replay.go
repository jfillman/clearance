package pipeline

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// Report is what a replay of recorded raw events made: the assessments, the change transactions, the exceptions, what
// was filtered or out of scope, and the health the scopes were left in. It is the golden corpus's expected form.
type Report struct {
	RuleSet       RuleSetRef        `json:"rule_set"`
	Events        int               `json:"events"`
	NotWrites     int               `json:"not_writes"`
	OutOfScope    map[string]int    `json:"out_of_scope"`
	Filtered      []FilteredCount   `json:"filtered"`
	FilteredLines []string          `json:"filtered_lines"`
	Assessments   []Assessment      `json:"assessments"`
	Transactions  []Transaction     `json:"transactions"`
	Exceptions    []Exception       `json:"exceptions"`
	Alerts        []Alert           `json:"alerts"`
	Health        map[string]string `json:"health"`
}

// MaxLine bounds one recorded event (a JSONL line).
const MaxLine = 4 << 20

// Replay runs recorded raw events (JSONL, one RawEvent per line, in time order; blank lines and lines starting with
// '#' are skipped) through the pipeline and closes the correlation. It is the test harness for rule sets and the
// golden corpus (`clearance observe replay`): no clock, no store, no network.
func Replay(r io.Reader, p *Pipeline) (*Report, error) {
	rep := &Report{RuleSet: p.RuleSet(), Assessments: []Assessment{}, Alerts: []Alert{}}
	prev := p.OnAlert
	p.OnAlert = func(a Alert) {
		rep.Alerts = append(rep.Alerts, a)
		if prev != nil {
			prev(a)
		}
	}
	defer func() { p.OnAlert = prev }()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLine)
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 || b[0] == '#' {
			continue
		}
		var raw RawEvent
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		a, _, _, err := p.Process(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if a != nil {
			rep.Assessments = append(rep.Assessments, *a)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading events: %w", err)
	}
	st := p.Stats()
	rep.Events, rep.NotWrites, rep.OutOfScope = st.Events, st.NotWrites, st.OutOfScope
	rep.Filtered = p.FilteredCounts()
	rep.FilteredLines = []string{}
	for _, f := range rep.Filtered {
		rep.FilteredLines = append(rep.FilteredLines, f.Line())
	}
	rep.Transactions, rep.Exceptions = p.Flush()
	if rep.Transactions == nil {
		rep.Transactions, rep.Exceptions = []Transaction{}, append([]Exception{}, rep.Exceptions...)
	}
	if rep.Exceptions == nil {
		rep.Exceptions = []Exception{}
	}
	rep.Health = map[string]string{}
	var scopes []string
	for _, a := range rep.Assessments {
		scopes = append(scopes, a.Scope)
	}
	sort.Strings(scopes)
	for _, s := range scopes {
		rep.Health[s] = p.Health(s)
	}
	return rep, nil
}
