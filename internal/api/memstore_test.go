package api

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
)

// memStore is Store over records and changes held in memory: the read adapter the HTTP tests run on without a
// database, and the reference the Postgres store is held against (the same tests run on both). Its scoping is
// PG's, written in Go.
type memStore struct {
	recs    []Record // in seq order, each with "assurance"
	changes []store.Change
	defs    []store.Definition
	fail    error
}

var _ Store = (*memStore)(nil)

// fromReader reads a whole chain (store/memory or a pg.Store) into a memStore.
func fromReader(ctx context.Context, r store.Reader) (*memStore, error) {
	m := &memStore{}
	for from := int64(0); ; {
		recs, err := r.Records(ctx, from, 1000)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			seq, _ := seqOf(rec)
			a, err := r.Assurance(ctx, seq)
			if err != nil {
				return nil, err
			}
			c := map[string]any{}
			for k, v := range rec {
				c[k] = v
			}
			c["assurance"] = a
			m.recs = append(m.recs, c)
		}
		if len(recs) < 1000 {
			break
		}
		from += int64(len(recs))
	}
	return m, nil
}

func str(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// owners is the `opened` CTE: the principal of each task's first session.open record.
func (m *memStore) owners() map[string]string {
	out := map[string]string{}
	for _, r := range m.recs {
		if r["tool"] != "session.open" {
			continue
		}
		t, ok := str(r["task_id"])
		if !ok {
			continue
		}
		if _, seen := out[t]; !seen {
			p, _ := str(r["principal"])
			out[t] = p
		}
	}
	return out
}

func (m *memStore) sees(r Record, v *Viewer, owners map[string]string) bool {
	if v.All() {
		return true
	}
	agent, _ := str(r["agent"])
	app, _ := str(r["app"])
	principal, _ := str(r["principal"])
	if (agent != "" && in(v.Agents, agent)) || (app != "" && in(v.Apps, app)) {
		return true
	}
	if r["session"] == nil {
		return principal == v.Person
	}
	t, ok := str(r["task_id"])
	return ok && owners[t] == v.Person
}

func (m *memStore) matches(r Record, f EvidenceFilter) bool {
	for field, want := range map[string]string{"task_id": f.Task, "session": f.Session, "agent": f.Agent,
		"tool": f.Tool, "principal": f.Principal, "decision": f.Decision, "rule": f.Rule, "app": f.App} {
		if want == "" {
			continue
		}
		if got, ok := str(r[field]); !ok || got != want {
			return false
		}
	}
	ts, _ := str(r["ts"])
	if f.Since != "" && ts < f.Since {
		return false
	}
	if f.Until != "" && ts >= f.Until {
		return false
	}
	_, isOutcome := r["outcome_of"]
	switch f.Outcomes {
	case OutcomesExclude:
		return !isOutcome
	case OutcomesOnly:
		return isOutcome
	}
	return true
}

func (m *memStore) Evidence(_ context.Context, f EvidenceFilter, v *Viewer, limit int, after *int64) ([]Record, error) {
	owners := m.owners()
	out := []Record{}
	for i := len(m.recs) - 1; i >= 0 && len(out) < limit; i-- {
		r := m.recs[i]
		seq, _ := seqOf(r)
		if (after == nil || seq < *after) && m.sees(r, v, owners) && m.matches(r, f) {
			out = append(out, r)
		}
	}
	return out, m.fail
}

func (m *memStore) EvidenceOne(_ context.Context, seq int64, v *Viewer) (Record, error) {
	for _, r := range m.recs {
		if s, _ := seqOf(r); s == seq && m.sees(r, v, m.owners()) {
			return r, m.fail
		}
	}
	return nil, m.fail
}

func group(keys []*string) []Count {
	n := map[string]int64{}
	var nulls int64
	for _, k := range keys {
		if k == nil {
			nulls++
		} else {
			n[*k]++
		}
	}
	out := []Count{}
	for k, c := range n {
		out = append(out, Count{Key: &k, Count: c})
	}
	if nulls > 0 {
		out = append(out, Count{Key: nil, Count: nulls})
	}
	// count desc, then key asc with null last (ORDER BY count(*) DESC, 1)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Key == nil || out[j].Key == nil {
			return out[j].Key == nil && out[i].Key != nil
		}
		return *out[i].Key < *out[j].Key
	})
	if len(out) > MaxLimit {
		out = out[:MaxLimit]
	}
	return out
}

func keyOf(v any) *string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return &x
	case json.Number:
		s := x.String()
		return &s
	case bool:
		s := strconv.FormatBool(x)
		return &s
	}
	b, _ := json.Marshal(v)
	s := string(b)
	return &s
}

func (m *memStore) Counts(_ context.Context, f EvidenceFilter, v *Viewer, by string) ([]Count, error) {
	owners := m.owners()
	var keys []*string
	for _, r := range m.recs {
		if m.sees(r, v, owners) && m.matches(r, f) {
			keys = append(keys, keyOf(r[by]))
		}
	}
	return group(keys), m.fail
}

func (m *memStore) ByPR(_ context.Context, tools []string, repo, pr string, v *Viewer) ([]Record, error) {
	owners := m.owners()
	out := []Record{}
	for i := len(m.recs) - 1; i >= 0 && len(out) < MaxLimit; i-- {
		r := m.recs[i]
		tool, _ := str(r["tool"])
		if !in(tools, tool) || !m.sees(r, v, owners) {
			continue
		}
		eff, _ := r["effect"].(map[string]any)
		er, _ := str(eff["repo"])
		ep := keyOf(eff["pr"])
		target, _ := str(r["target"])
		hit := eff != nil && er == repo && (pr == "" || (ep != nil && *ep == pr))
		if pr != "" {
			hit = hit || target == repo+"#"+pr
		} else {
			hit = hit || strings.HasPrefix(target, repo+"#")
		}
		if hit {
			out = append(out, r)
		}
	}
	return out, m.fail
}

func (m *memStore) Verify(context.Context) (Verified, error) {
	v := evidence.NewVerifier()
	for _, r := range m.recs {
		stored := map[string]any{}
		for k, x := range r {
			if k != "assurance" {
				stored[k] = x
			}
		}
		if err := v.Add(stored); err != nil {
			cp := v.Checkpoint()
			seq := cp.Count
			return Verified{OK: false, Count: cp.Count, Head: cp.Head, BadSeq: &seq}, nil
		}
	}
	cp := v.Checkpoint()
	return Verified{OK: true, Count: cp.Count, Head: cp.Head}, nil
}

type changeView struct {
	App         string  `json:"app"`
	Env         string  `json:"env"`
	State       string  `json:"state"`
	Repo        string  `json:"repo"`
	PR          int64   `json:"pr"`
	Tier        int64   `json:"tier"`
	UpdatedAt   string  `json:"updated_at"`
	Owner       string  `json:"owner"`
	ClearedBy   *string `json:"cleared_by"`
	Requirement *struct {
		OutsideGroups []string `json:"outsideGroups"`
	} `json:"requirement"`
}

func (m *memStore) changeSees(c changeView, v *Viewer) bool {
	return changeVisible(mustJSON(c), v)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (m *memStore) filtered(f ChangeFilter, v *Viewer, list bool) ([]store.Change, []changeView) {
	var rows []store.Change
	var views []changeView
	for _, c := range m.changes {
		var cv changeView
		_ = json.Unmarshal(c.Record, &cv)
		if !m.changeSees(cv, v) {
			continue
		}
		if (f.App != "" && c.App != f.App) || (f.Env != "" && c.Env != f.Env) || (f.State != "" && c.State != f.State) {
			continue
		}
		if list && ((f.Repo != "" && c.Repo != f.Repo) || (f.PR != nil && int64(c.PR) != *f.PR) ||
			(f.Tier != nil && cv.Tier != *f.Tier)) {
			continue
		}
		if f.Since != "" && cv.UpdatedAt < f.Since {
			continue
		}
		rows, views = append(rows, c), append(views, cv)
	}
	return rows, views
}

func (m *memStore) Changes(_ context.Context, f ChangeFilter, v *Viewer, limit int, after string) ([]json.RawMessage, error) {
	rows, views := m.filtered(f, v, true)
	idx := make([]int, len(rows))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return views[idx[a]].UpdatedAt > views[idx[b]].UpdatedAt })
	out := []json.RawMessage{}
	for _, i := range idx {
		if len(out) == limit {
			break
		}
		if after == "" || views[i].UpdatedAt < after {
			out = append(out, rows[i].Record)
		}
	}
	return out, m.fail
}

func (m *memStore) Change(_ context.Context, id string) (json.RawMessage, error) {
	for _, c := range m.changes {
		if c.ID == id {
			return c.Record, m.fail
		}
	}
	return nil, m.fail
}

func (m *memStore) ChangeCounts(_ context.Context, f ChangeFilter, v *Viewer, by string) ([]Count, error) {
	rows, views := m.filtered(f, v, false)
	var keys []*string
	for i, c := range rows {
		cv := views[i]
		switch by {
		case "state":
			keys = append(keys, &c.State)
		case "app":
			keys = append(keys, &c.App)
		case "env":
			keys = append(keys, &c.Env)
		case "tier":
			keys = append(keys, keyOf(json.Number(strconv.FormatInt(cv.Tier, 10))))
		case "cleared_by":
			keys = append(keys, cv.ClearedBy)
		}
	}
	out := group(keys)
	// change counts have no tie order in api.py (ORDER BY count(*) DESC only): the tests compare as sets on ties
	return out, m.fail
}

func (m *memStore) Definitions(context.Context) ([]store.Definition, error) { return m.defs, m.fail }

func (m *memStore) Ping(context.Context) error { return m.fail }
