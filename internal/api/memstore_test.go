package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	tokens  []store.Token
	keys    []store.SigningKey
	feeds   []store.Feed
	atts    []store.Attestation
	fail    error
	mu      sync.RWMutex // the stream tests append while a stream reads (Head, EvidenceAfter, DeploysAfter)
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
	if f.Installation != "" {
		if p, _ := str(r["principal"]); p != InstallationPrincipal(f.Installation) {
			return false
		}
	}
	if len(f.Coverage) > 0 {
		if cov, _ := str(r["coverage"]); !in(f.Coverage, cov) {
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
	if f.Exceptions {
		tool, _ := str(r["tool"])
		cov, _ := str(r["coverage"])
		if !in(ExceptionTools, tool) && cov != "coverage-unavailable" {
			return false
		}
	}
	if f.Scope != "" {
		if sc, _ := str(r["scope"]); sc != f.Scope {
			return false
		}
	}
	if f.Source != "" {
		src, _ := r["source"].(map[string]any)
		if n, _ := src["name"].(string); n != f.Source {
			return false
		}
	}
	if len(f.Tools) > 0 {
		if tool, _ := str(r["tool"]); !in(f.Tools, tool) {
			return false
		}
	}
	if f.Kind != "" {
		x, _ := r["exception"].(map[string]any)
		if k, _ := x["kind"].(string); k != f.Kind {
			return false
		}
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

func (m *memStore) Scopes(_ context.Context, v *Viewer, since, until string, limit int) ([]string, error) {
	owners := m.owners()
	seen := map[string]bool{}
	for _, r := range m.recs {
		tool, _ := str(r["tool"])
		sc, ok := str(r["scope"])
		ts, _ := str(r["ts"])
		if !ok || !m.sees(r, v, owners) {
			continue
		}
		if (tool == "observation" || tool == "observation.audit-gap") && ts >= since && ts < until || tool == "observation.health" && ts < until {
			seen[sc] = true
		}
	}
	out := make([]string, 0, len(seen))
	for sc := range seen {
		out = append(out, sc)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, m.fail
}

func (m *memStore) HealthBefore(_ context.Context, v *Viewer, scope, before string) ([]Record, error) {
	owners := m.owners()
	bySrc := map[string][]Record{}
	for _, r := range m.recs { // m.recs is in seq order
		if tool, _ := str(r["tool"]); tool != "observation.health" {
			continue
		}
		if sc, _ := str(r["scope"]); sc != scope {
			continue
		}
		if ts, _ := str(r["ts"]); ts >= before || !m.sees(r, v, owners) {
			continue
		}
		src, _ := r["source"].(map[string]any)
		name, _ := src["name"].(string)
		bySrc[name] = append(bySrc[name], r)
	}
	out := []Record{}
	for _, l := range bySrc {
		from := 0
		for i, r := range l {
			prov, _ := r["provider"].(map[string]any)
			h, _ := r["health"].(map[string]any)
			if pn, _ := prov["name"].(string); pn != evidence.CoreProviderName && h["state"] == "healthy" {
				from = i
			}
		}
		out = append(out, l[from:]...)
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

// intField is an integer field of a record's object (0 when absent or not a number), as PG's sumOf reads it.
func intField(r Record, obj, k string) int64 {
	o, _ := r[obj].(map[string]any)
	switch x := o[k].(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			return 0
		}
		return n
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	}
	return 0
}

func (m *memStore) Costs(_ context.Context, f EvidenceFilter, v *Viewer, per string) ([]Count, CostSum, error) {
	var all CostSum
	field, ok := costField[per]
	if !ok {
		return nil, all, fmt.Errorf("api: cost per %q", per)
	}
	f.Outcomes = OutcomesInclude
	owners := m.owners()
	groups := map[string]*Count{}
	var order []string
	for _, r := range m.recs {
		if !m.sees(r, v, owners) || !m.matches(r, f) {
			continue
		}
		tool, _ := str(r["tool"])
		_, isOutcome := r["outcome_of"]
		_, hasUsage := r["usage"]
		_, hasCost := r["cost"]
		call := tool == "model.call" && isOutcome && hasUsage
		run := tool == "run.finish" && hasCost
		if !call && !run {
			continue
		}
		k := keyOf(r[field])
		id := "\x00null"
		if k != nil {
			id = *k
		}
		c := groups[id]
		if c == nil {
			c = &Count{Key: k, Cost: &CostSum{}}
			groups[id] = c
			order = append(order, id)
		}
		if call {
			c.Count++
			c.Cost.ModelCalls++
			c.Cost.ChargedTokens += intField(r, "usage", "charged_tokens")
			c.Cost.InputTokens += intField(r, "usage", "input_tokens")
			c.Cost.OutputTokens += intField(r, "usage", "output_tokens")
			c.Cost.CacheCreationInputTokens += intField(r, "usage", "cache_creation_input_tokens")
			c.Cost.CacheReadInputTokens += intField(r, "usage", "cache_read_input_tokens")
		} else {
			c.Cost.Runs++
			c.Cost.WallSeconds += intField(r, "cost", "wall_seconds")
		}
	}
	out := []Count{}
	for _, id := range order {
		out = append(out, *groups[id])
		all.add(groups[id].Cost)
	}
	// charged desc, then key asc with null last (ORDER BY 3 DESC, 1)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Cost.ChargedTokens != out[j].Cost.ChargedTokens {
			return out[i].Cost.ChargedTokens > out[j].Cost.ChargedTokens
		}
		if out[i].Key == nil || out[j].Key == nil {
			return out[j].Key == nil && out[i].Key != nil
		}
		return *out[i].Key < *out[j].Key
	})
	if len(out) > MaxLimit {
		out = out[:MaxLimit]
	}
	return out, all, m.fail
}

func (m *memStore) ByPR(_ context.Context, tools []string, f PRFilter, v *Viewer) ([]Record, error) {
	repo, pr := f.Repo, f.PR
	owners := m.owners()
	checked := map[string]bool{} // the repo#pr targets the installation's provenance.verify records name
	inst := InstallationPrincipal(f.Installation)
	for _, r := range m.recs {
		if p, _ := str(r["principal"]); f.Installation != "" && p == inst && r["tool"] == "provenance.verify" {
			t, _ := str(r["target"])
			checked[t] = true
		}
	}
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
		if hit && f.Installation != "" {
			if f.ByInstaller {
				p, _ := str(r["principal"])
				hit = p == inst
			} else {
				on := target
				if eff != nil && er != "" && ep != nil {
					on = er + "#" + *ep
				}
				hit = checked[on]
			}
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
	ID          string  `json:"id"`
	App         string  `json:"app"`
	Cluster     string  `json:"cluster"`
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
			(f.Tier != nil && cv.Tier != *f.Tier) || (f.Cluster != "" && cv.Cluster != f.Cluster)) {
			continue
		}
		if list && f.LiveAt != nil {
			if _, live := m.live([]string{cv.ID}, *f.LiveAt)[cv.ID]; !live {
				continue
			}
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
		case "attestation":
			state := "none"
			var oc struct {
				Outcome *struct {
					Applied bool `json:"applied"`
				} `json:"outcome"`
			}
			_ = json.Unmarshal(c.Record, &oc)
			for _, a := range m.atts {
				if a.ChangeID == c.ID {
					state = "attested"
				}
			}
			if state == "none" && oc.Outcome != nil && oc.Outcome.Applied {
				state = "pending"
			}
			keys = append(keys, &state)
		}
	}
	out := group(keys)
	// change counts have no tie order in api.py (ORDER BY count(*) DESC only): the tests compare as sets on ties
	return out, m.fail
}

func (m *memStore) Definitions(context.Context) ([]store.Definition, error) { return m.defs, m.fail }

func (m *memStore) Ping(context.Context) error { return m.fail }

func (m *memStore) live(ids []string, now time.Time) map[string]store.Token {
	out := map[string]store.Token{}
	for _, tk := range m.tokens {
		for _, id := range ids {
			if tk.ChangeID == id && tk.RevokedAt == nil && tk.ExpiresAt.After(now) {
				out[id] = tk
			}
		}
	}
	return out
}

func (m *memStore) Tokens(_ context.Context, ids []string, now time.Time) (map[string]store.Token, error) {
	return m.live(ids, now), m.fail
}

func (m *memStore) SigningKeys(_ context.Context, since time.Time) ([]store.SigningKey, error) {
	out := []store.SigningKey{}
	for _, k := range m.keys {
		if k.RetiredAt == nil || k.RetiredAt.After(since) {
			out = append(out, k)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, m.fail
}

func (m *memStore) appendRec(r Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = append(m.recs, r)
}

func (m *memStore) Head(context.Context) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.recs) == 0 {
		return -1, m.fail
	}
	n, _ := seqOf(m.recs[len(m.recs)-1])
	return n, m.fail
}

func (m *memStore) EvidenceAfter(_ context.Context, f EvidenceFilter, v *Viewer, after int64, limit int) ([]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	owners := m.owners()
	out := []Record{}
	for _, r := range m.recs {
		if seq, _ := seqOf(r); seq > after && len(out) < limit && m.sees(r, v, owners) && m.matches(r, f) {
			out = append(out, r)
		}
	}
	return out, m.fail
}

func (m *memStore) DeploysAfter(_ context.Context, after int64, limit int) ([]DeployEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []DeployEvent{}
	for _, r := range m.recs {
		seq, _ := seqOf(r)
		tool, _ := str(r["tool"])
		ch, isObj := r["change"].(map[string]any)
		if seq <= after || !strings.HasPrefix(tool, "deploy.") || !isObj || len(out) >= limit {
			continue
		}
		ts, _ := str(r["ts"])
		d := DeployEvent{Seq: seq, Tool: tool, TS: ts, Summary: mustJSON(ch)}
		id, _ := str(ch["id"])
		for _, c := range m.changes {
			if c.ID == id {
				d.Change = c.Record
			}
		}
		out = append(out, d)
	}
	return out, m.fail
}

func (m *memStore) Attestation(_ context.Context, id string) (*store.Attestation, error) {
	for _, a := range m.atts {
		if a.ChangeID == id {
			a := a
			return &a, m.fail
		}
	}
	return nil, m.fail
}

func (m *memStore) Feed(_ context.Context, cluster string) (*store.Feed, error) {
	for _, f := range m.feeds {
		if f.Cluster == cluster {
			f := f
			return &f, m.fail
		}
	}
	return nil, m.fail
}

func (m *memStore) Installations(context.Context) ([]Installation, error) {
	byID := map[string]*Installation{}
	var order []string
	for _, r := range m.recs {
		p, _ := str(r["principal"])
		if !strings.HasPrefix(p, "app:") {
			continue
		}
		inst := byID[p]
		if inst == nil {
			inst = newInstallation(p)
			byID[p] = inst
			order = append(order, p)
		}
		seq, _ := seqOf(r)
		tool, _ := str(r["tool"])
		ts, _ := str(r["ts"])
		inst.add(tool, 1, seq, seq, ts, ts)
		target, _ := str(r["target"])
		switch tool {
		case "app.installation":
			result, _ := str(r["result"])
			var acc *string
			if t, ok := str(r["target"]); ok {
				acc = &t
			}
			inst.Action, inst.Status = nil, "active"
			inst.last(acc, result)
		case "provenance.verify":
			if repo, _, ok := strings.Cut(target, "#"); ok && !in(inst.Repos, repo) {
				inst.Repos = append(inst.Repos, repo)
			}
		}
	}
	sort.Strings(order)
	out := []Installation{}
	for _, p := range order {
		inst := byID[p]
		sort.Strings(inst.Repos)
		out = append(out, *inst)
	}
	return out, m.fail
}

func (m *memStore) ChangeRecords(_ context.Context, id, tool string, limit int, after *int64) ([]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []Record{}
	for _, r := range m.recs {
		seq, _ := seqOf(r)
		t, _ := str(r["tool"])
		ch, _ := r["change"].(map[string]any)
		if cid, _ := str(ch["id"]); cid != id || !strings.HasPrefix(t, "deploy.") || (tool != "" && t != tool) ||
			(after != nil && seq <= *after) || len(out) >= limit {
			continue
		}
		out = append(out, r)
	}
	return out, m.fail
}

func (m *memStore) Attestations(_ context.Context, f AttestationFilter, v *Viewer, limit int, after *int64) ([]AttestationRow, error) {
	var out []AttestationRow
	for _, a := range m.atts {
		for _, c := range m.changes {
			if c.ID != a.ChangeID || !changeVisible(c.Record, v) || (f.App != "" && c.App != f.App) || (f.Env != "" && c.Env != f.Env) {
				continue
			}
			if (!f.Since.IsZero() && a.CreatedAt.Before(f.Since)) || (!f.Until.IsZero() && !a.CreatedAt.Before(f.Until)) ||
				(after != nil && a.RecordSeq >= *after) {
				continue
			}
			a := a
			a.Bundle = nil
			out = append(out, AttestationRow{Attestation: a, Change: c.Record})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Attestation.RecordSeq > out[j].Attestation.RecordSeq })
	if len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []AttestationRow{}
	}
	return out, m.fail
}

func (m *memStore) AttestationsOf(_ context.Context, ids []string) (map[string]store.Attestation, error) {
	out := map[string]store.Attestation{}
	for _, a := range m.atts {
		for _, id := range ids {
			if a.ChangeID == id {
				a.Bundle = nil
				out[id] = a
			}
		}
	}
	return out, m.fail
}
