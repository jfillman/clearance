package api

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/store"
)

// memStore's Map reads: the reference the Postgres statements (mapstore.go) are held against.

func (m *memStore) Targets(context.Context) ([]store.TargetSet, error) {
	out := append([]store.TargetSet{}, m.targets...)
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out, m.fail
}

func (m *memStore) registeredBy(id string) string {
	for _, c := range m.changes {
		if c.ID == id {
			var x struct {
				RegisteredBy string `json:"registered_by"`
			}
			_ = json.Unmarshal(c.Record, &x)
			return x.RegisteredBy
		}
	}
	return ""
}

func (m *memStore) GateActivity(_ context.Context, v *Viewer, from, to string) ([]GateRow, bool, error) {
	owners := m.owners()
	type k struct{ p, rb, b, tool, d, c, app, env, applied, matched string }
	rows := map[k]*GateRow{}
	changes := map[k]map[string]bool{}
	var order []k
	for _, r := range m.recs {
		if !m.sees(r, v, owners) {
			continue
		}
		ts, _ := str(r["ts"])
		tool, _ := str(r["tool"])
		boundary, _ := str(r["boundary"])
		_, hasPolicy := r["policy"]
		_, outcome := r["outcome_of"]
		if ts < from || ts >= to {
			continue
		}
		if !(in([]string{"deploy.request", "deploy.clear", "deploy.deny", "deploy.expire", "deploy.outcome", "deploy.exception", "deploy.degraded"}, tool) ||
			(boundary == "runtime" && hasPolicy && !outcome)) {
			continue
		}
		prov, _ := r["provider"].(map[string]any)
		pn, _ := prov["name"].(string)
		if pn == evidence.CoreProviderName {
			pn = ""
		}
		ch, _ := r["change"].(map[string]any)
		id, _ := ch["id"].(string)
		env, _ := ch["env"].(string)
		dec, _ := str(r["decision"])
		cov, _ := str(r["coverage"])
		app, _ := str(r["app"])
		if boundary != "deployment" {
			app = ""
		}
		oc, _ := r["outcome"].(map[string]any)
		applied, matched := "", ""
		if b, ok := oc["applied"].(bool); ok {
			applied = strconv.FormatBool(b)
		}
		if b, ok := r["matched"].(bool); ok {
			matched = strconv.FormatBool(b)
		}
		kk := k{pn, m.registeredBy(id), boundary, tool, dec, cov, app, env, applied, matched}
		g := rows[kk]
		if g == nil {
			g = &GateRow{Provider: kk.p, RegisteredBy: kk.rb, Boundary: kk.b, Tool: kk.tool, Decision: kk.d, Coverage: kk.c, App: kk.app, Env: kk.env, Applied: kk.applied, Matched: kk.matched}
			rows[kk], changes[kk] = g, map[string]bool{}
			order = append(order, kk)
		}
		g.Count++
		if ch != nil && ch["id"] != nil {
			changes[kk][id] = true
		}
	}
	out := make([]GateRow, 0, len(order))
	for _, kk := range order {
		g := *rows[kk]
		g.Changes = int64(len(changes[kk]))
		out = append(out, g)
	}
	return out, false, m.fail
}

func (m *memStore) ScopeCoverage(_ context.Context, v *Viewer, scopes []string, from, to string) ([]ScopeRow, error) {
	owners := m.owners()
	type k struct{ scope, tool, cov string }
	n := map[k]int64{}
	abouts := map[k]map[string]bool{}
	for _, r := range m.recs {
		tool, _ := str(r["tool"])
		sc, _ := str(r["scope"])
		ts, _ := str(r["ts"])
		if (tool != "observation" && tool != "assessment") || !in(scopes, sc) || ts < from || ts >= to || !m.sees(r, v, owners) {
			continue
		}
		cov, _ := str(r["coverage"])
		kk := k{sc, tool, cov}
		if tool == "assessment" {
			a, _ := r["about"].(map[string]any)
			if abouts[kk] == nil {
				abouts[kk] = map[string]bool{}
			}
			abouts[kk][string(mustJSON(a["seq"]))] = true
			continue
		}
		n[kk]++
	}
	for kk, set := range abouts {
		n[kk] = int64(len(set))
	}
	var out []ScopeRow
	for kk, c := range n {
		out = append(out, ScopeRow{Scope: kk.scope, Tool: kk.tool, Coverage: kk.cov, Count: c})
	}
	return out, m.fail
}

func (m *memStore) HealthBeforeScopes(ctx context.Context, v *Viewer, scopes []string, before string) ([]Record, error) {
	var out []Record
	for _, sc := range scopes {
		rs, err := m.HealthBefore(ctx, v, sc, before)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, m.fail
}

func (m *memStore) Holding(_ context.Context, v *Viewer) ([]HoldRow, error) {
	type k struct {
		rb, app, env string
		tier         int
	}
	rows := map[k]*HoldRow{}
	for _, c := range m.changes {
		var cv changeView
		_ = json.Unmarshal(c.Record, &cv)
		if c.State != "holding" || !m.changeSees(cv, v) {
			continue
		}
		var x struct {
			RegisteredBy string `json:"registered_by"`
			CreatedAt    string `json:"created_at"`
		}
		_ = json.Unmarshal(c.Record, &x)
		kk := k{x.RegisteredBy, c.App, c.Env, int(cv.Tier)}
		h := rows[kk]
		if h == nil {
			h = &HoldRow{RegisteredBy: kk.rb, App: kk.app, Env: kk.env, Tier: kk.tier, Oldest: x.CreatedAt}
			rows[kk] = h
		}
		h.Count++
		if x.CreatedAt < h.Oldest {
			h.Oldest = x.CreatedAt
		}
	}
	var out []HoldRow
	for _, h := range rows {
		out = append(out, *h)
	}
	return out, m.fail
}
