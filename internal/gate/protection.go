package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jfillman/clearance/internal/pycompat"
)

// Protected pairs reported by a cluster's agent (G-ARGO-10c). CLEARANCE_PROTECTED_ENVIRONMENTS protects an
// environment; an agent that opts one Application in reports the app and
// environment as a pair, and the core protects that pair as well. The two sources add up: a pair the list does not
// name is protected when its cluster's agent says so, and the list never shrinks because an agent says less. A
// report that goes missing changes nothing (the last one stands); staleness is shown, never acted on.

// ProtectedPair is one app and environment a cluster's agent reports as protected.
type ProtectedPair struct {
	App string `json:"app"`
	Env string `json:"env"`
}

// MaxProtectedPairs bounds one cluster's report.
const MaxProtectedPairs = 5000

// NormalizePairs checks and sorts a report: names only (nameRx), no duplicates, at most MaxProtectedPairs.
func NormalizePairs(in []ProtectedPair) ([]ProtectedPair, error) {
	if len(in) > MaxProtectedPairs {
		return nil, fmt.Errorf("a report holds at most %d pairs", MaxProtectedPairs)
	}
	out := make([]ProtectedPair, 0, len(in))
	seen := map[ProtectedPair]bool{}
	for _, p := range in {
		if !nameRx.MatchString(p.App) || !nameRx.MatchString(p.Env) {
			return nil, fmt.Errorf("pair {%q, %q}: app and env are names", p.App, p.Env)
		}
		if seen[p] {
			return nil, fmt.Errorf("pair %s/%s is listed twice", p.App, p.Env)
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].App != out[j].App {
			return out[i].App < out[j].App
		}
		return out[i].Env < out[j].Env
	})
	return out, nil
}

// reportedPairs are the pairs the cluster's agent last reported. An error reading them is the caller's to treat as
// "protected" (fail closed).
func (s *Service) reportedPairs(ctx context.Context, cluster string) ([]ProtectedPair, error) {
	if s.Store == nil {
		return nil, nil
	}
	sets, err := s.Store.Protections(ctx)
	if err != nil {
		return nil, err
	}
	for _, set := range sets {
		if set.Cluster != cluster {
			continue
		}
		var pairs []ProtectedPair
		if err := json.Unmarshal(set.Doc, &pairs); err != nil {
			return nil, fmt.Errorf("the stored protection for %s is not a list of pairs: %w", cluster, err)
		}
		return pairs, nil
	}
	return nil, nil
}

// ProtectsApp says whether the deployment protects the app's changes to env on cluster: the environment is on
// CLEARANCE_PROTECTED_ENVIRONMENTS (or that list is empty), or the cluster's agent has reported the pair. A store
// that cannot be read counts as protected: nothing is ever cleared at tier 0 because the core could not look.
func (s *Service) ProtectsApp(ctx context.Context, cluster, app, env string) bool {
	if s.Protects(cluster, env) {
		return true
	}
	pairs, err := s.reportedPairs(ctx, cluster)
	if err != nil {
		return true
	}
	for _, p := range pairs {
		if p.App == app && p.Env == env {
			return true
		}
	}
	return false
}

// ProtectsEnv says whether anything in env on cluster is protected: the list names it, or the agent reported a pair in
// it (a break-glass window is per environment).
func (s *Service) ProtectsEnv(ctx context.Context, cluster, env string) bool {
	if s.Protects(cluster, env) {
		return true
	}
	pairs, err := s.reportedPairs(ctx, cluster)
	if err != nil {
		return true
	}
	for _, p := range pairs {
		if p.Env == env {
			return true
		}
	}
	return false
}

// StaticProtects says whether CLEARANCE_PROTECTED_ENVIRONMENTS alone protects the pair's environment: what an agent's
// report cannot take away.
func (s *Service) StaticProtects(cluster, env string) bool {
	return len(s.Config.Protected) == 0 || pycompat.MatchAny(cluster+"/"+env, s.Config.Protected)
}
