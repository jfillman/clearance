package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/targets"
)

// The declared target registry (GET /v1/targets): what the sources that publish (PUT /v1/targets/{source} on the core)
// declare should be protected. The union of every source's set, a target named by two sources taken from the one
// first by name and reported as a conflict.

// DeclaredTarget is a target with the source that declares it.
type DeclaredTarget struct {
	Source string `json:"source"`
	targets.Target
}

// TargetSource is one source's published set: its digest (the one the targets.load record carries), how many targets
// it declares and when the core stored it.
type TargetSource struct {
	Source    string `json:"source"`
	Digest    string `json:"digest"`
	Targets   int    `json:"targets"`
	UpdatedAt string `json:"updated_at"`
}

// TargetList is GET /v1/targets.
type TargetList struct {
	Items   []DeclaredTarget `json:"items"`
	Sources []TargetSource   `json:"sources"`
	// Conflicts name a target id that two sources declare (the first source's is kept); Invalid the sources whose stored
	// set could not be read.
	Conflicts []string `json:"conflicts"`
	Invalid   []string `json:"invalid"`
}

// registry reads the union of the declared sets.
func (s *Server) registry(ctx context.Context) (TargetList, error) {
	sets, err := s.opt.Store.Targets(ctx)
	out := TargetList{Items: []DeclaredTarget{}, Sources: []TargetSource{}, Conflicts: []string{}, Invalid: []string{}}
	if err != nil {
		return out, err
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].Source < sets[j].Source })
	owner := map[string]string{}
	for _, set := range sets {
		var ts []targets.Target
		if err := json.Unmarshal(set.Doc, &ts); err != nil {
			out.Invalid = append(out.Invalid, set.Source)
			continue
		}
		out.Sources = append(out.Sources, TargetSource{Source: set.Source, Digest: set.Digest, Targets: len(ts),
			UpdatedAt: set.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z")})
		for _, t := range ts {
			if t.Gates == nil {
				t.Gates = []targets.Gate{}
			}
			if t.Observers == nil {
				t.Observers = []targets.Observer{}
			}
			if o, dup := owner[t.ID]; dup {
				out.Conflicts = append(out.Conflicts, t.ID+" ("+o+", "+set.Source+")")
				continue
			}
			owner[t.ID] = set.Source
			out.Items = append(out.Items, DeclaredTarget{Source: set.Source, Target: t})
		}
	}
	return out, nil
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request, _ *Viewer) {
	q := query(r)
	list, err := s.registry(r.Context())
	if err != nil {
		s.readFailed(w, r, err)
		return
	}
	if k := q["kind"]; k != "" && !in(targets.Kinds, k) {
		writeError(w, 400, "kind is one of "+strings.Join(targets.Kinds, ", "))
		return
	}
	items := list.Items[:0:0]
	for _, t := range list.Items {
		if (q["source"] == "" || t.Source == q["source"]) && (q["group"] == "" || t.Group == q["group"]) &&
			(q["kind"] == "" || t.Kind == q["kind"]) && (q["env"] == "" || t.Env == q["env"]) &&
			(q["app"] == "" || t.App == q["app"]) {
			items = append(items, t)
		}
	}
	list.Items = items
	if list.Items == nil {
		list.Items = []DeclaredTarget{}
	}
	writeJSON(w, 200, list)
}
