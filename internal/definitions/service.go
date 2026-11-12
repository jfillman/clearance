package definitions

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
)

// Service is Gateway.apply_cluster_definitions: the loader's hand-off, recorded and persisted.
type Service struct {
	Registry *Registry
	Store    store.Store
	Clock    func() time.Time
	Writer   evidence.Writer // zero: evidence.Core("")
	mu       sync.Mutex
}

// Apply makes loaded + rejected the cluster set, records what changed (definition.load for a new or re-pinned
// definition, definition.unload for a pin that is gone, definition.reject for a pin that did not load, once each)
// and replaces the stored rows, all in one transaction. Nothing is recorded when the poll found the same set.
// The in-memory set is swapped only once the transaction commits.
func (s *Service) Apply(ctx context.Context, loaded []Loaded, rejected []Rejected) (Changes, error) {
	return s.ApplyWith(ctx, loaded, rejected, s.Writer.OrCore(), nil)
}

// ApplyWith is Apply with each record sealed by w and carrying extra's fields as well (a published set's caller:
// PUT /v1/definitions). extra may not name a field Event sets.
func (s *Service) ApplyWith(ctx context.Context, loaded []Loaded, rejected []Rejected, w evidence.Writer,
	extra map[string]any) (Changes, error) {
	return s.ApplyKeeping(ctx, loaded, rejected, w, extra, false)
}

// ApplyKeeping is ApplyWith, optionally keeping the definitions the provider published as shipping with it (source
// kind provider) when loaded and rejected carry none: a publish from a provider that does not send that set must
// not unload what an earlier publish of it loaded.
func (s *Service) ApplyKeeping(ctx context.Context, loaded []Loaded, rejected []Rejected, w evidence.Writer,
	extra map[string]any, keepProvided bool) (Changes, error) {
	if s.Registry == nil {
		return Changes{}, ErrNotRegistry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Registry.mu.Lock()
	defer s.Registry.mu.Unlock()
	if keepProvided {
		loaded, rejected = s.Registry.keepProvided(loaded, rejected)
	}
	p := s.Registry.plan(loaded, rejected)
	ch := p.changes
	if !ch.Any() {
		return ch, nil
	}
	now := s.Clock()
	err := s.Store.Atomic(ctx, func(tx store.Tx) error {
		rec := func(tool, name string, src Source, decision string, rule any, result string) error {
			ev := Event(now, tool, name, src, decision, rule, result)
			for k, v := range extra {
				if _, set := ev[k]; set {
					return fmt.Errorf("definitions: extra field %q is the record's own", k)
				}
				ev[k] = v
			}
			_, err := tx.Append(ctx, ev, w)
			return err
		}
		for _, n := range ch.Added {
			if err := rec("definition.load", n, ch.Sources[n], "allow", nil, "loaded "+ch.Sources[n].Pin()); err != nil {
				return err
			}
		}
		for _, n := range ch.Changed {
			if err := rec("definition.load", n, ch.Sources[n], "allow", nil, "re-pinned "+ch.Sources[n].Pin()); err != nil {
				return err
			}
		}
		for _, n := range ch.Removed {
			if err := rec("definition.unload", n, ch.Sources[n], "allow", nil, "pin removed "+ch.Sources[n].Pin()); err != nil {
				return err
			}
		}
		for _, r := range ch.Rejected {
			if err := rec("definition.reject", r.Name, r.Source, "deny", "DF-PIN", r.Reason); err != nil {
				return err
			}
		}
		rows := records(p.cluster, p.rejected)
		defs := make([]store.Definition, 0, len(rows))
		for _, row := range rows {
			raw, err := json.Marshal(row)
			if err != nil {
				return err
			}
			defs = append(defs, store.Definition{Name: row.Name, State: row.State, Record: raw})
		}
		return tx.ReplaceDefinitions(ctx, defs)
	})
	if err != nil {
		return Changes{}, fmt.Errorf("definitions: %w", err)
	}
	s.Registry.commit(p)
	return ch, nil
}

// Event is _definition_record's event: the pin as principal, the agent, the source's pin as target.
func Event(now time.Time, tool, name string, src Source, decision string, rule any, result string) store.Event {
	principal := "platform"
	switch src.Kind {
	case "cluster":
		principal = fmt.Sprintf("pin:%s/%s", pycompat.Str(strOrNone(src.Namespace)), pycompat.Str(strOrNone(src.XR)))
	case "provider":
		principal = "provider:" + deref(src.Provider)
	}
	return store.Event{
		"ts": pycompat.ISO(now), "task_id": nil, "session": nil, "parent": nil, "principal": principal,
		"agent": name, "tool": tool, "tier": nil, "decision": decision, "rule": rule, "target": src.Pin(),
		"args_sha256": pycompat.ArgsDigest(src.View()), "result": result,
	}
}
