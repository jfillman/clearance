package collector

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/observe/pipeline"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// GrantSource lists the ClearanceGrants of the cluster (the Argo CD agent keeps them; the collector only reads).
type GrantSource interface {
	ListGrants(ctx context.Context) ([]agent.Grant, error)
}

// BreakGlassSource is the core's open break-glass windows for a cluster.
type BreakGlassSource interface {
	Breakglass(ctx context.Context, cluster string) ([]agent.Window, error)
}

// Lookups backs the pipeline's attribution over the cluster's grants and the core's break-glass windows. It reads from a
// snapshot, refreshed by Refresh; a failed refresh keeps the last snapshot (a stale answer attributes less, never more:
// an unknown grant is out-of-band) and says so through Age. It implements pipeline.Lookups and pipeline.ObjectGrants.
type Lookups struct {
	Cluster string
	Grants  GrantSource
	BG      BreakGlassSource
	Now     func() time.Time

	// MissRefresh: an answer of "not known" re-reads the grants first if the snapshot is older than this (a grant cleared
	// a moment ago is stamped on objects Argo CD applies within seconds, long before the next scheduled refresh).
	// Zero: 5 seconds. A refresh on a miss is bounded to 5 seconds of its own.
	MissRefresh time.Duration

	mu      sync.RWMutex
	missMu  sync.Mutex
	byID    map[string][]string // grant (change) id -> the rendered hashes it lists, carried trees included
	listed  map[string]string   // "<namespace>/<lower-case kind>/<name>" -> grant id (active grants only)
	windows []agent.Window
	at      time.Time
}

var (
	_ pipeline.Lookups      = (*Lookups)(nil)
	_ pipeline.ObjectGrants = (*Lookups)(nil)
)

func trimSHA(s string) string { return strings.TrimPrefix(s, "sha256:") }

func (l *Lookups) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// Refresh reads the grants and the windows. An active grant is one that is valid (status.valid) and unexpired: the
// object lists of those, namespace by namespace, are what ObjectGrant answers from. Every grant's rendered hashes,
// the carried trees' too, are what Grant answers from (an object stamped with an older, still live change is cleared
// by that change's grant).
func (l *Lookups) Refresh(ctx context.Context) error {
	grants, err := l.Grants.ListGrants(ctx)
	if err != nil {
		return err
	}
	now := l.now()
	byID := map[string][]string{}
	listed := map[string]string{}
	add := func(id string, ns string, objs map[string]agent.GrantObject, active bool) {
		for key, o := range objs {
			if h := trimSHA(o.Rendered); h != "" {
				byID[id] = append(byID[id], h)
			}
			if !active {
				continue
			}
			// key is <group>/<kind>/<name>; the namespace is the grant's own
			parts := strings.SplitN(key, "/", 3)
			if len(parts) == 3 {
				listed[ns+"/"+strings.ToLower(parts[1])+"/"+parts[2]] = id
			}
		}
	}
	for _, g := range grants {
		id := g.Spec.Clearance.ID
		if id == "" {
			id = g.Name
		}
		expires, perr := time.Parse(time.RFC3339, g.Spec.ExpiresAt)
		active := g.Valid != nil && *g.Valid && perr == nil && now.Before(expires)
		add(id, g.Namespace, g.Spec.Objects, active)
		for _, c := range g.Spec.Carried {
			cexp, cerr := time.Parse(time.RFC3339, c.ExpiresAt)
			add(c.Change, g.Namespace, c.Objects, active && cerr == nil && now.Before(cexp))
		}
	}
	var windows []agent.Window
	if l.BG != nil {
		if windows, err = l.BG.Breakglass(ctx, l.Cluster); err != nil {
			return err
		}
	}
	l.mu.Lock()
	l.byID, l.listed, l.windows, l.at = byID, listed, windows, now
	l.mu.Unlock()
	return nil
}

// Age is how long ago the snapshot was taken (a very long time when there is none).
func (l *Lookups) Age() time.Duration {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.at.IsZero() {
		return 1<<63 - 1
	}
	return l.now().Sub(l.at)
}

// refreshOnMiss re-reads the grants when the snapshot is older than MissRefresh, so a miss is not an answer about a
// grant that was cleared after the last read. A failed read leaves the snapshot as it was.
func (l *Lookups) refreshOnMiss() {
	l.missMu.Lock()
	defer l.missMu.Unlock()
	d := l.MissRefresh
	if d <= 0 {
		d = 5 * time.Second
	}
	if l.Age() < d {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = l.Refresh(ctx)
}

// Grant is the grant with this id and the hashes it lists.
func (l *Lookups) Grant(id string) (pipeline.Grant, bool) {
	l.mu.RLock()
	h, ok := l.byID[id]
	l.mu.RUnlock()
	if !ok {
		l.refreshOnMiss()
		l.mu.RLock()
		h, ok = l.byID[id]
		l.mu.RUnlock()
	}
	return pipeline.Grant{ID: id, Hashes: h}, ok
}

// ObjectGrant is the active grant whose object list names the namespace, kind and name (the scope is the cluster the
// lookups are for).
func (l *Lookups) ObjectGrant(scope, namespace, kind, name string) (string, bool) {
	if scope != l.Cluster {
		return "", false
	}
	key := namespace + "/" + strings.ToLower(kind) + "/" + name // a Metadata-level event spells a kind from the resource name ("Rolloutwatch")
	l.mu.RLock()
	id, ok := l.listed[key]
	l.mu.RUnlock()
	if !ok {
		l.refreshOnMiss()
		l.mu.RLock()
		id, ok = l.listed[key]
		l.mu.RUnlock()
	}
	return id, ok
}

// BreakGlass is the id of a break-glass window open for the cluster. The core lists the windows open now; an event
// delayed past a window's close is not matched to it.
func (l *Lookups) BreakGlass(scope string, _ time.Time) (string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, w := range l.windows {
		if w.Cluster == "" || w.Cluster == scope {
			return w.ID, true
		}
	}
	return "", false
}

// The AWS lookups are not this collector's.
func (l *Lookups) Attestation(string) (string, bool)       { return "", false }
func (l *Lookups) Run(string) (string, bool)               { return "", false }
func (l *Lookups) Session(string, string) (string, bool)   { return "", false }
func (l *Lookups) Plan(string) (pipeline.Plan, bool)       { return pipeline.Plan{}, false }
func (l *Lookups) Window(string, time.Time) (string, bool) { return "", false }
