package collector

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"
)

const historyDepth = 4

type version struct {
	rv   string
	at   time.Time // when the collector saw it
	hash string    // pipeline.CanonicalHash: desired state
	obj  map[string]any
}

type cacheKey struct{ kind, ns, name string }

// Cache keeps the last few versions of each watched object, so an audit event (which carries only the new state) can
// be given the state before it (RawEvent.Before), and so a change to desired state can be told from a status write.
type Cache struct {
	mu   sync.Mutex
	hash func(map[string]any) string
	objs map[cacheKey][]version
}

// NewCache builds a Cache; hash is the pipeline's CanonicalHash.
func NewCache(hash func(map[string]any) string) *Cache {
	return &Cache{hash: hash, objs: map[cacheKey][]version{}}
}

// Change is what Put saw happen to an object.
type Change struct {
	Kind, Namespace, Name string
	RV                    string
	At                    time.Time
	Created, Deleted      bool
	// Desired: the desired state changed (a create, a delete, or a different canonical hash); a status write is not.
	Desired       bool
	Before, After map[string]any
}

func metaOf(o map[string]any) (ns, name, rv string) {
	m, _ := o["metadata"].(map[string]any)
	ns, _ = m["namespace"].(string)
	name, _ = m["name"].(string)
	rv, _ = m["resourceVersion"].(string)
	return
}

// Put records a version the watch delivered. typ is ADDED, MODIFIED or DELETED. initial: a list result (the state the
// collector started from), which is remembered and reports no change.
func (c *Cache) Put(kind, typ string, obj map[string]any, at time.Time, initial bool) (Change, bool) {
	ns, name, rv := metaOf(obj)
	if name == "" {
		return Change{}, false
	}
	k := cacheKey{kind, ns, name}
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.hash(obj)
	vs := c.objs[k]
	ch := Change{Kind: kind, Namespace: ns, Name: name, RV: rv, At: at, After: obj}
	if len(vs) > 0 {
		ch.Before = vs[len(vs)-1].obj
	}
	switch {
	case typ == "DELETED":
		ch.Deleted, ch.Desired = true, true
		ch.After = nil
		if len(vs) > 0 {
			ch.Before = vs[len(vs)-1].obj
		} else {
			ch.Before = obj
		}
		delete(c.objs, k)
		// the last versions are kept for the audit event of the delete, which arrives after the watch event
		c.objs[cacheKey{kind, ns, name + "\x00deleted"}] = append(vs, version{rv, at, h, obj})
		return ch, !initial
	case len(vs) == 0:
		ch.Created, ch.Desired = true, true
	case vs[len(vs)-1].rv == rv:
		return Change{}, false // a repeat (a bookmark, a re-list)
	default:
		ch.Desired = vs[len(vs)-1].hash != h
	}
	vs = append(vs, version{rv, at, h, obj})
	if len(vs) > historyDepth {
		vs = vs[len(vs)-historyDepth:]
	}
	c.objs[k] = vs
	if initial {
		return Change{}, false
	}
	return ch, true
}

// Before is the object as it stood before the change an audit event reports, or nil when the cache has no such
// version. eventRV is the resourceVersion the event's response object carries ("" at Metadata); at is the event's time.
// With a resourceVersion the answer is exact: the newest version older than it. Without one, the audit event is
// expected to have been seen after the watch event, so the object before it is the second newest version if the
// newest was seen at about the event's time, else the newest.
func (c *Cache) Before(kind, ns, name, eventRV string, at time.Time, deleted bool) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	vs := c.objs[cacheKey{kind, ns, name}]
	if deleted || len(vs) == 0 {
		if d := c.objs[cacheKey{kind, ns, name + "\x00deleted"}]; len(d) > 0 {
			if len(d) >= 2 {
				return d[len(d)-2].obj
			}
			return d[len(d)-1].obj
		}
	}
	if len(vs) == 0 {
		return nil
	}
	if eventRV != "" {
		e, err := strconv.ParseUint(eventRV, 10, 64)
		if err == nil {
			var best map[string]any
			for _, v := range vs {
				if n, err := strconv.ParseUint(v.rv, 10, 64); err == nil && n < e {
					best = v.obj
				}
			}
			return best
		}
	}
	newest := vs[len(vs)-1]
	if len(vs) >= 2 && !at.IsZero() && newest.at.Sub(at) > -time.Minute && newest.at.Sub(at) < time.Minute {
		return vs[len(vs)-2].obj
	}
	return newest.obj
}

// JSON is obj as a RawEvent.Before.
func JSON(obj map[string]any) json.RawMessage {
	if obj == nil {
		return nil
	}
	b, _ := json.Marshal(obj)
	return b
}

// Prune forgets the history kept for deleted objects once it is older than ttl.
func (c *Cache) Prune(now time.Time, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, vs := range c.objs {
		if strings.HasSuffix(k.name, deletedSuffix) && len(vs) > 0 && now.Sub(vs[len(vs)-1].at) > ttl {
			delete(c.objs, k)
		}
	}
}

const deletedSuffix = "\x00deleted"
