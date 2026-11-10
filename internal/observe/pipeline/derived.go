package pipeline

import "strings"

// Derived objects: a controller's write to an object a granted object owns (a ReplicaSet of a granted Rollout, a Pod of
// that ReplicaSet, a Job's Pod) is the grant's change taking effect, not a second change. The pipeline walks the object's
// ownerReferences up to an object some valid grant lists (ObjectGrants), and attributes the write to that grant, but
// only for a controller: a person, a kubectl client or an impersonation that edits a derived object is still out-of-band.
//
// An audit event carries the owners of the object it wrote when it carries the object (a write, a delete's response).
// The pipeline remembers the owners of every object it has seen, so a write with no body (a delete, a Metadata-level
// event) and the second hop of a chain (a Pod's ReplicaSet is owned by a Rollout it saw when it saw the ReplicaSet) can
// still be walked. The memory is in process and bounded: a restart forgets it, and an unwalkable chain is not attributed
// (it stays out-of-band, the safe direction).

const (
	// ownerIndexMax is how many objects the owner memory holds per generation; two generations are kept.
	ownerIndexMax = 20000
	// ownerDepth is how many ownerReference hops are followed.
	ownerDepth = 4
)

// Signals the pipeline's own code recognises by name (the rules that use them are in the bundle).
const (
	SignalUnknownGrant = "grant-annotation.unknown"
	SignalOwnerGrant   = "owner-grant"
	SignalListedGrant  = "listed-grant"
)

type ownerIndex struct {
	cur, old map[string][]Owner
}

func objKey(ns, kind, name string) string { return ns + "/" + strings.ToLower(kind) + "/" + name }

func (x *ownerIndex) get(k string) ([]Owner, bool) {
	if o, ok := x.cur[k]; ok {
		return o, true
	}
	o, ok := x.old[k]
	return o, ok
}

func (x *ownerIndex) put(k string, o []Owner) {
	if x.cur == nil {
		x.cur = map[string][]Owner{}
	}
	if len(x.cur) >= ownerIndexMax {
		x.old, x.cur = x.cur, map[string][]Owner{}
	}
	x.cur[k] = o
}

// learn remembers what an event shows of its object's owners. Called for every normalized write, whatever becomes of it.
func (p *Pipeline) learn(e *Event) {
	if e.Provider != Kubernetes || e.Name == "" || e.Kind == "" || len(e.Owners) == 0 {
		return
	}
	p.owners.put(objKey(e.Namespace, e.Kind, e.Name), e.Owners)
}

// ownersOf is the owners the event's object has: its own, or what an earlier event showed.
func (p *Pipeline) ownersOf(e *Event) []Owner {
	if len(e.Owners) > 0 {
		return e.Owners
	}
	if o, ok := p.owners.get(objKey(e.Namespace, e.Kind, e.Name)); ok {
		return o
	}
	return nil
}

// objectGrant is the active grant that lists the object, if the lookups can say.
func (p *Pipeline) objectGrant(e *Event, ns, kind, name string) (string, bool) {
	og, ok := p.lk.(ObjectGrants)
	if !ok {
		return "", false
	}
	return og.ObjectGrant(e.Scope, ns, kind, name)
}

// derivedGrants is the grant that lists the event's own object (listed), and, when the object is not listed itself, the
// grant an object up its owner chain is listed under (owner).
func (p *Pipeline) derivedGrants(e *Event) (listed, owner string) {
	if e.Name == "" || e.Kind == "" {
		return "", ""
	}
	if g, ok := p.objectGrant(e, e.Namespace, e.Kind, e.Name); ok {
		return g, ""
	}
	seen := map[string]bool{}
	level := p.ownersOf(e)
	for depth := 0; depth < ownerDepth && len(level) > 0; depth++ {
		var next []Owner
		for _, o := range level {
			k := objKey(e.Namespace, o.Kind, o.Name)
			if seen[k] {
				continue
			}
			seen[k] = true
			if g, ok := p.objectGrant(e, e.Namespace, o.Kind, o.Name); ok {
				return "", g
			}
			if up, ok := p.owners.get(k); ok {
				next = append(next, up...)
			}
		}
		level = next
	}
	return "", ""
}
