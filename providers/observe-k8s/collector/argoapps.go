package collector

import (
	"strings"
	"sync"

	"github.com/jfillman/clearance/internal/observe/pipeline"
)

// argoApps is the index of the Argo CD Applications the collector watches, for pipeline.ArgoApplications: each
// Application by namespace and name with the revision it is synced to, and the resources it manages (status.resources).
// It is fed by the Application watch (Lookups.PutApplication) and holds no copy of the object beyond those two things.
type argoApps struct {
	mu   sync.RWMutex
	apps map[string]*appEntry // "<namespace>/<name>"
}

type appEntry struct {
	app       pipeline.ArgoApp
	resources map[string]struct{} // "<namespace>/<lower-case kind>/<name>"
	// hooks are the resources of status.operationState.syncResult.resources that carry a hookType (the current or last
	// operation), same key as resources. hookRevision is that operation's revision (syncResult.revision, or its multi-source
	// revisions joined with ","); empty when the result names none.
	hooks        map[string]struct{}
	hookRevision string
}

func resKey(ns, kind, name string) string { return ns + "/" + strings.ToLower(kind) + "/" + name }

// revisionOf is the revision an Application is synced to: status.sync.revision, or a multi-source Application's
// status.sync.revisions joined with ",".
func revisionOf(obj map[string]any) string {
	st, _ := obj["status"].(map[string]any)
	sy, _ := st["sync"].(map[string]any)
	if r, _ := sy["revision"].(string); r != "" {
		return r
	}
	var revs []string
	if l, ok := sy["revisions"].([]any); ok {
		for _, r := range l {
			if s, _ := r.(string); s != "" {
				revs = append(revs, s)
			}
		}
	}
	return strings.Join(revs, ",")
}

// hooksOf reads the sync hooks of the Application's current or last operation: status.operationState.syncResult.resources
// entries with a hookType (Argo CD v3.5.0 ResourceResult.HookType is empty for a non-hook resource), and the operation's revision.
func hooksOf(obj map[string]any) (map[string]struct{}, string) {
	st, _ := obj["status"].(map[string]any)
	op, _ := st["operationState"].(map[string]any)
	sr, _ := op["syncResult"].(map[string]any)
	if sr == nil {
		return nil, ""
	}
	rev, _ := sr["revision"].(string)
	if rev == "" {
		var revs []string
		l, _ := sr["revisions"].([]any)
		for _, r := range l {
			if s, _ := r.(string); s != "" {
				revs = append(revs, s)
			}
		}
		rev = strings.Join(revs, ",")
	}
	hooks := map[string]struct{}{}
	l, _ := sr["resources"].([]any)
	for _, r := range l {
		m, _ := r.(map[string]any)
		kind, _ := m["kind"].(string)
		name, _ := m["name"].(string)
		ns, _ := m["namespace"].(string)
		if ht, _ := m["hookType"].(string); ht != "" && kind != "" && name != "" {
			hooks[resKey(ns, kind, name)] = struct{}{}
		}
	}
	return hooks, rev
}

func (x *argoApps) put(typ string, obj map[string]any) {
	ns, name, _ := metaOf(obj)
	if name == "" {
		return
	}
	k := ns + "/" + name
	x.mu.Lock()
	defer x.mu.Unlock()
	if typ == "DELETED" {
		delete(x.apps, k)
		return
	}
	e := &appEntry{app: pipeline.ArgoApp{Namespace: ns, Name: name, Revision: revisionOf(obj)}, resources: map[string]struct{}{}}
	st, _ := obj["status"].(map[string]any)
	if l, ok := st["resources"].([]any); ok {
		for _, r := range l {
			m, _ := r.(map[string]any)
			kind, _ := m["kind"].(string)
			rn, _ := m["name"].(string)
			rns, _ := m["namespace"].(string)
			if kind != "" && rn != "" {
				e.resources[resKey(rns, kind, rn)] = struct{}{}
			}
		}
	}
	e.hooks, e.hookRevision = hooksOf(obj)
	if x.apps == nil {
		x.apps = map[string]*appEntry{}
	}
	x.apps[k] = e
}

func (x *argoApps) application(namespace, name string) (pipeline.ArgoApp, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	e, ok := x.apps[namespace+"/"+name]
	if !ok {
		return pipeline.ArgoApp{}, false
	}
	return e.app, true
}

func (x *argoApps) managedBy(appNamespace, namespace, kind, name string) (pipeline.ArgoApp, bool) {
	k := resKey(namespace, kind, name)
	x.mu.RLock()
	defer x.mu.RUnlock()
	var found pipeline.ArgoApp
	n := 0
	for _, e := range x.apps {
		if e.app.Namespace != appNamespace {
			continue
		}
		if _, ok := e.resources[k]; ok {
			found = e.app
			n++
		}
	}
	return found, n == 1
}

func (x *argoApps) hookOf(appNamespace, namespace, kind, name string) (pipeline.ArgoApp, bool) {
	k := resKey(namespace, kind, name)
	x.mu.RLock()
	defer x.mu.RUnlock()
	var found pipeline.ArgoApp
	n := 0
	for _, e := range x.apps {
		if e.app.Namespace != appNamespace {
			continue
		}
		if _, ok := e.hooks[k]; ok {
			found = e.app
			if e.hookRevision != "" {
				found.Revision = e.hookRevision
			}
			n++
		}
	}
	return found, n == 1
}

// PutApplication records an Application the watch delivered (typ ADDED, MODIFIED or DELETED).
func (l *Lookups) PutApplication(typ string, obj map[string]any) { l.apps.put(typ, obj) }

var _ pipeline.ArgoApplications = (*Lookups)(nil)

// Application is the watched Application with this namespace and name.
func (l *Lookups) Application(scope, namespace, name string) (pipeline.ArgoApp, bool) {
	if scope != l.Cluster {
		return pipeline.ArgoApp{}, false
	}
	return l.apps.application(namespace, name)
}

// ManagedBy is the one watched Application in appNamespace whose status.resources list the object.
func (l *Lookups) ManagedBy(scope, appNamespace, namespace, kind, name string) (pipeline.ArgoApp, bool) {
	if scope != l.Cluster {
		return pipeline.ArgoApp{}, false
	}
	return l.apps.managedBy(appNamespace, namespace, kind, name)
}

var _ pipeline.ArgoHooks = (*Lookups)(nil)

// HookOf is the one watched Application in appNamespace whose current or last operation lists the object as a sync hook.
func (l *Lookups) HookOf(scope, appNamespace, namespace, kind, name string) (pipeline.ArgoApp, bool) {
	if scope != l.Cluster {
		return pipeline.ArgoApp{}, false
	}
	return l.apps.hookOf(appNamespace, namespace, kind, name)
}
