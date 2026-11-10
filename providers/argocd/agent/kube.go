package agent

import (
	"context"
	"encoding/json"
	"time"
)

// Kube is the cluster the agent runs on, as far as it reaches it. kubeapi.go is the REST implementation (in-cluster,
// no client library); the tests use an in-memory one, which is the fake Argo CD too.
type Kube interface {
	// ProtectedNamespaces are the namespaces labelled clearance.hangar.io/protected=true, with their labels.
	ProtectedNamespaces(ctx context.Context) (map[string]map[string]string, error)

	// ListGrants are the grants the agent manages, in every namespace.
	ListGrants(ctx context.Context) ([]Grant, error)
	// CreateGrant creates a grant the caller has seen is absent. If something created it in between (a 409) it reads
	// the grant and writes only when spec or labels differ. It never touches status.
	CreateGrant(ctx context.Context, g Grant) error
	// UpdateGrant replaces the spec and labels of a grant that exists, in the state cur (as listed): a patch, never a
	// create, so a refused attempt is not made. The caller has compared first and calls it only when g differs.
	UpdateGrant(ctx context.Context, g, cur Grant) error
	// SetGrantValid writes the grant's status.valid (the status subresource: only the agent has it).
	SetGrantValid(ctx context.Context, namespace, name string, valid bool, reason string, at time.Time) error
	DeleteGrant(ctx context.Context, namespace, name string) error

	// ListApplications and WatchApplications read the Applications in the Argo CD namespace. A watch starts after
	// resourceVersion rv and calls fn per added or modified Application until ctx ends or the stream breaks (it
	// returns the error; ErrWatchGone says rv is too old: list again).
	ListApplications(ctx context.Context) (apps []Application, rv string, err error)
	WatchApplications(ctx context.Context, rv string, fn func(Application)) error

	// ListObjects are the objects of one kind in one namespace.
	ListObjects(ctx context.Context, res Resource, namespace string) ([]ObjectDetail, error)

	// GetData and PutData keep the agent's state in a ConfigMap.
	GetData(ctx context.Context, namespace, name string) (map[string]string, error)
	PutData(ctx context.Context, namespace, name string, data map[string]string) error
}

// ObjectDetail is an Object with the last-applied configuration Argo CD (client-side apply) left on it.
type ObjectDetail struct {
	Object
	LastApplied string
	Spec        json.RawMessage // the live spec, read for Jobs only (isWaitJob)
}
