// Package agent is the Argo CD gate's agent on a protected cluster (G-ARGO-3): one controller, three loops.
//
//   - grant sync: reads the core's signed grant feed as the agent's own identity, verifies it and every token in it,
//     and keeps a ClearanceGrant per cleared change and protected namespace (create, update, remove; expiry through
//     status.valid; exactly one active grant per namespace);
//   - outcomes: watches Argo CD Applications and posts one deploy.outcome per finished operation;
//   - exceptions: compares what runs in the protected namespaces with the grants and posts deploy.exception for what
//     no grant covers, and for a sync the admission policy refused.
//
// It holds no key and decides nothing: Clearance's core decides, the admission policy enforces, the agent carries the
// core's signed answer to the cluster and the cluster's facts back. With the core unreachable it stops updating
// grants, lets them expire on their own clock and touches nothing that runs (docs/gate.md, "The Argo CD agent").
package agent

import (
	"encoding/json"
	"strings"
)

// Names the gate's cluster vocabulary: labels and annotations on grants, namespaces and rendered objects.
const (
	AnnRendered = "clearance.hangar.io/rendered" // an object's stamped hash (the CMP)
	AnnGrant    = "clearance.hangar.io/grant"    // the grant (change id) the object was rendered for
	AnnTree     = "clearance.hangar.io/tree"     // the tree digest it was rendered in
	AnnTracking = "argocd.argoproj.io/tracking-id"
	AnnRelease  = "hangar.io/release-id"

	LabelProtected   = "clearance.hangar.io/protected" // namespace: the gate protects it
	LabelActive      = "clearance.hangar.io/active"    // grant: the one the admission policy reads
	LabelManagedBy   = "app.kubernetes.io/managed-by"
	LabelApp         = "clearance.hangar.io/app"
	LabelChange      = "clearance.hangar.io/change"
	LabelEnvironment = "clearance.hangar.io/environment" // namespace: the environment it belongs to
	ManagedBy        = "clearance-argocd-agent"
)

// ProviderName is the provider the core registers the agent as (CLEARANCE_PROVIDERS); every record names it with the
// agent's version in source.provider.
const ProviderName = "argocd-agent"

// GrantObject is one object a grant lists. Rendered is the hash the CMP stamps on it.
type GrantObject struct {
	Group    string `json:"group"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Rendered string `json:"rendered"`
	Changed  bool   `json:"changed"`
}

// GrantKey is how a grant indexes an object: <group>/<kind>/<name> (the admission policy builds the same key from
// the admitted object; a core object has an empty group).
func GrantKey(group, kind, name string) string { return group + "/" + kind + "/" + name }

// GrantSpec is the ClearanceGrant spec the agent writes (the CRD is G-ARGO-2's).
type GrantSpec struct {
	Subject struct {
		Commit string `json:"commit"`
		Tree   string `json:"tree"`
	} `json:"subject"`
	ExpiresAt string `json:"expiresAt"`
	Clearance struct {
		ID   string `json:"id"`
		Tier int    `json:"tier"`
	} `json:"clearance"`
	Objects []GrantObject     `json:"objects"`
	Index   map[string]string `json:"index"`
}

// Grant is a ClearanceGrant: namespaced, with the agent's status.valid.
type Grant struct {
	Namespace string            `json:"-"`
	Name      string            `json:"-"`
	Labels    map[string]string `json:"-"`
	Spec      GrantSpec         `json:"spec"`
	Valid     *bool             `json:"-"` // status.valid; nil: never set
}

// Active reports whether g carries the active label.
func (g Grant) Active() bool { return g.Labels[LabelActive] == "true" }

// Object is a live namespaced object as the exception scan and the outcome read it.
type Object struct {
	APIVersion  string
	Kind        string
	Namespace   string
	Name        string
	UID         string
	Labels      map[string]string
	Annotations map[string]string
	Owned       bool   // controlled by another object (a controller made it, not a writer)
	Manager     string // the field manager of the newest write
}

// Group is the object's API group ("" for the core group).
func (o Object) Group() string {
	g, _, ok := strings.Cut(o.APIVersion, "/")
	if !ok {
		return ""
	}
	return g
}

// Resource names a kind the scan lists.
type Resource struct {
	Group, Version, Plural string
}

// Application is the slice of an Argo CD Application the agent reads.
type Application struct {
	Namespace string
	Name      string
	UID       string
	Project   string
	DestNS    string
	SyncState string
	Health    string
	Revisions []string // status.sync.revisions (or revision)
	Op        *Operation
}

// Operation is status.operationState.
type Operation struct {
	Phase      string
	Message    string
	StartedAt  string
	FinishedAt string
	Revisions  []string
	Resources  []SyncResource
}

// SyncResource is one syncResult.resources entry.
type SyncResource struct {
	Group, Version, Kind, Namespace, Name, Status, Message string
}

// Terminal says whether an operation phase is final.
func Terminal(phase string) bool {
	return phase == "Succeeded" || phase == "Failed" || phase == "Error"
}

func rawJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
