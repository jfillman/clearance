package pipeline

import (
	"strings"
)

// Platform GitOps (G-ARGO-10a) and what is not a change.
//
// A cluster has two kinds of Argo CD. The gated instance syncs what Clearance cleared: its writes are attributed to a
// grant (identities.argo_controller). The platform instance syncs the cluster repository itself (RBAC, ExternalSecrets,
// the platform's own Secrets): no grant exists for those, and every write it makes is a GitOps sync. The signal
// platform-gitops attributes a write by a platform instance's application controller to the Application whose tracking
// annotation the object carries, and to the revision that Application is synced to. The identity is exact and named in
// identities.platform_gitops; an object with no tracking annotation, or one that names an Application the collector does
// not see, stays out-of-band.

// ArgoApp is an Argo CD Application as the collector's watch sees it.
type ArgoApp struct {
	Namespace, Name string
	// Revision is the revision the Application is synced (or being synced) to: status.sync.revision, or the
	// revisions of a multi-source Application joined with ",". Empty when the Application has not been compared yet.
	Revision string
}

// ArgoApplications is an optional part of Lookups for the platform-gitops signal (see ObjectGrants for the pattern).
// Without it, nothing is attributed to GitOps. Both answers come from the Applications the collector watches, never
// from the event: an event only supplies the key.
type ArgoApplications interface {
	// Application is the Application with this namespace and name.
	Application(scope, namespace, name string) (ArgoApp, bool)
	// ManagedBy is the one Application in appNamespace whose status.resources list the object (kind compared without
	// regard to case, as a Metadata-level audit event spells a kind from the resource name). Used only for a write
	// whose audit event carries no object, hence no tracking annotation (a Secret, a delete). More than one claimant
	// is no answer.
	ManagedBy(scope, appNamespace, namespace, kind, name string) (ArgoApp, bool)
}

// trackingID is Argo CD's annotation value: "[<app namespace>_]<app>:<group>/<kind>:<namespace>/<name>".
type trackingID struct {
	appNS, app            string
	kind, namespace, name string
}

func parseTrackingID(v string) (trackingID, bool) {
	parts := strings.SplitN(v, ":", 3)
	if len(parts) != 3 {
		return trackingID{}, false
	}
	var t trackingID
	t.appNS, t.app = "", parts[0]
	if i := strings.Index(parts[0], "_"); i > 0 {
		t.appNS, t.app = parts[0][:i], parts[0][i+1:]
	}
	_, kind, ok := strings.Cut(parts[1], "/")
	if !ok || kind == "" || t.app == "" {
		return trackingID{}, false
	}
	ns, name, ok := strings.Cut(parts[2], "/")
	if !ok || name == "" {
		return trackingID{}, false
	}
	t.kind, t.namespace, t.name = kind, ns, name
	return t, true
}

// controllerSubjectNS is the namespace of a service-account subject.
func controllerSubjectNS(subject string) string {
	p := strings.Split(subject, ":")
	if len(p) == 4 && p[0] == "system" && p[1] == "serviceaccount" {
		return p[2]
	}
	return ""
}

// platformGitops is the Application and revision a platform instance's write is attributed to, or "".
func (p *Pipeline) platformGitops(e *Event, controller bool) (app ArgoApp, ok bool) {
	if !e.Succeeded || !controller || !contains(p.rs.ids.PlatformGitops, e.Subject) {
		return ArgoApp{}, false
	}
	aa, has := p.lk.(ArgoApplications)
	if !has {
		return ArgoApp{}, false
	}
	ctrlNS := controllerSubjectNS(e.Subject)
	if tid := e.ObjAnnotations[p.rs.ann.TrackingID]; tid != "" {
		t, good := parseTrackingID(tid)
		// The annotation must be about this object: a tracking id copied from another object is no attribution.
		if !good || !strings.EqualFold(t.kind, e.Kind) || t.namespace != e.Namespace || t.name != e.Name {
			return ArgoApp{}, false
		}
		appNS := t.appNS
		if appNS == "" {
			appNS = ctrlNS
		}
		app, ok = aa.Application(e.Scope, appNS, t.app)
	} else if e.After == nil && e.Before == nil && len(e.ObjAnnotations) == 0 && len(e.Labels) == 0 {
		// The event carries no object (a Secret is recorded at Metadata, a delete of an unwatched kind has no body), so
		// there is no annotation to read. The instance's own account of what it manages stands in for it.
		app, ok = aa.ManagedBy(e.Scope, ctrlNS, e.Namespace, e.Kind, e.Name)
	}
	if !ok || app.Revision == "" {
		return ArgoApp{}, false
	}
	return app, true
}

// isController: a service account or system identity acting as itself: no kubectl client, no impersonation, no
// federated agent. Only a controller is attributed through derived objects and only a controller's subresource writes are
// not changes.
func (p *Pipeline) isController(e *Event) bool {
	if e.Type != "serviceaccount" && e.Type != "system" {
		return false
	}
	if strings.HasPrefix(e.UserAgent, p.rs.ids.KubectlUserAgent) || e.Impersonated != "" {
		return false
	}
	return !p.federated(e.Subject)
}

func (p *Pipeline) federated(subject string) bool {
	for _, pre := range p.rs.ids.FederatedPrefix {
		if pre != "" && strings.HasPrefix(subject, pre) {
			return true
		}
	}
	return false
}

// notAChange reports whether a succeeded write is one that changes no object's desired state, and is counted instead of
// assessed: a controller's write to the status subresource, and a service account's create on serviceaccounts/token
// (a TokenRequest mints a credential and changes no object). It is a Scope decision (the write is outside what a
// coverage statement is about), made after the monitoring checks, which it never overrides.
//
// Never for a refusal, a person, kubectl, impersonation or a federated agent, and never for the token of a node
// (system:node:*: a kubelet minting a pod's token is an exact noise rule, so a node that is not named stays visible).
// A status write to an object a valid grant lists, or whose owner chain reaches one, is kept: attribution clears it
// (listed-grant, owner-grant) and the coverage statement counts it as verified. Everything else in the status
// subresource of a service account's or a controller's making is dropped here: scale and every other subresource are
// untouched.
func (p *Pipeline) notAChange(e *Event) bool {
	if e.Provider != Kubernetes || !e.Succeeded || e.Monitoring || e.Subresource == "" {
		return false
	}
	switch {
	case e.Subresource == "status" && e.Verb != "delete" && e.Verb != "deletecollection":
		if !p.isController(e) {
			return false
		}
		listed, owner := p.derivedGrants(e)
		return listed == "" && owner == ""
	case e.Subresource == "token" && e.Verb == "create" && e.Kind == "ServiceAccount":
		return e.Type == "serviceaccount" && p.isController(e)
	}
	return false
}
