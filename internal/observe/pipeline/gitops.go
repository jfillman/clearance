package pipeline

import (
	"slices"
	"strings"
	"time"
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

// ArgoHooks is an optional part of Lookups, beside ArgoApplications: the sync hooks an Application's operation recorded.
// A hook (a Job with argocd.argoproj.io/hook, say) is created and deleted by the controller during a sync and carries no
// tracking annotation, so the only account of it is the Application's status.operationState.syncResult.resources, where Argo CD
// records every hook it ran with a hookType (v3.5.0, ResourceResult.HookType: "Empty for non-hook resources").
type ArgoHooks interface {
	// HookOf is the one Application in appNamespace whose current or last operation's sync result lists the object as a hook
	// (a resource with a hookType; kind compared without regard to case). The returned Revision is the revision of that
	// operation (syncResult.revision, or the revisions of a multi-source sync joined with ","), else status.sync.revision. More
	// than one claimant is no answer.
	HookOf(scope, appNamespace, namespace, kind, name string) (ArgoApp, bool)
}

// ArgoHookHistory is an optional part of Lookups, beside ArgoHooks: the sync hooks of the operation an Application's current one
// replaced, kept for a bounded window (HookCleanupWindow) after the replacement. The TTL controller and the garbage collector
// remove a finished hook Job minutes after the sync that ran it, and the next operation may already have replaced the list.
type ArgoHookHistory interface {
	// HookOfRecent is HookOf, also counting the previous operation's hooks when the current one replaced them no longer ago than
	// the window at the time "at". An Application whose current operation lists the object answers with the current operation
	// (revision and all); otherwise one whose previous operation does answers with that operation's revision. More than one
	// claimant, across both lists, is no answer.
	HookOfRecent(scope, appNamespace, namespace, kind, name string, at time.Time) (ArgoApp, bool)
}

// HookCleanupWindow is how long after an operation was replaced its hooks still count for HookOfRecent. Kubernetes removes a hook
// Job when its ttlSecondsAfterFinished passes (seconds to minutes, rarely more); an hour covers that and no more.
const HookCleanupWindow = time.Hour

const (
	subjTTLController = "system:serviceaccount:kube-system:ttl-after-finished-controller"
	subjGC            = "system:serviceaccount:kube-system:generic-garbage-collector"
)

// isHook says an object carries an annotation Argo CD honours as a sync hook: argocd.argoproj.io/hook (any value but Skip,
// which Argo does not apply at all) or helm.sh/hook (Argo translates Helm's hooks to its own).
func isHook(ann map[string]string) bool {
	if v := strings.TrimSpace(ann[annArgoHook]); v != "" {
		return !strings.EqualFold(v, "Skip")
	}
	return strings.TrimSpace(ann[annHelmHook]) != ""
}

const (
	annArgoHook = "argocd.argoproj.io/hook"
	annHelmHook = "helm.sh/hook"
)

// trackingID is Argo CD's annotation value: "[<app namespace>_]<app>:<group>/<kind>:<namespace>/<name>". For a
// cluster-scoped object Argo CD (v3.5.0, util/argo/resource_tracking.go, UnstructuredToAppInstanceValue) writes the
// Application's destination namespace where the object has none: ClusterRole x of an Application deploying to clearance-system
// carries ":clearance-system/x". The namespace part of a cluster-scoped object's id is therefore the Application's, not the
// object's, and is not compared.
type trackingID struct {
	appNS, app            string
	kind, namespace, name string
	group                 string
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
	group, kind, ok := strings.Cut(parts[1], "/")
	if !ok || kind == "" || t.app == "" {
		return trackingID{}, false
	}
	ns, name, ok := strings.Cut(parts[2], "/")
	if !ok || name == "" {
		return trackingID{}, false
	}
	t.kind, t.namespace, t.name, t.group = kind, ns, name, group
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
		// Group, kind and name always; the namespace only for a namespaced object (see trackingID).
		if !good || t.group != e.Group || !strings.EqualFold(t.kind, e.Kind) || t.name != e.Name ||
			(e.Namespace != "" && t.namespace != e.Namespace) {
			return ArgoApp{}, false
		}
		appNS := t.appNS
		if appNS == "" {
			appNS = ctrlNS
		}
		app, ok = aa.Application(e.Scope, appNS, t.app)
	} else if isHook(e.ObjAnnotations) {
		// A sync hook carries no tracking annotation. It is attributed only when exactly one Application of the instance
		// lists it, as a hook, in its current or last operation's sync result. The annotation is read from the object, or from
		// the before-state of a delete (hook-delete-policy).
		if hk, has := p.lk.(ArgoHooks); has {
			app, ok = hk.HookOf(e.Scope, ctrlNS, e.Namespace, e.Kind, e.Name)
		}
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

// hookCleanup is the Application and revision of the platform GitOps change whose sync hook Kubernetes itself is removing, or "".
// A hook Job with ttlSecondsAfterFinished is deleted by the TTL controller; its dependents (the hook ServiceAccount, Role,
// RoleBinding, owned by the Job) and sometimes the Job itself by the garbage collector. Those are the consequence of the sync,
// not a new change, and carry no tracking annotation. Deny by default: all of these must hold.
//   - the actor is exactly the TTL controller deleting a Job, or exactly the garbage collector deleting any object, a succeeded
//     "delete", acting as itself (isController);
//   - the event shows the deleted object (the response body or the collector's before-state: ObjectSeen), never a Metadata-level
//     event that shows nothing;
//   - the object is a Job that exactly one Application in a platform instance's namespace lists as a hook (HookOfRecent: the
//     current operation, or the previous one within HookCleanupWindow); or, for the garbage collector only, a namespaced object
//     with an ownerReference of kind Job naming such a hook Job, or one that itself carries a hook annotation and is so listed.
//
// A person, another service account and a different verb never match. Attribution is to the Application and the revision of the
// operation that listed the hook, like the hook's own write.
func (p *Pipeline) hookCleanup(e *Event, controller bool) (ArgoApp, bool) {
	gc := e.Subject == subjGC
	// The garbage collector finishes a foreground delete of the hook Job by patching its finalizers off through the
	// metadata-only client (a PartialObjectMetadata body), seen live on hangar-prod 2026-11-12 right after the TTL
	// controller's delete. That patch is part of the same cleanup; any other patch is not.
	gcFinalize := gc && e.Verb == "patch" && e.PartialMetadata && strings.EqualFold(e.Kind, "Job")
	if !e.Succeeded || !controller || e.Provider != Kubernetes || (e.Verb != "delete" && !gcFinalize) || !e.ObjectSeen ||
		e.Name == "" || e.Namespace == "" {
		return ArgoApp{}, false
	}
	if !gc && !(e.Subject == subjTTLController && strings.EqualFold(e.Kind, "Job")) {
		return ArgoApp{}, false
	}
	hk, has := p.lk.(ArgoHookHistory)
	if !has || len(p.rs.ids.PlatformGitops) == 0 {
		return ArgoApp{}, false
	}
	// The platform instances' namespaces: the Applications are searched there, and nowhere else.
	var nss []string
	for _, s := range p.rs.ids.PlatformGitops {
		if ns := controllerSubjectNS(s); ns != "" && !slices.Contains(nss, ns) {
			nss = append(nss, ns)
		}
	}
	// listed is the one Application, over all those namespaces, that lists this object as a hook; two is none.
	listed := func(kind, name string) (ArgoApp, bool) {
		var found ArgoApp
		n := 0
		for _, ns := range nss {
			if a, ok := hk.HookOfRecent(e.Scope, ns, e.Namespace, kind, name, e.Time); ok {
				found = a
				n++
			}
		}
		return found, n == 1
	}
	var app ArgoApp
	var ok bool
	switch {
	case strings.EqualFold(e.Kind, "Job"):
		app, ok = listed("Job", e.Name)
	case gc && isHook(e.ObjAnnotations):
		app, ok = listed(e.Kind, e.Name)
	}
	if !ok && gc && !strings.EqualFold(e.Kind, "Job") {
		// The object is owned by a hook Job. Every Job owner must be one Application's hook; two different Applications' is none.
		var owned ArgoApp
		n := 0
		for _, o := range e.Owners {
			if o.Kind != "Job" || o.Name == "" {
				continue
			}
			a, good := listed("Job", o.Name)
			if !good || (n > 0 && (a.Namespace != owned.Namespace || a.Name != owned.Name)) {
				return ArgoApp{}, false
			}
			owned, n = a, n+1
		}
		app, ok = owned, n > 0
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

// ArgoIndexState is an optional part of Lookups: whether the Application index is complete enough to attribute from (every
// Application watch has listed at least once). A platform-gitops write assessed before it is would find no Application and be
// recorded out-of-band for a reason that has nothing to do with the write, so the pipeline holds such a write (HoldUnsyncedApplications)
// until it is true.
type ArgoIndexState interface {
	ApplicationsSynced() bool
}

// PlatformGitopsConfigured says the rule set names a platform Argo CD instance, so the Application index matters.
func (p *Pipeline) PlatformGitopsConfigured() bool { return len(p.rs.ids.PlatformGitops) > 0 }

// holdForIndex: a succeeded write by a platform instance's application controller, while the Application index has not
// synced. The write is held, not decided: the caller gives it back as Final after the index syncs or its timeout.
func (p *Pipeline) holdForIndex(e *Event) bool {
	if !p.holdIndex || e.Provider != Kubernetes || !e.Succeeded || !contains(p.rs.ids.PlatformGitops, e.Subject) || !p.isController(e) {
		return false
	}
	st, ok := p.lk.(ArgoIndexState)
	return ok && !st.ApplicationsSynced()
}

// notARefusal reports whether a failed write by a controller is not a security refusal, and is counted out of scope instead
// of assessed as attempted-refused. attempted-refused means the system said no to a caller it did not trust: 401, 403, or an
// admission denial (a webhook or a policy denied it, whatever code it carries). A 409 Conflict (a status update that lost
// an optimistic-concurrency race, a create that found the object already there), a 404 NotFound (a delete or patch of an
// object that is gone) and a 422 Invalid that admission did not deny are an ordinary controller's retries: nothing was
// refused for who the caller is. Never for an operation on monitoring, a person, kubectl, impersonation or a federated agent
// (a controller is a service account or a system identity acting as itself, see isController), nor for any other code.
func (p *Pipeline) notARefusal(e *Event) bool {
	if e.Provider != Kubernetes || e.Succeeded || e.Monitoring || e.AdmissionDenied || !p.isController(e) {
		return false
	}
	switch e.Code {
	case 404, 409, 422:
		return true
	}
	return false
}

// controllerChild reports whether a succeeded write is a kube-system controller managing an object it created: a
// ReplicaSet controller creating the Pods of a ReplicaSet, a Deployment controller its ReplicaSets, a Job controller its Pods,
// a CronJob controller its Jobs, the garbage collector and the TTL controller removing what is finished. That is the
// consequence of a desired-state change someone else made (the Deployment, the Job), not a change to desired state, and it
// is counted out of scope (scope.controller_children names the exact controllers and the kinds).
//
// The object must have a controller ownerReference, as the event shows it (the body, the collector's before-state) or the
// pipeline remembered an earlier event show it. A Metadata-level event that shows nothing of the object cannot be checked;
// the controller's identity and the child kinds it may write stand for it. An object that is shown without one is not a child.
// Never an operation on monitoring, a refusal, a person or another service account, and not when attribution can
// already tie the write to a grant (a granted object's derived children stay cleared and counted as verified).
func (p *Pipeline) controllerChild(e *Event) bool {
	if e.Provider != Kubernetes || !e.Succeeded || e.Monitoring {
		return false
	}
	rule, ok := p.rs.children[e.Subject]
	kinds := rule.Kinds
	if !ok || (!slices.Contains(kinds, e.Kind) && !slices.Contains(kinds, "*")) || slices.Contains(monitoringKinds, e.Kind) ||
		!p.isController(e) {
		return false
	}
	if len(rule.Verbs) > 0 && !slices.Contains(rule.Verbs, e.Verb) &&
		!(e.PartialMetadata && slices.Contains(rule.PartialMetadataVerbs, e.Verb)) {
		return false
	}
	seen, controlled := e.ObjectSeen, e.ControllerOwned
	if remembered := p.ownersOf(e); len(remembered) > 0 && !controlled {
		seen = true
		for _, o := range remembered {
			controlled = controlled || o.Controller
		}
	}
	if seen && !controlled {
		return false
	}
	listed, owner := p.derivedGrants(e)
	return listed == "" && owner == ""
}
