package argosrc

import (
	"sort"
	"strings"
)

// The scope rules of the Clearance plugin. Argo CD asks the cluster's discovery whether a kind takes a namespace; a
// plugin cannot, so it has this list. It lives here, not in the plugin's main package, so the agent that writes the
// plugin's `clusterScopedKinds` parameter (G-ARGO-10c) uses the very rules the plugin applies.

var builtinClusterScoped = map[string]bool{}

func init() {
	for _, k := range []string{"Namespace", "Node", "PersistentVolume", "StorageClass", "PriorityClass", "IngressClass",
		"RuntimeClass", "CSIDriver", "CSINode", "VolumeAttachment", "APIService", "CustomResourceDefinition",
		"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", "ValidatingAdmissionPolicy",
		"ValidatingAdmissionPolicyBinding", "MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding",
		"CertificateSigningRequest", "GatewayClass", "VolumeSnapshotClass", "VolumeSnapshotContent", "ValidatingPolicy",
		"MutatingPolicy", "GeneratingPolicy", "PolicyException", "ResourceQuotaClass", "TokenReview",
		"SubjectAccessReview", "SelfSubjectAccessReview", "SelfSubjectRulesReview"} {
		builtinClusterScoped[k] = true
	}
}

// BuiltinClusterScoped is the plugin's own guess: the listed kinds, and any kind named Cluster*.
func BuiltinClusterScoped(kind string) bool {
	return builtinClusterScoped[kind] || strings.HasPrefix(kind, "Cluster")
}

// IsClusterScoped is whether kind takes no namespace. extra is the Application's clusterScopedKinds: a kind in it is
// cluster-scoped; `!Kind` says the opposite, for a kind the built-in rules guess wrongly (CloudNativePG's `Cluster`
// is namespaced, though it is named Cluster*).
func IsClusterScoped(kind string, extra []string) bool {
	for _, k := range extra {
		if k == "!"+kind {
			return false
		}
	}
	if BuiltinClusterScoped(kind) {
		return true
	}
	for _, k := range extra {
		if k == kind {
			return true
		}
	}
	return false
}

// ScopeCorrections is the clusterScopedKinds parameter that makes the plugin's rules agree with a cluster's discovery
// (truth: kind -> cluster-scoped): `Kind` for a kind the cluster says is cluster-scoped and the built-in rules take
// for namespaced, `!Kind` for the reverse. Sorted, so the parameter is the same whenever the cluster's answer is.
func ScopeCorrections(truth map[string]bool) []string {
	var out []string
	for kind, cluster := range truth {
		switch {
		case cluster && !BuiltinClusterScoped(kind):
			out = append(out, kind)
		case !cluster && BuiltinClusterScoped(kind):
			out = append(out, "!"+kind)
		}
	}
	sort.Strings(out)
	return out
}
