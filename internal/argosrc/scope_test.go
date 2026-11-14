package argosrc

import (
	"reflect"
	"testing"
)

func TestScopeCorrectionsAreWhatTheDiscoveryDisagreesWithTheBuiltInRulesAbout(t *testing.T) {
	truth := map[string]bool{
		"Namespace":     true, // the built-in rules agree
		"Deployment":    false,
		"Composition":   true, // cluster-scoped, and the rules take it for namespaced
		"Provider":      true,
		"Cluster":       false, // CloudNativePG's: namespaced, and the rules take it (Cluster*) for cluster-scoped
		"ClusterIssuer": true,  // Cluster*: the rules agree
		"ClusterRole":   true,
	}
	want := []string{"!Cluster", "Composition", "Provider"}
	if got := ScopeCorrections(truth); !reflect.DeepEqual(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
	// What the agent writes is what the plugin reads: with the corrections, the plugin's rules say what the cluster says.
	for kind, cluster := range truth {
		if IsClusterScoped(kind, ScopeCorrections(truth)) != cluster {
			t.Errorf("%s: the plugin's rules with the corrections disagree with the cluster", kind)
		}
	}
	if got := ScopeCorrections(nil); got != nil {
		t.Errorf("%v", got)
	}
}
