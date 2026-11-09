package observe

import (
	"encoding/json"
	"strings"
)

// FilteredSchema names the document a collector puts in the detail of its `noise-filtered` health check: how many
// events each noise rule of the observation pipeline dropped since the last record, and the population counts. The
// packet sums them over its window and prints "filtered: N events under rule X" (packet.Params.Filtered). They ride in
// the health record so they are in the chain, covered by its hash, and windowed by its time.
const FilteredSchema = "clearance.observe-filtered/v1"

// FilteredCheck is the name of that check.
const FilteredCheck = "noise-filtered"

// Filtered is the noise-filtered check's detail document.
type Filtered struct {
	Schema   string `json:"schema"`
	Since    string `json:"since"` // the counts cover [Since, Until)
	Until    string `json:"until"`
	RuleSet  string `json:"rule_set"` // "<name>@<version>"
	Filtered []struct {
		Rule  string `json:"rule"`
		Count int    `json:"count"`
		Why   string `json:"why,omitempty"`
	} `json:"filtered"`
	Events     int            `json:"events"`
	Assessed   int            `json:"assessed"`
	NotWrites  int            `json:"not_writes"`
	OutOfScope map[string]int `json:"out_of_scope,omitempty"`
	OwnEvents  int            `json:"collector_own_events"`
	Malformed  int            `json:"malformed"`
	Truncated  bool           `json:"truncated,omitempty"`
}

// ParseFiltered reads the detail of a noise-filtered check; ok is false for anything else.
func ParseFiltered(detail string) (Filtered, bool) {
	var f Filtered
	if err := json.Unmarshal([]byte(detail), &f); err != nil || f.Schema != FilteredSchema {
		return Filtered{}, false
	}
	return f, true
}

// KubeObjectKey is the key two reporters of the same Kubernetes change share: the Argo CD agent's deploy.exception
// (cluster, and each object's kind, namespace and name) and the audit collector's observation (scope, and the
// resource's kind, namespace and name). The cluster name is the scope: both are configured with the same one. The
// packet folds a gate exception and an observation with the same key, close in time, into one exception row.
func KubeObjectKey(scope, kind, namespace, name string) string {
	return strings.Join([]string{scope, kind, namespace, name}, "|")
}
