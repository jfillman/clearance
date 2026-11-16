package charttest

import (
	"strings"
	"testing"
)

// The api's opt-in /metrics listener: nothing rendered when unset; the port but no rule when set without peers; the rule
// for that port only, from the named peers, when peers are named.
func TestAPIMetricsPortAndNetworkPolicy(t *testing.T) {
	ports := func(objs []obj) (names []string) {
		l, _ := get(container(t, find(objs, "Deployment", "t-clearance-api")), "ports").([]any)
		for _, p := range l {
			names = append(names, get(p, "name").(string))
		}
		return
	}
	rules := func(objs []obj) []any {
		np := find(objs, "NetworkPolicy", "t-clearance-api")
		if np == nil {
			t.Fatal("no api NetworkPolicy")
		}
		l, _ := get(np, "spec", "ingress").([]any)
		return l
	}
	base := []string{"-f", valuesFile("full-values.yaml")}

	off := render(t, base...)
	if strings.Join(ports(off), ",") != "http" {
		t.Errorf("unset: ports %v", ports(off))
	}
	if e := env(container(t, find(off, "Deployment", "t-clearance-api"))); e["CLEARANCE_API_METRICS_LISTEN"] != "" {
		t.Errorf("unset: %q", e["CLEARANCE_API_METRICS_LISTEN"])
	}
	for _, r := range rules(off) {
		for _, p := range get(r, "ports").([]any) {
			if get(p, "port") != 8080 {
				t.Errorf("unset: ingress on %v", get(p, "port"))
			}
		}
	}

	noPeers := render(t, append(base, "--set", "api.metricsListen=:9102")...)
	if strings.Join(ports(noPeers), ",") != "http,metrics" {
		t.Errorf("set: ports %v", ports(noPeers))
	}
	if got, want := len(rules(noPeers)), len(rules(off)); got != want {
		t.Errorf("set without peers: %d ingress rules, want the same %d (nothing new admitted)", got, want)
	}

	peers := render(t, append(base, "--set", "api.metricsListen=:9102",
		"--set", "networkPolicy.api.metricsFrom[0].namespaceSelector.matchLabels.kubernetes\\.io/metadata\\.name=monitoring")...)
	if got, want := len(rules(peers)), len(rules(off))+1; got != want {
		t.Fatalf("set with peers: %d ingress rules, want %d", got, want)
	}
	var found int
	for _, r := range rules(peers) {
		for _, p := range get(r, "ports").([]any) {
			if get(p, "port") == 9102 {
				found++
				if n := len(get(r, "ports").([]any)); n != 1 {
					t.Errorf("the metrics rule opens %d ports", n)
				}
				if ns := get(r, "from", 0, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"); ns != "monitoring" {
					t.Errorf("the metrics rule admits %v", get(r, "from"))
				}
			}
		}
	}
	if found != 1 {
		t.Errorf("%d rules for 9102, want 1", found)
	}
}
