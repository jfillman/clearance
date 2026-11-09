package pipeline

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// Done when: every rule compiles under the cost limit.
func TestEveryRuleCompilesUnderTheCostLimit(t *testing.T) {
	rs := mustRules(t)
	if len(rs.Costs) == 0 {
		t.Fatal("no rule was costed: the check is vacuous")
	}
	n := 0
	for name, c := range rs.Costs {
		n++
		if c > rs.CostLimit {
			t.Errorf("%s: estimated cost %d over the limit %d", name, c, rs.CostLimit)
		}
	}
	// every attribution signal, every conditional noise rule, every conditional scope entry is in the table
	want := len(rs.attribute[Kubernetes]) + len(rs.attribute[AWS])
	for _, r := range rs.noise {
		if r.when != nil {
			want++
		}
	}
	if n != want {
		t.Fatalf("%d rules costed, %d compiled", n, want)
	}
}

func bundleWith(t *testing.T, from, to string) error {
	t.Helper()
	src := string(DefaultRules())
	if !strings.Contains(src, from) {
		t.Fatalf("the default bundle has no %q", from)
	}
	_, err := Load([]byte(strings.Replace(src, from, to, 1)))
	return err
}

// Fail closed: a rule that does not compile, or is over the cost limit, means the bundle does not load.
func TestBundleRefusesBadRules(t *testing.T) {
	cases := []struct{ name, from, to, msg string }{
		{"does not compile", "when: facts.vap_denial", "when: facts.vap_denial &&", "vap-denial"},
		{"unknown function", "when: facts.vap_denial", "when: nosuchfn(facts)", "vap-denial"},
		{"not a bool", "when: facts.vap_denial", `when: '"yes"'`, "vap-denial"},
		{"over the cost limit", "cost_limit: 10000", "cost_limit: 3", "cost limit"},
		{"no catch-all", `      when: "true"
      outcome: out-of-band
      severity: medium
      detail: written by a person`, `      when: facts.refused
      outcome: out-of-band
      severity: medium
      detail: written by a person`, "catch-all"},
		{"rule set unnamed", `name: observe-default`, `name: ""`, "name and version"},
		{"unknown field", "cost_limit: 10000", "cost_limt: 1", "cost_limt"},
		{"a rule sets monitoring-protection", "outcome: attempted-refused\n      severity: medium", "outcome: monitoring-protection\n      severity: medium", "outcome is one of"},
		{"classify lowers monitoring", "monitoring-protection: {coverage: out-of-band-detected, tier: 3}", "monitoring-protection: {coverage: out-of-band-detected, tier: 2}", "tier 3"},
		{"classify missing", "  break-glass: {coverage: break-glass, tier: 2}\n", "", "break-glass"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := bundleWith(t, c.from, c.to)
			if err == nil {
				t.Fatal("the bundle loaded")
			}
			if !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("error %q does not mention %q", err, c.msg)
			}
		})
	}
	if _, err := Load([]byte(strings.Replace(string(DefaultRules()), "when: 'event.owners.exists(o, o.kind == \"Certificate\")'",
		"when: 'event.owners.exists(o, o.kind ==)'", 1))); err == nil {
		t.Fatal("a noise rule that does not compile loaded")
	}
}

// A rule that loads but whose evaluation goes over the cost limit is cut off, and for attribution that is an error,
// never a pass.
func TestRuntimeCostLimitCutsOffEvaluation(t *testing.T) {
	const expr = `event.owners.all(o, o.name.startsWith("a") && o.kind.contains("b") && o.name.endsWith("c"))`
	rs := mustRules(t)
	rs.CostLimit = 5
	if _, err := rs.compile("probe", expr); err == nil {
		t.Fatal("a rule whose worst-case estimate is over the limit loaded")
	}
	// The estimator assumes at most 64 owners: a limit set to that estimate loads, and more owners than that go over it.
	rs.CostLimit = 1 << 30
	if _, err := rs.compile("probe", expr); err != nil {
		t.Fatal(err)
	}
	rs.CostLimit = rs.Costs["probe"]
	prg, err := rs.compile("probe", expr)
	if err != nil {
		t.Fatalf("the limit equal to the estimate should load: %v", err)
	}
	ev := &Event{Owners: make([]Owner, 5000)}
	for i := range ev.Owners {
		ev.Owners[i] = Owner{Kind: "b", Name: "abc"}
	}
	if _, err := evalBool(prg, ev, nil); err == nil {
		t.Fatal("an evaluation over the cost limit completed")
	}
}

// Done when (scope note): "anything from a service account" is refused by a validator at bundle load, with a test.
func TestNoiseRuleAnythingFromAServiceAccountIsRefused(t *testing.T) {
	const good = `  - name: hpa-scale
    provider: kubernetes
    why: the HorizontalPodAutoscaler setting replicas through the /scale subresource.
    identity: {subject: "system:serviceaccount:kube-system:horizontal-pod-autoscaler"}
    shape: {kinds: [Deployment, StatefulSet, ReplicaSet], verbs: [update, patch], subresources: [scale], namespaces: [shop, payments]}`
	cases := []struct{ name, rule string }{
		{"every service account", `  - {name: any-sa, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount:*"}, shape: {kinds: [Deployment], verbs: [update]}}`},
		{"every service account of a namespace", `  - {name: ns-sa, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount:argocd:*"}, shape: {kinds: [Deployment], verbs: [update]}}`},
		{"a namespace's service accounts without a name", `  - {name: ns-sa2, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount:argocd"}, shape: {kinds: [Deployment], verbs: [update]}}`},
		{"the service-account group", `  - {name: grp, provider: kubernetes, why: x, identity: {subject: "system:serviceaccounts"}, shape: {kinds: [Deployment], verbs: [update]}}`},
		{"a namespace's group", `  - {name: grp2, provider: kubernetes, why: x, identity: {subject: "system:serviceaccounts:argocd"}, shape: {kinds: [Deployment], verbs: [update]}}`},
		{"an unnamed namespace", `  - {name: nons, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount::default"}, shape: {kinds: [Deployment], verbs: [update]}}`},
		{"authenticated users", `  - {name: auth, provider: kubernetes, why: x, identity: {subject: "system:authenticated"}, shape: {kinds: [Deployment], verbs: [update]}}`},
		{"no identity", `  - {name: noid, provider: kubernetes, why: x, shape: {kinds: [Deployment], verbs: [update]}}`},
		{"no shape", `  - {name: noshape, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount:a:b"}}`},
		{"no kinds", `  - {name: nokinds, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount:a:b"}, shape: {verbs: [update]}}`},
		{"no verbs", `  - {name: noverbs, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount:a:b"}, shape: {kinds: [Secret]}}`},
		{"every kind", `  - {name: allkinds, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount:a:b"}, shape: {kinds: ["*"], verbs: [update]}}`},
		{"a pattern verb", `  - {name: allverbs, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount:a:b"}, shape: {kinds: [Secret], verbs: ["*"]}}`},
		{"an unconditional when", `  - {name: tru, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount:a:b"}, shape: {kinds: [Secret], verbs: [update], when: "true"}}`},
		{"no reason", `  - {name: nowhy, provider: kubernetes, identity: {subject: "system:serviceaccount:a:b"}, shape: {kinds: [Secret], verbs: [update]}}`},
		{"a field the schema does not have", `  - {name: any, provider: kubernetes, why: x, identity: {any_service_account: true}, shape: {kinds: [Secret], verbs: [update]}}`},
		{"monitoring", `  - {name: hooks, provider: kubernetes, why: x, identity: {subject: "system:serviceaccount:a:b"}, shape: {kinds: [ValidatingWebhookConfiguration], verbs: [update]}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := bundleWith(t, good, c.rule)
			if err == nil {
				t.Fatalf("a bundle with the rule loaded:\n%s", c.rule)
			}
			if !strings.Contains(err.Error(), "noise") && !strings.Contains(err.Error(), "any_service_account") {
				t.Fatalf("not a noise validation error: %v", err)
			}
		})
	}
	// and the rule the card allows loads, as does an exact service account
	if err := bundleWith(t, good, good); err != nil {
		t.Fatal(err)
	}
	err := bundleWith(t, good, strings.Replace(good, "horizontal-pod-autoscaler", "*", 1))
	if err == nil || !errors.Is(err, ErrBlanketNoise) {
		t.Fatalf("a pattern identity: %v", err)
	}
}

func TestDuplicateNoiseRuleNamesRefused(t *testing.T) {
	const a = "  - name: hpa-scale\n"
	if err := bundleWith(t, a, "  - name: cert-manager-secret-rotation\n"); err == nil {
		t.Fatal("two rules named the same loaded")
	}
}

func TestBundleThatGovernsNothingIsRefused(t *testing.T) {
	src := string(DefaultRules())
	i, j := strings.Index(src, "scope:\n"), strings.Index(src, "# Noise:")
	if i < 0 || j < i {
		t.Fatal("the default bundle's layout changed")
	}
	if _, err := Load([]byte(src[:i] + "scope:\n  governed: []\n\n" + src[j:])); err == nil || !strings.Contains(err.Error(), "governs nothing") {
		t.Fatalf("%v", err)
	}
}
