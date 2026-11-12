package pipeline

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/observe"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/vocab"
)

var update = flag.Bool("update", false, "rewrite the golden reports from the corpus")

func mustRules(t testing.TB) *RuleSet {
	t.Helper()
	rs, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func mustLookups(t testing.TB, rs *RuleSet) StaticLookups {
	t.Helper()
	b, err := os.ReadFile("testdata/lookups.json")
	if err != nil {
		t.Fatal(err)
	}
	lk, err := LoadLookups(b, rs)
	if err != nil {
		t.Fatal(err)
	}
	return lk
}

func corpus(t testing.TB, name string) []RawEvent {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var out []RawEvent
	for _, l := range bytes.Split(b, []byte("\n")) {
		if l = bytes.TrimSpace(l); len(l) == 0 || l[0] == '#' {
			continue
		}
		var r RawEvent
		if err := json.Unmarshal(l, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		t.Fatalf("%s holds no events", name)
	}
	return out
}

func replay(t testing.TB, name string, lk Lookups) (*Report, *Pipeline) {
	t.Helper()
	rs := mustRules(t)
	if lk == nil {
		lk = mustLookups(t, rs)
	}
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	p := New(rs, lk, vocab.Default())
	rep, err := Replay(bytes.NewReader(b), p)
	if err != nil {
		t.Fatal(err)
	}
	return rep, p
}

// Done when: a golden corpus of recorded Kubernetes and AWS raw events replays to the expected assessments.
func TestGoldenCorpus(t *testing.T) {
	for _, name := range []string{"kubernetes", "aws"} {
		t.Run(name, func(t *testing.T) {
			rep, _ := replay(t, name+".jsonl", nil)
			got, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			golden := filepath.Join("testdata", name+".golden.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("the replay differs from %s (go test ./internal/observe/pipeline -update rewrites it; read the diff first)", golden)
			}
			if len(rep.Assessments) == 0 {
				t.Fatal("the corpus produced no assessments: the comparison is vacuous")
			}
		})
	}
}

// byID indexes a report's assessments by the last two hex digits of the corpus event ids (…0001 → "01").
func byID(t *testing.T, rep *Report, prefix string) map[string]Assessment {
	t.Helper()
	m := map[string]Assessment{}
	for _, a := range rep.Assessments {
		m[strings.TrimPrefix(a.EventID[:8], prefix)] = a
	}
	return m
}

func TestKubernetesAttributionOrder(t *testing.T) {
	rep, _ := replay(t, "kubernetes.jsonl", nil)
	want := []struct {
		id, signal, outcome, severity string
		tier                          int
	}{
		{"7c1d0001", "grant-annotation+rendered-hash", "cleared", "info", 0},
		{"7c1d0002", "grant-annotation+hash-differs", "out-of-band", "high", 2},
		{"7c1d0003", "grant-annotation+mutating-webhook", "cleared", "low", 0},
		{"7c1d0004", "argo-controller.no-grant", "out-of-band", "high", 2},
		{"7c1d0005", "federated-identity.no-task-id", "observed-not-attributed", "medium", 1},
		{"7c1d0006", "kubectl-agent", "out-of-band", "medium", 2},
		{"7c1d000a", "break-glass.live", "break-glass", "medium", 2},
		{"7c1d000b", "impersonation", "out-of-band", "medium", 2},
		{"7c1d000c", "service-account.unknown", "out-of-band", "medium", 2},
		{"7c1d000d", "federated-identity.no-grant", "out-of-band", "medium", 2},
		{"7c1d000e", "audit-annotation.vap-denial", "attempted-refused", "medium", 1},
		{"7c1d000f", "response.refused", "attempted-refused", "low", 1},
		{"7c1d0010", "human.no-grant", "out-of-band", "medium", 2},
	}
	got := map[string]Assessment{}
	for _, a := range rep.Assessments {
		got[a.EventID[:8]] = a
	}
	for _, w := range want {
		a, ok := got[w.id]
		if !ok {
			t.Errorf("%s: no assessment", w.id)
			continue
		}
		if a.Signal != w.signal || a.Outcome != w.outcome || a.Severity != w.severity || a.Tier != w.tier {
			t.Errorf("%s: got %s/%s/%s/tier %d, want %s/%s/%s/tier %d", w.id, a.Signal, a.Outcome, a.Severity, a.Tier, w.signal, w.outcome, w.severity, w.tier)
		}
		if a.RuleSet.Name != "observe-default" || a.RuleSet.Version == "" || len(a.RuleSet.Digest) != 64 {
			t.Errorf("%s: the assessment does not name its rule set: %+v", w.id, a.RuleSet)
		}
	}
	if a := got["7c1d0002"]; len(a.Diff) == 0 || !strings.Contains(strings.Join(a.Diff, " "), "image") {
		t.Errorf("an out-of-band change carries the diff: %v", a.Diff)
	}
	if got["7c1d0006"].Diff == nil {
		t.Error("the kubectl write carries its diff")
	}
}

func TestKubectlBurstIsOneTransaction(t *testing.T) {
	rep, _ := replay(t, "kubernetes.jsonl", nil)
	for _, tx := range rep.Transactions {
		if len(tx.Events) == 4 {
			if len(tx.Resources) != 4 || tx.Outcome != OutcomeOutOfBand {
				t.Fatalf("the burst's transaction: %+v", tx)
			}
			n := 0
			for _, e := range rep.Exceptions {
				if len(e.Events) == 4 {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("the burst is one exception, got %d", n)
			}
			return
		}
	}
	t.Fatal("no transaction collapsed the four kubectl events")
}

func TestOwnerCascadeJoinsTransaction(t *testing.T) {
	rs := mustRules(t)
	p := New(rs, nil, vocab.Default())
	mk := func(id, ts, user, kind, res, name string, owner string) RawEvent {
		a := map[string]any{"auditID": id, "stage": "ResponseComplete", "verb": "create", "stageTimestamp": ts,
			"user":      map[string]any{"username": user},
			"objectRef": map[string]any{"resource": res, "namespace": "shop", "name": name},
			"responseObject": map[string]any{"kind": kind, "apiVersion": "apps/v1",
				"metadata": map[string]any{"name": name, "namespace": "shop"}}}
		if owner != "" {
			a["responseObject"].(map[string]any)["metadata"].(map[string]any)["ownerReferences"] =
				[]any{map[string]any{"kind": "Deployment", "name": owner}}
		}
		b, _ := json.Marshal(a)
		return RawEvent{Provider: Kubernetes, Scope: "prod-eu-1", Raw: b}
	}
	for _, r := range []RawEvent{
		mk("a1", "2026-11-05T12:00:00Z", "alice@example.com", "Deployment", "deployments", "web", ""),
		// a different actor, a controller, a few seconds later: related by ownership only
		mk("a2", "2026-11-05T12:00:05Z", "system:serviceaccount:kube-system:replicaset-controller", "ReplicaSet", "replicasets", "web-7d4b9", "web"),
	} {
		if _, d, _, err := p.Process(r); err != nil || d != Assessed {
			t.Fatalf("%v %v", d, err)
		}
	}
	txs, _ := p.Flush()
	if len(txs) != 1 || len(txs[0].Events) != 2 {
		t.Fatalf("a Deployment and its ReplicaSet are one change: %+v", txs)
	}
}

// Done when: a seeded apply-and-revert produces one exception.
func TestApplyAndRevertIsOneException(t *testing.T) {
	rep, _ := replay(t, "kubernetes.jsonl", nil)
	var rev []Exception
	for _, e := range rep.Exceptions {
		for _, r := range e.Resources {
			if r == "ConfigMap/shop/feature-flags" {
				rev = append(rev, e)
			}
		}
	}
	if len(rev) != 1 {
		t.Fatalf("an apply and its revert are one exception, got %d: %+v", len(rev), rev)
	}
	e := rev[0]
	if !e.Reverted || e.Resolution != "reverted" || len(e.Events) != 2 || e.Cause == "" {
		t.Fatalf("%+v", e)
	}
	// they were two transactions (three minutes apart), folded into the one exception
	n := 0
	for _, tx := range rep.Transactions {
		for _, r := range tx.Resources {
			if r == "ConfigMap/shop/feature-flags" {
				n++
			}
		}
	}
	if n != 2 {
		t.Fatalf("the apply and the revert are two transactions: %d", n)
	}
	// a revert past the window is not folded: two exceptions
	raws := corpus(t, "kubernetes.jsonl")
	var pair []RawEvent
	for _, r := range raws {
		if strings.Contains(string(r.Raw), "7c1d0010-") || strings.Contains(string(r.Raw), "7c1d0011-") {
			pair = append(pair, r)
		}
	}
	if len(pair) != 2 {
		t.Fatalf("the seeded pair: %d", len(pair))
	}
	pair[1].Raw = bytes.ReplaceAll(pair[1].Raw, []byte("2026-11-05T10:33:00"), []byte("2026-11-05T13:33:00"))
	p := New(mustRules(t), nil, vocab.Default())
	for _, r := range pair {
		if _, _, _, err := p.Process(r); err != nil {
			t.Fatal(err)
		}
	}
	if _, exs := p.Flush(); len(exs) != 2 {
		t.Fatalf("a revert after the window is its own exception: %d", len(exs))
	}
}

// Done when: a seeded StopLogging produces a tier 3 observation and degraded health.
func TestStopLoggingIsTier3AndFlipsHealth(t *testing.T) {
	rs := mustRules(t)
	var stop RawEvent
	for _, r := range corpus(t, "aws.jsonl") {
		if strings.Contains(string(r.Raw), `"StopLogging"`) {
			stop = r
		}
	}
	if stop.Raw == nil {
		t.Fatal("the corpus seeds no StopLogging")
	}
	var alerts []Alert
	p := New(rs, nil, vocab.Default())
	p.OnAlert = func(a Alert) { alerts = append(alerts, a) }
	if h := p.Health("111122223333"); h != observe.Healthy {
		t.Fatalf("before: %s", h)
	}
	a, d, _, err := p.Process(stop)
	if err != nil || d != Assessed {
		t.Fatalf("%v %v", d, err)
	}
	// the seeded StopLogging was refused (errorCode AccessDenied): tier 3 and degraded, as docs/evidence.md says
	if a.Tier != 3 || !a.Monitoring || a.Outcome != OutcomeMonitoring || a.Coverage != "out-of-band-detected" || a.Severity != "critical" {
		t.Fatalf("%+v", a)
	}
	if h := p.Health("111122223333"); h != observe.Degraded {
		t.Fatalf("a refused operation on monitoring degrades the scope: %s", h)
	}
	if len(alerts) != 1 || alerts[0].Health != observe.Degraded || alerts[0].Check != "monitoring-protection" {
		t.Fatalf("it alerts immediately, from Process: %+v", alerts)
	}
	_, exs := p.Flush()
	if len(exs) != 1 || exs[0].Kind != "monitoring-protection" || exs[0].Tier != 3 {
		t.Fatalf("%+v", exs)
	}
	// the same call, succeeded: tier 3 and blind (the contract's stronger state)
	ok := RawEvent{Provider: stop.Provider, Scope: stop.Scope, Raw: bytes.Replace(stop.Raw, []byte(`"errorCode":"AccessDenied",`), nil, 1)}
	ok.Raw = bytes.ReplaceAll(ok.Raw, []byte("3f9c000e"), []byte("3f9c00ff"))
	p2 := New(rs, nil, vocab.Default())
	a, _, _, err = p2.Process(ok)
	if err != nil || !a.Succeeded || a.Tier != 3 || p2.Health("111122223333") != observe.Blind {
		t.Fatalf("succeeded: %+v %v %s", a, err, p2.Health("111122223333"))
	}
	// only the provider's next healthy record clears the flip
	p2.Healthy("111122223333")
	if h := p2.Health("111122223333"); h != observe.Healthy {
		t.Fatalf("after a healthy record: %s", h)
	}
}

func TestEveryMonitoringOperationIsTier3(t *testing.T) {
	rs := mustRules(t)
	for _, op := range rs.monitoring.AWS {
		p := New(rs, nil, vocab.Default())
		raw := `{"eventID":"e-` + op + `","eventName":"` + op + `","eventSource":"x.amazonaws.com","eventTime":"2026-11-05T12:00:00Z","recipientAccountId":"111122223333",
		 "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/eve"},"requestParameters":{"name":"n"}}`
		a, d, _, err := p.Process(RawEvent{Provider: AWS, Raw: json.RawMessage(raw)})
		if err != nil || d != Assessed || a.Tier != 3 {
			t.Errorf("%s: %v %v %+v", op, d, err, a)
		}
	}
	if len(rs.monitoring.AWS) != 8 {
		t.Fatalf("the card's eight AWS operations: %v", rs.monitoring.AWS)
	}
	// the vocabulary's list is the same list: an operation only it names is also tier 3
	v := vocab.Default()
	v.MonitoringProtectionOps = []string{"aws:PutLifecycleHook"}
	p := New(rs, nil, v)
	raw := `{"eventID":"e-1","eventName":"PutLifecycleHook","eventSource":"autoscaling.amazonaws.com","eventTime":"2026-11-05T12:00:00Z","recipientAccountId":"111122223333",
		 "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111122223333:user/eve"},"requestParameters":{"name":"n"}}`
	if a, _, _, err := p.Process(RawEvent{Provider: AWS, Raw: json.RawMessage(raw)}); err != nil || a.Tier != 3 {
		t.Fatalf("vocabulary op: %v %+v", err, a)
	}
}

// A noise rule can never hide an operation on monitoring, even one the validator let through.
func TestNoiseNeverDropsMonitoring(t *testing.T) {
	src := strings.Replace(string(DefaultRules()), "  - name: hpa-scale", `  - name: audit-policy-bot
    provider: kubernetes
    why: a fixture rule that names the audit policy ConfigMap.
    identity: {subject: "system:serviceaccount:kube-system:policy-bot"}
    shape: {kinds: [ConfigMap], verbs: [update], namespaces: [kube-system]}
  - name: hpa-scale`, 1)
	rs, err := Load([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	p := New(rs, nil, vocab.Default())
	raw := `{"auditID":"m1","stage":"ResponseComplete","verb":"update","stageTimestamp":"2026-11-05T12:00:00Z",
	 "user":{"username":"system:serviceaccount:kube-system:policy-bot"},
	 "objectRef":{"resource":"configmaps","namespace":"kube-system","name":"audit-policy"},
	 "responseObject":{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"audit-policy","namespace":"kube-system"},"data":{"policy.yaml":"rules: []"}}}`
	a, d, _, err := p.Process(RawEvent{Provider: Kubernetes, Scope: "prod-eu-1", Raw: json.RawMessage(raw)})
	if err != nil || d != Assessed || a.Tier != 3 {
		t.Fatalf("an audit-policy change is tier 3, not noise: %v %v %+v", d, err, a)
	}
	other := strings.ReplaceAll(raw, "audit-policy", "other")
	if _, d, rule, _ := p.Process(RawEvent{Provider: Kubernetes, Scope: "prod-eu-1", Raw: json.RawMessage(other)}); d != Filtered || rule != "audit-policy-bot" {
		t.Fatalf("the same rule does filter what is not monitoring: %v %s", d, rule)
	}
}

func TestAWSAttributionOrder(t *testing.T) {
	rep, _ := replay(t, "aws.jsonl", nil)
	want := map[string]struct {
		signal, outcome, severity string
		tier                      int
	}{
		"3f9c0001": {"correlation.attestation", "cleared", "info", 0},
		"3f9c0002": {"correlation.pipeline-run", "cleared", "info", 0},
		"3f9c0003": {"correlation.apply-role-session", "cleared", "info", 0},
		"3f9c0004": {"correlation.plan-change-set", "cleared", "info", 0},
		"3f9c0007": {"correlation.outside-plan", "out-of-band", "high", 2},
		"3f9c0008": {"correlation.plan-digest", "cleared", "low", 0},
		"3f9c0009": {"correlation.apply-window", "cleared", "low", 0},
		"3f9c000a": {"sessionIssuer.sso-admin", "out-of-band", "high", 2},
		"3f9c000b": {"principal.no-grant", "out-of-band", "medium", 2},
		"3f9c000c": {"userIdentity.root", "out-of-band", "critical", 2},
		"3f9c000d": {"errorCode", "attempted-refused", "medium", 1},
		"3f9c000e": {"errorCode", "monitoring-protection", "critical", 3},
		"3f9c000f": {"principal.no-grant", "monitoring-protection", "critical", 3},
	}
	got := map[string]Assessment{}
	for _, a := range rep.Assessments {
		got[a.EventID[:8]] = a
	}
	for id, w := range want {
		a := got[id]
		if a.Signal != w.signal || a.Outcome != w.outcome || a.Severity != w.severity || a.Tier != w.tier {
			t.Errorf("%s: got %s/%s/%s/tier %d, want %+v", id, a.Signal, a.Outcome, a.Severity, a.Tier, w)
		}
	}
	if a := got["3f9c000a"]; a.ActorQuote != "dana@example.com" {
		t.Errorf("the actor the record quotes (sourceIdentity): %q", a.ActorQuote)
	}
	if got["3f9c0004"].Grant != "clr_aws_002" || got["3f9c0009"].Grant != "clr_aws_004" {
		t.Errorf("the grant each cleared call is tied to: %q %q", got["3f9c0004"].Grant, got["3f9c0009"].Grant)
	}
	// the Terraform resource's three calls are one change transaction
	for _, tx := range rep.Transactions {
		if len(tx.Events) == 3 && tx.Outcome == OutcomeCleared {
			return
		}
	}
	t.Fatal("the three calls of one Terraform resource are one transaction")
}

// The strongest signal wins: an event that matches several of the correlation hierarchy's signals takes the first.
func TestStrongestSignalFirst(t *testing.T) {
	rs := mustRules(t)
	lk := mustLookups(t, rs)
	raws := corpus(t, "aws.jsonl")
	r := raws[2] // the apply-role-session event
	var m map[string]any
	_ = json.Unmarshal(r.Raw, &m)
	lk.Attestations = map[string]string{m["eventID"].(string): "clr_aws_001"}
	lk.Windows = append(lk.Windows, span{"clr_aws_004", "111122223333", mustTime("2026-11-05T11:00:00Z"), mustTime("2026-11-05T12:00:00Z")})
	a, _, _, err := New(rs, lk, vocab.Default()).Process(r)
	if err != nil || a.Signal != "correlation.attestation" {
		t.Fatalf("%v %+v", err, a)
	}
	// and with no lookups at all nothing is cleared: the apply role alone proves nothing
	a, _, _, err = New(rs, nil, vocab.Default()).Process(r)
	if err != nil || a.Outcome != OutcomeOutOfBand {
		t.Fatalf("%v %+v", err, a)
	}
}

func TestSecretBodiesNeverLeaveNormalize(t *testing.T) {
	rs := mustRules(t)
	const val = "c3ludGhldGljLXNlY3JldC1ib2R5" // synthetic
	raw := `{"auditID":"s1","stage":"ResponseComplete","verb":"update","stageTimestamp":"2026-11-05T12:00:00Z",
	 "user":{"username":"alice@example.com"},"userAgent":"kubectl/v1.31.2",
	 "objectRef":{"resource":"secrets","namespace":"shop","name":"db"},
	 "requestObject":{"kind":"Secret","apiVersion":"v1","metadata":{"name":"db","namespace":"shop"},"data":{"password":"` + val + `"}},
	 "responseObject":{"kind":"Secret","apiVersion":"v1","metadata":{"name":"db","namespace":"shop","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"data\":{\"password\":\"` + val + `\"}}"}},"data":{"password":"` + val + `"}}}`
	before := `{"kind":"Secret","apiVersion":"v1","metadata":{"name":"db","namespace":"shop"},"stringData":{"password":"` + val + `"}}`
	p := New(rs, nil, vocab.Default())
	a, d, _, err := p.Process(RawEvent{Provider: Kubernetes, Scope: "prod-eu-1", Raw: json.RawMessage(raw), Before: json.RawMessage(before)})
	if err != nil || d != Assessed {
		t.Fatalf("%v %v", d, err)
	}
	if a.AfterHash != "" || a.BeforeHash != "" || a.Diff != nil {
		t.Fatalf("a Secret is not hashed or diffed: %+v", a)
	}
	txs, exs := p.Flush()
	out, _ := json.Marshal([]any{a, txs, exs, p.Stats()})
	if bytes.Contains(out, []byte(val)) || bytes.Contains(out, []byte("password")) {
		t.Fatalf("a Secret's body is in the output: %s", out)
	}
}

func TestOutOfScopeAndReadsAreCountedNotAssessed(t *testing.T) {
	rep, _ := replay(t, "kubernetes.jsonl", nil)
	if rep.NotWrites != 3 || rep.OutOfScope["dev-scratch"] != 2 || rep.OutOfScope["prod-eu-1"] != 1 {
		t.Fatalf("not writes %d, out of scope %v", rep.NotWrites, rep.OutOfScope)
	}
	n := len(rep.Assessments)
	f := 0
	for _, c := range rep.Filtered {
		f += c.Count
	}
	oos := 0
	for _, c := range rep.OutOfScope {
		oos += c
	}
	if n+f+oos+rep.NotWrites != rep.Events {
		t.Fatalf("every event is accounted for: %d+%d+%d+%d != %d", n, f, oos, rep.NotWrites, rep.Events)
	}
}

func TestFilteredCountsPerRule(t *testing.T) {
	rep, p := replay(t, "kubernetes.jsonl", nil)
	want := map[string]int{"argo-application-bookkeeping": 3, "cert-manager-secret-rotation": 2, "hpa-scale": 2}
	if len(rep.Filtered) != len(want) {
		t.Fatalf("%+v", rep.Filtered)
	}
	for _, f := range rep.Filtered {
		if want[f.Rule] != f.Count || f.RuleSet != "observe-default@2026.11.2" || f.Why == "" {
			t.Errorf("%+v", f)
		}
	}
	if len(rep.FilteredLines) != 3 || !strings.HasPrefix(rep.FilteredLines[0], "filtered: 3 events under rule argo-application-bookkeeping") {
		t.Fatalf("%v", rep.FilteredLines)
	}
	// the cert-manager service account outside its shape (a ConfigMap) is attributed, not filtered
	if p.Stats().Assessed == 0 {
		t.Fatal("nothing assessed")
	}
}

// The classify table agrees with the gate's own coverage for each exception kind it shares.
func TestClassifyMatchesGateCoverage(t *testing.T) {
	rs := mustRules(t)
	for kind, outcome := range map[string]string{"out-of-band": OutcomeOutOfBand, "attempted-refused": OutcomeRefused,
		"monitoring-protection": OutcomeMonitoring, "drift": OutcomeNotAttributed} {
		if got, want := rs.classify[outcome].Coverage, gate.ExceptionCoverage[kind]; got != want {
			t.Errorf("%s: classify gives %s, the gate gives %s", kind, got, want)
		}
	}
}

func TestDifferentBundleDifferentDigest(t *testing.T) {
	a := mustRules(t)
	b, err := Load([]byte(strings.Replace(string(DefaultRules()), `version: "2026.11.2"`, `version: "2026.11.3"`, 1)))
	if err != nil || a.Ref.Digest == b.Ref.Digest || b.Ref.Version != "2026.11.3" {
		t.Fatalf("%v %+v %+v", err, a.Ref, b.Ref)
	}
}

// The packet's line and the pipeline's are the same sentence.
func TestFilteredLineMatchesThePacket(t *testing.T) {
	f := FilteredCount{Rule: "hpa-scale", Count: 2, RuleSet: "observe-default@2026.11.2"}
	pf := packet.FilteredRule{Rule: f.Rule, Count: f.Count, RuleSet: f.RuleSet}
	if f.Line() != pf.Line() || !strings.HasPrefix(f.Line(), "filtered: 2 events under rule hpa-scale") {
		t.Fatalf("%q %q", f.Line(), pf.Line())
	}
}

// A delete names a known grant but has no after hash to compare: that is not a differing hash. Argo's write is seen and
// not attributed; anyone else carrying the same stamp is still out-of-band.
func TestKnownGrantWithNoHashIsNotAHashMismatch(t *testing.T) {
	var base RawEvent
	for _, r := range corpus(t, "kubernetes.jsonl") {
		if strings.Contains(string(r.Raw), "7c1d0001") {
			base = r
		}
	}
	if len(base.Raw) == 0 {
		t.Fatal("corpus event 7c1d0001 not found")
	}
	for _, c := range []struct{ name, user, agent, signal, outcome string }{
		{"argo", "system:serviceaccount:argocd:argocd-application-controller", "argocd-application-controller/v3.1.0", "grant-annotation.no-hash", "observed-not-attributed"},
		{"kubectl", "dana@example.com", "kubectl/v1.36.0", "kubectl-agent", "out-of-band"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(base.Raw, &m); err != nil {
				t.Fatal(err)
			}
			m["verb"], m["auditID"], m["userAgent"] = "delete", "7c1d00ff-"+c.name, c.agent
			m["user"] = map[string]any{"username": c.user, "groups": []any{"system:authenticated"}}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			rs := mustRules(t)
			a, _, _, err := New(rs, mustLookups(t, rs), vocab.Default()).Process(RawEvent{Provider: base.Provider, Scope: base.Scope, Raw: raw})
			if err != nil {
				t.Fatal(err)
			}
			if a == nil || a.Signal != c.signal || a.Outcome != c.outcome {
				t.Fatalf("got %+v, want %s/%s", a, c.signal, c.outcome)
			}
		})
	}
}

// A Secret is recorded at Metadata: no object, so no grant annotation. Argo's write of a Secret a grant lists (found
// through ObjectGrants) is observed-not-attributed, not an exception; Argo's write of one no grant lists, and anyone
// else's write of the listed one, is out-of-band. The same holds for Argo's delete of a listed object.
func TestSecretWriteResolvesThroughTheGrantsObjectList(t *testing.T) {
	const argo = "system:serviceaccount:argocd:argocd-application-controller"
	rs := mustRules(t)
	lk := mustLookups(t, rs)
	lk.Listed = map[string]string{"prod-1/shop/Secret/db-creds": "clr_k8s_001", "prod-1/shop/Deployment/web": "clr_k8s_001"}
	secret := func(user, ua, verb, resource, name string) RawEvent {
		m := map[string]any{"auditID": "s-" + user + verb + name, "stage": "ResponseComplete", "verb": verb, "level": "Metadata",
			"user": map[string]any{"username": user}, "userAgent": ua, "stageTimestamp": "2026-11-09T10:00:00Z",
			"objectRef":      map[string]any{"resource": resource, "namespace": "shop", "name": name},
			"responseStatus": map[string]any{"code": 200}}
		raw, _ := json.Marshal(m)
		return RawEvent{Provider: Kubernetes, Scope: "prod-1", Raw: raw}
	}
	for _, c := range []struct {
		name    string
		ev      RawEvent
		signal  string
		outcome string
	}{
		{"argo listed secret", secret(argo, "argocd-application-controller/v3", "update", "secrets", "db-creds"), "grant-annotation.no-hash", OutcomeNotAttributed},
		{"argo unlisted secret", secret(argo, "argocd-application-controller/v3", "update", "secrets", "other"), "argo-controller.no-grant", OutcomeOutOfBand},
		{"human listed secret", secret("dana@example.com", "kubectl/v1.36", "update", "secrets", "db-creds"), "kubectl-agent", OutcomeOutOfBand},
		{"argo prune of a listed object", secret(argo, "argocd-application-controller/v3", "delete", "deployments", "web"), "grant-annotation.no-hash", OutcomeNotAttributed},
		{"argo prune of an unlisted object", secret(argo, "argocd-application-controller/v3", "delete", "deployments", "api"), "argo-controller.no-grant", OutcomeOutOfBand},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, disp, _, err := New(rs, lk, vocab.Default()).Process(c.ev)
			if err != nil || disp != Assessed {
				t.Fatalf("%v %v", disp, err)
			}
			if a.Signal != c.signal || a.Outcome != c.outcome {
				t.Fatalf("got %s/%s, want %s/%s", a.Signal, a.Outcome, c.signal, c.outcome)
			}
		})
	}
}

// The named monitoring exemptions: routine noise for exactly the listed writes, monitoring-protection for the rest.
func TestMonitoringExemptions(t *testing.T) {
	const kyverno = "system:serviceaccount:kyverno:kyverno-admission-controller"
	const cainjector = "system:serviceaccount:cert-manager:cert-manager-cainjector"
	rs := mustRules(t)
	cases := []struct {
		name, user, verb, resource, kind, obj, ns string
		code                                      int
		exempt                                    bool
	}{
		{"kyverno update of its validating config", kyverno, "update", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "kyverno-resource-validating-webhook-cfg", "", 200, true},
		{"kyverno update of its mutating config", kyverno, "update", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration", "kyverno-resource-mutating-webhook-cfg", "", 200, true},
		{"kyverno patch of a kyverno-* config", kyverno, "patch", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "kyverno-policy-validating-webhook-cfg", "", 200, true},
		{"cainjector patch of another product's config", cainjector, "patch", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration", "istio-sidecar-injector", "", 200, true},
		{"person updating the kyverno config", "dana", "update", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "kyverno-resource-validating-webhook-cfg", "", 200, false},
		{"kyverno updating a config not named kyverno-*", kyverno, "update", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "payments-guard", "", 200, false},
		{"kyverno deleting its own config", kyverno, "delete", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "kyverno-resource-validating-webhook-cfg", "", 200, false},
		{"kyverno create of its own config", kyverno, "create", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "kyverno-resource-validating-webhook-cfg", "", 200, false},
		{"cainjector update", cainjector, "update", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "istio-validator", "", 200, false},
		{"cainjector delete", cainjector, "delete", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "istio-validator", "", 200, false},
		{"refused kyverno update", kyverno, "update", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "kyverno-resource-validating-webhook-cfg", "", 403, false},
		{"kyverno writing the audit policy", kyverno, "update", "configmaps", "ConfigMap", "audit-policy", "kube-system", 200, false},
		{"kyverno patching the audit policy", kyverno, "patch", "configmaps", "ConfigMap", "audit-policy", "kube-system", 200, false},
		{"cainjector patching the audit policy", cainjector, "patch", "configmaps", "ConfigMap", "audit-policy", "kube-system", 200, false},
		{"tekton operator update of its own config", "system:serviceaccount:tekton-operator:tekton-operator", "update", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration", "webhook.operator.tekton.dev", "", 200, true},
		{"tekton proxy update of its own config", "system:serviceaccount:tekton-pipelines:tekton-operators-proxy-webhook", "update", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration", "proxy.operator.tekton.dev", "", 200, true},
		{"tekton pipelines update of its own config", "system:serviceaccount:tekton-pipelines:tekton-pipelines-webhook", "update", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "validation.webhook.pipeline.tekton.dev", "", 200, true},
		{"tekton triggers update of its own config", "system:serviceaccount:tekton-pipelines:tekton-triggers-webhook", "update", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration", "webhook.triggers.tekton.dev", "", 200, true},
		{"pipelines-as-code update of its own config", "system:serviceaccount:tekton-pipelines:pipelines-as-code-webhook", "update", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "validation.pipelinesascode.tekton.dev", "", 200, true},
		{"kyverno cleanup update of its ttl config", "system:serviceaccount:kyverno:kyverno-cleanup-controller", "update", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "kyverno-ttl-validating-webhook-cfg", "", 200, true},
		{"tekton pipelines updating the operator's config", "system:serviceaccount:tekton-pipelines:tekton-pipelines-webhook", "update", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration", "webhook.operator.tekton.dev", "", 200, false},
		{"tekton operator updating another product's config", "system:serviceaccount:tekton-operator:tekton-operator", "update", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "cert-manager-webhook", "", 200, false},
		{"tekton operator deleting its own config", "system:serviceaccount:tekton-operator:tekton-operator", "delete", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration", "webhook.operator.tekton.dev", "", 200, false},
		{"refused tekton operator update", "system:serviceaccount:tekton-operator:tekton-operator", "update", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration", "webhook.operator.tekton.dev", "", 403, false},
		{"kyverno cleanup updating the policy webhook", "system:serviceaccount:kyverno:kyverno-cleanup-controller", "update", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "kyverno-policy-validating-webhook-cfg", "", 200, false},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ns := ""
			if c.ns != "" {
				ns = `"namespace":"` + c.ns + `",`
			}
			raw := fmt.Sprintf(`{"auditID":"ex%d","stage":"ResponseComplete","verb":%q,"stageTimestamp":"2026-11-05T12:00:00Z",
			 "user":{"username":%q},"objectRef":{"resource":%q,%s"name":%q},"responseStatus":{"code":%d},
			 "responseObject":{"kind":%q,"apiVersion":"v1","metadata":{"name":%q}}}`,
				i, c.verb, c.user, c.resource, ns, c.obj, c.code, c.kind, c.obj)
			var alerts []Alert
			p := New(rs, nil, vocab.Default())
			p.OnAlert = func(a Alert) { alerts = append(alerts, a) }
			a, d, rule, err := p.Process(RawEvent{Provider: Kubernetes, Scope: "prod-eu-1", Raw: json.RawMessage(raw)})
			if err != nil {
				t.Fatal(err)
			}
			if c.exempt {
				if d != Filtered || !strings.HasPrefix(rule, "monitoring-exempt:") || a != nil {
					t.Fatalf("an exempted write is routine noise: %v %q %+v", d, rule, a)
				}
				if h := p.Health("prod-eu-1"); h != observe.Healthy || len(alerts) != 0 {
					t.Fatalf("no flip, no alert: %s %+v", h, alerts)
				}
				if st := p.Stats(); st.Filtered[rule] != 1 || st.Assessed != 0 {
					t.Fatalf("counted as filtered: %+v", st)
				}
				if _, exs := p.Flush(); len(exs) != 0 {
					t.Fatalf("no exception: %+v", exs)
				}
				return
			}
			if d != Assessed || a == nil || !a.Monitoring || a.Outcome != OutcomeMonitoring || a.Tier != 3 {
				t.Fatalf("still monitoring-protection: %v %+v", d, a)
			}
			want := observe.Blind
			if c.code != 200 {
				want = observe.Degraded
			}
			if h := p.Health("prod-eu-1"); h != want || len(alerts) != 1 {
				t.Fatalf("flips health and alerts: %s %+v", h, alerts)
			}
		})
	}
}

func TestMonitoringExemptionsAreValidatedAtLoad(t *testing.T) {
	const entry = `    - name: x
      why: a fixture exemption.
      subject: "system:serviceaccount:kyverno:kyverno-admission-controller"
      verbs: [update]
      kinds: [ValidatingWebhookConfiguration]
      names: ["kyverno-*"]
`
	base := string(DefaultRules())
	if !strings.Contains(base, "  kubernetes_exempt:\n") {
		t.Fatal("the default rules carry no exemptions")
	}
	with := func(e string) string {
		return strings.Replace(base, "  kubernetes_exempt:\n", "  kubernetes_exempt:\n"+e, 1)
	}
	if _, err := Load([]byte(with(entry))); err != nil {
		t.Fatalf("the well-formed entry loads: %v", err)
	}
	bad := map[string]string{
		"duplicate name":       entry + entry,
		"empty subject":        strings.Replace(entry, `subject: "system:serviceaccount:kyverno:kyverno-admission-controller"`, `subject: ""`, 1),
		"pattern subject":      strings.Replace(entry, "kyverno:kyverno-admission-controller", "kyverno:*", 1),
		"group subject":        strings.Replace(entry, "system:serviceaccount:kyverno:kyverno-admission-controller", "system:serviceaccounts:kyverno", 1),
		"empty verbs":          strings.Replace(entry, "verbs: [update]", "verbs: []", 1),
		"no kinds":             strings.Replace(entry, "kinds: [ValidatingWebhookConfiguration]", "kinds: []", 1),
		"kind not a webhook":   strings.Replace(entry, "kinds: [ValidatingWebhookConfiguration]", "kinds: [ConfigMap]", 1),
		"a webhook and a kind": strings.Replace(entry, "kinds: [ValidatingWebhookConfiguration]", "kinds: [ValidatingWebhookConfiguration, ClusterRole]", 1),
		"no names":             strings.Replace(entry, `names: ["kyverno-*"]`, "names: []", 1),
		"no why":               strings.Replace(entry, "why: a fixture exemption.", "why: \"\"", 1),
	}
	for name, e := range bad {
		if e == entry {
			t.Fatalf("%s: the fixture did not change", name)
		}
		if _, err := Load([]byte(with(e))); err == nil {
			t.Errorf("%s: the loader accepted it", name)
		}
	}
}
