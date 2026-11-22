package charttest

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
)

// I-44: the grant-expiry webhook, the gate-mode rule and the agent's HA in charts/clearance-argocd-agent.

func agentDocs(t *testing.T, args ...string) map[string]obj {
	t.Helper()
	text, err := helmAgent(t, args...)
	if err != nil {
		t.Fatalf("helm template %v: %v\n%s", args, err, text)
	}
	return decodeDocs(t, text)
}

var geOn = []string{"--set", "grantExpiry.enabled=true"}
var geEnforce = []string{"--set", "grantExpiry.enabled=true", "--set", "grantExpiry.enforce=true"}

func vwc(t *testing.T, docs map[string]obj) obj {
	t.Helper()
	w := docs["ValidatingWebhookConfiguration/<nil>/clearance-grant-expiry"]
	if w == nil {
		t.Fatalf("no ValidatingWebhookConfiguration clearance-grant-expiry in %v", keysOfDocs(docs))
	}
	return get(w, "webhooks", 0).(obj)
}

func keysOfDocs(d map[string]obj) []string {
	var out []string
	for k := range d {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func geContainer(t *testing.T, docs map[string]obj) obj {
	t.Helper()
	d := docs["Deployment/<nil>/clearance-grant-expiry"]
	if d == nil {
		t.Fatalf("no grant-expiry Deployment in %v", keysOfDocs(docs))
	}
	return get(d, "spec", "template", "spec", "containers", 0).(obj)
}

func argsOf(c obj) []string { return toStrings(c["args"]) }

func wave(o obj) int {
	w, _ := get(o, "metadata", "annotations", "argocd.argoproj.io/sync-wave").(string)
	n, err := strconv.Atoi(w)
	if err != nil {
		return -1000
	}
	return n
}

// Everything is off by default; turning each switch off explicitly renders the same as leaving it unset, and the default
// render has none of the new objects. (The byte comparison with main is TestTheAgentChartRendersAsBeforeUnlessTheOptInIsOn's
// golden, and the PR's evidence.)
func TestGrantExpiryAndHAAreOffByDefault(t *testing.T) {
	def := agentDocs(t)
	off := agentDocs(t, "--set", "grantExpiry.enabled=false", "--set", "grantExpiry.enforce=false", "--set", "gate.enforce=false",
		"--set", "ha.enabled=false", "--set", "alerts.enabled=false", "--set", "statusHeartbeat=")
	if !reflect.DeepEqual(def, off) {
		t.Fatal("every I-44 switch off explicitly must render as the default")
	}
	text, _ := helmAgent(t)
	for _, no := range []string{"grant-expiry", "ValidatingWebhookConfiguration", "PodDisruptionBudget", "leader", "status-heartbeat",
		"PrometheusRule", "cert-manager.io", "name: POD_NAME\n"} {
		if strings.Contains(text, no) {
			t.Errorf("the default render has %q", no)
		}
	}
	if on := agentDocs(t, geOn...); reflect.DeepEqual(on, def) {
		t.Fatal("grantExpiry.enabled renders nothing new, so the comparison above proves nothing")
	}
}

func TestAuditIsIgnoreAndEnforceIsFailFromOneSwitch(t *testing.T) {
	for _, c := range []struct {
		args          []string
		mode, failure string
	}{
		{geOn, "audit", "Ignore"},
		{geEnforce, "enforce", "Fail"},
	} {
		docs := agentDocs(t, c.args...)
		w := vwc(t, docs)
		if w["failurePolicy"] != c.failure || w["timeoutSeconds"] != 3 || w["sideEffects"] != "None" || w["matchPolicy"] != "Equivalent" ||
			w["name"] != "clearance.hangar.io" || !reflect.DeepEqual(toStrings(w["admissionReviewVersions"]), []string{"v1"}) {
			t.Errorf("%s: webhook %v", c.mode, w)
		}
		if !reflect.DeepEqual(get(w, "namespaceSelector"), obj{"matchLabels": obj{"clearance.hangar.io/protected": "true"}}) {
			t.Errorf("%s: namespaceSelector %v", c.mode, get(w, "namespaceSelector"))
		}
		rule := get(w, "rules", 0).(obj)
		if !reflect.DeepEqual(toStrings(rule["operations"]), []string{"CREATE", "UPDATE"}) || rule["scope"] != "Namespaced" ||
			!reflect.DeepEqual(toStrings(rule["resources"]), []string{"*"}) || len(get(w, "rules").([]any)) != 1 {
			t.Errorf("%s: rules %v", c.mode, get(w, "rules"))
		}
		if svc := get(w, "clientConfig", "service").(obj); svc["name"] != "clearance-grant-expiry" || svc["path"] != "/validate" ||
			svc["namespace"] != "clearance-system" || svc["port"] != 443 {
			t.Errorf("%s: clientConfig %v", c.mode, svc)
		}
		ctr := geContainer(t, docs)
		if !slices.Contains(argsOf(ctr), "--mode="+c.mode) || get(ctr, "readinessProbe", "httpGet", "path") != "/readyz?mode="+c.mode {
			t.Errorf("%s: args %v, readiness %v", c.mode, argsOf(ctr), get(ctr, "readinessProbe"))
		}
		if get(ctr, "livenessProbe", "httpGet", "path") != "/healthz" || !reflect.DeepEqual(toStrings(ctr["command"]), []string{"/grant-expiry"}) {
			t.Errorf("%s: liveness or command: %v", c.mode, ctr)
		}
		if !slices.Contains(argsOf(ctr), "--skew=0s") {
			t.Errorf("%s: no clock-skew allowance by default: %v", c.mode, argsOf(ctr))
		}
	}
}

// The webhook's Deployment runs two replicas, never fewer Ready during a rollout, spread, behind a PDB; it is never the
// agent's process (its own Deployment and service account), and its RBAC only reads grants.
func TestTheWebhookDeploymentIsHAAndReadOnly(t *testing.T) {
	docs := agentDocs(t, geEnforce...)
	d := docs["Deployment/<nil>/clearance-grant-expiry"]
	if get(d, "spec", "replicas") != 2 || get(d, "spec", "strategy", "rollingUpdate", "maxUnavailable") != 0 {
		t.Errorf("replicas and strategy: %v", get(d, "spec"))
	}
	if get(d, "spec", "template", "spec", "serviceAccountName") != "clearance-grant-expiry" {
		t.Error("the webhook runs as its own service account, not the agent's")
	}
	tsc := get(d, "spec", "template", "spec", "topologySpreadConstraints").([]any)
	if len(tsc) != 2 || get(tsc[0], "topologyKey") != "kubernetes.io/hostname" {
		t.Errorf("topology spread: %v", tsc)
	}
	pdb := docs["PodDisruptionBudget/<nil>/clearance-grant-expiry"]
	if get(pdb, "spec", "minAvailable") != 1 {
		t.Errorf("PDB: %v", pdb)
	}
	cr := docs["ClusterRole/<nil>/clearance-grant-expiry"]
	rules := get(cr, "rules").([]any)
	if len(rules) != 1 || !reflect.DeepEqual(toStrings(get(rules[0], "verbs")), []string{"get", "list", "watch"}) ||
		!reflect.DeepEqual(toStrings(get(rules[0], "resources")), []string{"clearancegrants"}) {
		t.Errorf("the webhook's RBAC reads grants and nothing else: %v", rules)
	}
	ctr := geContainer(t, docs)
	if get(ctr, "securityContext", "readOnlyRootFilesystem") != true || get(ctr, "securityContext", "allowPrivilegeEscalation") != false {
		t.Errorf("hardening: %v", get(ctr, "securityContext"))
	}
	for _, a := range argsOf(ctr) {
		if strings.Contains(a, "token") || strings.Contains(a, "url=https://clearance-api") {
			t.Errorf("the webhook holds no Clearance credential and calls no Clearance API: %s", a)
		}
	}
	if docs["Deployment/<nil>/clearance-argocd-agent"] == nil {
		t.Fatal("the agent's Deployment is still its own")
	}
}

// Sync waves: certificate < Deployment (and its Service and PDB) < configuration.
func TestSyncWavesOrderTheDeploymentBeforeTheConfiguration(t *testing.T) {
	docs := agentDocs(t, geEnforce...)
	cert := wave(docs["Certificate/<nil>/clearance-grant-expiry-tls"])
	dep := wave(docs["Deployment/<nil>/clearance-grant-expiry"])
	cfg := wave(docs["ValidatingWebhookConfiguration/<nil>/clearance-grant-expiry"])
	if !(cert < dep && dep < cfg) || cert < 0 {
		t.Fatalf("waves certificate %d, deployment %d, configuration %d", cert, dep, cfg)
	}
	for _, k := range []string{"Service/<nil>/clearance-grant-expiry", "PodDisruptionBudget/<nil>/clearance-grant-expiry"} {
		if wave(docs[k]) != dep {
			t.Errorf("%s is in wave %d, the Deployment's is %d", k, wave(docs[k]), dep)
		}
	}
	if _, err := helmAgent(t, append(geOn, "--set", "grantExpiry.syncWaves.webhook=1")...); err == nil {
		t.Error("a configuration in the Deployment's wave is refused")
	}
}

// The gate-mode rule: Deny only behind an enforcing webhook, in both directions, with one recorded override.
func TestTheGateModeRule(t *testing.T) {
	cases := []struct {
		name string
		args []string
		ok   bool
		want string
	}{
		{"Warn, no webhook (today)", nil, true, ""},
		{"Deny with no webhook", []string{"--set", "gate.enforce=true"}, false, "needs grantExpiry.enabled: true and grantExpiry.enforce: true"},
		{"Deny with the webhook in audit (also: the webhook leaving enforce while the policy denies)",
			append([]string{"--set", "gate.enforce=true"}, geOn...), false, "grantExpiry.enforce: true"},
		{"Deny behind an enforcing webhook", append([]string{"--set", "gate.enforce=true"}, geEnforce...), true, ""},
		{"Warn behind an enforcing webhook (the first step in, the last step out)", geEnforce, true, ""},
		{"Deny with the recorded override", []string{"--set", "gate.enforce=true", "--set", "grantExpiry.acceptResidualRisk=true"}, true, ""},
		{"enforce without enabled", []string{"--set", "grantExpiry.enforce=true"}, false, "grantExpiry.enforce needs grantExpiry.enabled"},
		{"enforce with one replica", append(geEnforce, "--set", "grantExpiry.replicas=1"), false, "replicas of 2 or more"},
		{"audit with one replica is allowed", append(geOn, "--set", "grantExpiry.replicas=1"), true, ""},
		{"a timeout over 30 s", append(geOn, "--set", "grantExpiry.timeoutSeconds=31"), false, "timeoutSeconds"},
		{"a negative skew", append(geOn, "--set", "grantExpiry.skew=-1s"), false, "skew cannot be negative"},
		{"no cert-manager and no Secret", append(geOn, "--set", "grantExpiry.tls.certManager.enabled=false"), false, "existingSecret"},
		{"alerts without the webhook", []string{"--set", "alerts.enabled=true", "--set", "statusHeartbeat=5m"}, false, "alerts.enabled needs grantExpiry.enabled"},
		{"alerts without the heartbeat", append(geOn, "--set", "alerts.enabled=true"), false, "alerts.enabled needs statusHeartbeat"},
		{"alerts with a bad duration", append(geOn, "--set", "alerts.enabled=true", "--set", "statusHeartbeat=5m", "--set", "alerts.checkedAtStaleAfter=1h30m"), false, "one unit"},
		{"HA with one replica", []string{"--set", "ha.enabled=true", "--set", "ha.replicas=1"}, false, "ha.replicas of 2 or more"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := helmAgent(t, c.args...)
			if (err == nil) != c.ok {
				t.Fatalf("ok=%v, want %v: %s", err == nil, c.ok, out)
			}
			if !c.ok && !strings.Contains(out, c.want) {
				t.Fatalf("refused, but not for %q: %s", c.want, out)
			}
		})
	}
}

// TLS reuses the core's scheme (A-19, I-43): cert-manager, the chart's own namespaced CA by default (no trust-manager, no
// Apron), an existing (Cluster)Issuer when named, cert-manager's CA injection either way; or a Secret and caBundle given.
func TestTheWebhookTLSIsTheCoresScheme(t *testing.T) {
	own := agentDocs(t, geOn...)
	for _, k := range []string{"Issuer/<nil>/clearance-grant-expiry-selfsigned", "Certificate/<nil>/clearance-grant-expiry-ca",
		"Issuer/<nil>/clearance-grant-expiry-ca", "Certificate/<nil>/clearance-grant-expiry-tls"} {
		if own[k] == nil {
			t.Errorf("own CA: %s missing", k)
		}
	}
	cert := own["Certificate/<nil>/clearance-grant-expiry-tls"]
	if get(cert, "spec", "issuerRef", "name") != "clearance-grant-expiry-ca" ||
		!slices.Contains(toStrings(get(cert, "spec", "dnsNames")), "clearance-grant-expiry.clearance-system.svc") {
		t.Errorf("serving certificate: %v", get(cert, "spec"))
	}
	cfg := own["ValidatingWebhookConfiguration/<nil>/clearance-grant-expiry"]
	if get(cfg, "metadata", "annotations", "cert-manager.io/inject-ca-from") != "clearance-system/clearance-grant-expiry-tls" {
		t.Errorf("CA injection: %v", get(cfg, "metadata", "annotations"))
	}
	if get(vwc(t, own), "clientConfig", "caBundle") != nil {
		t.Error("with cert-manager the caBundle is the injector's, not the chart's")
	}
	shared := agentDocs(t, append(geOn, "--set", "grantExpiry.tls.certManager.issuerRef.name=cluster-ca", "--set", "grantExpiry.tls.certManager.issuerRef.kind=ClusterIssuer")...)
	if shared["Issuer/<nil>/clearance-grant-expiry-selfsigned"] != nil || shared["Certificate/<nil>/clearance-grant-expiry-ca"] != nil {
		t.Error("with a named issuer the chart builds no CA of its own")
	}
	if c := shared["Certificate/<nil>/clearance-grant-expiry-tls"]; get(c, "spec", "issuerRef", "name") != "cluster-ca" || get(c, "spec", "issuerRef", "kind") != "ClusterIssuer" {
		t.Errorf("shared issuer: %v", get(c, "spec", "issuerRef"))
	}
	given := agentDocs(t, append(geOn, "--set", "grantExpiry.tls.certManager.enabled=false", "--set", "grantExpiry.tls.existingSecret=my-tls",
		"--set", "grantExpiry.tls.caBundle=Q0E=")...)
	if given["Certificate/<nil>/clearance-grant-expiry-tls"] != nil || get(vwc(t, given), "clientConfig", "caBundle") != "Q0E=" {
		t.Error("certManager.enabled false: no Certificate, the given caBundle")
	}
	if v := get(given["Deployment/<nil>/clearance-grant-expiry"], "spec", "template", "spec", "volumes", 0, "secret", "secretName"); v != "my-tls" {
		t.Errorf("the given Secret is mounted: %v", v)
	}
}

// The wait Job's pins reach the webhook (it exempts the same Job the policy does), the previous URL included.
func TestTheWebhookGetsTheWaitJobPins(t *testing.T) {
	docs := agentDocs(t, append(geOn, "--set", "waitJob.image=registry.example.test/wait@sha256:00", "--set", "waitJob.previousURL=http://old.example.test",
		"--set", "waitJob.caConfigMap=clearance-ca")...)
	a := argsOf(geContainer(t, docs))
	for _, want := range []string{"--wait-image=registry.example.test/wait@sha256:00", "--wait-url=https://clearance.example.test",
		"--wait-previous-url=http://old.example.test", "--wait-ca-configmap=clearance-ca"} {
		if !slices.Contains(a, want) {
			t.Errorf("args lack %s: %v", want, a)
		}
	}
	if a := argsOf(geContainer(t, agentDocs(t, geOn...))); slices.ContainsFunc(a, func(s string) bool { return strings.HasPrefix(s, "--wait-") }) {
		t.Errorf("no wait image: no pins at all: %v", a)
	}
}

// matchConditions: each expression compiles in CEL, is has()-guarded (evaluates without error on requests missing each
// field), the Argo user is the one the handler gets, and each exclusion keeps the webhook from being called while a normal
// resource is. The API server evaluates them over the AdmissionRequest as a map: here a dyn map, where has() on an absent
// key is false and selecting it is an error, so an unguarded expression fails these tests.
func TestMatchConditionsAreGuardedAndExcludeWhatThePolicyExcludes(t *testing.T) {
	docs := agentDocs(t, geEnforce...)
	w := vwc(t, docs)
	env, err := cel.NewEnv(cel.Variable("request", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	type cond struct {
		name string
		prg  cel.Program
	}
	var conds []cond
	for _, c := range w["matchConditions"].([]any) {
		m := c.(obj)
		expr := m["expression"].(string)
		if !strings.Contains(expr, "has(") {
			t.Errorf("%s is not has()-guarded: %s", m["name"], expr)
		}
		ast, iss := env.Compile(expr)
		if iss.Err() != nil {
			t.Fatalf("%s: %v", m["name"], iss.Err())
		}
		if ast.OutputType() != cel.BoolType {
			t.Fatalf("%s is not a bool", m["name"])
		}
		prg, err := env.Program(ast)
		if err != nil {
			t.Fatal(err)
		}
		conds = append(conds, cond{m["name"].(string), prg})
	}
	if len(conds) != 6 {
		t.Fatalf("%d matchConditions, want the user's and five exclusions", len(conds))
	}
	argo := "system:serviceaccount:argocd:argocd-application-controller" // argocd.namespace in testdata
	if !slices.Contains(argsOf(geContainer(t, docs)), "--argocd-user="+argo) {
		t.Fatalf("the handler's user is not %s: %v", argo, argsOf(geContainer(t, docs)))
	}
	base := func() map[string]any {
		return map[string]any{"userInfo": map[string]any{"username": argo}, "subResource": "",
			"resource": map[string]any{"group": "", "version": "v1", "resource": "configmaps"}}
	}
	// matched: every condition true, no error.
	matched := func(t *testing.T, req map[string]any) (bool, string) {
		t.Helper()
		for _, c := range conds {
			v, _, err := c.prg.Eval(map[string]any{"request": req})
			if err != nil {
				t.Fatalf("%s errors on %v: %v (a CEL error refuses under failurePolicy Fail)", c.name, req, err)
			}
			if v.Value() != true {
				return false, c.name
			}
		}
		return true, ""
	}
	t.Run("a normal resource is matched", func(t *testing.T) {
		for _, r := range []map[string]any{
			{"group": "", "resource": "configmaps"}, {"group": "apps", "resource": "deployments"},
			{"group": "argoproj.io", "resource": "rollouts"}, {"group": "clearance.hangar.io", "resource": "other"},
			{"group": "", "resource": "leases"}, {"group": "coordination.k8s.io", "resource": "events"},
		} {
			req := base()
			req["resource"] = r
			if ok, by := matched(t, req); !ok {
				t.Errorf("%v is not matched (by %s)", r, by)
			}
		}
		req := base()
		delete(req, "subResource")
		if ok, by := matched(t, req); !ok {
			t.Errorf("no subResource field is the main resource; not matched by %s", by)
		}
	})
	t.Run("each exclusion is not matched", func(t *testing.T) {
		for _, r := range []map[string]any{
			{"group": "clearance.hangar.io", "resource": "clearancegrants"},
			{"group": "", "resource": "events"}, {"resource": "events"},
			{"group": "", "resource": "endpoints"}, {"resource": "endpoints"},
			{"group": "events.k8s.io", "resource": "events"},
			{"group": "discovery.k8s.io", "resource": "endpointslices"},
			{"group": "coordination.k8s.io", "resource": "leases"},
		} {
			req := base()
			req["resource"] = r
			if ok, _ := matched(t, req); ok {
				t.Errorf("%v is matched; the policy excludes it", r)
			}
		}
	})
	t.Run("each guard, with its field absent", func(t *testing.T) {
		for name, c := range map[string]struct {
			mutate func(map[string]any)
			want   bool
		}{
			"no userInfo":           {func(r map[string]any) { delete(r, "userInfo") }, false},
			"userInfo, no username": {func(r map[string]any) { r["userInfo"] = map[string]any{} }, false},
			"another user":          {func(r map[string]any) { r["userInfo"] = map[string]any{"username": "x"} }, false},
			"a subresource":         {func(r map[string]any) { r["subResource"] = "status" }, false},
			"no resource":           {func(r map[string]any) { delete(r, "resource") }, true},
			"resource, no group":    {func(r map[string]any) { r["resource"] = map[string]any{"resource": "configmaps"} }, true},
			"resource, no resource": {func(r map[string]any) { r["resource"] = map[string]any{"group": "clearance.hangar.io"} }, true},
			"an empty resource":     {func(r map[string]any) { r["resource"] = map[string]any{} }, true},
			"an empty request":      {func(r map[string]any) { clear(r) }, false},
			"grants, no resource key": {func(r map[string]any) {
				r["resource"] = map[string]any{"group": "clearance.hangar.io", "version": "v1"}
			}, true},
		} {
			req := base()
			c.mutate(req)
			if ok, by := matched(t, req); ok != c.want {
				t.Errorf("%s: matched %v (by %s), want %v", name, ok, by, c.want)
			}
		}
	})
}

// Option 0: the agent's HA, off by default (above), and with it on: replicas behind the leader Lease, a PDB, a spread, the
// Lease RBAC on one name, and the status heartbeat when set.
func TestTheAgentHA(t *testing.T) {
	docs := agentDocs(t, "--set", "ha.enabled=true", "--set", "statusHeartbeat=5m")
	d := docs["Deployment/<nil>/clearance-argocd-agent"]
	if get(d, "spec", "replicas") != 2 || get(d, "spec", "strategy", "type") != "RollingUpdate" {
		t.Errorf("HA agent: %v", get(d, "spec", "strategy"))
	}
	c := container(t, d)
	for _, want := range []string{"--leader-elect", "--leader-lease-duration=15s", "--leader-renew-deadline=10s", "--leader-retry-period=2s", "--status-heartbeat=5m"} {
		if !slices.Contains(argsOf(c), want) {
			t.Errorf("args lack %s", want)
		}
	}
	if !slices.ContainsFunc(c["env"].([]any), func(e any) bool {
		return get(e, "name") == "POD_NAME" && get(e, "valueFrom", "fieldRef", "fieldPath") == "metadata.name"
	}) {
		t.Error("POD_NAME (the pod's name) is the lease identity")
	}
	if get(docs["PodDisruptionBudget/<nil>/clearance-argocd-agent"], "spec", "minAvailable") != 1 {
		t.Error("the agent's PDB")
	}
	role := docs["Role/<nil>/clearance-argocd-agent-leader"]
	if role == nil || !reflect.DeepEqual(toStrings(get(role, "rules", 1, "resourceNames")), []string{"clearance-argocd-agent"}) {
		t.Errorf("lease RBAC: %v", role)
	}
	// The heartbeat alone (no HA) is allowed: one replica refreshing checkedAt.
	one := agentDocs(t, "--set", "statusHeartbeat=5m")
	if c := container(t, one["Deployment/<nil>/clearance-argocd-agent"]); !slices.Contains(argsOf(c), "--status-heartbeat=5m") || slices.Contains(argsOf(c), "--leader-elect") {
		t.Errorf("heartbeat without HA: %v", argsOf(c))
	}
}

func TestTheAlerts(t *testing.T) {
	docs := agentDocs(t, append(geOn, "--set", "alerts.enabled=true", "--set", "statusHeartbeat=5m", "--set", "alerts.labels.release=prom")...)
	rule := docs["PrometheusRule/<nil>/clearance-argocd-agent"]
	pm := docs["PodMonitor/<nil>/clearance-grant-expiry"]
	if rule == nil || pm == nil {
		t.Fatalf("PrometheusRule and PodMonitor: %v", keysOfDocs(docs))
	}
	if get(rule, "metadata", "labels", "release") != "prom" || get(pm, "metadata", "labels", "release") != "prom" {
		t.Error("alerts.labels reach both")
	}
	var names []string
	for _, r := range get(rule, "spec", "groups", 0, "rules").([]any) {
		names = append(names, get(r, "alert").(string))
		if get(r, "alert") == "ClearanceGrantStatusStale" && !strings.HasSuffix(get(r, "expr").(string), "> 900") {
			t.Errorf("checkedAtStaleAfter 15m is 900 s: %v", get(r, "expr"))
		}
	}
	if !reflect.DeepEqual(names, []string{"ClearanceGrantStatusStale", "ClearanceGrantExpiredButValid", "ClearanceGrantExpiryNotSynced"}) {
		t.Errorf("alerts %v", names)
	}
	if get(pm, "spec", "podMetricsEndpoints", 0, "port") != "probe" {
		t.Error("the PodMonitor scrapes the probe port's /metrics")
	}
}
