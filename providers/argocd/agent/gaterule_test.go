package agent_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// W-42: the platform's gate rule, against the fakes.

func TestTheRuleMatchesAsDocumented(t *testing.T) {
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	r, err := agent.ParseRule([]byte(`version: 1
select:
  - name: prod-tenants
    projects: [tenants, "team-*"]
    namespaces: ["app-*-prod"]
    labels: {tier: prod, owner: web}
  - name: platform
    projects: [platform]
exempt:
  - application: argocd/web-prod
    reason: a migration to the new chart
    expires: 2026-12-19
  - application: argocd/short
    reason: short
    expires: 2026-12-19
  - application: argocd/far
    reason: a migration to the new chart
    expires: 2027-12-19
  - application: argocd/bad-date
    reason: a migration to the new chart
    expires: next week
`), now, agent.DefaultExemptMax)
	if err != nil {
		t.Fatal(err)
	}
	app := func(project, ns string, labels map[string]string) agent.Application {
		return agent.Application{Namespace: "argocd", Name: "x", Project: project, DestNS: ns, Labels: labels}
	}
	both := map[string]string{"tier": "prod", "owner": "web"}
	for _, c := range []struct {
		app  agent.Application
		want string
	}{
		{app("tenants", "app-web-prod", both), "prod-tenants"},
		{app("team-a", "app-web-prod", both), "prod-tenants"},                                     // OR inside a key
		{app("tenants", "app-web-dev", both), ""},                                                 // AND across keys
		{app("tenants", "app-web-prod", map[string]string{"tier": "prod"}), ""},                   // every label
		{app("tenants", "app-web-prod", map[string]string{"tier": "prod", "owner": "web-x"}), ""}, // exact value
		{app("tenants", "app-web-prod", nil), ""},                                                 // no labels
		{app("platform", "anything", nil), "platform"},                                            // a project-only entry
		{app("platform", "", nil), "platform"},                                                    // ... in every environment
		{app("other", "app-web-prod", both), ""},                                                  // OR across entries, none
	} {
		if got, _ := r.Match(c.app); got != c.want {
			t.Errorf("%+v: matched %q, want %q", c.app, got, c.want)
		}
	}
	inv := map[string]string{}
	for _, e := range r.Exempt {
		inv[e.Application] = e.Invalid
	}
	if inv["argocd/web-prod"] != "" || !strings.Contains(inv["argocd/short"], "reason") || !strings.Contains(inv["argocd/far"], "more than") ||
		!strings.Contains(inv["argocd/bad-date"], "expires") {
		t.Fatalf("exempt validation: %v", inv)
	}
	if !r.Exempt[0].At.Equal(time.Date(2026, 12, 19, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("a date is 00:00 UTC: %v", r.Exempt[0].At)
	}
	for name, text := range map[string]string{
		"empty entry": "version: 1\nselect:\n  - name: all\n",
		"no name":     "version: 1\nselect:\n  - projects: [a]\n",
		"twice":       "version: 1\nselect:\n  - {name: a, projects: [a]}\n  - {name: a, projects: [b]}\n",
		"version":     "version: 2\nselect: []\n",
		"unknown key": "version: 1\nselect:\n  - {name: a, project: [a]}\n",
		"empty":       "",
		"empty glob":  "version: 1\nselect:\n  - {name: a, projects: [\"\"]}\n",
		"approvedBy":  "version: 1\nexempt:\n  - {application: a/b, reason: a long enough reason, expires: 2026-12-01, approvedBy: me}\n",
	} {
		if _, err := agent.ParseRule([]byte(text), now, agent.DefaultExemptMax); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if r, err := agent.ParseRule([]byte("version: 1\nselect: []\n"), now, agent.DefaultExemptMax); err != nil || len(r.Select) != 0 {
		t.Fatalf("an empty rule gates nothing: %v", err)
	}
}

// ruleWorld is the opt-in world with a gate rule file.
type ruleWorld struct {
	*optWorld
	file string
	edit func(*agent.Config)
}

func newRuleWorld(t *testing.T, rule string) *ruleWorld {
	w := &ruleWorld{optWorld: newOptWorld(t), file: filepath.Join(t.TempDir(), "rule.yaml")}
	w.writeRule(rule)
	w.a = w.restartRule()
	return w
}

func (w *ruleWorld) writeRule(rule string) {
	if err := os.WriteFile(w.file, []byte(rule), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func (w *ruleWorld) restartRule() *agent.Agent {
	cfg := agent.Config{Cluster: "hangar-prod", Environment: "prod", Version: "0.0.0-test", Wait: agent.TestWaitPin,
		ArgoNamespace: "argocd-apps", Projects: []string{"tenants"}, StateNS: "clearance-system",
		OptIn: agent.OptIn{Enabled: true, DenyApps: agent.DefaultDenyApps, Namespaces: []string{"*"}, Rule: agent.GateRule{File: w.file}}}
	if w.edit != nil {
		w.edit(&cfg)
	}
	a, err := agent.New(cfg, w.kube, w.feeds, w.core, w.clock.now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		w.t.Fatal(err)
	}
	if err := a.Load(bg); err != nil {
		w.t.Fatal(err)
	}
	return a
}

func (w *ruleWorld) status() map[string]string {
	var m map[string]string
	_ = json.Unmarshal([]byte(w.kube.data["clearance-system/clearance-argocd-agent-state"]["optin.json"]), &m)
	return m
}

func (w *ruleWorld) exemptions(state string) []map[string]any {
	var out []map[string]any
	for _, r := range w.core.records {
		if r.Record.Exception["kind"] != "gate-exemption" {
			continue
		}
		x := r.Record.Exception["exemption"].(map[string]any)
		if state == "" || x["state"] == state {
			out = append(out, x)
		}
	}
	return out
}

const tenantsRule = "version: 1\nselect:\n  - name: tenants\n    projects: [tenants]\n"

func TestARuleGatesAnUnannotatedApplicationAndTheAnnotationCannotReleaseIt(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	if !w.isSwitched("web-prod") || len(lastReport(w.optWorld)) != 1 {
		t.Fatalf("a ruled Application is switched after its pair is reported: %v", w.core.reports)
	}
	if st := w.status()["argocd-apps/web-prod"]; !strings.Contains(st, "rule tenants") {
		t.Fatalf("the status names the rule: %q", st)
	}
	if w.app("web-prod").Annotations[agent.AnnProtect] != "" {
		t.Fatal("the agent never writes the annotation for a ruled Application")
	}
	// An exempt annotation is not read at all.
	w.setAnn("web-prod", "clearance.hangar.io/exempt", str("true"))
	w.setAnn("web-prod", agent.AnnProtect, str("false"))
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if !w.isSwitched("web-prod") || len(lastReport(w.optWorld)) != 1 {
		t.Fatal("the tenant cannot opt out of the rule")
	}
}

func TestNarrowingTheRuleReleasesOnlyWhatNothingElseGates(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.addApp("api-prod", "app-api-prod", protect())
	w.mustReconcile()
	if !w.isSwitched("web-prod") || !w.isSwitched("api-prod") {
		t.Fatal("both gated")
	}
	w.writeRule("version: 1\nselect: []\n")
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if w.isSwitched("web-prod") || !w.isSwitched("api-prod") {
		t.Fatal("the rule's Application is released; the annotated one stays")
	}
	if r := w.core.reports[len(w.core.reports)-1].Reason; !strings.Contains(r, "argocd-apps/web-prod the rule no longer matches (web/prod)") {
		t.Fatalf("the reason names the rule: %q", r)
	}
}

func TestRuleCausedReleasesAreBoundedPerHour(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	for _, n := range []string{"a-prod", "b-prod", "c-prod", "d-prod"} {
		w.addApp(n, "app-"+n, nil)
	}
	w.mustReconcile()
	w.writeRule("version: 1\nselect: []\n")
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	released := 0
	for _, n := range []string{"a-prod", "b-prod", "c-prod", "d-prod"} {
		if !w.isSwitched(n) {
			released++
		}
	}
	if released != 3 {
		t.Fatalf("%d released in an hour, want 3", released)
	}
	if st := w.status()["argocd-apps/d-prod"]; !strings.Contains(st, "release bound") {
		t.Fatalf("the held one says so: %q", st)
	}
	// A restart does not reset the bound.
	w.a = w.restartRule()
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if !w.isSwitched("d-prod") {
		t.Fatal("the fourth waits for the hour")
	}
	w.clock.add(time.Hour)
	w.mustReconcile()
	if w.isSwitched("d-prod") {
		t.Fatal("released in the next hour")
	}
}

func exemptRule(expires string) string {
	return tenantsRule + "exempt:\n  - application: argocd-apps/web-prod\n    reason: a migration to the new chart\n    expires: " + expires + "\n    ref: PR-1\n"
}

func TestAnExemptionTheCoreTakesReleasesTheApplicationAndIsRecorded(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("an accepted exemption releases a rule-gated Application")
	}
	last := w.core.reports[len(w.core.reports)-1]
	if len(last.Exempted) != 1 || last.Exempted[0].App != "web" || !strings.Contains(last.Reason, "exempted from rule tenants") {
		t.Fatalf("the removal names the exemption: %+v", last)
	}
	if len(w.exemptions("requested")) == 0 || len(w.exemptions("active")) != 1 {
		t.Fatalf("requested and active records: %v", w.exemptions(""))
	}
	x := w.exemptions("active")[0]
	if x["ref"] != "PR-1" || x["rule"] != "tenants" || len(fmt.Sprint(x["rule_digest"])) != 64 || x["approvedBy"] != nil {
		t.Fatalf("the record: %v", x)
	}
	// Seven days before it lapses: expiring, once.
	w.clock.add(24 * 24 * time.Hour)
	w.mustReconcile()
	w.clock.add(time.Hour)
	w.mustReconcile()
	if n := len(w.exemptions("expiring")); n != 1 {
		t.Fatalf("%d expiring records", n)
	}
	// It lapses: gated again, at once, and expired is posted.
	w.clock.add(7 * 24 * time.Hour)
	w.mustReconcile()
	if !w.isSwitched("web-prod") || len(w.exemptions("expired")) != 1 || w.exemptions("expired")[0]["why"] != "lapsed" {
		t.Fatalf("expired: switched %v, %v", w.isSwitched("web-prod"), w.exemptions("expired"))
	}
}

func TestAnExemptionIsNotHonouredBeforeTheCoreTakesIt(t *testing.T) {
	for name, refuse := range map[string]error{
		"static":       &client.APIError{Op: "record", Status: 409, Message: "refused: static: hangar-prod/prod is protected"},
		"unknown kind": &client.APIError{Op: "record", Status: 400, Message: "exception.kind is one of [...]"},
		"unreachable":  errors.New("core unreachable"),
	} {
		t.Run(name, func(t *testing.T) {
			w := newRuleWorld(t, tenantsRule)
			w.core.exempt = func(state, env string) error {
				if state == "requested" {
					return refuse
				}
				return nil
			}
			w.addApp("web-prod", "app-web-prod", nil)
			// Never gated before: the request alone is refused, and the rule gates it.
			w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
			w.mustReconcile()
			w.clock.add(2 * time.Minute)
			w.mustReconcile()
			if !w.isSwitched("web-prod") {
				t.Fatal("an exemption the core did not take is ignored: the Application is gated")
			}
			if name == "static" {
				if st := w.status()["argocd-apps/web-prod"]; !strings.Contains(st, "exemption refused: static") {
					t.Fatalf("status: %q", st)
				}
				if len(w.exemptions("refused")) != 1 {
					t.Fatalf("the refusal is recorded once: %v", w.exemptions(""))
				}
			}
		})
	}
}

func TestARevokedOrDroppedExemptionGatesAgainWithoutTheCore(t *testing.T) {
	for _, how := range []string{"revoked", "dropped"} {
		t.Run(how, func(t *testing.T) {
			w := newRuleWorld(t, tenantsRule)
			w.addApp("web-prod", "app-web-prod", nil)
			w.mustReconcile()
			w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
			w.clock.add(2 * time.Minute)
			w.mustReconcile()
			if w.isSwitched("web-prod") {
				t.Fatal("released")
			}
			reports := len(w.core.reports)
			switch how {
			case "revoked": // the platform added the pair to CLEARANCE_PROTECTED_ENVIRONMENTS
				w.core.exempt = func(state, env string) error {
					if state == "requested" {
						return &client.APIError{Op: "record", Status: 409, Message: "refused: static: protected"}
					}
					return nil
				}
			case "dropped": // the core is gone: nothing can be asked, or reported
				w.core.down = true
			}
			w.clock.add(11 * time.Minute) // past the recheck, and the write bound's window
			_ = w.reconcile()
			if !w.isSwitched("web-prod") {
				t.Fatal("gated again at the recheck, without waiting for the core to take the pair")
			}
			if how == "dropped" {
				if len(w.core.reports) != reports {
					t.Fatal("nothing reached the core")
				}
				// A restart keeps the re-gate, and the pair is reported when the core is back.
				w.a = w.restartRule()
				w.writeRule(tenantsRule) // (with the exemption still there, a core that is back would take it again)
				w.core.down = false
				w.clock.add(time.Minute)
				w.mustReconcile()
				if ex := w.exemptions("expired"); len(ex) != 1 || ex[0]["why"] != "dropped" {
					t.Fatalf("the end of the dropped exemption is delivered when the core is back, across a restart: %v", w.exemptions(""))
				}
				if !w.isSwitched("web-prod") || len(lastReport(w.optWorld)) != 1 {
					t.Fatalf("the pair is reported on return: %v", lastReport(w.optWorld))
				}
			} else if len(w.exemptions("expired")) == 0 || w.exemptions("expired")[0]["why"] != "revoked" {
				t.Fatalf("revoked is recorded: %v", w.exemptions(""))
			}
		})
	}
}

func TestAnExemptionNeverUngatesAnAnnotatedApplicationOrADeniedOne(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", protect())
	w.addApp("clearance", "clearance-system", nil)
	w.mustReconcile()
	if w.isSwitched("clearance") {
		t.Fatal("the deny list beats the rule")
	}
	if st := w.status()["argocd-apps/clearance"]; !strings.HasPrefix(st, "denied") {
		t.Fatalf("a rule-only denied Application says so: %q", st)
	}
	w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("the annotation keeps it gated")
	}
	if st := w.status()["argocd-apps/web-prod"]; !strings.Contains(st, "ineffective") {
		t.Fatalf("status: %q", st)
	}
}

func TestABadRuleFileKeepsTheLastGoodRuleAndReleasesNothing(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	w.writeRule("version: 1\nselect:\n  - name: everything\n")
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if !w.isSwitched("web-prod") || !strings.Contains(w.status()["gate/rule"], "kept the last good rule") {
		t.Fatalf("last good kept: %v", w.status())
	}
	// A restart with the file still bad uses the state's copy.
	w.a = w.restartRule()
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("the state's copy is used")
	}
	// Neither a good file nor a copy: not ready, nothing switched, nothing released.
	w2 := newRuleWorld(t, "not: [yaml")
	w2.addApp("web-prod", "app-web-prod", nil)
	if err := w2.reconcile(); !errors.Is(err, agent.ErrRuleNotReady) || w2.isSwitched("web-prod") {
		t.Fatalf("not ready: %v", err)
	}
	w2.feeds.publish()
	if err := w2.sync(); !errors.Is(err, agent.ErrRuleNotReady) {
		t.Fatalf("the grant loop holds too: %v", err)
	}
	// The file is fixed: re-read without a restart.
	w2.writeRule(tenantsRule)
	w2.mustReconcile()
	if !w2.isSwitched("web-prod") {
		t.Fatal("picked up without a restart")
	}
}

func TestAMatchedApplicationOutsideTheNamespacesIsBlockedAndReported(t *testing.T) {
	w := newRuleWorld(t, "version: 1\nselect:\n  - name: prod\n    namespaces: [\"app-*-prod\"]\n")
	w.edit = func(c *agent.Config) { c.OptIn.Namespaces = []string{"app-api-prod"} }
	w.a = w.restartRule()
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	if w.isSwitched("web-prod") || len(lastReport(w.optWorld)) != 1 {
		t.Fatal("not switched, still reported as a pair")
	}
	if st := w.status()["argocd-apps/web-prod"]; !strings.HasPrefix(st, "blocked:") {
		t.Fatalf("status: %q", st)
	}
}

func TestARuleNeedsTheOptIn(t *testing.T) {
	_, err := agent.New(agent.Config{Cluster: "c", ArgoNamespace: "argocd", StateNS: "s", Version: "v",
		OptIn: agent.OptIn{Rule: agent.GateRule{File: "/rule.yaml"}}}, nil, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--optin") {
		t.Fatalf("refused: %v", err)
	}
}

func TestARuledNamespaceGetsItsGrantAndLabelAndLosesThemWhenReleased(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	feedClaims(w.optWorld, "web", "app-web-prod", ch1, hex("a"))
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	if !w.labelled("app-web-prod") {
		t.Fatal("the ruled Application's namespace is labelled once its merged grant is active")
	}
	w.writeRule("version: 1\nselect: []\n")
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	if w.isSwitched("web-prod") || w.labelled("app-web-prod") {
		t.Fatal("released: put back and unlabelled")
	}
}

func TestARuledApplicationSetChildNeedsTheMarkerPreserved(t *testing.T) {
	w := newRuleWorld(t, "version: 1\nselect:\n  - name: web\n    namespaces: [app-web, app-both]\n")
	c := w.addApp("web", "app-web", nil)
	c.Owners = []agent.OwnerRef{{Kind: "ApplicationSet", Name: "tenants"}}
	b := w.addApp("both", "app-both", protect()) // the rule and the annotation both select it
	b.Owners = []agent.OwnerRef{{Kind: "ApplicationSet", Name: "tenants"}}
	d := w.addApp("api", "app-api", protect()) // the annotation alone
	d.Owners = []agent.OwnerRef{{Kind: "ApplicationSet", Name: "tenants"}}
	ignore := []agent.IgnoreDifference{{JSONPointers: []string{"/spec/source", "/spec/sources"}}}
	w.kube.appsets["tenants"] = agent.AppSet{Name: "tenants", IgnoreApplicationDifferences: ignore}
	w.mustReconcile()
	if w.isSwitched("web") || w.isSwitched("both") || !w.isSwitched("api") {
		t.Fatal("a rule-selected child waits for preservedFields, annotated or not; an annotation-only one does not")
	}
	if st := w.status()["argocd-apps/web"]; !strings.Contains(st, "preservedFields") {
		t.Fatalf("status: %q", st)
	}
	w.kube.appsets["tenants"] = agent.AppSet{Name: "tenants", IgnoreApplicationDifferences: ignore, PreservedAnnotations: []string{agent.AnnSwitched}}
	w.mustReconcile()
	if !w.isSwitched("web") || !w.isSwitched("both") {
		t.Fatal("switched once the marker is preserved")
	}
	// The ApplicationSet wipes the marker anyway: left alone, and reported as drift.
	w.setAnn("web", agent.AnnSwitched, nil)
	w.clock.add(time.Minute)
	w.mustReconcile()
	drift := 0
	for _, r := range w.core.records {
		if r.Record.Exception["kind"] == "drift" {
			drift++
		}
	}
	if drift != 1 || !w.isSwitched("web") {
		t.Fatalf("one drift exception, the Application left alone: %d", drift)
	}
	w.clock.add(time.Hour)
	w.mustReconcile()
	for _, r := range w.core.records {
		if r.Record.Exception["kind"] == "drift" {
			drift--
		}
	}
	if drift != 0 {
		t.Fatal("at most once a day")
	}
}

func TestARuleFileWithASecondDocumentIsRefused(t *testing.T) {
	if _, err := agent.ParseRule([]byte("version: 1\nselect: []\n---\nnot: [valid\n"), t0, agent.DefaultExemptMax); err == nil {
		t.Fatal("a broken second document is refused")
	}
	if _, err := agent.ParseRule([]byte("version: 1\nselect: []\n---\nversion: 1\n"), t0, agent.DefaultExemptMax); err == nil {
		t.Fatal("any second document is refused")
	}
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	w.writeRule("version: 1\nselect: []\n---\nnot: [valid\n")
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("the valid head of a broken file is not put in force: the last good rule stays")
	}
}

func (w *ruleWorld) savedState() map[string]any {
	var m map[string]any
	_ = json.Unmarshal([]byte(w.kube.data["clearance-system/clearance-argocd-agent-state"]["state.json"]), &m)
	return m
}

func failStateWritesWhen(w *ruleWorld, cond func(raw string) bool) {
	w.kube.putErr = func(d map[string]string) error {
		if raw, ok := d["state.json"]; ok && cond(raw) {
			return errors.New("the state ConfigMap cannot be written")
		}
		return nil
	}
}

func TestTheRulesCopyIsSavedOnceTheStateCanBeWritten(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	failStateWritesWhen(w, func(string) bool { return true })
	w.addApp("web-prod", "app-web-prod", nil)
	_ = w.reconcile()
	if w.savedState()["ruleDigest"] != nil {
		t.Fatal("nothing saved while the state cannot be written")
	}
	w.kube.putErr = nil
	w.clock.add(time.Minute)
	_ = w.reconcile()
	if d, _ := w.savedState()["ruleDigest"].(string); len(d) != 64 {
		t.Fatalf("the copy is saved on the next pass, the file unchanged: %v", w.savedState()["ruleDigest"])
	}
}

func TestARenewedExemptionIsHonouredInTheSamePass(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("released")
	}
	// No pass for six minutes: the acceptance is too old to be honoured until it is renewed, which the next pass does.
	w.clock.add(6 * time.Minute)
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("the pass renewed the acceptance and switched the Application anyway")
	}
}

func TestAReservedReleaseCountsUntilItCompletes(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	names := []string{"a-prod", "b-prod", "c-prod", "d-prod", "e-prod", "f-prod"}
	for _, n := range names {
		w.addApp(n, "app-"+n, nil)
	}
	w.mustReconcile()
	w.kube.failApp["a-prod"] = errors.New("conflict") // a's release is reserved and cannot complete
	w.writeRule("version: 1\nselect: []\n")
	w.clock.add(2 * time.Minute)
	_ = w.reconcile()
	if w.isSwitched("b-prod") || w.isSwitched("c-prod") || !w.isSwitched("a-prod") {
		t.Fatal("b and c released, a reserved")
	}
	// An hour on: b and c have left the window, a's reservation has not (it never completed), so two more go.
	w.clock.add(61 * time.Minute)
	_ = w.reconcile()
	released := 0
	for _, n := range names[3:] {
		if !w.isSwitched(n) {
			released++
		}
	}
	if released != 2 {
		t.Fatalf("%d of d, e, f released beside a's open reservation, want 2", released)
	}
	// a completes: it counts from now, so the last one waits another hour.
	delete(w.kube.failApp, "a-prod")
	w.clock.add(11 * time.Minute)
	_ = w.reconcile()
	still := 0
	for _, n := range names {
		if w.isSwitched(n) {
			still++
		}
	}
	if w.isSwitched("a-prod") || still != 1 {
		t.Fatalf("a released on its reservation, one left waiting: %d switched", still)
	}
}

func TestNoReleaseWithoutASavedReservation(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	failStateWritesWhen(w, func(raw string) bool { return strings.Contains(raw, `"ruleReleases"`) })
	w.writeRule("version: 1\nselect: []\n")
	w.clock.add(2 * time.Minute)
	_ = w.reconcile()
	_ = w.reconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("released though its reservation could not be saved")
	}
	w.kube.putErr = nil
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if w.isSwitched("web-prod") {
		t.Fatal("released once the reservation is saved")
	}
}

func TestAnExemptionsReleaseIsRecordedBeforeTheSourceIsPutBack(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	failStateWritesWhen(w, func(raw string) bool { return strings.Contains(raw, `"exemptReleased"`) })
	w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
	w.clock.add(2 * time.Minute)
	_ = w.reconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("put back though the release could not be recorded")
	}
	w.kube.putErr = nil
	w.clock.add(11 * time.Minute)
	w.mustReconcile()
	rel, _ := w.savedState()["exemptReleased"].(map[string]any)
	if w.isSwitched("web-prod") || rel["argocd-apps/web-prod"] == nil {
		t.Fatalf("released, with the release in the state: %v", w.savedState()["exemptReleased"])
	}
}

func TestAnExemptionRemovalWhoseAnswerWasLostIsSentAgainAsItWas(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
	w.core.loseReport = true
	w.clock.add(2 * time.Minute)
	_ = w.reconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("nothing is put back while the report's answer is lost")
	}
	lost := w.core.reports[len(w.core.reports)-1]
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	again := w.core.reports[len(w.core.reports)-1]
	if again.Seq != lost.Seq || len(again.Exempted) != 1 || w.isSwitched("web-prod") {
		t.Fatalf("the same report again (seq %d, then %d), then the release: %+v", lost.Seq, again.Seq, again)
	}
	if s := w.savedState(); fmt.Sprint(s["reportSeq"]) != fmt.Sprint(lost.Seq) {
		t.Fatalf("the state holds the committed report: %v", s["reportSeq"])
	}
}

func TestTheLoopsCanLoadABadRuleTogether(t *testing.T) {
	w := newRuleWorld(t, "not: [yaml")
	w.feeds.publish()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			_ = w.a.SyncGrants(bg)
		}
		close(done)
	}()
	for i := 0; i < 50; i++ {
		_ = w.reconcile()
	}
	<-done
}

// Only the opt-in loop settles a release reservation: the grant loop, whatever rule its classification saw, reads them.
func TestTheGrantLoopNeverCancelsAReleaseReservation(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("a-prod", "app-a-prod", nil)
	w.mustReconcile()
	w.kube.failApp["a-prod"] = errors.New("conflict") // the release is reserved and cannot complete yet
	w.writeRule("version: 1\nselect: []\n")
	w.clock.add(2 * time.Minute)
	_ = w.reconcile()
	reserved := func() bool {
		l, _ := w.savedState()["ruleReleases"].([]any)
		for _, r := range l {
			if m := r.(map[string]any); m["key"] == "argocd-apps/a-prod" && m["done"] != true {
				return true
			}
		}
		return false
	}
	if !reserved() {
		t.Fatal("a's release is reserved")
	}
	// The rule gates a again (as a stale classification would see it); the grant loop classifies, the opt-in loop does not.
	w.writeRule(tenantsRule)
	w.feeds.publish()
	_ = w.sync()
	if !reserved() {
		t.Fatal("the grant loop cancelled the opt-in loop's reservation")
	}
	// The opt-in loop, which owns it, gives it back once the Application is gated again.
	w.mustReconcile()
	if reserved() {
		t.Fatal("abandoned: given back by its owner")
	}
}

func TestTheEndOfAnExemptionIsRecordedAfterItsEntryLeavesTheFile(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	w.core.down = true
	w.writeRule(tenantsRule) // removed while the core is down
	w.clock.add(2 * time.Minute)
	_ = w.reconcile()
	w.core.down = false
	w.clock.add(11 * time.Minute)
	_ = w.reconcile()
	ex := w.exemptions("expired")
	if len(ex) != 1 || ex[0]["why"] != "withdrawn" || ex[0]["entry"] != "argocd-apps/web-prod" || ex[0]["reason"] == nil {
		t.Fatalf("the withdrawn end names the entry it ended: %v", w.exemptions(""))
	}
}

func twoExemptRule() string {
	return tenantsRule + "exempt:\n  - application: argocd-apps/web-prod\n    reason: a migration to the new chart\n    expires: " +
		t0.Add(30*24*time.Hour).Format(time.RFC3339) + "\n  - application: argocd-apps/api-prod\n    reason: a migration to the new chart\n    expires: " +
		t0.Add(30*24*time.Hour).Format(time.RFC3339) + "\n"
}

// A lost answer, and then another exemption before the retry: the core refuses the rebuilt report (the number is taken
// with another set), the agent reads the held number and set again, and both releases go through.
func TestARemovalReportIsRebuiltFromTheCoreAfterALostAnswer(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.addApp("api-prod", "app-api-prod", nil)
	w.mustReconcile()
	w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
	w.core.loseReport = true
	w.clock.add(2 * time.Minute)
	_ = w.reconcile()
	w.writeRule(twoExemptRule())
	for i := 0; i < 4; i++ {
		w.clock.add(2 * time.Minute)
		_ = w.reconcile()
	}
	if w.isSwitched("web-prod") || w.isSwitched("api-prod") || len(lastReport(w.optWorld)) != 0 {
		t.Fatalf("both released, the core holding none: %v; reports %+v", lastReport(w.optWorld), w.core.reports)
	}
	if s := w.savedState(); s["reported"] != nil {
		t.Fatalf("the state holds the committed (empty) set: %v", s["reported"])
	}
}

// Ends of exemptions past the queue's bound are counted and reported once the core is back, never lost silently, and
// the state stays small.
func TestExemptionEndsPastTheQueueBoundAreReportedAsLost(t *testing.T) {
	defer agent.SetMaxPendingBytes(agent.SetMaxPendingBytes(1))
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.addApp("api-prod", "app-api-prod", nil)
	w.mustReconcile()
	w.writeRule(twoExemptRule())
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	w.core.down = true
	w.clock.add(11 * time.Minute) // the recheck fails: both dropped, both ends queued past the bound
	_ = w.reconcile()
	if !w.isSwitched("web-prod") || !w.isSwitched("api-prod") {
		t.Fatal("dropped exemptions gate again at once")
	}
	if s := w.savedState(); fmt.Sprint(s["pendingLost"]) != "2" || s["pendingRecords"] != nil {
		t.Fatalf("counted, not stored: %v %v", s["pendingLost"], s["pendingRecords"])
	}
	w.core.down = false
	w.clock.add(time.Minute)
	_ = w.reconcile()
	lost := 0
	for _, r := range w.core.records {
		if r.Record.Result != nil && *r.Record.Result == "gate exemption records lost" {
			lost++
			if !strings.Contains(fmt.Sprint(r.Record.Exception["detail"]), "2 gate exemption") {
				t.Fatalf("the count: %v", r.Record.Exception["detail"])
			}
		}
	}
	if lost != 1 || w.savedState()["pendingLost"] != nil {
		t.Fatalf("one exception, then reset: %d %v", lost, w.savedState()["pendingLost"])
	}
}

func TestAThrottledQueuedRecordIsKept(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	w.core.down = true
	w.clock.add(11 * time.Minute)
	_ = w.reconcile() // dropped; its end queued
	w.core.down = false
	w.core.exempt = func(state, env string) error {
		if state == "expired" {
			return &client.APIError{Op: "record", Status: 429, Message: "slow down"}
		}
		return nil
	}
	w.clock.add(time.Minute)
	_ = w.reconcile()
	if q, _ := w.savedState()["pendingRecords"].(map[string]any); len(q) != 1 {
		t.Fatalf("a 429 keeps the record queued: %v", w.savedState()["pendingRecords"])
	}
	w.core.exempt = nil
	w.clock.add(time.Minute)
	_ = w.reconcile()
	if len(w.exemptions("expired")) != 1 || w.savedState()["pendingRecords"] != nil {
		t.Fatalf("delivered once the throttle lifts: %v", w.exemptions("expired"))
	}
}

func TestAnExemptionsEndNamesTheRuleItWasAcceptedUnder(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	d1 := w.exemptions("active")[0]["rule_digest"]
	w.writeRule(tenantsRule + "# another file\n")
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	ex := w.exemptions("expired")
	if len(ex) != 1 || ex[0]["rule_digest"] != d1 {
		t.Fatalf("the end names the digest its acceptance was for (%v): %v", d1, ex)
	}
}

// A near-full state: a record that would take the serialized state past its bound is not stored (the end is counted),
// whatever room the queue itself has.
func TestAQueuedRecordIsHeldToTheWholeStatesBound(t *testing.T) {
	w := newRuleWorld(t, tenantsRule)
	w.addApp("web-prod", "app-web-prod", nil)
	w.mustReconcile()
	w.writeRule(exemptRule(t0.Add(30 * 24 * time.Hour).Format(time.RFC3339)))
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	raw := w.kube.data["clearance-system/clearance-argocd-agent-state"]["state.json"]
	defer agent.SetMaxStateBytes(agent.SetMaxStateBytes(len(raw) + 200)) // the queue has room; the state does not
	w.core.down = true
	w.clock.add(11 * time.Minute)
	_ = w.reconcile()
	if s := w.savedState(); fmt.Sprint(s["pendingLost"]) != "1" || s["pendingRecords"] != nil {
		t.Fatalf("counted, not stored: %v %v", s["pendingLost"], s["pendingRecords"])
	}
}

// The loss exception names as many Applications as its detail holds, and how many more.
func TestTheLossExceptionFitsItsDetail(t *testing.T) {
	defer agent.SetMaxPendingBytes(agent.SetMaxPendingBytes(1))
	long := strings.Repeat("x", 40)
	rule := tenantsRule + "exempt:\n  - application: \"argocd-apps/*\"\n    reason: a migration to the new chart\n    expires: " +
		t0.Add(30*24*time.Hour).Format(time.RFC3339) + "\n"
	w := newRuleWorld(t, tenantsRule)
	for i := 0; i < 30; i++ {
		w.addApp(fmt.Sprintf("a%02d-%s", i, long), fmt.Sprintf("app-a%02d", i), nil)
	}
	w.mustReconcile()
	w.writeRule(rule)
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	w.core.down = true
	w.clock.add(11 * time.Minute)
	_ = w.reconcile()
	w.core.down = false
	w.clock.add(time.Minute)
	_ = w.reconcile()
	for _, r := range w.core.records {
		if r.Record.Result != nil && *r.Record.Result == "gate exemption records lost" {
			d := fmt.Sprint(r.Record.Exception["detail"])
			if len(d) > 1000 || !strings.HasPrefix(d, "30 gate exemption") || !strings.Contains(d, " more") || strings.HasSuffix(d, "...") {
				t.Fatalf("the detail (%d bytes): %s", len(d), d)
			}
			return
		}
	}
	t.Fatal("no loss exception")
}
