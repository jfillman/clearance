package agent_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/token"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

func objKeys(g agent.Grant) string {
	var ks []string
	for k, v := range g.Spec.Objects {
		ks = append(ks, k+"="+v.Rendered[:1])
	}
	sortStrings(ks)
	return strings.Join(ks, ",")
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

func opt2(w *optWorld) { // web-prod and api-prod, both protected, one namespace
	w.addApp("web-prod", "app-a", protect())
	w.addApp("api-prod", "app-a", protect())
	w.mustReconcile()
}

func TestTheMergedGrantHoldsEveryProtectedApplicationsClearedObjects(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")), cmap("web-cfg", hex("b")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("api", hex("c")))
	w.publishSync()
	g, ok := w.merged("app-a")
	if !ok || !g.Active() || g.Valid == nil || !*g.Valid {
		t.Fatalf("no active, valid merged grant: %v", w.kube.log)
	}
	if got, want := objKeys(g), "/ConfigMap/web-cfg=b,apps/Deployment/api=c,apps/Deployment/web=a"; got != want {
		t.Errorf("objects %s, want %s", got, want)
	}
	if g.Labels[agent.LabelMerged] != "true" || g.Labels[agent.LabelManagedBy] != agent.ManagedBy {
		t.Errorf("labels %v", g.Labels)
	}
	if n := len(w.kube.grants); n != 1 {
		t.Errorf("one grant per namespace: %v", keysOf(w.kube.grants))
	}
	if len(g.Spec.Subject.Tree) != 64 || g.Spec.Clearance.ID != "merged" {
		t.Errorf("subject %+v clearance %+v (the CRD wants a 64-digit tree)", g.Spec.Subject, g.Spec.Clearance)
	}
	if !w.labelled("app-a") {
		t.Error("the namespace is labelled once its grant is active")
	}
}

func TestOnlyProtectedClearedObjectsInTheirOwnDestinationAreInTheGrant(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.addApp("api-prod", "app-a", nil) // never asked
	w.addApp("db-prod", "app-b", protect())
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("api", hex("c"))) // an unprotected Application's clearance
	// db's clearance also lists an object in app-a (it renders a namespace it does not own).
	c := claim(w.feeds, ch3, "app-b", t0, deploy("db", hex("d")))
	c.Objects = append(c.Objects, token.Object{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "app-a", Name: "sneaky", Rendered: hex("e")})
	c.Target.App = "db"
	c.Expires = t0.Add(time.Hour).Unix()
	w.feeds.claims = append(w.feeds.claims, c)
	// a clearance of the right app but another environment, and another cluster
	feedObjs(w, "web", "app-a", ch4, t0, deploy("other-env", hex("f")))
	w.feeds.claims[len(w.feeds.claims)-1].Target.Env = "staging"
	w.publishSync()
	a, _ := w.merged("app-a")
	if got := objKeys(a); got != "apps/Deployment/web=a" {
		t.Errorf("app-a: %s", got)
	}
	b, _ := w.merged("app-b")
	if got := objKeys(b); got != "apps/Deployment/db=d" {
		t.Errorf("app-b: %s: an object of a clearance in another namespace is not this Application's to grant", got)
	}
	// api-prod's clearance is a per-change grant if anything (the namespace had none before): it is not in the merged one.
	for _, g := range []agent.Grant{a, b} {
		for _, c := range g.Spec.Carried {
			for k := range c.Objects {
				if strings.Contains(k, "api") || strings.Contains(k, "sneaky") || strings.Contains(k, "other-env") {
					t.Errorf("carried tree holds %s", k)
				}
			}
		}
	}
}

func TestNothingUncleredIsGrantedOrLabelled(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	w.kube.ns["app-a"] = map[string]string{} // exists, not labelled
	w.publishSync()                          // an empty feed: no cleared tree
	if _, ok := w.merged("app-a"); ok || w.labelled("app-a") {
		t.Fatal("a grant or a label from no clearance")
	}
}

func TestOlderClearancesAreCarriedAndAnotherApplicationsObjectsAreNot(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")), cmap("shared", hex("1")))
	feedObjs(w, "web", "app-a", ch2, t0.Add(time.Minute), deploy("web", hex("b"))) // the newer one
	feedObjs(w, "api", "app-a", ch3, t0, cmap("shared", hex("2")))                 // api's newest claims "shared"
	w.clock.add(2 * time.Minute)
	w.feeds.claims[2].Expires = w.clock.now().Add(time.Hour).Unix()
	w.publishSync()
	// web's newest (ch2) lists only web; api's newest (ch3) lists shared: no conflict (a claim is the newest of each).
	g, ok := w.merged("app-a")
	if !ok {
		t.Fatalf("no grant: %v", w.kube.log)
	}
	if got := objKeys(g); got != "/ConfigMap/shared=2,apps/Deployment/web=b" {
		t.Errorf("objects: %s", got)
	}
	// web's older clearance is carried for its Deployment at the older hash; its "shared" is api's now and is not carried.
	if len(g.Spec.Carried) != 1 || g.Spec.Carried[0].Change != ch1 {
		t.Fatalf("carried: %+v", g.Spec.Carried)
	}
	if o := g.Spec.Carried[0].Objects; len(o) != 1 || o["apps/Deployment/web"].Rendered != hex("a") {
		t.Errorf("carried objects: %v", o)
	}
}

// -- two Applications, one object -----------------------------------------------------------------------------------

func exceptions(w *optWorld) []string {
	var out []string
	for _, r := range w.core.of("deploy.exception") {
		out = append(out, fmt.Sprint(*r.Record.Result, " | ", r.Record.Exception["detail"]))
	}
	return out
}

func TestAConflictWithNoLastGoodGrantWritesNoMergedGrantAndNoLabel(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	w.kube.ns["app-a"] = map[string]string{}
	feedObjs(w, "web", "app-a", ch1, t0, deploy("shared", hex("a")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("shared", hex("b")))
	w.publishSync()
	if _, ok := w.merged("app-a"); ok || w.labelled("app-a") {
		t.Fatal("a merged grant or a label from a conflict")
	}
	if len(exceptions(w)) != 1 {
		t.Errorf("exceptions: %v", exceptions(w))
	}
}

// -- the size limit -------------------------------------------------------------------------------------------------

func TestAMergedGrantOverTheLimitIsRefusedAndTheLastGoodStays(t *testing.T) {
	w := newOptWorld(t)
	w.a = mustAgent(t, w, func(c *agent.Config) { c.OptIn.MaxGrantBytes = 1500 })
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	good, ok := w.merged("app-a")
	if !ok {
		t.Fatal("no first grant")
	}
	var objs []token.Object
	for i := 0; i < 40; i++ {
		objs = append(objs, deploy(fmt.Sprintf("api-%02d", i), hex("c")))
	}
	w.clock.add(time.Minute)
	feedObjs(w, "api", "app-a", ch2, w.clock.now(), objs...)
	ops := len(w.kube.log)
	w.publishSync()
	now, _ := w.merged("app-a")
	if objKeys(now) != objKeys(good) || len(w.kube.log) != ops {
		t.Errorf("the grant changed: %s", objKeys(now))
	}
	ex := exceptions(w)
	if len(ex) != 1 || !strings.Contains(ex[0], "merged grant over the size limit") || !strings.Contains(ex[0], "limit of 1500") {
		t.Fatalf("exceptions: %v", ex)
	}
	w.publishSync()
	if len(exceptions(w)) != 1 {
		t.Error("reported again")
	}
}

func TestAMergedGrantOverTheCRDsObjectLimitIsRefused(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	var objs []token.Object
	for i := 0; i < 2001; i++ {
		objs = append(objs, deploy(fmt.Sprintf("d-%04d", i), hex("c")))
	}
	feedObjs(w, "web", "app-a", ch1, t0, objs...)
	w.publishSync()
	if _, ok := w.merged("app-a"); ok {
		t.Fatal("a grant the CRD would refuse (maxProperties 2000) was written")
	}
	if ex := exceptions(w); len(ex) != 1 || !strings.Contains(ex[0], "over the limit of 2000") {
		t.Errorf("exceptions: %v", ex)
	}
}

// -- label order ----------------------------------------------------------------------------------------------------

func indexOf(log []string, prefix string) int {
	for i, l := range log {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

func TestTheLabelComesAfterTheGrantAndGoesBeforeItOnRemoval(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync() // the fake fails the test if the label lands before the grant is active and valid
	in := w.kube.log
	if c, l := indexOf(in, "create app-a/"+agent.MergedGrantName), indexOf(in, "label app-a"); c < 0 || l < c {
		t.Fatalf("add order: %v", in)
	}
	if v, l := indexOf(in, "valid app-a/"+agent.MergedGrantName), indexOf(in, "label app-a"); v < 0 || l < v {
		t.Fatalf("labelled before the grant was valid: %v", in)
	}
	w.kube.log = nil
	// The opt-out: the label first, then the Application, then the grant.
	w.setAnn("web-prod", agent.AnnProtect, nil)
	w.clock.add(70 * time.Second) // past the report debounce
	w.mustReconcile()
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	out := w.kube.log
	u, a, d := indexOf(out, "unlabel app-a"), indexOf(out, "app argocd-apps/web-prod"), indexOf(out, "delete app-a/"+agent.MergedGrantName)
	if u < 0 || a < 0 || !(u < a) {
		t.Fatalf("the label comes off before the Application is put back: %v", out)
	}
	if d >= 0 && d < u {
		t.Fatalf("the grant was deleted before the label came off: %v", out)
	}
	if w.labelled("app-a") {
		t.Error("still labelled")
	}
	if _, ok := w.merged("app-a"); ok {
		t.Errorf("the merged grant of an unprotected namespace stays: %v", out)
	}
}

func TestANamespaceAnOperatorLabelledIsNeverUnlabelled(t *testing.T) {
	w := newOptWorld(t)
	w.kube.protect("app-a", nil) // an operator's label: no marker
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	if g, ok := w.merged("app-a"); !ok || !g.Active() {
		t.Fatalf("the merged grant takes over: %v", w.kube.log)
	}
	if w.kube.ns["app-a"][agent.LabelProtectedBy] != "" {
		t.Error("the agent put its marker on an operator's label")
	}
	w.setAnn("web-prod", agent.AnnProtect, nil)
	w.clock.add(70 * time.Second) // past the report debounce
	w.mustReconcile()
	w.publishSync()
	if !w.labelled("app-a") {
		t.Fatal("the agent removed a label it did not put")
	}
	if g := w.grant("app-a", ch1); !g.Active() {
		t.Error("after the opt-out the per-change grant is the active one again")
	}
}

func TestANamespaceStaysLabelledWhileAnotherProtectedApplicationTargetsIt(t *testing.T) {
	w := newOptWorld(t)
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("api", hex("c")))
	w.publishSync()
	w.setAnn("web-prod", agent.AnnProtect, nil)
	w.clock.add(70 * time.Second) // past the report debounce
	w.mustReconcile()
	w.publishSync()
	if !w.labelled("app-a") {
		t.Fatal("unlabelled while api still asks for protection")
	}
	g, _ := w.merged("app-a")
	if got := objKeys(g); got != "apps/Deployment/api=c" {
		t.Errorf("web's objects left the grant with its opt-out: %s", got)
	}
}

func TestIfTheLabelCannotComeOffTheGrantStays(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	w.setAnn("web-prod", agent.AnnProtect, nil)
	w.clock.add(70 * time.Second) // past the report debounce
	w.kube.failNS["app-a"] = errBoom
	_ = w.reconcile()
	_ = w.sync()
	if !w.isSwitched("web-prod") || !w.labelled("app-a") {
		t.Fatal("the Application was put back or the label dropped though the label could not come off")
	}
	if _, ok := w.merged("app-a"); !ok {
		t.Fatal("the grant was deleted from a namespace that is still labelled (the fake would have failed the test)")
	}
	delete(w.kube.failNS, "app-a")
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	w.publishSync()
	if w.isSwitched("web-prod") || w.labelled("app-a") {
		t.Fatal("not repaired by the next passes")
	}
}

// -- the crash points -----------------------------------------------------------------------------------------------

// Each crash point is a failed write; a new agent process (a restart) then finds the state it left and finishes.
func TestEveryCrashPointIsRepairedByTheNextPass(t *testing.T) {
	type step struct {
		name string
		fail func(w *optWorld) // makes the write at that point fail
		heal func(w *optWorld)
		// state after the failed pass
		check func(t *testing.T, w *optWorld)
	}
	steps := []step{
		{"the Application write (after the pair is reported)",
			func(w *optWorld) { w.kube.failApp["web-prod"] = errBoom },
			func(w *optWorld) { delete(w.kube.failApp, "web-prod") },
			func(t *testing.T, w *optWorld) {
				if w.isSwitched("web-prod") || fmt.Sprint(lastReport(w)) != "[web/prod]" {
					t.Error("expected: reported (protected at the core), not switched")
				}
			}},
		{"the merged grant write (after the Application switched)",
			func(w *optWorld) { w.kube.failName = map[string]bool{agent.MergedGrantName: true} },
			func(w *optWorld) { w.kube.failName = nil },
			func(t *testing.T, w *optWorld) {
				if _, ok := w.merged("app-a"); ok || w.labelled("app-a") {
					t.Error("a grant or label from a failed write")
				}
			}},
		{"the label (after the grant is active)",
			func(w *optWorld) { w.kube.failNS["app-a"] = errBoom },
			func(w *optWorld) { delete(w.kube.failNS, "app-a") },
			func(t *testing.T, w *optWorld) {
				if g, ok := w.merged("app-a"); !ok || !g.Active() || w.labelled("app-a") {
					t.Error("expected: grant active, namespace not labelled yet")
				}
			}},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			w := newOptWorld(t)
			w.addApp("web-prod", "app-a", protect())
			s.fail(w)
			_ = w.reconcile()
			feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
			w.feeds.publish()
			_ = w.sync()
			s.check(t, w)
			s.heal(w)
			w.a = w.restart() // the process died; its memory is gone
			w.clock.add(2 * time.Minute)
			w.mustReconcile()
			w.feeds.claims[0].Expires = w.clock.now().Add(time.Hour).Unix()
			w.publishSync()
			if !w.isSwitched("web-prod") || !w.labelled("app-a") {
				t.Fatalf("not repaired: switched %v labelled %v log %v", w.isSwitched("web-prod"), w.labelled("app-a"), w.kube.log)
			}
			if g, ok := w.merged("app-a"); !ok || !g.Active() || objKeys(g) != "apps/Deployment/web=a" {
				t.Errorf("grant after the repair: %v %v", g.Labels, ok)
			}
		})
	}
}

func TestOptOutCrashPointsLeaveTheNamespaceProtectedOrUnenforcedNeverHalfway(t *testing.T) {
	setup := func(t *testing.T) *optWorld {
		w := newOptWorld(t)
		w.addApp("web-prod", "app-a", protect())
		w.mustReconcile()
		feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
		w.publishSync()
		if !w.labelled("app-a") {
			t.Fatal("setup")
		}
		w.setAnn("web-prod", agent.AnnProtect, nil)
		w.clock.add(70 * time.Second) // past the report debounce
		return w
	}
	t.Run("the Application write fails after the label came off", func(t *testing.T) {
		w := setup(t)
		w.kube.failApp["web-prod"] = errBoom
		_ = w.reconcile()
		if w.labelled("app-a") || !w.isSwitched("web-prod") {
			t.Fatal("expected: unlabelled, still on the plugin (the plugin's stamped objects are harmless without a label)")
		}
		delete(w.kube.failApp, "web-prod")
		w.a = w.restart()
		w.clock.add(2 * time.Minute)
		w.mustReconcile()
		w.feeds.claims[0].Expires = w.clock.now().Add(time.Hour).Unix()
		w.publishSync()
		if w.isSwitched("web-prod") || w.labelled("app-a") {
			t.Fatal("not finished")
		}
		if _, ok := w.merged("app-a"); ok {
			t.Error("the merged grant of an unprotected namespace stays")
		}
	})
	t.Run("the process dies after the report, before anything else", func(t *testing.T) {
		w := setup(t)
		w.kube.failNS["app-a"] = errBoom
		_ = w.reconcile() // reported; unlabel failed; Application untouched
		if !w.labelled("app-a") || !w.isSwitched("web-prod") {
			t.Fatal("expected: still labelled and switched")
		}
		delete(w.kube.failNS, "app-a")
		w.a = w.restart()
		w.mustReconcile()
		if w.labelled("app-a") || w.isSwitched("web-prod") {
			t.Fatal("not finished by a restarted agent")
		}
	})
}

// -- the grant loop with the opt-in on, and the Applications unreadable -------------------------------------------

func TestWithTheOptInOnAnUnreadableApplicationListLeavesTheGrantsAlone(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	w.publishSync()
	w.kube.listAppErr = errBoom
	before := w.writes()
	ops := len(w.kube.log)
	w.feeds.claims = nil // the feed now lists nothing; without the Applications the agent must not act on it
	w.feeds.publish()
	if err := w.sync(); err == nil {
		t.Fatal("expected the error")
	}
	w.noNewWrites(before, "a grant pass that could not read the Applications", "put") // put: the feed's new seq
	if len(w.kube.log) != ops {
		t.Errorf("the grants changed: %v", w.kube.log[ops:])
	}
	if _, ok := w.merged("app-a"); !ok || !w.labelled("app-a") {
		t.Error("protection dropped")
	}
}

func TestAnOptInAgentKeepsPerChangeGrantsForNamespacesNoSwitchedApplicationTargets(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	feedObjs(w, "gate-api", "app-gate", ch2, t0, deploy("gate-api", hex("c")))
	w.publishSync()
	if g := w.grant("app-gate", ch2); !g.Active() {
		t.Error("the per-change grant of an unprotected namespace is as before")
	}
	if _, ok := w.merged("app-gate"); ok {
		t.Error("a merged grant for a namespace no protected Application targets")
	}
}

// -- the merged grant never admits more than was cleared ---------------------------------------------------------

// Random Applications (asking, not asking, a value that is not "true", another environment) and random clearances
// (other apps, other namespaces, objects in namespaces not the Application's): whatever the agent writes, every
// object and hash in a merged grant, carried trees included, is in a clearance of an Application that asks for
// protection, was switched, targets that namespace, and is in the environment the clearance names.
func TestAMergedGrantNeverAdmitsMoreThanWasCleared(t *testing.T) {
	r := rand.New(rand.NewSource(10))
	nsNames := []string{"ns-a", "ns-b", "ns-c"}
	checked, objectsChecked := 0, 0
	appNames := []string{"a1", "a2", "a3", "a4", "a5", "a6"}
	for round := 0; round < 400; round++ {
		w := newOptWorld(t)
		type spec struct {
			dest, env string
			asks      bool
		}
		apps := map[string]spec{}
		for _, n := range appNames {
			s := spec{dest: nsNames[r.Intn(len(nsNames))], env: []string{"prod", "prod", "staging"}[r.Intn(3)]}
			ann := map[string]string{}
			switch r.Intn(5) {
			case 0, 1, 2:
				ann[agent.AnnProtect], s.asks = "true", true
			case 3:
				ann[agent.AnnProtect] = []string{"True", "yes", "false", ""}[r.Intn(4)]
			}
			a := w.addApp(n+"-x", s.dest, ann)
			a.Labels[agent.LabelAppName], a.Labels[agent.LabelAppEnv] = n, s.env
			apps[n] = s
		}
		w.mustReconcile()
		id := 0
		for i := 0; i < 2+r.Intn(8); i++ {
			app := append(appNames, "stranger")[r.Intn(len(appNames)+1)]
			var objs []token.Object
			for j := 0; j < 1+r.Intn(3); j++ {
				o := deploy(fmt.Sprintf("o%d", r.Intn(6)), strings.Repeat(string(rune('a'+r.Intn(5))), 64))
				o.Namespace = nsNames[r.Intn(len(nsNames))]
				objs = append(objs, o)
			}
			id++
			c := claim(w.feeds, fmt.Sprintf("ch-%016x", id), "ns-a", t0.Add(-time.Duration(r.Intn(10))*time.Minute), objs...)
			for j := range c.Objects { // claim() put every object in ns-a; the random namespaces are the test's
				c.Objects[j].Namespace = objs[j].Namespace
			}
			c.Target.App, c.Target.Env = app, []string{"prod", "staging"}[r.Intn(2)]
			c.Expires = t0.Add(time.Hour).Unix()
			w.feeds.claims = append(w.feeds.claims, c)
		}
		w.feeds.publish()
		if err := w.sync(); err != nil {
			t.Fatal(err)
		}
		for key, g := range w.kube.grants {
			if g.Name != agent.MergedGrantName {
				continue
			}
			justified := func(objKey, hash string) bool {
				for n, s := range apps {
					if !s.asks || s.dest != g.Namespace || !w.isSwitched(n+"-x") {
						continue
					}
					for _, c := range w.feeds.claims {
						if c.Target.App != n || c.Target.Env != s.env {
							continue
						}
						for _, o := range c.Objects {
							grp := ""
							if i := strings.Index(o.APIVersion, "/"); i >= 0 {
								grp = o.APIVersion[:i]
							}
							if o.Namespace == g.Namespace && agent.GrantKey(grp, o.Kind, o.Name) == objKey && o.Rendered == hash {
								return true
							}
						}
					}
				}
				return false
			}
			checked++
			for k, o := range g.Spec.Objects {
				objectsChecked++
				if !justified(k, o.Rendered) {
					t.Fatalf("round %d: %s lists %s=%s that no clearance of a protected, switched Application in the namespace has", round, key, k, o.Rendered[:1])
				}
			}
			for _, c := range g.Spec.Carried {
				for k, o := range c.Objects {
					if !justified(k, o.Rendered) {
						t.Fatalf("round %d: %s carries %s=%s that no clearance of a protected Application has", round, key, k, o.Rendered[:1])
					}
				}
			}
		}
		// And only an Application that asked is ever on the plugin.
		for n, s := range apps {
			if w.isSwitched(n+"-x") && !s.asks {
				t.Fatalf("round %d: %s was switched without asking", round, n)
			}
		}
	}
	if checked < 20 || objectsChecked < 40 { // a check that looked at nothing proves nothing
		t.Fatalf("only %d merged grants and %d objects were checked", checked, objectsChecked)
	}
}

// The exception scan reads the merged grant too: an object running at a hash only a carried tree lists is cleared (the
// merged grant has no per-change grant beside it that would list it), and one nothing lists is still an exception.
func TestTheExceptionScanReadsTheCarriedTreesOfAMergedGrant(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.mustReconcile()
	w.kube.ns["app-a"] = map[string]string{agent.LabelEnvironment: "prod"}
	d, dHash := stamped(t, "Deployment", "web", "app-a", "web-prod", ch1, hex("c"))
	c, _ := stamped(t, "ConfigMap", "cfg", "app-a", "web-prod", ch1, hex("c"))
	// ch1 (older) cleared the Deployment as it runs; ch2 (newer) clears another hash for it.
	feedObjs(w, "web", "app-a", ch1, t0.Add(-time.Minute), token.Object{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Rendered: dHash})
	feedObjs(w, "web", "app-a", ch2, t0, deploy("web", hex("f")))
	w.publishSync()
	g, ok := w.merged("app-a")
	if !ok || g.Spec.Objects["apps/Deployment/web"].Rendered != hex("f") || len(g.Spec.Carried) != 1 {
		t.Fatalf("grant: %v %+v", ok, g.Spec)
	}
	w.kube.objs["app-a"] = []agent.ObjectDetail{d, c}
	if err := w.a.ScanExceptions(bg); err != nil {
		t.Fatal(err)
	}
	ex := w.core.of("deploy.exception")
	if len(ex) != 1 || *ex[0].Record.Result != agent.ReasonNotListd {
		t.Fatalf("exceptions: %+v", ex)
	}
	if objs := ex[0].Record.Exception["objects"].([]map[string]any); len(objs) != 1 || objs[0]["name"] != "cfg" {
		t.Errorf("only the ConfigMap no grant lists is an exception, not the Deployment a carried tree lists: %v", objs)
	}
}
