package agent_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/token"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

// Third-round review fixes for G-ARGO-10c (pull request 175).

// heldMerged is a labelled namespace with a held merged grant, and an agent that has just restarted.
func heldMerged(t *testing.T) *optWorld {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.addApp("api-prod", "app-a", protect())
	w.mustReconcile()
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("api", hex("c")))
	w.publishSync()
	if g, ok := w.merged("app-a"); !ok || len(g.Spec.Objects) != 2 || !w.labelled("app-a") {
		t.Fatal("setup")
	}
	w.a = w.restart()
	return w
}

// -- 1. a failing schema read must not tear down a held merged grant ---------------------------------------------------

func TestAFailedSchemaReadKeepsTheHeldMergedGrantAndTheLabelButStillDropsRevokedObjects(t *testing.T) {
	cases := map[string]func(w *optWorld){
		"forbidden": func(w *optWorld) {
			w.kube.schemaErr = &agent.StatusError{Code: 403, Body: "customresourcedefinitions is forbidden"}
		},
		"timing out":     func(w *optWorld) { w.kube.schemaErr = context.DeadlineExceeded },
		"fields missing": func(w *optWorld) { w.kube.schemaMissing = []string{"objects.app", "objects.expiresAt"} },
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			w := heldMerged(t)
			fail(w)
			// web's clearance is revoked; the schema read answers badly on every pass after the restart.
			w.dropClaims(ch1)
			before := w.writes()
			w.publishSync()
			g, ok := w.merged("app-a")
			if !ok || !g.Active() || g.Valid == nil || !*g.Valid {
				t.Fatalf("the held merged grant was torn down: %v %v", ok, w.kube.log)
			}
			if got := objKeys(g); got != "apps/Deployment/api=c" {
				t.Fatalf("the revoked object must still leave and nothing else change: %s", got)
			}
			if !w.labelled("app-a") || !w.isSwitched("web-prod") || !w.isSwitched("api-prod") {
				t.Fatal("the label or an Application changed")
			}
			after := w.writes()
			if after["delete"] != before["delete"] || after["create"] != before["create"] || after["ns"] != before["ns"] || after["app"] != before["app"] {
				t.Fatalf("other writes: before %v after %v (%v)", before, after, w.kube.log)
			}
			if len(w.core.reports) != 1 {
				t.Errorf("the opt-in is off: no report: %d", len(w.core.reports))
			}
			// A repeat pass writes nothing.
			ops := len(w.kube.log)
			w.clock.add(10 * time.Second)
			w.publishSync()
			if len(w.kube.log) != ops {
				t.Errorf("a repeat pass wrote: %v", w.kube.log[ops:])
			}
			// Recovery: the read succeeds (after the backoff) and the opt-in carries on.
			w.kube.schemaErr, w.kube.schemaMissing = nil, nil
			w.clock.add(6 * time.Minute)
			w.mustReconcile()
			w.feeds.claims[0].Expires = w.clock.now().Add(time.Hour).Unix()
			w.feeds.claims[0].IssuedAt = w.clock.now().Add(-time.Second).Unix()
			feedObjs(w, "web", "app-a", ch3, w.clock.now(), deploy("web", hex("e")))
			w.publishSync()
			if got := w.mergedObjects("app-a"); got != "apps/Deployment/api=c,apps/Deployment/web=e" {
				t.Fatalf("after recovery: %s", got)
			}
		})
	}
}

func TestAFailedSchemaReadIsRetriedWithBackoffNotAfterFiveMinutes(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.kube.schemaErr = errors.New("api briefly down")
	w.mustReconcile()
	n := w.kube.reads["schema"]
	if n != 1 {
		t.Fatalf("%d reads", n)
	}
	w.clock.add(35 * time.Second) // the ordinary pass interval, with the first backoff
	w.kube.schemaErr = nil
	w.mustReconcile()
	if !w.isSwitched("web-prod") {
		t.Fatal("a failed read waited five minutes before it was retried")
	}
	// Last known good: a later failure keeps the opt-in running.
	w.kube.schemaErr = errors.New("down again")
	w.clock.add(time.Minute)
	if err := w.reconcile(); err != nil || !w.isSwitched("web-prod") {
		t.Fatalf("%v", err)
	}
}

// -- 2. the CRD exception: after 5 minutes of failing, once a day ---------------------------------------------------------

func TestTheCRDExceptionWaitsFiveMinutesAndIsPostedOncePerDay(t *testing.T) {
	// A flap shorter than five minutes posts nothing.
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	w.kube.schemaErr = errors.New("api briefly down")
	w.mustReconcile()
	w.clock.add(40 * time.Second)
	w.mustReconcile()
	w.kube.schemaErr = nil
	w.clock.add(2 * time.Minute)
	w.mustReconcile()
	if !w.isSwitched("web-prod") || len(w.core.of("deploy.exception")) != 0 {
		t.Fatalf("a short failure posted: %d", len(w.core.of("deploy.exception")))
	}
	// Failing continuously: nothing before five minutes, then one naming the CRD from the configured group, then nothing
	// for 24 hours however often it is read, then one more.
	w2 := newOptWorld(t)
	w2.addApp("web-prod", "app-a", protect())
	w2.kube.schemaMissing = []string{"objects.app"}
	w2.mustReconcile()
	w2.clock.add(2 * time.Minute)
	w2.mustReconcile()
	if len(w2.core.of("deploy.exception")) != 0 {
		t.Fatal("reported before five minutes")
	}
	w2.clock.add(4 * time.Minute)
	w2.mustReconcile()
	ex := w2.core.of("deploy.exception")
	if len(ex) != 1 || !strings.Contains(fmt.Sprint(ex[0].Record.Exception["objects"]), "clearancegrants.clearance.hangar.io") {
		t.Fatalf("%+v", ex)
	}
	for i := 0; i < 40; i++ {
		w2.clock.add(30 * time.Minute)
		w2.mustReconcile()
	}
	if n := len(w2.core.of("deploy.exception")); n != 1 {
		t.Fatalf("posted again within 24 hours: %d", n)
	}
	w2.clock.add(6 * time.Hour)
	w2.mustReconcile()
	if n := len(w2.core.of("deploy.exception")); n != 2 {
		t.Fatalf("after a day it may be posted again: %d", n)
	}
	// The CRD name comes from the configured group.
	w3 := newOptWorld(t)
	w3.a = mustAgent(t, w3, func(c *agent.Config) { c.GrantCRD = "clearancegrants.example.test" })
	w3.addApp("web-prod", "app-a", protect())
	w3.kube.schemaMissing = []string{"objects.app"}
	w3.mustReconcile()
	w3.clock.add(6 * time.Minute)
	w3.mustReconcile()
	if ex := w3.core.of("deploy.exception"); len(ex) != 1 || !strings.Contains(fmt.Sprint(ex[0].Record.Exception["objects"]), "clearancegrants.example.test") {
		t.Fatalf("%+v", ex)
	}
}

// -- 5. ownerless held objects ---------------------------------------------------------------------------------------------

func TestAnOwnerlessObjectIsNotLiveOnceTheGrantHasOwners(t *testing.T) {
	w := newOptWorld(t)
	w.a = mustAgent(t, w, func(c *agent.Config) { c.OptIn.MaxGrantBytes = 1500 })
	opt2(w)
	feedObjs(w, "web", "app-a", ch1, t0, deploy("web", hex("a")))
	feedObjs(w, "api", "app-a", ch2, t0, deploy("api", hex("c")))
	w.publishSync()
	// Damage the held grant: web's object loses its owner (the grant otherwise has owners), then web's clearance is
	// revoked while api's clearance lists the same key at the same hash and is too big to merge (a refusal keeps the held grant).
	g, _ := w.merged("app-a")
	web := g.Spec.Objects["apps/Deployment/web"]
	web.App = ""
	g.Spec.Objects["apps/Deployment/web"] = web
	w.kube.grants["app-a/"+agent.MergedGrantName] = g
	var objs []token.Object
	for i := 0; i < 40; i++ {
		objs = append(objs, deploy(fmt.Sprintf("big-%02d", i), hex("d")))
	}
	objs = append(objs, deploy("web", hex("a")))
	w.clock.add(time.Minute)
	feedObjs(w, "api", "app-a", ch3, w.clock.now(), objs...)
	w.feeds.claims[1].Expires = w.clock.now().Add(time.Hour).Unix()
	w.dropClaims(ch1)
	w.publishSync()
	if g, _ := w.merged("app-a"); g.Spec.Objects["apps/Deployment/web"].Rendered != "" {
		t.Fatalf("an ownerless object stayed alive on another Application's clearance: %+v", g.Spec.Objects)
	}
}

// -- 6. an addition that coincides with an unexplained opt-out ---------------------------------------------------------

func TestAnAdditionIsNotDelayedByAnUnexplainedOptOut(t *testing.T) {
	w := newOptWorld(t)
	w.addApp("web-prod", "app-a", protect())
	b := w.addApp("web-copy", "app-b", protect())
	b.Labels[agent.LabelAppName] = "web"
	w.mustReconcile()
	w.clock.add(10 * time.Second)               // inside the debounce
	w.setAnn("web-copy", agent.AnnProtect, nil) // an opt-out that changes no set: a reason, no removal
	w.addApp("db-prod", "app-c", protect())
	w.mustReconcile()
	if !w.isSwitched("db-prod") {
		t.Fatal("the new Application waited for the opt-out's debounce")
	}
	_ = client.ProtectedPair{}
}
