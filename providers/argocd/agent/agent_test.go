package agent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/token"
	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

var bg = context.Background()

const (
	ch1 = "ch-00000000000000a1"
	ch2 = "ch-00000000000000a2"
	ch3 = "ch-00000000000000a3"
	ch4 = "ch-00000000000000a4"
)

func (w *world) grant(ns, name string) agent.Grant {
	g, ok := w.kube.grants[ns+"/"+name]
	if !ok {
		w.t.Fatalf("no grant %s/%s (have %v)", ns, name, keysOf(w.kube.grants))
	}
	return g
}

func keysOf(m map[string]agent.Grant) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestGrantSync(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	w.feeds.claims = []token.Claims{
		claim(w.feeds, ch1, "app-a", t0.Add(-2*time.Minute), deploy("web", hex("a")), cmap("cfg", hex("b"))),
		claim(w.feeds, ch2, "app-a", t0.Add(-time.Minute), deploy("web", hex("c")), cmap("cfg", hex("b"))),
		claim(w.feeds, ch3, "elsewhere", t0.Add(-time.Minute), deploy("web", hex("d"))),
	}
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	// A grant is written for a namespace that is not (yet) labelled protected: the operator labels a namespace only once
	// its grant is active, so the label never lands on a namespace that would freeze.
	if len(w.kube.grants) != 3 || !w.grant("elsewhere", ch3).Active() {
		t.Fatalf("grants: %v", keysOf(w.kube.grants))
	}
	g1, g2 := w.grant("app-a", ch1), w.grant("app-a", ch2)
	if g1.Active() || !g2.Active() {
		t.Errorf("the newest cleared grant is the active one: %v %v", g1.Labels, g2.Labels)
	}
	if g2.Valid == nil || !*g2.Valid || g1.Valid == nil || !*g1.Valid {
		t.Errorf("status.valid is the agent's: %v %v", g1.Valid, g2.Valid)
	}
	if g2.Spec.Objects["apps/Deployment/web"] != (agent.GrantObject{Rendered: hex("c"), Changed: true}) ||
		g2.Spec.Objects["/ConfigMap/cfg"] != (agent.GrantObject{Rendered: hex("b")}) || len(g2.Spec.Objects) != 2 || g2.Spec.Subject.Tree != hex("c") || g2.Spec.Clearance.ID != ch2 ||
		g2.Spec.ExpiresAt != t0.Add(-time.Minute+15*time.Minute).Format(time.RFC3339) {
		t.Errorf("spec: %+v", g2.Spec)
	}
	if g2.Labels[agent.LabelManagedBy] != agent.ManagedBy || g2.Labels[agent.LabelApp] != "web" {
		t.Errorf("labels: %v", g2.Labels)
	}
	// The same feed again changes nothing.
	ops := w.kube.grantOps
	if err := w.sync(); err != nil || w.kube.grantOps != ops {
		t.Errorf("an unchanged feed wrote: %v (%d ops)", err, w.kube.grantOps-ops)
	}
	// ch-1 leaves the feed (superseded, revoked) and a newer change arrives: the old grant goes, the active label moves,
	// and the fake kube fails the test if a namespace ever holds two active grants.
	w.clock.add(time.Minute)
	w.kube.log = nil
	w.feeds.claims = []token.Claims{w.feeds.claims[1], claim(w.feeds, ch4, "app-a", w.clock.now(), deploy("web", hex("e")), cmap("cfg", hex("b")))}
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.kube.grants["app-a/"+ch1]; ok {
		t.Error("a grant no entry names is removed")
	}
	if w.grant("app-a", ch2).Active() || !w.grant("app-a", ch4).Active() {
		t.Error("the active label moves to the newest")
	}
	// The rotation order: the new grant is written (not active) and valid before the old one is deactivated, and the
	// old one is deactivated and the new one activated back to back (no other call between them).
	var ns []string
	for _, l := range w.kube.log {
		if strings.Contains(l, "app-a") {
			ns = append(ns, l)
		}
	}
	wantOrder := []string{"apply app-a/" + ch4 + " active=false", "valid app-a/" + ch4 + " true",
		"apply app-a/" + ch2 + " active=false", "apply app-a/" + ch4 + " active=true"}
	if strings.Join(ns[:4], ";") != strings.Join(wantOrder, ";") {
		t.Errorf("rotation order:\n%v\nwant\n%v", ns, wantOrder)
	}
	// An empty feed removes every grant.
	w.feeds.claims = nil
	w.feeds.publish()
	if err := w.sync(); err != nil || len(w.kube.grants) != 0 {
		t.Errorf("empty feed: %v %v", err, keysOf(w.kube.grants))
	}
	if w.kube.workOps != 0 {
		t.Error("the agent touched a workload")
	}
}

func TestFailClosedAndExpiry(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	w.feeds.claims = []token.Claims{claim(w.feeds, ch2, "app-a", t0, deploy("web", hex("c")))}
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	live := w.grant("app-a", ch2)
	w.kube.objs["app-a"] = []agent.ObjectDetail{{Object: agent.Object{Kind: "Deployment", Name: "web"}}}
	// clearance-api goes away: grants stop updating, and nothing is removed or touched.
	w.feeds.down = true
	w.clock.add(5 * time.Minute)
	if err := w.sync(); err == nil || !strings.Contains(err.Error(), "grants stay as they are") {
		t.Fatalf("an unreachable feed: %v", err)
	}
	if g := w.grant("app-a", ch2); !g.Active() || g.Valid == nil || !*g.Valid {
		t.Errorf("before its expiry the grant is as it was: %+v", g)
	}
	// ... and on their own clock they run out (status.valid false, the active label gone), still not deleted.
	w.clock.add(15 * time.Minute)
	if err := w.sync(); err == nil {
		t.Fatal("still unreachable")
	}
	g := w.grant("app-a", ch2)
	if g.Valid == nil || *g.Valid || g.Active() || g.Spec.ExpiresAt != live.Spec.ExpiresAt {
		t.Errorf("expired grant: %+v", g)
	}
	if w.kube.workOps != 0 || len(w.kube.objs["app-a"]) != 1 {
		t.Error("something running was touched")
	}
}

func TestFeedRefusals(t *testing.T) {
	good := func(t *testing.T) *world {
		w := newWorld(t)
		w.kube.protect("app-a", nil)
		w.feeds.claims = []token.Claims{claim(w.feeds, ch2, "app-a", t0, deploy("web", hex("c")))}
		w.feeds.seq = 1
		w.feeds.publishAt("epoch-one", 2, "hangar-prod", w.feeds.signer)
		if err := w.sync(); err != nil {
			t.Fatal(err)
		}
		return w
	}
	other, _ := newSignerFor(t)
	cases := map[string]func(w *world){
		"signed by another key": func(w *world) { w.feeds.publishAt("epoch-one", 3, "hangar-prod", other) },
		"another cluster's":     func(w *world) { w.feeds.publishAt("epoch-one", 3, "other-cluster", w.feeds.signer) },
		"a replay (same epoch, lower seq)": func(w *world) {
			w.feeds.publishAt("epoch-one", 1, "hangar-prod", w.feeds.signer)
		},
		"no epoch": func(w *world) { w.feeds.publishAt("", 3, "hangar-prod", w.feeds.signer) },
		"a token withheld": func(w *world) {
			w.feeds.publishAt("epoch-one", 3, "hangar-prod", w.feeds.signer)
			var m map[string]any
			_ = json.Unmarshal(w.feeds.raw, &m)
			m["tokens"] = []any{}
			w.feeds.raw, _ = json.Marshal(m)
		},
		"stale": func(w *world) { w.clock.add(10 * time.Minute) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := good(t)
			before := w.grant("app-a", ch2)
			mutate(w)
			// Replace the feed's claim so that acting on it would be visible.
			if err := w.sync(); err == nil {
				t.Fatal("accepted")
			}
			after := w.grant("app-a", ch2)
			if after.Spec.Subject != before.Spec.Subject || len(w.kube.grants) != 1 {
				t.Errorf("a refused feed changed a grant")
			}
		})
	}
}

func TestEpochAndSeqSurviveARestart(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	w.feeds.claims = []token.Claims{claim(w.feeds, ch2, "app-a", t0, deploy("web", hex("c")))}
	w.feeds.epoch, w.feeds.seq = "epoch-one", 6
	w.feeds.publish() // seq 7
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	w.a = w.agent() // a restart reads the epoch and seq back from the state ConfigMap
	w.feeds.publishAt("epoch-one", 5, "hangar-prod", w.feeds.signer)
	if err := w.sync(); err == nil || !strings.Contains(err.Error(), "seq went back") {
		t.Fatalf("a replay after a restart: %v", err)
	}
	// A rebuilt core: another epoch, seq starts again at 1, no operator reset.
	w.feeds.publishAt("epoch-two", 1, "hangar-prod", w.feeds.signer)
	if err := w.sync(); err != nil {
		t.Fatalf("a new epoch: %v", err)
	}
	w.feeds.publishAt("epoch-two", 3, "hangar-prod", w.feeds.signer)
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	w.a = w.agent()
	w.feeds.publishAt("epoch-two", 2, "hangar-prod", w.feeds.signer)
	if err := w.sync(); err == nil {
		t.Fatal("the new epoch's replay is refused as well")
	}
	w.feeds.publishAt("epoch-one", 9, "hangar-prod", w.feeds.signer) // the old database's feed is another epoch: taken (its exp bounds it)
	if err := w.sync(); err != nil {
		t.Fatalf("another epoch: %v", err)
	}
}

// A new grant that cannot be written leaves the old one active: the namespace is never left without one because a
// rotation failed.
func TestARotationThatFailsKeepsTheActiveGrant(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	w.feeds.claims = []token.Claims{claim(w.feeds, ch1, "app-a", t0.Add(-time.Minute), deploy("web", hex("a")))}
	w.feeds.publish()
	if err := w.sync(); err != nil || !w.grant("app-a", ch1).Active() {
		t.Fatal(err)
	}
	w.feeds.claims = append(w.feeds.claims, claim(w.feeds, ch2, "app-a", t0, deploy("web", hex("c"))))
	w.feeds.publish()
	w.kube.failName = map[string]bool{ch2: true}
	if err := w.sync(); err == nil {
		t.Fatal("the failed write is an error")
	}
	if !w.grant("app-a", ch1).Active() {
		t.Error("the old grant lost its label though the new one is not in place")
	}
	w.kube.failName = nil
	if err := w.sync(); err != nil || w.grant("app-a", ch1).Active() || !w.grant("app-a", ch2).Active() {
		t.Errorf("recovery: %v", err)
	}
}

// The running tree stays admissible beside a newer change: the active grant (the newest cleared change) carries the
// other live cleared trees of the namespace, and only while each one's own clearance lasts.
func TestTheActiveGrantCarriesTheRunningTree(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	// ch1 is the tree prod runs (cleared and merged earlier); ch2 is a newer change cleared on its PR, not merged.
	w.feeds.claims = []token.Claims{
		claim(w.feeds, ch1, "app-a", t0.Add(-10*time.Minute), deploy("web", hex("a")), cmap("cfg", hex("b"))),
		claim(w.feeds, ch2, "app-a", t0, deploy("web", hex("c")), cmap("cfg", hex("b"))),
	}
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	g1, g2 := w.grant("app-a", ch1), w.grant("app-a", ch2)
	if g1.Active() || !g2.Active() || len(g1.Spec.Carried) != 0 {
		t.Fatalf("the newest is active and only it carries: %v %v %+v", g1.Labels, g2.Labels, g1.Spec.Carried)
	}
	// Self-heal of the running tree: web at hash a is carried. cfg is at b in both, so it is not said twice.
	if len(g2.Spec.Carried) != 1 || g2.Spec.Carried[0].Change != ch1 ||
		g2.Spec.Carried[0].Objects["apps/Deployment/web"].Rendered != hex("a") || len(g2.Spec.Carried[0].Objects) != 1 {
		t.Fatalf("carried: %+v", g2.Spec.Carried)
	}
	if g2.Spec.Objects["apps/Deployment/web"].Rendered != hex("c") {
		t.Errorf("the active grant's own objects stay the newest tree's: %+v", g2.Spec.Objects)
	}
	ops := w.kube.grantOps
	if err := w.sync(); err != nil || w.kube.grantOps != ops {
		t.Errorf("an unchanged feed wrote: %v", err)
	}

	// Hub path down: the carried tree's own clearance runs out first (ch1 was cleared 10 minutes before ch2), and the
	// agent drops it on its own clock while the active grant stays valid.
	w.feeds.down = true
	w.clock.add(6 * time.Minute) // ch1 expires at t0+5m; ch2 at t0+15m
	if err := w.sync(); err == nil {
		t.Fatal("still unreachable")
	}
	if g := w.grant("app-a", ch2); !g.Active() || len(g.Spec.Carried) != 0 || g.Valid == nil || !*g.Valid {
		t.Errorf("the expired tree is dropped, the active grant stays: %+v", g)
	}
	w.clock.add(10 * time.Minute) // ch2 expires too: nothing is active (Deny freezes the namespace until the path is back)
	if err := w.sync(); err == nil {
		t.Fatal("still unreachable")
	}
	if g := w.grant("app-a", ch2); g.Active() || g.Valid == nil || *g.Valid {
		t.Errorf("the hub path stayed down past the last token: %+v", g)
	}
	// The path returns with fresh tokens: the grant is valid and active again with no operator action.
	w.feeds.down = false
	w.feeds.claims = []token.Claims{
		claim(w.feeds, ch1, "app-a", w.clock.now().Add(-2*time.Minute), deploy("web", hex("a")), cmap("cfg", hex("b"))),
		claim(w.feeds, ch2, "app-a", w.clock.now(), deploy("web", hex("c")), cmap("cfg", hex("b"))),
	}
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	if g := w.grant("app-a", ch2); !g.Active() || g.Valid == nil || !*g.Valid || len(g.Spec.Carried) != 1 {
		t.Errorf("recovery: %+v", g)
	}

	// A revoked or superseded change leaves the feed: its hashes are carried no longer. And a change cleared and never
	// merged does not matter to the running tree: dropping ch2 makes ch1 the active grant, carrying nothing.
	w.feeds.claims = w.feeds.claims[:1]
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	if g := w.grant("app-a", ch1); !g.Active() || len(g.Spec.Carried) != 0 {
		t.Errorf("after ch2 left the feed: %+v", g)
	}
	// A tree that is revoked while a newer one is active is dropped from the carried list at the next feed.
	w.feeds.claims = []token.Claims{
		claim(w.feeds, ch1, "app-a", w.clock.now().Add(-2*time.Minute), deploy("web", hex("a")), cmap("cfg", hex("b"))),
		claim(w.feeds, ch4, "app-a", w.clock.now(), deploy("web", hex("e")), cmap("cfg", hex("b"))),
	}
	w.feeds.publish()
	if err := w.sync(); err != nil || len(w.grant("app-a", ch4).Spec.Carried) != 1 {
		t.Fatalf("carried again: %v %+v", err, w.grant("app-a", ch4).Spec.Carried)
	}
	w.feeds.claims = w.feeds.claims[1:]
	w.feeds.publish()
	if err := w.sync(); err != nil || len(w.grant("app-a", ch4).Spec.Carried) != 0 {
		t.Errorf("revoked: %v %+v", err, w.grant("app-a", ch4).Spec.Carried)
	}
}

// Only a namespace's own trees are carried, and no more than MaxCarried.
func TestCarriedIsPerNamespaceAndBounded(t *testing.T) {
	w := newWorld(t)
	w.kube.protect("app-a", nil)
	var cs []token.Claims
	for i := 0; i < agent.MaxCarried+4; i++ {
		cs = append(cs, claim(w.feeds, fmt.Sprintf("ch-%016d", i), "app-a", t0.Add(-time.Minute+time.Duration(i)*time.Second),
			deploy("web", hex("a")[:60]+fmt.Sprintf("%04d", i))))
	}
	cs = append(cs, claim(w.feeds, ch3, "elsewhere", t0.Add(-time.Second), deploy("web", hex("d"))))
	w.feeds.claims = cs
	w.feeds.publish()
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	if g := w.grant("app-a", fmt.Sprintf("ch-%016d", agent.MaxCarried+3)); len(g.Spec.Carried) > agent.MaxCarried {
		t.Errorf("carried %d", len(g.Spec.Carried))
	}
	if g := w.grant("elsewhere", ch3); len(g.Spec.Carried) != 0 {
		t.Errorf("another namespace's trees are not carried: %+v", g.Spec.Carried)
	}
}
