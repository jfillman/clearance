package grantexpiry

import (
	"strings"
	"testing"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

var (
	now     = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	past    = now.Add(-time.Minute).Format(time.RFC3339)
	future  = now.Add(10 * time.Minute).Format(time.RFC3339)
	h1, h2  = strings.Repeat("a", 64), strings.Repeat("b", 64)
	h3      = strings.Repeat("c", 64)
	tru     = true
	cmKey   = "/ConfigMap/app-cm"
	depKey  = "apps/Deployment/web"
	noPins  = Pins{}
	nothing = time.Duration(0)
)

func cmObj(name, rendered string) Object {
	o := Object{APIVersion: "v1", Kind: "ConfigMap", Name: name}
	if rendered != "" {
		o.Annotations = map[string]string{agent.AnnRendered: rendered}
	}
	return o
}

// grant is an active grant with status.valid true (the I-44 shape: valid, whatever its expiry says).
func grant(name, expiresAt string, objects map[string]agent.GrantObject, carried ...agent.CarriedTree) agent.Grant {
	return agent.Grant{Namespace: "prot", Name: name, Labels: map[string]string{agent.LabelActive: "true"}, Valid: &tru,
		Spec: agent.GrantSpec{ExpiresAt: expiresAt, Objects: objects, Carried: carried}}
}

func objs(kv ...string) map[string]agent.GrantObject {
	m := map[string]agent.GrantObject{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = agent.GrantObject{Rendered: kv[i+1], Changed: true}
	}
	return m
}

func TestDecide(t *testing.T) {
	merged := func(objExp string) agent.Grant {
		g := grant("clearance-merged", future, map[string]agent.GrantObject{cmKey: {Rendered: h1, ExpiresAt: objExp}})
		g.Labels[agent.LabelMerged] = "true"
		return g
	}
	cases := []struct {
		name    string
		obj     Object
		grants  []agent.Grant
		skew    time.Duration
		allowed bool
		expired bool
		reason  string // a substring of Verdict.Reason
	}{
		{"own object, unexpired: allowed", cmObj("app-cm", h1), []agent.Grant{grant("g1", future, objs(cmKey, h1))}, nothing, true, false, "unexpired"},
		{"own object, expired: refused by the clock", cmObj("app-cm", h1), []agent.Grant{grant("g1", past, objs(cmKey, h1))}, nothing, false, true, "expired at"},
		{"I-44: status.valid true, spec.expiresAt passed: refused", cmObj("app-cm", h1),
			[]agent.Grant{grant("g1", now.Add(-time.Hour).Format(time.RFC3339), objs(cmKey, h1))}, nothing, false, true, "only in expired entries"},
		{"own object at another hash: refused, not the clock's", cmObj("app-cm", h3), []agent.Grant{grant("g1", future, objs(cmKey, h1))}, nothing, false, false, "does not list /ConfigMap/app-cm at " + h3},
		{"an object the grant does not list: refused", cmObj("unlisted", h1), []agent.Grant{grant("g1", future, objs(cmKey, h1))}, nothing, false, false, "does not list /ConfigMap/unlisted"},
		{"the apps group is in the key", Object{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Annotations: map[string]string{agent.AnnRendered: h2}},
			[]agent.Grant{grant("g1", future, objs(depKey, h2))}, nothing, true, false, ""},
		{"merged grant, the object's own expiry unexpired: allowed", cmObj("app-cm", h1), []agent.Grant{merged(future)}, nothing, true, false, ""},
		{"merged grant, the object's own expiry passed while the grant's has not: refused", cmObj("app-cm", h1), []agent.Grant{merged(past)}, nothing, false, true, "its own entry: expired at"},
		{"merged grant, the object's own expiry unreadable: refused", cmObj("app-cm", h1), []agent.Grant{merged("soon")}, nothing, false, true, "not an RFC 3339 time"},
		{"carried entry at the hash, unexpired: allowed", cmObj("app-cm", h3),
			[]agent.Grant{grant("g1", future, objs(cmKey, h1), agent.CarriedTree{Change: "ch-old", ExpiresAt: future, Objects: objs(cmKey, h3)})}, nothing, true, false, "carried[0]"},
		{"carried entry at the hash, expired, beside an unexpired entry that does not match: refused", cmObj("app-cm", h3),
			[]agent.Grant{grant("g1", future, objs(cmKey, h1),
				agent.CarriedTree{Change: "ch-old", ExpiresAt: past, Objects: objs(cmKey, h3)},
				agent.CarriedTree{Change: "ch-other", ExpiresAt: future, Objects: objs(cmKey, h2, "/ConfigMap/else", h3)})}, nothing, false, true, "carried[0] (change ch-old): expired"},
		{"an unexpired carried entry for another key does not rescue the object", cmObj("app-cm", h3),
			[]agent.Grant{grant("g1", future, objs(cmKey, h1), agent.CarriedTree{Change: "ch-x", ExpiresAt: future, Objects: objs("/ConfigMap/other", h3)})}, nothing, false, false, "does not list"},
		{"the grant itself expired: its own entry is refused, a live carried entry at the hash still admits", cmObj("app-cm", h3),
			[]agent.Grant{grant("g1", past, objs(cmKey, h1), agent.CarriedTree{Change: "ch-old", ExpiresAt: future, Objects: objs(cmKey, h3)})}, nothing, true, false, "carried[0]"},
		{"own entry expired, a carried entry at the same hash unexpired: allowed by the carried entry", cmObj("app-cm", h1),
			[]agent.Grant{grant("g1", past, objs(cmKey, h1), agent.CarriedTree{Change: "ch-old", ExpiresAt: future, Objects: objs(cmKey, h1)})}, nothing, true, false, "carried[0]"},
		{"a carried object's own expiry passed: refused", cmObj("app-cm", h3),
			[]agent.Grant{grant("g1", future, objs(cmKey, h1), agent.CarriedTree{Change: "ch-old", ExpiresAt: future,
				Objects: map[string]agent.GrantObject{cmKey: {Rendered: h3, ExpiresAt: past}}})}, nothing, false, true, "carried[0]"},
		{"no active grant: refused", cmObj("app-cm", h1), nil, nothing, false, false, "no active ClearanceGrant"},
		{"two active grants, the object in one only: refused (each must pass, as in the policy)", cmObj("app-cm", h1),
			[]agent.Grant{grant("g1", future, objs(cmKey, h1)), grant("g2", future, objs("/ConfigMap/other", h1))}, nothing, false, false, "grant g2 does not list"},
		{"two active grants, both list it unexpired: allowed", cmObj("app-cm", h1),
			[]agent.Grant{grant("g1", future, objs(cmKey, h1)), grant("g2", future, objs(cmKey, h1))}, nothing, true, false, ""},
		{"two active grants, one lists it expired: refused by the clock", cmObj("app-cm", h1),
			[]agent.Grant{grant("g1", future, objs(cmKey, h1)), grant("g2", past, objs(cmKey, h1))}, nothing, false, true, "grant g2"},
		{"missing spec.expiresAt: refused", cmObj("app-cm", h1), []agent.Grant{grant("g1", "", objs(cmKey, h1))}, nothing, false, true, "no expiresAt"},
		{"unparsable spec.expiresAt: refused", cmObj("app-cm", h1), []agent.Grant{grant("g1", "2099-01-01", objs(cmKey, h1))}, nothing, false, true, "not an RFC 3339 time"},
		{"a carried entry with no expiresAt: refused", cmObj("app-cm", h3),
			[]agent.Grant{grant("g1", future, objs(cmKey, h1), agent.CarriedTree{Change: "ch-old", Objects: objs(cmKey, h3)})}, nothing, false, true, "no expiresAt"},
		{"expiry exactly now is expired", cmObj("app-cm", h1), []agent.Grant{grant("g1", now.Format(time.RFC3339), objs(cmKey, h1))}, nothing, false, true, "expired at"},
		{"skew: a minute past expiry with a two-minute allowance is live", cmObj("app-cm", h1), []agent.Grant{grant("g1", past, objs(cmKey, h1))}, 2 * time.Minute, true, false, ""},
		{"skew: a minute past expiry with a thirty-second allowance is expired", cmObj("app-cm", h1), []agent.Grant{grant("g1", past, objs(cmKey, h1))}, 30 * time.Second, false, true, ""},
		{"skew: the default (none) refuses a second past expiry", cmObj("app-cm", h1),
			[]agent.Grant{grant("g1", now.Add(-time.Second).Format(time.RFC3339), objs(cmKey, h1))}, nothing, false, true, ""},
		{"no rendered stamp: refused (the policy refuses it too)", cmObj("bare", ""), []agent.Grant{grant("g1", future, objs("/ConfigMap/bare", h1))}, nothing, false, false, "no clearance.hangar.io/rendered"},
		{"generateName, no name: the key has no name and matches nothing", cmObj("", h1), []agent.Grant{grant("g1", future, objs(cmKey, h1))}, nothing, false, false, "does not list /ConfigMap/ at"},
		{"the stamp is compared literally (no sha256: prefix folding, as the policy)", cmObj("app-cm", "sha256:"+h1), []agent.Grant{grant("g1", future, objs(cmKey, h1))}, nothing, false, false, "does not list"},
		{"never grants: status.valid false is the policy's to refuse; the clock says live", cmObj("app-cm", h1),
			[]agent.Grant{func() agent.Grant { g := grant("g1", future, objs(cmKey, h1)); f := false; g.Valid = &f; return g }()}, nothing, true, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := Decide(c.obj, c.grants, now, c.skew, noPins)
			if v.Allowed != c.allowed || v.Expired != c.expired || !strings.Contains(v.Reason, c.reason) {
				t.Fatalf("got allowed=%v expired=%v reason=%q; want allowed=%v expired=%v reason containing %q",
					v.Allowed, v.Expired, v.Reason, c.allowed, c.expired, c.reason)
			}
		})
	}
}

func TestObjectKeyIsThePolicys(t *testing.T) {
	for _, c := range []struct{ apiVersion, kind, name, want string }{
		{"v1", "ConfigMap", "a", "/ConfigMap/a"},
		{"apps/v1", "Deployment", "web", "apps/Deployment/web"},
		{"argoproj.io/v1alpha1", "Rollout", "r", "argoproj.io/Rollout/r"},
		{"", "", "", "//"},
	} {
		if got := (Object{APIVersion: c.apiVersion, Kind: c.kind, Name: c.name}).Key(); got != c.want {
			t.Errorf("%s %s %s: key %q, want %q", c.apiVersion, c.kind, c.name, got, c.want)
		}
	}
}
