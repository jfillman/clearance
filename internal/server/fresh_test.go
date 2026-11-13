package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/core"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/vocab"
)

// G3 and G4 through the whole core, on the memory store and on Postgres (when CLEARANCE_TEST_DSN is set).

// ageAuth is an authenticator whose token is "user:name" (just signed in, no age claim at all when it has "#none") or
// "user:name#<duration>" (signed in that long ago, as the token's auth_time).
func ageAuth() authn.Authenticator {
	dev := core.DevAuthenticator()
	return authn.AuthenticatorFunc(func(ctx context.Context, tok string) (authn.Principal, error) {
		name, age, ok := strings.Cut(tok, "#")
		p, err := dev.Authenticate(ctx, name)
		if err != nil || !ok {
			return p, err
		}
		p.Claims = map[string]any{}
		if age == "none" {
			return p, nil
		}
		d, err := time.ParseDuration(age)
		if err != nil {
			return p, err
		}
		p.Claims[authn.ClaimAuthTime] = time.Now().Add(-d).Unix()
		return p, nil
	})
}

func stores(t *testing.T, run func(t *testing.T, cfg core.Config)) {
	t.Run("memory", func(t *testing.T) { run(t, config(t, "")) })
	t.Run("postgres", func(t *testing.T) { run(t, config(t, pgDSN(t))) })
}

func (f *fixture) doH(method, path, token string, body any, h map[string]string) answer {
	f.t.Helper()
	var rd *strings.Reader
	if s, ok := body.(string); ok {
		rd = strings.NewReader(s)
	} else {
		rd = strings.NewReader(jsonOf(f.t, body))
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	return f.send(req)
}

func jsonOf(t testing.TB, v any) string {
	t.Helper()
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// secretChange is a tier 3 registration (a Secret).
func secretChange(head string) map[string]any {
	c := registration(head)
	c["objects"] = []any{map[string]any{"apiVersion": "v1", "kind": "Secret", "namespace": "app-gate-api-prod",
		"name": "gate-api", "op": "changed", "fields": []any{"/data"}}}
	return c
}

func lastRecord(f *fixture, tool string) store.Record {
	var out store.Record
	for _, r := range f.records() {
		if r["tool"] == tool {
			out = r
		}
	}
	return out
}

func hasField(v any, k string) bool {
	l, _ := v.([]any)
	for _, x := range l {
		if x == k {
			return true
		}
	}
	return false
}

func TestFreshAuthOnAClearByTheChangesTier(t *testing.T) {
	stores(t, func(t *testing.T, cfg core.Config) {
		cfg.Auth = ageAuth()
		cfg.Gate.Fresh = gate.Freshness{Tier2: 10 * time.Minute}
		f := newFixture(t, cfg)
		reg := f.do("POST", "/v1/clearances", ci, registration(headSHA)).want(t, 200, "")
		id := reg.body["id"].(string)
		if reg.body["tier"] != float64(2) || reg.body["state"] != "holding" {
			t.Fatal(reg.body)
		}
		path := "/v1/clearances/" + id + "/clear"
		// stale: 401 with its own rule and the limit; nothing is recorded
		r := f.do("POST", path, "user:erin#20m", nil).want(t, 401, "sign-in")
		if r.body["rule"] != gate.RuleAuthNotFresh || r.body["max_age"] != "10m0s" || r.body["age"] == nil {
			t.Fatal(r.body)
		}
		// a token with no sign-in time at all is not fresh either
		f.do("POST", path, "user:erin#none", nil).want(t, 401, "")
		// a sign-in time in the future is not fresh
		f.do("POST", path, "user:erin#-2h", nil).want(t, 401, "")
		if n := countTool(f, "deploy.clear"); n != 0 {
			t.Fatalf("a refused clear wrote %d records", n)
		}
		// fresh: it clears. The rule does not turn the other checks off.
		f.do("POST", path, "user:sam#1m", nil).want(t, 403, "")
		f.do("POST", path, "user:erin#9m", nil).want(t, 200, "")
		if recs := f.records(); recs[len(recs)-1]["tool"] != "deploy.clear" && countTool(f, "deploy.clear") != 1 {
			t.Fatal("no deploy.clear")
		}
	})
}

func TestFreshAuthTier3AndBreakglassHaveTheirOwnLimit(t *testing.T) {
	stores(t, func(t *testing.T, cfg core.Config) {
		cfg.Auth = ageAuth()
		cfg.Gate.Fresh = gate.Freshness{Tier3Breakglass: 15 * time.Minute}
		f := newFixture(t, cfg)
		// tier 2 has no limit here
		t2 := f.do("POST", "/v1/clearances", ci, registration(headSHA)).want(t, 200, "").body["id"].(string)
		f.do("POST", "/v1/clearances/"+t2+"/clear", "user:erin#5h", nil).want(t, 200, "")
		// tier 3 does
		reg := f.do("POST", "/v1/clearances", ci, secretChange(strings.Repeat("e", 40))).want(t, 200, "")
		if reg.body["tier"] != float64(3) {
			t.Fatal(reg.body)
		}
		t3 := "/v1/clearances/" + reg.body["id"].(string) + "/clear"
		f.do("POST", t3, "user:erin#16m", nil).want(t, 401, "")
		f.do("POST", t3, "user:erin#14m", nil).want(t, 200, "")
		// break-glass: open and close
		glass := map[string]any{"reason": "prod is down", "ttl": "45m", "cluster": "hangar-prod", "env": "prod"}
		f.do("POST", "/v1/breakglass", "user:admin#1h", glass).want(t, 401, "")
		f.do("POST", "/v1/breakglass", "user:dana#1m", glass).want(t, 403, "") // not an admin: still 403, not 401
		g := f.do("POST", "/v1/breakglass", "user:admin#1m", glass).want(t, 200, "")
		f.do("POST", "/v1/breakglass/"+g.body["id"].(string)+"/close", "user:admin#1h", nil).want(t, 401, "")
		f.do("POST", "/v1/breakglass/"+g.body["id"].(string)+"/close", "user:admin#1m", nil).want(t, 200, "")
		// deny and resolutions have no freshness class
		d := f.do("POST", "/v1/clearances", ci, func() map[string]any {
			c := registration(strings.Repeat("f", 40))
			c["pr"] = 8
			return c
		}()).want(t, 200, "").body["id"].(string)
		f.do("POST", "/v1/clearances/"+d+"/deny", "user:erin#20h", map[string]any{"reason": "no"}).want(t, 200, "")
	})
}

func TestATierThreeClearUsesTheTierTwoLimitWhenItHasNoOwn(t *testing.T) {
	cfg := config(t, "")
	cfg.Auth = ageAuth()
	cfg.Gate.Fresh = gate.Freshness{Tier2: 10 * time.Minute}
	f := newFixture(t, cfg)
	reg := f.do("POST", "/v1/clearances", ci, secretChange(headSHA)).want(t, 200, "")
	f.do("POST", "/v1/clearances/"+reg.body["id"].(string)+"/clear", "user:erin#11m", nil).want(t, 401, "")
	// break-glass has no limit of its own then
	f.do("POST", "/v1/breakglass", "user:admin#5h", map[string]any{"reason": "x y z", "ttl": "5m", "cluster": "hangar-prod",
		"env": "prod"}).want(t, 200, "")
}

func TestFreshAuthIsOffByDefault(t *testing.T) {
	cfg := config(t, "")
	cfg.Auth = ageAuth()
	f := newFixture(t, cfg)
	id := f.do("POST", "/v1/clearances", ci, registration(headSHA)).want(t, 200, "").body["id"].(string)
	f.do("POST", "/v1/clearances/"+id+"/clear", "user:erin#none", nil).want(t, 200, "")
}

func TestADelegatesNamedPersonIsExemptUnlessTheDeploymentRequiresTheSignInTime(t *testing.T) {
	onBehalf := vocab.Get().OnBehalfOfHeader
	for _, c := range []struct {
		mode    string
		headers map[string]string
		want    int
	}{
		{"", nil, 200},
		{gate.FreshDelegatesExempt, nil, 200},
		{gate.FreshDelegatesRequire, nil, 401},
		{gate.FreshDelegatesRequire, map[string]string{gate.HeaderAuthTime: "12"}, 401},
		{gate.FreshDelegatesRequire, map[string]string{gate.HeaderAuthTime: "yesterday"}, 400},
		{gate.FreshDelegatesRequire, map[string]string{gate.HeaderAuthTime: strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)}, 200},
	} {
		t.Run(c.mode+"/"+fmt.Sprint(c.headers, c.want), func(t *testing.T) {
			cfg := config(t, "")
			cfg.Auth = ageAuth()
			cfg.Gate.Fresh = gate.Freshness{Tier2: 10 * time.Minute, Delegates: c.mode}
			f := newFixture(t, cfg)
			id := f.do("POST", "/v1/clearances", ci, registration(headSHA)).want(t, 200, "").body["id"].(string)
			h := map[string]string{onBehalf: "user:erin"}
			for k, v := range c.headers {
				h[k] = v
			}
			r := f.doH("POST", "/v1/clearances/"+id+"/clear", tower, nil, h).want(t, c.want, "")
			if c.want == 401 && r.body["rule"] != gate.RuleAuthNotFresh {
				t.Fatal(r.body)
			}
		})
	}
}

// G8: the core applies its admin check to the person a delegate names, and CLEARANCE_DELEGATE_PERSON_ALLOWED is the
// allowlist's counterpart for that path.
func TestG8TheCoreChecksThePersonADelegateNames(t *testing.T) {
	onBehalf := vocab.Get().OnBehalfOfHeader
	cfg := config(t, "")
	f := newFixture(t, cfg)
	oob := outOfBand()
	f.do("POST", "/v1/records", argo, oob).want(t, 200, "")
	seq := strconv.FormatInt(seqOfRec(lastRecord(f, "deploy.exception")), 10)
	res := map[string]any{"state": "ratified"}
	// an admin check on the named person, as for a person who signed in themselves
	f.doH("POST", "/v1/observations/"+seq+"/resolution", tower, res, map[string]string{onBehalf: "user:dana"}).want(t, 403, "not a Clearance admin")
	f.doH("POST", "/v1/observations/"+seq+"/resolution", tower, res, map[string]string{onBehalf: "user:admin"}).want(t, 200, "")
	// a delegate that is not one, and a name that is not a person
	f.doH("POST", "/v1/observations/"+seq+"/resolution", ci, res, map[string]string{onBehalf: "user:admin"}).want(t, 403, "")
	f.doH("POST", "/v1/observations/"+seq+"/resolution", tower, res, map[string]string{onBehalf: "admin"}).want(t, 400, "")
	// the OIDC allowlist is the authenticator's, so a delegate's named person never meets it: before the setting a
	// name outside it passes the person check (the clear is refused for what the person is, not who)
	id := f.do("POST", "/v1/clearances", ci, registration(headSHA)).want(t, 200, "").body["id"].(string)
	r := f.doH("POST", "/v1/clearances/"+id+"/clear", tower, nil, map[string]string{onBehalf: "user:mallory@evil.example"}).want(t, 403, "")
	if r.body["rule"] != "DG-FORBIDDEN" {
		t.Fatal(r.body)
	}

	cfg = config(t, "")
	cfg.Gate.DelegatePersons = []string{"user:*@corp.example", "user:admin", "user:erin"}
	f = newFixture(t, cfg)
	id = f.do("POST", "/v1/clearances", ci, registration(headSHA)).want(t, 200, "").body["id"].(string)
	r = f.doH("POST", "/v1/clearances/"+id+"/clear", tower, nil, map[string]string{onBehalf: "user:mallory@evil.example"}).want(t, 403, "")
	if r.body["rule"] != "DG-PERSON-ALLOWED" {
		t.Fatal(r.body)
	}
	f.doH("POST", "/v1/clearances/"+id+"/deny", tower, map[string]any{"reason": "nope"}, map[string]string{onBehalf: "user:mallory@evil.example"}).want(t, 403, "")
	f.doH("POST", "/v1/clearances/"+id+"/clear", tower, nil, map[string]string{onBehalf: "user:erin"}).want(t, 200, "")
	// a person who signs in themselves is not subject to it (the authenticator's allowlist already was)
	f.do("POST", "/v1/breakglass", "user:admin", map[string]any{"reason": "x y z", "ttl": "5m", "cluster": "hangar-prod", "env": "prod"}).want(t, 200, "")
}

func TestTheSurfaceIsValidatedAndRecordedAsClaimed(t *testing.T) {
	stores(t, func(t *testing.T, cfg core.Config) {
		onBehalf := vocab.Get().OnBehalfOfHeader
		cfg.Gate.ExtraVias = []string{"tower"}
		f := newFixture(t, cfg)
		reg := func(head string, pr int) string {
			c := registration(head)
			c["pr"] = pr
			return f.do("POST", "/v1/clearances", ci, c).want(t, 200, "").body["id"].(string)
		}
		id := reg(headSHA, 7)
		path := "/v1/clearances/" + id + "/clear"
		// refused before anything is written
		f.doH("POST", path, "user:erin", nil, map[string]string{gate.HeaderVia: "carrier-pigeon"}).want(t, 400, "X-Clearance-Via")
		f.doH("POST", path, "user:erin", nil, map[string]string{gate.HeaderVia: "Tower"}).want(t, 400, "X-Clearance-Via")
		f.doH("POST", path, "user:erin", nil, map[string]string{gate.HeaderSurfaceRef: "https://x"}).want(t, 400, "needs")
		f.doH("POST", path, "user:erin", nil, map[string]string{gate.HeaderVia: "slack", gate.HeaderSurfaceRef: strings.Repeat("a", 513)}).want(t, 400, "at most")
		if n := countTool(f, "deploy.clear"); n != 0 {
			t.Fatalf("refused calls wrote %d clears", n)
		}
		const ref = "https://example.slack.com/archives/C1/p1"
		f.doH("POST", path, "user:erin", nil, map[string]string{gate.HeaderVia: "slack", gate.HeaderSurfaceRef: ref}).want(t, 200, "")
		cl := lastRecord(f, "deploy.clear")
		if s, _ := cl["surface"].(map[string]any); s["via"] != "slack" || s["ref"] != ref {
			t.Fatal(cl)
		}
		if hasField(cl["verified"], "surface") || !hasField(cl["claimed"], "surface") {
			t.Fatalf("surface is claimed, not verified: %v %v", cl["verified"], cl["claimed"])
		}
		// no via, no surface
		id2 := reg(strings.Repeat("e", 40), 8)
		f.do("POST", "/v1/clearances/"+id2+"/deny", "user:erin", map[string]any{"reason": "no"}).want(t, 200, "")
		if _, ok := lastRecord(f, "deploy.deny")["surface"]; ok {
			t.Fatal("a write that said nothing recorded a surface")
		}
		// a delegate says tower for the person it names
		id3 := reg(strings.Repeat("d", 40), 9)
		f.doH("POST", "/v1/clearances/"+id3+"/deny", tower, map[string]any{"reason": "no"},
			map[string]string{onBehalf: "user:erin", gate.HeaderVia: "tower"}).want(t, 200, "")
		if s, _ := lastRecord(f, "deploy.deny")["surface"].(map[string]any); s["via"] != "tower" || s["ref"] != nil {
			t.Fatal(lastRecord(f, "deploy.deny"))
		}

		// resolutions: single and bulk, every record of the call
		f.do("POST", "/v1/records", argo, outOfBand()).want(t, 200, "")
		a := seqOfRec(lastRecord(f, "deploy.exception"))
		f.do("POST", "/v1/records", argo, outOfBand()).want(t, 200, "")
		b := seqOfRec(lastRecord(f, "deploy.exception"))
		h := map[string]string{gate.HeaderVia: "cli"}
		f.doH("POST", "/v1/observations/"+strconv.FormatInt(a, 10)+"/resolution", "user:admin", map[string]any{"state": "ratified"}, h).want(t, 200, "")
		if s, _ := lastRecord(f, "resolution")["surface"].(map[string]any); s["via"] != "cli" {
			t.Fatal(lastRecord(f, "resolution"))
		}
		f.doH("POST", "/v1/observations/resolutions", "user:admin", map[string]any{"items": []int64{a, b}, "state": "still-live"}, h).want(t, 200, "")
		n := 0
		for _, r := range f.records() {
			if r["tool"] == "resolution" && seqOfRec(r) > seqOfRec(lastRecord(f, "resolution"))-2 {
				if s, _ := r["surface"].(map[string]any); s["via"] != "cli" {
					t.Fatal(r)
				}
				n++
			}
		}
		if n != 2 {
			t.Fatalf("bulk wrote %d records", n)
		}

		// break-glass open and an early close carry it; a TTL close has none
		glass := map[string]any{"reason": "prod is down", "ttl": "45m", "cluster": "hangar-prod", "env": "prod"}
		g := f.doH("POST", "/v1/breakglass", "user:admin", glass, map[string]string{gate.HeaderVia: "web"}).want(t, 200, "")
		if s, _ := lastRecord(f, "breakglass.open")["surface"].(map[string]any); s["via"] != "web" {
			t.Fatal(lastRecord(f, "breakglass.open"))
		}
		f.doH("POST", "/v1/breakglass/"+g.body["id"].(string)+"/close", "user:admin", nil, map[string]string{gate.HeaderVia: "api"}).want(t, 200, "")
		if s, _ := lastRecord(f, "breakglass.close")["surface"].(map[string]any); s["via"] != "api" {
			t.Fatal(lastRecord(f, "breakglass.close"))
		}
	})
}

func TestAClearMayCarryAReasonRecordedAsClaimed(t *testing.T) {
	stores(t, func(t *testing.T, cfg core.Config) {
		f := newFixture(t, cfg)
		id := f.do("POST", "/v1/clearances", ci, registration(headSHA)).want(t, 200, "").body["id"].(string)
		path := "/v1/clearances/" + id + "/clear"
		f.do("POST", path, "user:erin", map[string]any{"reason": "   "}).want(t, 400, "reason")
		f.do("POST", path, "user:erin", map[string]any{"reason": strings.Repeat("x", 5000)}).want(t, 400, "longer")
		f.do("POST", path, "user:erin", map[string]any{"reason": 7}).want(t, 400, "reason")
		if countTool(f, "deploy.clear") != 0 {
			t.Fatal("a refused clear wrote a record")
		}
		f.do("POST", path, "user:erin", map[string]any{"reason": " reviewed the diff ", "other": 1}).want(t, 200, "")
		rec := lastRecord(f, "deploy.clear")
		if rec["reason"] != "reviewed the diff" || hasField(rec["verified"], "reason") || !hasField(rec["claimed"], "reason") {
			t.Fatal(rec)
		}
		// no body (and a delegate's {}) still clears, with no reason recorded
		id2 := f.do("POST", "/v1/clearances", ci, secretChange(strings.Repeat("e", 40))).want(t, 200, "").body["id"].(string)
		f.do("POST", "/v1/clearances/"+id2+"/clear", "user:erin", nil).want(t, 200, "")
		if _, ok := lastRecord(f, "deploy.clear")["reason"]; ok {
			t.Fatal("a reason appeared")
		}
	})
}
