package gate_test

// The people behind a change (request.source: authors, mergers, promoter): validated, immutable, and excluded from
// clearing it at every tier where a person clears.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/vocab"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
)

// srcGroups: dev and lead are in the owner group, sec is in the outside group, lead2 is in both.
type srcGroups struct{}

func (srcGroups) Groups(_ context.Context, p string) []string {
	return map[string][]string{
		"user:dev": {owner}, "user:lead": {owner}, "user:dana": {owner}, "user:erin": {owner},
		"user:sec": {"group:default/admins"}, "user:both": {owner, "group:default/admins"},
	}[p]
}

func person(name string) authn.Principal {
	return authn.Principal{ID: "user:" + name, Kind: authn.KindPerson}
}

func newSrcGate(t *testing.T) *fixture {
	t.Helper()
	f := newGate(t)
	f.svc.Directory = srcGroups{}
	return f
}

func src(authors, mergers []string, promoter string) map[string]any {
	m := map[string]any{}
	if authors != nil {
		m["authors"] = strs(authors)
	}
	if mergers != nil {
		m["mergers"] = strs(mergers)
	}
	if promoter != "" {
		m["promoter"] = promoter
	}
	return m
}

func rule(err error) string { r, _ := ruleOf(err); return r }

func msg(err error) string {
	var ge *gate.Error
	if errors.As(err, &ge) {
		return ge.Message
	}
	return ""
}

// -- parsing ---------------------------------------------------------------------------------------------------------

func TestSourceIsParsedAndBounded(t *testing.T) {
	ok := func(v any) gate.ChangeRequest {
		t.Helper()
		r, err := gate.ParseRequest(change(map[string]any{"source": v}))
		if err != nil {
			t.Fatal(v, err)
		}
		return r
	}
	r := ok(src([]string{"user:dev", "bob"}, []string{"lead"}, "user:dana"))
	if r.Source == nil || len(r.Source.Authors) != 2 || len(r.Source.Mergers) != 1 || r.Source.Promoter != "user:dana" {
		t.Fatal(r.Source)
	}
	if ok(map[string]any{}).Source != nil || ok(src([]string{}, []string{}, "")).Source != nil {
		t.Fatal("an empty set is no set")
	}
	if r, _ := gate.ParseRequest(change(nil)); r.Source != nil {
		t.Fatal("absent stays absent")
	}
	many := func(n int) []string {
		var xs []string
		for i := 0; i < n; i++ {
			xs = append(xs, fmt.Sprintf("u%d", i))
		}
		return xs
	}
	ok(src(many(64), many(64), ""))
	for name, v := range map[string]any{
		"65 authors":      src(many(65), nil, ""),
		"65 mergers":      src(nil, many(65), ""),
		"duplicate":       src([]string{"dev", "dev"}, nil, ""),
		"dup by case":     src([]string{"Dev", "dev"}, nil, ""),
		"dup by prefix":   src(nil, []string{"user:dev", "dev"}, ""),
		"bad chars":       src([]string{"de v"}, nil, ""),
		"too long":        src([]string{strings.Repeat("a", 201)}, nil, ""),
		"empty entry":     src([]string{""}, nil, ""),
		"bad promoter":    src(nil, nil, "no way"),
		"unknown key":     map[string]any{"authors": strs([]string{"dev"}), "owner": "x"},
		"not an object":   "dev",
		"authors a str":   map[string]any{"authors": "dev"},
		"author a number": map[string]any{"authors": []any{json.Number("3")}},
		"promoter a list": map[string]any{"promoter": []any{"dev"}},
	} {
		_, err := gate.ParseRequest(change(map[string]any{"source": v}))
		var bc *gate.BadChange
		if !errors.As(err, &bc) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// -- the clearing rule -----------------------------------------------------------------------------------------------

func TestEachRoleBehindATierTwoChangeIsExcluded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source map[string]any
		who    string
		want   string // part of the message
	}{
		{"author", src([]string{"dev"}, nil, ""), "dev", "source author"},
		{"merger", src(nil, []string{"dev"}, ""), "dev", "source merger"},
		{"promoter", src(nil, nil, "dev"), "dev", "promoter"},
		{"author by case", src([]string{"DEV"}, nil, ""), "dev", "source author"},
		{"author with prefix", src([]string{"user:dev"}, nil, ""), "dev", "source author"},
		{"merger with mixed prefix", src(nil, []string{"User:Dev"}, ""), "dev", "source merger"},
		{"promoter with prefix", src(nil, nil, "user:dev"), "dev", "promoter"},
		{"two roles", src([]string{"dev"}, []string{"dev"}, ""), "dev", "source author and a source merger"},
		{"three roles", src([]string{"dev"}, []string{"dev"}, "dev"), "dev", "the promoter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSrcGate(t)
			cid := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": tc.source})).ID
			_, err := f.svc.Clear(f.ctx, person(tc.who), cid, "")
			if rule(err) != "DG-PROPOSER" || !strings.Contains(msg(err), tc.want) {
				t.Fatal(err)
			}
			if out, err := f.svc.Clear(f.ctx, person("erin"), cid, ""); err != nil || out.State != "cleared" {
				t.Fatal(out, err)
			}
		})
	}
}

func TestTheProposerIsComparedWithTheSameNormalisation(t *testing.T) {
	f := newSrcGate(t)
	// the proposer was written with a capital and the prefix; the person is user:dana
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas, "proposer": "User:Dana"})).ID
	_, err := f.svc.Clear(f.ctx, person("dana"), cid, "")
	if rule(err) != "DG-PROPOSER" || msg(err) != "the proposer of a change cannot clear it" {
		t.Fatal(err)
	}
	cid = f.register(t, "ci", change(map[string]any{"objects": replicas, "proposer": "dana", "head": strings.Repeat("c", 40)})).ID
	if _, err := f.svc.Clear(f.ctx, person("dana"), cid, ""); rule(err) != "DG-PROPOSER" {
		t.Fatal("a proposer without the prefix cleared", err)
	}
}

func TestEachRoleBehindATierThreeChangeIsExcludedFromBothSeats(t *testing.T) {
	f := newSrcGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": secret,
		"source": src([]string{"dev"}, []string{"sec"}, "both")})).ID
	for _, who := range []string{"dev", "sec", "both", "dana"} {
		if _, err := f.svc.Clear(f.ctx, person(who), cid, ""); rule(err) != "DG-PROPOSER" {
			t.Fatal(who, err)
		}
	}
	if out, err := f.svc.Clear(f.ctx, person("erin"), cid, ""); err != nil || out.State != "holding" {
		t.Fatal(out, err)
	}
	// the outside seat: nobody outside the set is in the outside group yet but lead is not, so it stays held
	if _, err := f.svc.Clear(f.ctx, person("lead"), cid, ""); rule(err) == "" {
		// lead is owner-only and the owner seat is full: refused DG-FILLED
		t.Fatal("expected a refusal")
	}
}

func TestADelegateNamingAnExcludedPersonIsRefused(t *testing.T) {
	f := newSrcGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src(nil, []string{"dev"}, "")})).ID
	if _, err := f.svc.Clear(f.ctx, principals["tower"], cid, "user:DEV"); rule(err) != "DG-PROPOSER" {
		t.Fatal(err)
	}
}

func TestDenyStaysOpenToTheGroupsWhetherOrNotInTheSet(t *testing.T) {
	f := newSrcGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, nil, "")})).ID
	out, err := f.svc.Deny(f.ctx, person("dev"), cid, "no", "")
	if err != nil || out.State != "denied" {
		t.Fatal(out, err)
	}
}

// The steer this closes: a release's source PRs were opened by dev and by a bot; the bot is made the proposer;
// dev, an owner, then cleared their own change.
func TestAttackADeveloperCannotClearTheirOwnReleaseByMakingABotTheProposer(t *testing.T) {
	f := newSrcGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas, "proposer": "dependabot[bot]",
		"source": src([]string{"dev", "dependabot[bot]"}, []string{"lead"}, "lead")})).ID
	_, err := f.svc.Clear(f.ctx, person("dev"), cid, "")
	if rule(err) != "DG-PROPOSER" || !strings.Contains(msg(err), "source author") {
		t.Fatal(err)
	}
	if got := f.get(t, cid); got.State != "holding" || len(got.Approvals) != 0 {
		t.Fatal(got)
	}
	// without the set, the same registration lets dev clear it: that is the hole
	// (another tree: the people behind a tree are the tree's, whatever the head)
	cid2 := f.register(t, "ci", change(map[string]any{"objects": replicas, "proposer": "dependabot[bot]", "head": strings.Repeat("d", 40),
		"treeDigest": strings.Repeat("ab", 32)})).ID
	if out, err := f.svc.Clear(f.ctx, person("dev"), cid2, ""); err != nil || out.State != "cleared" {
		t.Fatal("the unfixed behaviour changed", out, err)
	}
}

// -- stored, returned, recorded ----------------------------------------------------------------------------------------

func TestTheSetIsStoredReturnedAndRecorded(t *testing.T) {
	f := newSrcGate(t)
	out := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"dev", "bob"}, []string{"lead"}, "dana")}))
	want := `{"authors":["dev","bob"],"mergers":["lead"],"promoter":"dana"}`
	if raw, _ := json.Marshal(out.Source); string(raw) != want {
		t.Fatal(string(raw))
	}
	if raw, _ := json.Marshal(f.get(t, out.ID).Source); string(raw) != want {
		t.Fatal("stored", string(raw))
	}
	// the deploy.request record carries the registration's digest (args_sha256): the set is bound into the chain
	// and is not copied into the record's body, so the record's shape is what it was.
	g := newSrcGate(t)
	g.register(t, "ci", change(map[string]any{"objects": replicas}))
	with, without := f.records(t, "deploy.request"), g.records(t, "deploy.request")
	if with[0]["args_sha256"] == without[0]["args_sha256"] {
		t.Fatal("the record's digest does not cover the set")
	}
}

func TestWithoutASetNothingChanges(t *testing.T) {
	f := newSrcGate(t)
	out := f.register(t, "ci", change(map[string]any{"objects": replicas}))
	if out.Source != nil {
		t.Fatal(out.Source)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), `"source"`) {
		t.Fatal("a change without a set has no source key:", string(raw))
	}
	// a record stored before the field existed reads as empty
	old, err := gate.FromRecord(raw)
	if err != nil || old.Source != nil {
		t.Fatal(old, err)
	}
	if _, err := f.svc.Clear(f.ctx, person("erin"), out.ID, ""); err != nil {
		t.Fatal(err)
	}
}

// -- immutability ----------------------------------------------------------------------------------------------------

func names(xs []string) string { return strings.Join(xs, ",") }

// A re-registration may add people, never remove them; a different proposer is added to the excluded set.
func TestThePeopleOnlyGrow(t *testing.T) {
	f := newSrcGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"dev", "bob"}, []string{"lead"}, "dana")})).ID
	// a shrink has no effect and is recorded
	out := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, nil, "")}))
	if names(out.Source.Authors) != "dev,bob" || names(out.Source.Mergers) != "lead" || out.Source.Promoter != "dana" {
		t.Fatal("the set shrank:", out.Source)
	}
	if n := len(f.records(t, "deploy.people")); n != 1 || !strings.Contains(f.records(t, "deploy.people")[0]["result"].(string), "omitted") {
		t.Fatal("the shrink attempt is not recorded:", f.records(t, "deploy.people"))
	}
	// no source at all is the same: kept
	if out := f.register(t, "ci", change(map[string]any{"objects": replicas})); names(out.Source.Authors) != "dev,bob" {
		t.Fatal(out.Source)
	}
	// growth works while holding; spelling does not add a duplicate
	out = f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"User:DEV", "eve"}, []string{"lead"}, "dana")}))
	if names(out.Source.Authors) != "dev,bob,eve" {
		t.Fatal(out.Source)
	}
	// a different proposer is added, the first stays displayed
	out = f.register(t, "ci", change(map[string]any{"objects": replicas, "proposer": "user:zed", "source": src([]string{"dev"}, nil, "")}))
	if out.Proposer != "user:dana" || len(out.AlsoBehind) != 1 || out.AlsoBehind[0] != (gate.Behind{"proposer", "user:zed"}) {
		t.Fatal(out.Proposer, out.AlsoBehind)
	}
	// a /retest by another promoter adds a promoter
	out = f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src(nil, nil, "lead")}))
	if len(out.AlsoBehind) != 2 || out.AlsoBehind[1] != (gate.Behind{"promoter", "lead"}) {
		t.Fatal(out.AlsoBehind)
	}
	for _, who := range []string{"eve", "bob", "lead", "dana"} {
		if _, err := f.svc.Clear(f.ctx, person(who), cid, ""); rule(err) != "DG-PROPOSER" {
			t.Errorf("%s: %v", who, err)
		}
	}
	_, err := f.svc.Clear(f.ctx, person("zed"), cid, "")
	if rule(err) != "DG-PROPOSER" || !strings.Contains(msg(err), "further proposer") {
		t.Fatal(err)
	}
	if _, err := f.svc.Clear(f.ctx, person("erin"), cid, ""); err != nil {
		t.Fatal(err)
	}
	// decided: the state does not change, the set still grows
	out = f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"late"}, nil, "")}))
	if out.State != "cleared" || names(f.get(t, cid).Source.Authors) != "dev,bob,eve,late" {
		t.Fatal(out.State, f.get(t, cid).Source)
	}
}

// A change already holding when this shipped (no set) is re-registered with one: it gains it, with no refusal.
func TestAChangeHoldingAtUpgradeGainsTheSet(t *testing.T) {
	f := newSrcGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas})).ID
	if _, err := f.svc.Register(f.ctx, principals["ci"], change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, nil, "")})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Clear(f.ctx, person("dev"), cid, ""); rule(err) != "DG-PROPOSER" {
		t.Fatal(err)
	}
}

// The same tree registered again as pr 0 (the Argo CD plugin) must not be clearable by the PR's authors, whichever
// registers first.
func TestTheSetFollowsATreeAcrossChanges(t *testing.T) {
	plugin := func() map[string]any {
		return change(map[string]any{"objects": replicas, "pr": json.Number("0"), "proposer": "system:argocd-cmp", "head": strings.Repeat("9", 40)})
	}
	pr := func() map[string]any {
		return change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, []string{"lead"}, "")})
	}
	for _, order := range []string{"pr first", "plugin first"} {
		t.Run(order, func(t *testing.T) {
			f := newSrcGate(t)
			var prID, pluginID string
			if order == "pr first" {
				prID = f.register(t, "ci", pr()).ID
				pluginID = f.register(t, "ci", plugin()).ID
			} else {
				pluginID = f.register(t, "ci", plugin()).ID
				prID = f.register(t, "ci", pr()).ID
			}
			if prID == pluginID {
				t.Fatal("one change")
			}
			for _, who := range []string{"dev", "lead", "dana"} {
				if _, err := f.svc.Clear(f.ctx, person(who), pluginID, ""); rule(err) != "DG-PROPOSER" {
					t.Errorf("%s cleared the plugin's change: %v", who, err)
				}
			}
			if out, err := f.svc.Clear(f.ctx, person("erin"), pluginID, ""); err != nil || out.State != "cleared" {
				t.Fatal(out, err)
			}
		})
	}
	// another tree is untouched
	f := newSrcGate(t)
	f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, nil, "")}))
	other := f.register(t, "ci", change(map[string]any{"objects": replicas, "pr": json.Number("0"), "head": strings.Repeat("8", 40),
		"treeDigest": strings.Repeat("ab", 32), "proposer": "system:argocd-cmp"}))
	if _, err := f.svc.Clear(f.ctx, person("dev"), other.ID, ""); err != nil {
		t.Fatal("a different tree took the set:", err)
	}
}

func TestAnAliasOfAPersonBehindTheChangeIsExcluded(t *testing.T) {
	v := vocabtest.Lab()
	v.ApproverAliases = [][]string{{"user:dev", "user:erin"}}
	vocab.Set(v)
	t.Cleanup(func() { vocab.Set(vocabtest.Lab()) })
	f := newSrcGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, nil, "")})).ID
	if _, err := f.svc.Clear(f.ctx, person("erin"), cid, ""); rule(err) != "DG-PROPOSER" {
		t.Fatal("the alias of an author cleared:", err)
	}
}

// The exclusion matches names, so an email-form identity does not match a login: documented, and tested so that it
// is a known limit.
func TestAnEmailFormIdentityDoesNotMatchALogin(t *testing.T) {
	f := newSrcGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"erin"}, nil, "")})).ID
	f.svc.Directory = emailGroups{}
	p := authn.Principal{ID: "user:erin@example.com", Kind: authn.KindPerson}
	if _, err := f.svc.Clear(f.ctx, p, cid, ""); err != nil {
		t.Fatal(err)
	}
}

type emailGroups struct{}

func (emailGroups) Groups(context.Context, string) []string { return []string{owner} }

// Evidence: a refused clear is a record, bounded; the request and clear records carry the excluded set.
func TestTheRecordsSayWhoWasExcluded(t *testing.T) {
	f := newSrcGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, []string{"lead"}, "")})).ID
	req := f.records(t, "deploy.request")[0]["change"].(map[string]any)["people"].(map[string]any)
	if req["digest"] == "" || fmt.Sprint(req["count"]) != "3" {
		t.Fatal(req)
	}
	for i := 0; i < gate.MaxPeopleNotes+5; i++ {
		f.svc.Clear(f.ctx, person("dev"), cid, "")
	}
	refusals := f.records(t, "deploy.refuse")
	if len(refusals) != gate.MaxPeopleNotes || refusals[0]["rule"] != "DG-PROPOSER" || refusals[0]["principal"] != "user:dev" ||
		!strings.Contains(refusals[0]["result"].(string), "source author") || refusals[0]["decision"] != "deny" {
		t.Fatal(len(refusals), refusals[0])
	}
	// a change without them records what it always did
	g := newSrcGate(t)
	g.register(t, "ci", change(map[string]any{"objects": replicas}))
	if _, has := g.records(t, "deploy.request")[0]["change"].(map[string]any)["people"]; has {
		t.Fatal("people in a record of a change without a set")
	}
	out, err := f.svc.Clear(f.ctx, person("erin"), cid, "")
	if err != nil || out.State != "cleared" {
		t.Fatal(out, err)
	}
	clr := f.records(t, "deploy.clear")
	if clr[len(clr)-1]["change"].(map[string]any)["people"].(map[string]any)["digest"] != req["digest"] {
		t.Fatal("the clear does not name the set version it checked")
	}
}

// A new head carries its own set; on the same tree the tree's people stay behind it too, on another tree they do not.
func TestANewHeadCarriesItsOwnSet(t *testing.T) {
	f := newSrcGate(t)
	a := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, nil, "")}))
	b := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("e", 40), "source": src([]string{"bob"}, nil, "")}))
	if b.ID == a.ID || names(b.Source.Authors) != "bob,dev" || f.get(t, a.ID).State != "superseded" {
		t.Fatal(a, b)
	}
	if _, err := f.svc.Clear(f.ctx, person("dev"), b.ID, ""); rule(err) != "DG-PROPOSER" {
		t.Fatal("the same tree's author cleared its next head:", err)
	}
	c := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("f", 40), "treeDigest": strings.Repeat("cd", 32),
		"source": src([]string{"bob"}, nil, "")}))
	if _, err := f.svc.Clear(f.ctx, person("dev"), c.ID, ""); err != nil {
		t.Fatal("another tree took the set:", err)
	}
}

func TestOnlyAVerifierSuppliesASet(t *testing.T) {
	f := newSrcGate(t)
	body := change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, nil, "")})
	for _, who := range []string{"dev", "tower", "other"} {
		p, ok := principals[who]
		if !ok {
			p = person(who)
		}
		_, err := f.svc.Register(f.ctx, p, body)
		var nv *gate.NotVerifier
		if !errors.As(err, &nv) {
			t.Errorf("%s: %v", who, err)
		}
	}
}

// The tree's people are a record of their own: no change's state or lifetime can lose them.
func TestThePeopleOfATreeOutliveTheChangeThatBroughtThem(t *testing.T) {
	plugin := func() map[string]any {
		return change(map[string]any{"objects": replicas, "pr": json.Number("0"), "proposer": "system:argocd-cmp", "head": strings.Repeat("9", 40)})
	}
	for _, how := range []string{"expires", "denied", "superseded", "revoked", "cleared then superseded"} {
		t.Run(how, func(t *testing.T) {
			f := newSrcGate(t)
			c := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, nil, "")}))
			switch how {
			case "expires":
				f.clock.advance(30 * 24 * time.Hour)
				if _, err := f.svc.Expire(f.ctx); err != nil {
					t.Fatal(err)
				}
			case "denied":
				if _, err := f.svc.Deny(f.ctx, person("erin"), c.ID, "no", ""); err != nil {
					t.Fatal(err)
				}
			case "superseded":
				f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("e", 40), "source": src([]string{"bob"}, nil, "")}))
			case "revoked", "cleared then superseded":
				if _, err := f.svc.Clear(f.ctx, person("erin"), c.ID, ""); err != nil {
					t.Fatal(err)
				}
				f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("e", 40)}))
			}
			if st := f.get(t, c.ID).State; st == "holding" {
				t.Fatal("the first change still holds:", st)
			}
			p := f.register(t, "ci", plugin())
			if _, err := f.svc.Clear(f.ctx, person("dev"), p.ID, ""); rule(err) != "DG-PROPOSER" {
				t.Fatalf("dev cleared the plugin's change after the first one %s: %v", how, err)
			}
		})
	}
}

// A refused registration leaves nothing behind: the old head is not superseded and nothing is recorded.
func TestARefusedRegistrationIsAllOrNothing(t *testing.T) {
	f := newSrcGate(t)
	old := f.register(t, "ci", change(map[string]any{"objects": replicas}))
	before := len(f.records(t, ""))
	var many []string
	for i := 0; i < gate.MaxTreePeople+1; i++ {
		many = append(many, fmt.Sprintf("u%d", i))
	}
	// 64 per request, so fill the tree to the cap over several registrations of the one head, then pass it
	for i := 0; i < gate.MaxTreePeople; i += 64 {
		f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src(many[i:min(i+64, gate.MaxTreePeople)], nil, "")}))
	}
	before = len(f.records(t, ""))
	_, err := f.svc.Register(f.ctx, principals["ci"], change(map[string]any{"objects": replicas, "head": strings.Repeat("e", 40),
		"source": src(many[gate.MaxTreePeople:], nil, "")}))
	if rule(err) != "DG-SOURCE-LIMIT" {
		t.Fatal(err)
	}
	if f.get(t, old.ID).State != "holding" || len(f.records(t, "")) != before {
		t.Fatal("a refused registration left something behind")
	}
	if _, err := f.st.Change(f.ctx, gate.ChangeRequest{Repo: "jfillman/gitops-gate-api", PR: 7, Head: strings.Repeat("e", 40)}.ID()); err == nil {
		t.Fatal("the refused change was opened")
	}
	// the names already there are still there, and a registration that adds none still works
	if _, err := f.svc.Register(f.ctx, principals["ci"], change(map[string]any{"objects": replicas, "source": src(many[:3], nil, "")})); err != nil {
		t.Fatal(err)
	}
}

// A verifier running in app-<app>-cicd registers manifest trees for its own app only.
func TestAVerifierIsBoundToItsOwnApp(t *testing.T) {
	f := newGate(t)
	_, err := f.svc.Register(f.ctx, principals["ci"], change(map[string]any{"objects": replicas, "app": "other-app"}))
	if rule(err) != "DG-VERIFIER-APP" {
		t.Fatal(err)
	}
	f.svc.Config.VerifierAppBindingOff = true
	if _, err := f.svc.Register(f.ctx, principals["ci"], change(map[string]any{"objects": replicas, "app": "other-app"})); err != nil {
		t.Fatal(err)
	}
}

// Behaviour with no source anywhere: one proposer on a tree records exactly what it did; a second proposer on the tree
// is excluded on it (the point of the per-tree record) and shows in the record.
func TestTheProposerOfEveryChangeOnATreeIsExcludedOnIt(t *testing.T) {
	f := newSrcGate(t)
	f.register(t, "ci", change(map[string]any{"objects": replicas}))
	if _, has := f.records(t, "deploy.request")[0]["change"].(map[string]any)["people"]; has {
		t.Fatal("a tree with one proposer and no source changed the record's shape")
	}
	p := f.register(t, "ci", change(map[string]any{"objects": replicas, "pr": json.Number("0"), "proposer": "system:argocd-cmp", "head": strings.Repeat("9", 40)}))
	// dana proposed the PR change on this tree; she cannot clear the pr 0 change either
	if _, err := f.svc.Clear(f.ctx, person("dana"), p.ID, ""); rule(err) != "DG-PROPOSER" {
		t.Fatal(err)
	}
}
