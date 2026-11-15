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

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/gate"
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
	cid2 := f.register(t, "ci", change(map[string]any{"objects": replicas, "proposer": "dependabot[bot]", "head": strings.Repeat("d", 40)})).ID
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

func TestTheSetAndTheProposerAreFixedAtRegistration(t *testing.T) {
	f := newSrcGate(t)
	first := change(map[string]any{"objects": replicas, "source": src([]string{"dev", "bob"}, []string{"lead"}, "dana")})
	cid := f.register(t, "ci", first).ID
	// the same set, in another order and spelling, is the same set (a re-run)
	same := change(map[string]any{"objects": replicas, "source": src([]string{"user:BOB", "dev"}, []string{"lead"}, "user:dana")})
	if out := f.register(t, "ci", same); out.ID != cid {
		t.Fatal(out.ID)
	}
	for name, over := range map[string]map[string]any{
		"shrunk":       {"source": src([]string{"dev"}, []string{"lead"}, "dana")},
		"emptied":      {"source": nil, "proposer": "user:dana"},
		"grown":        {"source": src([]string{"dev", "bob", "eve"}, []string{"lead"}, "dana")},
		"moved role":   {"source": src([]string{"dev", "bob"}, []string{"lead"}, "")},
		"new proposer": {"proposer": "user:eve"},
	} {
		over["objects"] = replicas
		if _, ok := over["source"]; !ok && name != "emptied" {
			over["source"] = src([]string{"dev", "bob"}, []string{"lead"}, "dana")
		}
		_, err := f.svc.Register(f.ctx, principals["ci"], change(over))
		if rule(err) != "DG-IMMUTABLE" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// and it is refused after the change was decided too
	if _, err := f.svc.Clear(f.ctx, person("erin"), cid, ""); rule(err) != "" {
		t.Fatal(err)
	}
	if _, err := f.svc.Register(f.ctx, principals["ci"], change(map[string]any{"objects": replicas})); rule(err) != "DG-IMMUTABLE" {
		t.Fatal("a decided change's set was dropped:", err)
	}
	if got := f.get(t, cid); got.Source == nil || len(got.Source.Authors) != 2 {
		t.Fatal(got.Source)
	}
}

func TestANewHeadCarriesItsOwnSet(t *testing.T) {
	f := newSrcGate(t)
	a := f.register(t, "ci", change(map[string]any{"objects": replicas, "source": src([]string{"dev"}, nil, "")}))
	b := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("e", 40), "source": src([]string{"bob"}, nil, "")}))
	if b.ID == a.ID || b.Source.Authors[0] != "bob" || f.get(t, a.ID).State != "superseded" {
		t.Fatal(a, b)
	}
	if _, err := f.svc.Clear(f.ctx, person("dev"), b.ID, ""); err != nil {
		t.Fatal("dev is not behind the new head's set:", err)
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
