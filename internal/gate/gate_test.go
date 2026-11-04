package gate_test

// Ported from tests/test_gate.py (classification, the gateway's register/clear/deny/expire, the HTTP routes), the
// gate halves of tests/test_review.py (a definition release) and tests/test_register.py (DG-REPO). The read-API
// tests (test_the_api_lists_changes_..., test_the_api_without_a_gate_policy_answers_404) belong to clearance-api,
// which is not part of this package. On R-1b's memory store.

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jfillman/clearance/internal/vocab"
	"github.com/jfillman/clearance/internal/vocab/vocabtest"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
)

const (
	tower = "hangar-prod/app-backstage-prod/backstage"
	head  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	base  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	owner = "group:default/team-gate"
)

// tree is a rendered tree's digest (a real sha256: 64 copies of one digit is a placeholder, flagged tree:unbound).
var tree = canon.SHA256Hex([]byte("the rendered tree"))

// T0 is conftest's clock start.
var T0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func obj(kind, name, op string, fields []string, images []string, apiVersion string) map[string]any {
	return map[string]any{"apiVersion": apiVersion, "kind": kind, "namespace": "app-gate-api-prod", "name": name, "op": op,
		"fields": strs(fields), "images": strs(images), "digest": strings.Repeat("d", 64)}
}

func strs(xs []string) []any {
	out := []any{}
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

func objs(os ...map[string]any) []any {
	out := []any{}
	for _, o := range os {
		out = append(out, o)
	}
	return out
}

// change is test_gate.change: a valid body with overrides (a nil value deletes the key).
func change(over map[string]any) map[string]any {
	b := map[string]any{"app": "gate-api", "env": "prod", "cluster": "hangar-prod", "repo": "jfillman/gitops-gate-api", "pr": json.Number("7"),
		"head": head, "base": base, "proposer": "user:dana", "proposerKind": "person", "owner": owner, "protected": true,
		"treeDigest": tree, "paths": strs([]string{"hangar-prod/prod/release.yaml"}), "linesChanged": json.Number("4"),
		"objects": []any{}, "checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok", "admission": "pass"}}
	for k, v := range over {
		if v == nil {
			delete(b, k)
		} else {
			b[k] = v
		}
	}
	// normalise to what a decoded body is (ints as json.Number)
	raw, _ := json.Marshal(b)
	v, _ := pycompat.Decode(strings.NewReader(string(raw)))
	return v.(map[string]any)
}

var imageBump = objs(obj("Rollout", "gate-api", "changed", []string{"/spec/template/spec/containers/0/image"},
	[]string{"ghcr.io/jfillman/flight/gate-api@sha256:" + strings.Repeat("e", 64)}, "argoproj.io/v1alpha1"))
var replicas = objs(obj("Rollout", "gate-api", "changed", []string{"/spec/replicas"}, nil, "argoproj.io/v1alpha1"))
var secret = objs(obj("Secret", "db", "changed", []string{"/data/password"}, nil, "v1"))

func classify(t *testing.T, body map[string]any, pol gate.Policy) (gate.Classification, error) {
	t.Helper()
	req, err := gate.ParseRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	return gate.Classify(req, pol, deftest.Tools(), nil)
}

func mustClassify(t *testing.T, body map[string]any, pol gate.Policy) gate.Classification {
	t.Helper()
	c, err := classify(t, body, pol)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ruleList(c gate.Classification) []string {
	var out []string
	for _, r := range c.Reasons {
		out = append(out, r.Rule)
	}
	return out
}

func has(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// baseline is the lab deployment's (its outside group is vocabulary, set before the package's variables are).
var baseline = func() gate.Policy { vocab.Set(vocabtest.Lab()); return gate.DefaultPolicy() }()

// -- classification -------------------------------------------------------------------------------------------------

func TestDocsOnlyIsTier0ClearedByPolicy(t *testing.T) {
	c := mustClassify(t, change(map[string]any{"paths": strs([]string{"docs/runbook.md", "README.md"})}), baseline)
	if c.Tier != 0 || c.Decision != "clear" || c.Requirement != nil {
		t.Fatal(c)
	}
}

func TestAnImageBumpWithGreenChecksIsTier1(t *testing.T) {
	c := mustClassify(t, change(map[string]any{"objects": imageBump}), baseline)
	if c.Tier != 1 || c.Decision != "clear" {
		t.Fatal(c)
	}
	var t1 []string
	for _, r := range c.Reasons {
		if r.Tier == 1 {
			t1 = append(t1, r.Rule)
		}
	}
	if !reflect.DeepEqual(t1, []string{"image-bump"}) {
		t.Fatal(t1)
	}
}

func TestAnImageBumpWaitsForCIAndBecomesTier2(t *testing.T) {
	c := mustClassify(t, change(map[string]any{"objects": imageBump, "checks": map[string]any{"ci": "pending", "provenance": "not-agent", "render": "ok"}}), baseline)
	if c.Tier != 2 || c.Decision != "hold" || !has(ruleList(c), "checks:ci") {
		t.Fatal(c)
	}
	if c.Requirement.Owner != 1 || c.Requirement.Outside != 0 || c.Requirement.OwnerGroup != owner {
		t.Fatal(c.Requirement)
	}
}

func TestAnImageFromOutsideTheFlightRegistryIsTier2(t *testing.T) {
	pol := gate.DefaultPolicy()
	pol.TrustedRegistries = []string{"ghcr.io/jfillman/flight/"}
	if c := mustClassify(t, change(map[string]any{"objects": imageBump}), pol); c.Tier != 1 {
		t.Fatal(c.Tier)
	}
	other := objs(obj("Rollout", "gate-api", "changed", []string{"/spec/template/spec/containers/0/image"}, []string{"docker.io/library/nginx:latest"}, "argoproj.io/v1alpha1"))
	c := mustClassify(t, change(map[string]any{"objects": other}), pol)
	if c.Tier != 2 || !has(ruleList(c), "image:not-trusted-registry") {
		t.Fatal(c)
	}
}

func TestABigDiffIsNotATier1Bump(t *testing.T) {
	if c := mustClassify(t, change(map[string]any{"objects": imageBump, "linesChanged": 401}), baseline); c.Tier != 2 {
		t.Fatal(c.Tier)
	}
}

func TestRuntimeShapeIsTier2(t *testing.T) {
	c := mustClassify(t, change(map[string]any{"objects": replicas}), baseline)
	if c.Tier != 2 || c.Decision != "hold" {
		t.Fatal(c)
	}
	for _, o := range []map[string]any{obj("ConfigMap", "gate-api-config", "changed", []string{"/data/LOG_LEVEL"}, nil, "v1"), obj("Weird", "x", "added", nil, nil, "x.io/v1")} {
		if c := mustClassify(t, change(map[string]any{"objects": objs(o)}), baseline); c.Tier != 2 {
			t.Fatal(o, c.Tier)
		}
	}
}

func TestSecretsIdentityAndPolicyAreTier3HoweverSmall(t *testing.T) {
	for _, o := range []map[string]any{obj("Secret", "s", "changed", []string{"/metadata/labels/x"}, nil, "v1"), obj("ServiceAccount", "sa", "added", nil, nil, "v1")} {
		if c := mustClassify(t, change(map[string]any{"objects": objs(o)}), baseline); c.Tier != 3 {
			t.Fatal(o, c.Tier)
		}
	}
	c := mustClassify(t, change(map[string]any{"objects": objs(obj("Rollout", "gate-api", "changed", []string{"/spec/template/spec/containers/0/env/3/valueFrom/secretKeyRef/key"}, nil, "argoproj.io/v1alpha1"))}), baseline)
	if c.Tier != 3 || !has(ruleList(c), "field:secretKeyRef") {
		t.Fatal(c)
	}
	c = mustClassify(t, change(map[string]any{"paths": strs([]string{"hangar-prod/prod/values.yaml", "clearance.yaml"}), "objects": imageBump}), baseline)
	if c.Tier != 3 || !has(ruleList(c), "path:clearance.yaml") {
		t.Fatal(c)
	}
	if c.Requirement.Owner != 1 || c.Requirement.Outside != 1 || !reflect.DeepEqual(c.Requirement.OutsideGroups, []string{"group:default/admins"}) {
		t.Fatal(c.Requirement)
	}
}

func TestMetadataOnlyChangesAreTier0(t *testing.T) {
	c := mustClassify(t, change(map[string]any{"objects": objs(obj("Rollout", "gate-api", "changed", []string{"/metadata/annotations/note"}, nil, "argoproj.io/v1alpha1"))}), baseline)
	if c.Tier != 0 {
		t.Fatal(c.Tier)
	}
}

func TestAnAgentsPrIsAtLeastTier1AndAnUnknownOneIsDenied(t *testing.T) {
	c := mustClassify(t, change(map[string]any{"paths": strs([]string{"docs/x.md"}), "proposerKind": "agent", "proposer": "autopilot-runs/release-proposer", "agent": "release-proposer"}), baseline)
	if c.Tier != 1 || c.Decision != "clear" || !has(ruleList(c), "provenance:agent") {
		t.Fatal(c)
	}
	c = mustClassify(t, change(map[string]any{"objects": imageBump, "proposerKind": "unknown"}), baseline)
	if c.Decision != "deny" || *c.Rule != "DG-PROVENANCE" {
		t.Fatal(c)
	}
}

func TestClearanceYamlTightensAndNeverLoosens(t *testing.T) {
	tighter := map[string]any{"tiers": map[string]any{"3": map[string]any{"kinds": strs([]string{"ConfigMap"})}, "2": map[string]any{"paths": strs([]string{"**/values.yaml"})}},
		"approvers": map[string]any{"2": map[string]any{"owner": 2}}, "ttlDays": 2}
	c := mustClassify(t, change(map[string]any{"objects": objs(obj("ConfigMap", "cm", "changed", []string{"/data/x"}, nil, "v1")), "policy": tighter}), baseline)
	if c.Tier != 3 || c.Policy.TTLDays != 2 || c.Policy.RepoPolicyDigest == nil {
		t.Fatal(c)
	}
	// hashlib.sha256(json.dumps(tighter, sort_keys=True, default=str).encode()).hexdigest() in Python
	if *c.Policy.RepoPolicyDigest != "3905e6096876f604915034458c354e7c01ca4266dde97b4fcd23efdfe3eee3e5" {
		t.Fatal(*c.Policy.RepoPolicyDigest)
	}
	c = mustClassify(t, change(map[string]any{"objects": objs(obj("Rollout", "r", "changed", []string{"/spec/replicas"}, nil, "argoproj.io/v1alpha1")), "policy": tighter}), baseline)
	if c.Requirement.Owner != 2 {
		t.Fatal(c.Requirement)
	}
	c = mustClassify(t, change(map[string]any{"paths": strs([]string{"hangar-prod/prod/values.yaml"}), "policy": tighter}), baseline)
	if c.Tier != 2 || !has(ruleList(c), "path:tier2") {
		t.Fatal(c)
	}
	for _, l := range []struct {
		policy map[string]any
		msg    string
	}{
		{map[string]any{"approvers": map[string]any{"3": map[string]any{"outside": 0}}}, "raised"},
		{map[string]any{"ttlDays": 30}, "shortened"},
		{map[string]any{"tiers": map[string]any{"1": map[string]any{"kinds": strs([]string{"Secret"})}}}, "tiers names 2 and 3"},
		{map[string]any{"surprise": 1}, "unknown key"},
	} {
		_, err := classify(t, change(map[string]any{"objects": imageBump, "policy": l.policy}), baseline)
		var ge *gate.Error
		if !errors.As(err, &ge) || ge.Rule != "DG-POLICY" || !strings.Contains(ge.Message, l.msg) {
			t.Fatal(l.policy, err)
		}
	}
}

func TestAMalformedChangeIsRefused(t *testing.T) {
	cases := []struct {
		bad any
		msg string
	}{
		{change(map[string]any{"head": "short"}), "head"}, {change(map[string]any{"pr": -1}), "pr"},
		{change(map[string]any{"owner": "team"}), "owner"}, {change(map[string]any{"treeDigest": "x"}), "treeDigest"},
		{change(map[string]any{"proposerKind": "robot"}), "proposerKind"},
		{change(map[string]any{"objects": objs(map[string]any{"kind": "Secret"})}), "objects[]"},
		{change(map[string]any{"checks": map[string]any{"ci": 1}}), "checks"}, {change(map[string]any{"policy": "no"}), "policy"},
		{"nope", "JSON object"},
		// strict decoding (a deliberate tightening): unknown fields are refused
		{change(map[string]any{"surprise": 1}), "unknown field"},
		{change(map[string]any{"pr": true}), "pr"}, {change(map[string]any{"pr": json.Number("7.0")}), "pr"},
		{change(map[string]any{"head": head + "\n"}), "head"},
	}
	for _, c := range cases {
		_, err := gate.ParseRequest(c.bad)
		var bc *gate.BadChange
		if !errors.As(err, &bc) || !strings.Contains(bc.Message, c.msg) {
			t.Errorf("%v: %v", c.msg, err)
		}
	}
}

func TestTheChangeIDIsThePrHead(t *testing.T) {
	a, _ := gate.ParseRequest(change(nil))
	b, _ := gate.ParseRequest(change(map[string]any{"head": strings.Repeat("f", 40)}))
	a2, _ := gate.ParseRequest(change(nil))
	if !strings.HasPrefix(a.ID(), "ch-") || a.ID() == b.ID() || a.ID() != a2.ID() {
		t.Fatal(a.ID(), b.ID())
	}
	// the Python id: "ch-" + sha256("jfillman/gitops-gate-api#7@aaaa...")[:16]
	if want := "ch-" + canon.SHA256Hex([]byte("jfillman/gitops-gate-api#7@" + head))[:16]; a.ID() != want {
		t.Fatal(a.ID(), want)
	}
}

// -- the gateway ------------------------------------------------------------------------------------------------------

var principals = map[string]authn.Principal{
	"ci":    {ID: "app-gate-api-cicd/pipeline-runner", Kind: authn.KindServiceAccount},
	"other": {ID: "ns/other", Kind: authn.KindServiceAccount},
	"tower": {ID: tower, Kind: authn.KindForeignWorkload},
	"dana":  {ID: "user:dana", Kind: authn.KindPerson}, "erin": {ID: "user:erin", Kind: authn.KindPerson},
	"fay": {ID: "user:fay", Kind: authn.KindPerson}, "root": {ID: "user:root", Kind: authn.KindPerson},
	"sam": {ID: "user:sam", Kind: authn.KindPerson},
}

type groups struct{}

func (groups) Groups(_ context.Context, p string) []string {
	return map[string][]string{"user:dana": {owner}, "user:erin": {owner}, "user:fay": {owner, "group:default/admins"},
		"user:root": {"group:default/admins"}}[p]
}

type owners struct{}

func (owners) OwnerOf(_ context.Context, app string) string {
	return map[string]string{"gate-api": owner}[app]
}

type fixture struct {
	svc   *gate.Service
	st    *memory.Store
	clock *clock
	ctx   context.Context
}

func newGate(t *testing.T) *fixture {
	c := &clock{T0}
	st := memory.New()
	svc := gate.NewService(gate.Config{Verifiers: []string{"app-*-cicd/pipeline-runner"}, Delegates: []string{tower},
		Admins: []string{"user:root"}}, st, c.now)
	svc.Owners, svc.Directory, svc.Tools, svc.Parse = owners{}, groups{}, deftest.Tools(), parseDef
	return &fixture{svc, st, c, context.Background()}
}

func (f *fixture) records(t *testing.T, tool string) []store.Record {
	t.Helper()
	all, err := f.st.Records(f.ctx, 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.Record
	for _, r := range all {
		if tool == "" || r["tool"] == tool {
			out = append(out, r)
		}
	}
	return out
}

func (f *fixture) register(t *testing.T, who string, body any) *gate.Change {
	t.Helper()
	c, err := f.svc.Register(f.ctx, principals[who], body)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fixture) get(t *testing.T, id string) *gate.Change {
	t.Helper()
	row, err := f.st.Change(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	c, err := gate.FromRecord(row.Record)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ruleOf(err error) (string, int) {
	var ge *gate.Error
	if errors.As(err, &ge) {
		return ge.Rule, ge.Status
	}
	return "", 0
}

func TestOnlyAVerifierMayRegisterAndTheGateCanBeOff(t *testing.T) {
	f := newGate(t)
	var nv *gate.NotVerifier
	if _, err := f.svc.Register(f.ctx, principals["other"], change(nil)); !errors.As(err, &nv) {
		t.Fatal(err)
	}
	var bc *gate.BadChange
	if _, err := f.svc.Register(f.ctx, principals["ci"], map[string]any{"app": "x"}); !errors.As(err, &bc) {
		t.Fatal(err)
	}
	off := gate.NewService(gate.Config{Off: true, Verifiers: []string{"app-*-cicd/pipeline-runner"}}, memory.New(), f.clock.now)
	if _, err := off.Register(f.ctx, principals["ci"], change(nil)); func() string { r, _ := ruleOf(err); return r }() != "DG-OFF" {
		t.Fatal(err)
	}
}

func TestATier1ChangeIsClearedByPolicyWithTwoRecords(t *testing.T) {
	f := newGate(t)
	out := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	if out.State != "cleared" || *out.ClearedBy != "policy" || out.Tier != 1 {
		t.Fatal(out)
	}
	recs := f.records(t, "")
	var got [][3]any
	for _, r := range recs {
		got = append(got, [3]any{r["tool"], r["principal"], r["decision"]})
	}
	want := [][3]any{{"deploy.request", "app-gate-api-cicd/pipeline-runner", "allow"}, {"deploy.clear", "policy", "allow"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	r0 := recs[0]
	if r0["boundary"] != "deployment" || r0["app"] != "gate-api" || r0["target"] != "jfillman/gitops-gate-api#7@aaaaaaa" {
		t.Fatal(r0)
	}
	if tier, _ := gate.SeqInt(r0["change"].(map[string]any)["tier"]); tier != 1 || !inList(r0["claimed"], "change") || !inList(r0["verified"], "target") {
		t.Fatal(r0)
	}
	// again: nothing changes, nothing is recorded
	if out := f.register(t, "ci", change(map[string]any{"objects": imageBump})); out.State != "cleared" || len(f.records(t, "")) != 2 {
		t.Fatal(out.State, len(f.records(t, "")))
	}
}

func inList(v any, s string) bool {
	l, _ := v.([]any)
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestAHoldingChangeClearsWhenCIPassesOnReRegistration(t *testing.T) {
	f := newGate(t)
	out := f.register(t, "ci", change(map[string]any{"objects": imageBump, "checks": map[string]any{"ci": "pending", "provenance": "not-agent", "render": "ok"}}))
	if out.State != "holding" || out.Tier != 2 || out.Requirement.Owner != 1 {
		t.Fatal(out)
	}
	recs := f.records(t, "")
	if !strings.HasPrefix(recs[len(recs)-1]["result"].(string), "tier 2: holding for 1 from group:default/team-gate") {
		t.Fatal(recs[len(recs)-1]["result"])
	}
	out = f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	if out.State != "cleared" || out.Tier != 1 || *out.ClearedBy != "policy" {
		t.Fatal(out)
	}
	var tools []any
	for _, r := range f.records(t, "") {
		tools = append(tools, r["tool"])
	}
	if !reflect.DeepEqual(tools, []any{"deploy.request", "deploy.clear"}) {
		t.Fatal(tools)
	}
}

func TestWhoMayClearATier2Change(t *testing.T) {
	f := newGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas})).ID
	for _, c := range []struct {
		who, rule string
		status    int
	}{{"dana", "DG-PROPOSER", 403}, {"sam", "DG-FORBIDDEN", 403}, {"ci", "DG-PERSON", 403}} {
		_, err := f.svc.Clear(f.ctx, principals[c.who], cid, "")
		if r, s := ruleOf(err); r != c.rule || s != c.status {
			t.Fatal(c.who, err)
		}
	}
	// a delegate that is not one may not name a person
	if _, err := f.svc.Clear(f.ctx, principals["other"], cid, "user:erin"); func() string { r, _ := ruleOf(err); return r }() != "DG-DELEGATE" {
		t.Fatal(err)
	}
	out, err := f.svc.Clear(f.ctx, principals["tower"], cid, "user:erin")
	if err != nil || out.State != "cleared" || *out.ClearedBy != "people" {
		t.Fatal(out, err)
	}
	via := tower
	if !reflect.DeepEqual(out.Approvals, []gate.Approval{{"user:erin", &via, "owner", "2026-09-26T12:00:00Z", "user:erin", "delegate:" + tower}}) {
		t.Fatal(out.Approvals)
	}
	recs := f.records(t, "deploy.clear")
	rec := recs[len(recs)-1]
	if rec["principal"] != "user:erin" || rec["decision"] != "allow" || !strings.HasSuffix(rec["result"].(string), "via "+tower) {
		t.Fatal(rec)
	}
	if _, err := f.svc.Clear(f.ctx, principals["erin"], cid, ""); func() string { r, _ := ruleOf(err); return r }() != "DG-STATE" {
		t.Fatal(err)
	}
}

func TestATier3ChangeNeedsTwoPeopleOneFromOutside(t *testing.T) {
	f := newGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": secret})).ID
	out, err := f.svc.Clear(f.ctx, principals["erin"], cid, "")
	if err != nil || out.State != "holding" || out.Approvals[0].Role != "owner" {
		t.Fatal(out, err)
	}
	for who, want := range map[string]string{"erin": "DG-TWICE", "dana": "DG-PROPOSER", "sam": "DG-FORBIDDEN"} {
		if _, err := f.svc.Clear(f.ctx, principals[who], cid, ""); func() string { r, _ := ruleOf(err); return r }() != want {
			t.Fatal(who, err)
		}
	}
	out, err = f.svc.Clear(f.ctx, principals["root"], cid, "")
	if err != nil || out.State != "cleared" || out.Approvals[0].Role != "owner" || out.Approvals[1].Role != "outside" {
		t.Fatal(out, err)
	}
	recs := f.records(t, "deploy.clear")
	if recs[len(recs)-1]["result"] != "cleared as outside (requirement met)" {
		t.Fatal(recs[len(recs)-1]["result"])
	}
}

func TestAPersonInBothGroupsCountsOnce(t *testing.T) {
	f := newGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": secret})).ID
	out, _ := f.svc.Clear(f.ctx, principals["fay"], cid, "")
	if out.Approvals[0].Role != "owner" || out.State != "holding" {
		t.Fatal(out)
	}
	if _, err := f.svc.Clear(f.ctx, principals["fay"], cid, ""); func() string { r, _ := ruleOf(err); return r }() != "DG-TWICE" {
		t.Fatal(err)
	}
	if out, _ := f.svc.Clear(f.ctx, principals["root"], cid, ""); out.State != "cleared" {
		t.Fatal(out)
	}
}

func TestAFilledRequirementSaysSo(t *testing.T) {
	// role_for's DG-FILLED: a second owner-group member on a tier-3 change already holding its owner approval, who is
	// also in the outside group's place... here: erin approves, then dana's peer in the owner group only.
	f := newGate(t)
	body := change(map[string]any{"objects": secret, "proposer": "user:zed"})
	cid := f.register(t, "ci", body).ID
	if _, err := f.svc.Clear(f.ctx, principals["erin"], cid, ""); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.Clear(f.ctx, principals["dana"], cid, "")
	if r, s := ruleOf(err); r != "DG-FILLED" || s != 409 {
		t.Fatal(err)
	}
}

func TestDenyWithAReason(t *testing.T) {
	f := newGate(t)
	cid := f.register(t, "ci", change(map[string]any{"objects": replicas})).ID
	if _, err := f.svc.Deny(f.ctx, principals["erin"], cid, "", ""); func() string { r, _ := ruleOf(err); return r }() != "DG-REASON" {
		t.Fatal(err)
	}
	if _, err := f.svc.Deny(f.ctx, principals["erin"], cid, strings.Repeat("x", 501), ""); func() string { r, _ := ruleOf(err); return r }() != "DG-REASON" {
		t.Fatal(err)
	}
	if _, err := f.svc.Deny(f.ctx, principals["sam"], cid, "no", ""); func() string { r, _ := ruleOf(err); return r }() != "DG-FORBIDDEN" {
		t.Fatal(err)
	}
	out, err := f.svc.Deny(f.ctx, principals["tower"], cid, "the replica count is wrong for prod", "user:erin")
	if err != nil || out.State != "denied" || *out.DeniedBy != "user:erin" || *out.DenyReason != "the replica count is wrong for prod" {
		t.Fatal(out, err)
	}
	recs := f.records(t, "deploy.deny")
	rec := recs[len(recs)-1]
	if rec["decision"] != "deny" || rec["rule"] != "DG-DENIED" || rec["principal"] != "user:erin" {
		t.Fatal(rec)
	}
	if _, err := f.svc.Clear(f.ctx, principals["erin"], cid, ""); func() string { r, _ := ruleOf(err); return r }() != "DG-STATE" {
		t.Fatal(err)
	}
}

func TestAnUnknownProposerAndALooseningPolicyAreDeniedByPolicy(t *testing.T) {
	f := newGate(t)
	out := f.register(t, "ci", change(map[string]any{"objects": imageBump, "proposerKind": "unknown"}))
	if out.State != "denied" || *out.DeniedBy != "policy" {
		t.Fatal(out)
	}
	var got [][2]any
	for _, r := range f.records(t, "") {
		got = append(got, [2]any{r["tool"], r["rule"]})
	}
	if !reflect.DeepEqual(got, [][2]any{{"deploy.request", nil}, {"deploy.deny", "DG-PROVENANCE"}}) {
		t.Fatal(got)
	}
	out = f.register(t, "ci", change(map[string]any{"objects": imageBump, "head": strings.Repeat("1", 40), "policy": map[string]any{"ttlDays": 99}}))
	recs := f.records(t, "deploy.deny")
	if out.State != "denied" || recs[len(recs)-1]["rule"] != "DG-POLICY" {
		t.Fatal(out, recs)
	}
	if out.Reasons[0].Rule != "policy:loosens" || out.Tier != 3 {
		t.Fatal(out.Reasons)
	}
}

func TestANewHeadSupersedesTheHoldingOneAndTheTTLExpires(t *testing.T) {
	f := newGate(t)
	first := f.register(t, "ci", change(map[string]any{"objects": replicas}))
	second := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("2", 40)}))
	old := f.get(t, first.ID)
	if old.State != "superseded" || *old.SupersededBy != strings.Repeat("2", 40) {
		t.Fatal(old)
	}
	exp := f.records(t, "deploy.expire")
	if exp[len(exp)-1]["result"] != "superseded by 2222222" {
		t.Fatal(exp)
	}
	f.clock.advance(7*24*time.Hour + time.Second)
	done, err := f.svc.Expire(f.ctx)
	if err != nil || !reflect.DeepEqual(done, []string{second.ID}) {
		t.Fatal(done, err)
	}
	exp = f.records(t, "deploy.expire")
	if f.get(t, second.ID).State != "expired" || exp[len(exp)-1]["result"] != "not cleared within 7 days" {
		t.Fatal(exp)
	}
	if _, err := f.svc.Clear(f.ctx, principals["erin"], second.ID, ""); func() string { r, _ := ruleOf(err); return r }() != "DG-STATE" {
		t.Fatal(err)
	}
	// a holding change found past its TTL while someone clears it expires then and there (and stays expired)
	third := f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("3", 40)}))
	f.clock.advance(8 * 24 * time.Hour)
	_, err = f.svc.Clear(f.ctx, principals["erin"], third.ID, "")
	if r, s := ruleOf(err); r != "DG-STATE" || s != 409 || f.get(t, third.ID).State != "expired" {
		t.Fatal(err, f.get(t, third.ID).State)
	}
}

func TestTheOwnerGroupComesFromTheCatalogWhenTheCheckDoesNotSay(t *testing.T) {
	f := newGate(t)
	out := f.register(t, "ci", change(map[string]any{"objects": replicas, "owner": nil}))
	if out.Owner != owner || out.Requirement.OwnerGroup != owner {
		t.Fatal(out)
	}
}

func TestTheOwnerGroupCanBeOmittedOnlyWhenSomethingAnswers(t *testing.T) {
	f := newGate(t)
	f.svc.Owners = nil
	out := f.register(t, "ci", change(map[string]any{"objects": imageBump, "app": "orphan-app", "owner": nil}))
	if out.Owner != "group:default/admins" {
		t.Fatal(out.Owner)
	}
}

func TestTheRecordsVerifyFromGenesis(t *testing.T) {
	f := newGate(t)
	f.register(t, "ci", change(map[string]any{"objects": secret}))
	recs := f.records(t, "")
	if _, err := memory.Load(recs); err != nil {
		t.Fatal(err)
	}
}

// -- HTTP ---------------------------------------------------------------------------------------------------------------

func serve(f *fixture) *http.ServeMux {
	mux := http.NewServeMux()
	(&gate.Handler{Svc: f.svc}).Routes(mux)
	return mux
}

func call(mux *http.ServeMux, method, path, who string, body any, hdr map[string]string) (int, map[string]any) {
	var rd *strings.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = strings.NewReader(string(raw))
	} else {
		rd = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, rd)
	if p, ok := principals[who]; ok {
		r = r.WithContext(authn.WithPrincipal(r.Context(), p))
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestHTTPRoutes(t *testing.T) {
	f := newGate(t)
	mux := serve(f)
	if code, _ := call(mux, "POST", "/v1/clearances", "", change(nil), nil); code != 401 {
		t.Fatal(code)
	}
	if code, _ := call(mux, "POST", "/v1/clearances", "other", change(nil), nil); code != 403 {
		t.Fatal(code)
	}
	if code, _ := call(mux, "POST", "/v1/clearances", "ci", map[string]any{"app": "x"}, nil); code != 400 {
		t.Fatal(code)
	}
	code, out := call(mux, "POST", "/v1/clearances", "ci", change(map[string]any{"objects": objs(obj("Rollout", "r", "changed", []string{"/spec/replicas"}, nil, "argoproj.io/v1alpha1"))}), nil)
	if code != 200 || out["state"] != "holding" {
		t.Fatal(code, out)
	}
	cid := out["id"].(string)
	if code, out := call(mux, "POST", "/v1/clearances/"+cid+"/clear", "dana", nil, nil); code != 403 || out["rule"] != "DG-PROPOSER" {
		t.Fatal(code, out)
	}
	if code, out := call(mux, "POST", "/v1/clearances/"+cid+"/deny", "erin", map[string]any{"reason": ""}, nil); code != 400 || out["rule"] != "DG-REASON" {
		t.Fatal(code, out)
	}
	code, out = call(mux, "POST", "/v1/clearances/"+cid+"/clear", "tower", nil, map[string]string{vocabtest.Lab().OnBehalfOfHeader: "user:erin"})
	if code != 200 || out["state"] != "cleared" || out["audit_seq"] == nil {
		t.Fatal(code, out)
	}
	if code, _ := call(mux, "POST", "/v1/clearances/nope/clear", "erin", nil, nil); code != 404 {
		t.Fatal(code)
	}
	// negative: not JSON, too large, an unknown deny field
	r := httptest.NewRequest("POST", "/v1/clearances", strings.NewReader("{nope"))
	r = r.WithContext(authn.WithPrincipal(r.Context(), principals["ci"]))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("POST", "/v1/clearances", strings.NewReader(strings.Repeat(" ", gate.MaxRegisterBody+1)))
	r = r.WithContext(authn.WithPrincipal(r.Context(), principals["ci"]))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
	if code, _ := call(mux, "POST", "/v1/clearances/"+cid+"/deny", "erin", map[string]any{"reason": "x", "extra": 1}, nil); code != 400 {
		t.Fatal(code)
	}
}

func TestTheViewHasPythonsKeysInOrder(t *testing.T) {
	f := newGate(t)
	out := f.register(t, "ci", change(map[string]any{"objects": replicas}))
	raw, _ := json.Marshal(out)
	keys := []string{"id", "app", "env", "cluster", "repo", "pr", "head", "base", "proposer", "proposer_kind", "agent", "task_id", "owner",
		"protected", "tree_digest", "subject", "paths", "lines_changed", "objects", "checks", "policy_version", "repo_policy_digest", "policy_ref", "tier",
		"reasons", "requirement", "state", "created_at", "updated_at", "expires_at", "registered_by", "approvals", "cleared_by",
		"decided_at", "deny_reason", "denied_by", "superseded_by", "deployments", "target", "objects_count", "paths_count"}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	_, _ = dec.Token()
	var got []string
	for dec.More() {
		k, _ := dec.Token()
		got = append(got, k.(string))
		var skip json.RawMessage
		_ = dec.Decode(&skip)
	}
	if !reflect.DeepEqual(got, keys) {
		t.Fatal(got)
	}
	if !strings.Contains(string(raw), `"created_at":"2026-09-26T12:00:00+00:00"`) || !strings.Contains(string(raw), `"expires_at":"2026-10-03T12:00:00+00:00"`) {
		t.Fatal(string(raw))
	}
}

// -- a definition release (test_review.py) -------------------------------------------------------------------------------

func defDoc(t *testing.T) map[string]any {
	v, err := pycompat.Decode(strings.NewReader(`{"name": "gate-triage", "description": "Explains why a gate-api pipeline run failed.",
 "owner": "group:default/team-gate", "kind": "event",
 "identity": {"type": "workload", "serviceAccount": "autopilot-runs/gate-triage"},
 "profile": {"tierCeiling": "T1", "tools": ["glidepath.runs.list", "glidepath.run.get", "glidepath.logs.get", "glidepath.explain", "repo.file.get", "repo.pr.open"],
   "glidepath": {"apps": ["gate-api"]}, "repos": {"allow": ["jfillman/gate-api"]}, "models": ["claude-sonnet-5-5"],
   "network": "clearance+model", "compute": "small",
   "limits": {"ttlMinutes": 20, "toolCalls": 60, "githubCalls": 40, "openPrs": 1, "modelTokens": 400000, "children": 0}},
 "runtime": {"image": "ghcr.io/jfillman/autopilot-agent-runtime@sha256:` + strings.Repeat("a", 64) + `", "framework": "generic", "instructions": "Find out why."},
 "triggers": [{"type": "event", "source": "glidepath", "bindingKey": "gate-api.pipelinerun.finished",
   "match": {"subject.content.outcome": "failure"}, "maxPerHour": 4}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func release(old, new any, over map[string]any) map[string]any {
	b := map[string]any{"app": "gate-api", "env": "agents", "cluster": "hangar-dev", "repo": "jfillman/gitops-hangar-dev-tenants", "pr": 40,
		"head": strings.Repeat("e", 40), "proposer": "user:dana", "owner": "group:default/team-gate", "treeDigest": canon.SHA256Hex([]byte("gate-triage")),
		"paths": strs([]string{"tenants/gate-api/xr-requests/gate-triage.yaml"}), "checks": map[string]any{"ci": "pass"},
		"definition": map[string]any{"name": "gate-triage", "path": "agents/gate-triage.yaml", "old": old, "new": new}}
	for k, v := range over {
		b[k] = v
	}
	raw, _ := json.Marshal(b)
	v, _ := pycompat.Decode(strings.NewReader(string(raw)))
	return v.(map[string]any)
}

func TestTheGateTiersADefinitionRelease(t *testing.T) {
	f := newGate(t)
	f.svc.Config.ImageAllow = []string{"ghcr.io/jfillman/autopilot-agent-runtime@*"}
	narrower := defDoc(t)
	narrower["profile"].(map[string]any)["limits"].(map[string]any)["toolCalls"] = json.Number("10")
	out := f.register(t, "ci", release(defDoc(t), narrower, nil))
	if out.Tier != 1 || out.State != "cleared" || *out.ClearedBy != "policy" {
		t.Fatal(out)
	}
	if !reflect.DeepEqual(out.Reasons, []gate.Reason{{"agent gate-triage: profile.limits.toolCalls", "60 -> 10", 1}}) {
		t.Fatal(out.Reasons)
	}
	wider := defDoc(t)
	wider["profile"].(map[string]any)["repos"] = map[string]any{"allow": strs([]string{"jfillman/gate-api", "jfillman/baggage-api"})}
	out = f.register(t, "ci", release(defDoc(t), wider, map[string]any{"head": strings.Repeat("1", 40), "pr": 41}))
	if out.Tier != 3 || out.State != "holding" || out.Requirement.Outside != 1 {
		t.Fatal(out)
	}
	if c, err := f.svc.Clear(f.ctx, principals["erin"], out.ID, ""); err != nil || c.State != "holding" {
		t.Fatal(c, err)
	}
	broken := defDoc(t)
	broken["runtime"].(map[string]any)["image"] = "docker.io/x@sha256:" + strings.Repeat("c", 64)
	out = f.register(t, "ci", release(defDoc(t), broken, map[string]any{"head": strings.Repeat("2", 40), "pr": 42}))
	if out.State != "denied" || !strings.Contains(out.Reasons[0].Rule, "DF-IMAGE") {
		t.Fatal(out)
	}
	denies := f.records(t, "deploy.deny")
	if denies[len(denies)-1]["rule"] != "DG-DEFINITION" {
		t.Fatal(denies)
	}
	out = f.register(t, "ci", release(nil, defDoc(t), map[string]any{"head": strings.Repeat("3", 40), "pr": 43}))
	if out.Tier != 3 || out.State != "holding" {
		t.Fatal(out)
	}
}

func TestAMalformedDefinitionReleaseIsRefused(t *testing.T) {
	var bc *gate.BadChange
	if _, err := gate.ParseRequest(release(nil, nil, nil)); !errors.As(err, &bc) {
		t.Fatal(err)
	}
	if _, err := gate.ParseRequest(release(defDoc(t), defDoc(t), map[string]any{"definition": map[string]any{"name": "Bad Name"}})); !errors.As(err, &bc) {
		t.Fatal(err)
	}
}

// -- DG-REPO (test_register.py) -------------------------------------------------------------------------------------------

func TestAWorkflowRegistersForItsOwnRepositoryOnly(t *testing.T) {
	const repo = "jfillman/clearance-deploy-scratch"
	svc := gate.NewService(gate.Config{Verifiers: []string{"github:repo:jfillman/*"}}, memory.New(), (&clock{T0}).now)
	wf := authn.Principal{ID: "github:repo:" + repo + ":environment:prod", Kind: authn.KindGitHubActions, Claims: map[string]any{"repository": repo}}
	body := func(r string) map[string]any {
		return change(map[string]any{"app": "deploy-scratch", "cluster": "hangar-dev", "repo": r, "pr": 0, "base": nil,
			"proposerKind": nil, "protected": nil, "linesChanged": nil, "objects": nil, "checks": nil,
			"proposer": "user:jfillman", "paths": strs([]string{"README.md"}), "owner": "group:default/admins"})
	}
	out, err := svc.Register(context.Background(), wf, body(repo))
	if err != nil || out.State != "cleared" || out.Repo != repo || out.Target != repo+"@aaaaaaa" {
		t.Fatal(out, err)
	}
	_, err = svc.Register(context.Background(), wf, body("jfillman/gate-api"))
	if r, s := ruleOf(err); r != "DG-REPO" || s != 403 {
		t.Fatal(err)
	}
}

// -- the policy-engine verdict in the record (C-8) ---------------------------------------------------------------------

var kyvernoPass = map[string]any{"engine": "kyverno/1.19.0", "verdict": "pass",
	"bundle": "https://github.com/jfillman/gitops-hangar-dev.git//30-policy@" + strings.Repeat("d", 40), "deny": 0, "warn": 1}

func policyOf(t *testing.T, r store.Record) map[string]any {
	t.Helper()
	p, ok := r["policy"].(map[string]any)
	if !ok {
		t.Fatalf("record %v has no policy group", r["tool"])
	}
	return p
}

func TestEveryDeploymentRecordCarriesThePolicyRefEngineAndVerdict(t *testing.T) {
	f := newGate(t)
	commit := strings.Repeat("9", 40)
	tighter := map[string]any{"ttlDays": 3}
	out := f.register(t, "ci", change(map[string]any{"objects": imageBump, "policy": tighter, "policyCommit": commit,
		"admission": kyvernoPass, "checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok"}}))
	if out.State != "cleared" || out.PolicyRef != "clearance.yaml@"+commit || out.Admission == nil || out.Admission.Warn != 1 ||
		out.Checks["admission"] != "pass" {
		t.Fatal(out)
	}
	recs := f.records(t, "")
	if len(recs) != 2 {
		t.Fatal(len(recs))
	}
	want := map[string]any{"ref": "clearance.yaml@" + commit, "version": "baseline-2026-10-31+sha256:" + *out.RepoPolicyDigest,
		"engine": "kyverno/1.19.0", "verdict": "pass", "bundle": kyvernoPass["bundle"]}
	for _, r := range recs {
		if got := policyOf(t, r); !reflect.DeepEqual(got, want) {
			t.Fatalf("%v: %v", r["tool"], got)
		}
		// the verifier reported it: claimed, never verified
		if !inList(r["claimed"], "policy") || inList(r["verified"], "policy") {
			t.Fatal(r["claimed"], r["verified"])
		}
	}
	// the same change from a later clearance.yaml commit is another ref (and a new head, so a new change)
	later := strings.Repeat("8", 40)
	f.register(t, "ci", change(map[string]any{"head": strings.Repeat("2", 40), "objects": imageBump, "policy": tighter,
		"policyCommit": later, "admission": kyvernoPass}))
	recs = f.records(t, "deploy.clear")
	if got := policyOf(t, recs[len(recs)-1])["ref"]; got != "clearance.yaml@"+later {
		t.Fatal(got)
	}
	if _, err := memory.Load(f.records(t, "")); err != nil {
		t.Fatal(err)
	}
}

func TestWithoutAnAdmissionResultTheRecordSaysNotEvaluated(t *testing.T) {
	f := newGate(t)
	out := f.register(t, "ci", change(map[string]any{"objects": replicas}))
	if out.State != "holding" || out.PolicyRef != "baseline" || out.Admission != nil {
		t.Fatal(out)
	}
	want := map[string]any{"ref": "baseline", "version": "baseline-2026-10-31", "engine": "none", "verdict": "not-evaluated"}
	if got := policyOf(t, f.records(t, "deploy.request")[0]); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	// a clearance.yaml without its commit is named by its content digest
	out = f.register(t, "ci", change(map[string]any{"pr": 8, "head": strings.Repeat("3", 40), "objects": replicas, "policy": map[string]any{"ttlDays": 2}}))
	if out.PolicyRef != "clearance.yaml@sha256:"+*out.RepoPolicyDigest {
		t.Fatal(out.PolicyRef)
	}
	// a person's clear of the first change records the same group
	first := f.records(t, "deploy.request")[0]["change"].(map[string]any)["id"].(string)
	if _, err := f.svc.Clear(f.ctx, principals["erin"], first, ""); err != nil {
		t.Fatal(err)
	}
	clears := f.records(t, "deploy.clear")
	if got := policyOf(t, clears[len(clears)-1]); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestReRegistrationRecordsTheNewAdmissionVerdict(t *testing.T) {
	f := newGate(t)
	pending := map[string]any{"ci": "pending", "provenance": "not-agent", "render": "ok"}
	warn := map[string]any{"engine": "kyverno/1.19.0", "verdict": "warn", "warn": 2}
	out := f.register(t, "ci", change(map[string]any{"objects": imageBump, "checks": pending, "admission": warn}))
	if out.State != "holding" || out.Admission.Verdict != "warn" {
		t.Fatal(out)
	}
	out = f.register(t, "ci", change(map[string]any{"objects": imageBump, "admission": kyvernoPass, "checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok"}}))
	if out.State != "cleared" || out.Admission.Verdict != "pass" {
		t.Fatal(out)
	}
	if got := policyOf(t, f.records(t, "deploy.clear")[0])["verdict"]; got != "pass" {
		t.Fatal(got)
	}
	if got := policyOf(t, f.records(t, "deploy.request")[0])["verdict"]; got != "warn" {
		t.Fatal(got)
	}
}

func TestADenyAndAnUnregisteredDeploymentCarryAPolicyGroup(t *testing.T) {
	f := newGate(t)
	commit := strings.Repeat("7", 40)
	fail := map[string]any{"engine": "kyverno/1.19.0", "verdict": "fail", "deny": 1}
	f.register(t, "ci", change(map[string]any{"objects": imageBump, "policy": map[string]any{"ttlDays": 99}, "policyCommit": commit,
		"admission": fail, "checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok"}}))
	d := policyOf(t, f.records(t, "deploy.deny")[0])
	if d["ref"] != "clearance.yaml@"+commit || d["version"] != "baseline-2026-10-31" || d["verdict"] != "fail" {
		t.Fatal(d)
	}
	if _, err := f.svc.DeploymentRequested(f.ctx, "1", "jfillman/nothing", head, "prod", 5, ""); err != nil {
		t.Fatal(err)
	}
	reqs := f.records(t, "deploy.request")
	if got := policyOf(t, reqs[len(reqs)-1]); got["ref"] != "baseline" || got["verdict"] != "not-evaluated" {
		t.Fatal(got)
	}
}

func TestAMalformedAdmissionResultIsRefused(t *testing.T) {
	commit := strings.Repeat("9", 40)
	with := func(a any) map[string]any {
		return change(map[string]any{"admission": a, "checks": map[string]any{"ci": "pass"}})
	}
	cases := []struct {
		bad any
		msg string
	}{
		{with("pass"), "admission is"},
		{with(map[string]any{"engine": "kyverno", "verdict": "pass"}), "admission.engine"},
		{with(map[string]any{"engine": "Kyverno/1.19.0", "verdict": "pass"}), "admission.engine"},
		{with(map[string]any{"engine": "kyverno/1.19.0", "verdict": "ok"}), "admission.verdict"},
		{with(map[string]any{"engine": "kyverno/1.19.0", "verdict": "pass", "bundle": "a b"}), "admission.bundle"},
		{with(map[string]any{"engine": "kyverno/1.19.0", "verdict": "pass", "deny": -1}), "admission.deny"},
		{with(map[string]any{"engine": "kyverno/1.19.0", "verdict": "pass", "rules": 1}), "unknown field"},
		{change(map[string]any{"admission": kyvernoPass, "checks": map[string]any{"admission": "fail"}}), "checks.admission"},
		{change(map[string]any{"policyCommit": commit}), "policyCommit names"},
		{change(map[string]any{"policy": map[string]any{}, "policyCommit": "abc"}), "policyCommit is"},
	}
	for _, c := range cases {
		_, err := gate.ParseRequest(c.bad)
		var bc *gate.BadChange
		if !errors.As(err, &bc) || !strings.Contains(bc.Message, c.msg) {
			t.Errorf("%v: %v", c.msg, err)
		}
	}
}

func TestReRegistrationRefreshesThePolicyRef(t *testing.T) {
	f := newGate(t)
	pending := map[string]any{"ci": "pending", "provenance": "not-agent", "render": "ok"}
	pol := map[string]any{"ttlDays": 3}
	out := f.register(t, "ci", change(map[string]any{"objects": imageBump, "checks": pending, "policy": pol}))
	if out.State != "holding" || out.PolicyRef != "clearance.yaml@sha256:"+*out.RepoPolicyDigest {
		t.Fatal(out.PolicyRef)
	}
	commit := strings.Repeat("6", 40)
	out = f.register(t, "ci", change(map[string]any{"objects": imageBump, "policy": pol, "policyCommit": commit,
		"checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok"}}))
	if out.State != "cleared" || out.PolicyRef != "clearance.yaml@"+commit {
		t.Fatal(out.State, out.PolicyRef)
	}
	if got := policyOf(t, f.records(t, "deploy.clear")[0])["ref"]; got != "clearance.yaml@"+commit {
		t.Fatal(got)
	}
}

func TestThePolicyGroupSitsBesideTheC1FieldsOnEveryDeployRecord(t *testing.T) {
	f := newGate(t)
	f.register(t, "ci", change(map[string]any{"objects": imageBump, "admission": kyvernoPass,
		"checks": map[string]any{"ci": "pass", "provenance": "not-agent", "render": "ok"}}))
	out := f.register(t, "ci", change(map[string]any{"pr": 9, "head": strings.Repeat("4", 40), "objects": replicas}))
	if _, err := f.svc.Clear(f.ctx, principals["erin"], out.ID, ""); err != nil {
		t.Fatal(err)
	}
	recs := f.records(t, "")
	if len(recs) < 4 {
		t.Fatal(len(recs))
	}
	for _, r := range recs {
		p := policyOf(t, r)
		if p["ref"] == nil || p["engine"] == nil || p["verdict"] == nil {
			t.Fatalf("%v: %v", r["tool"], p)
		}
		if _, ok := r["task_id"]; !ok {
			t.Fatalf("%v has no task_id", r["tool"])
		}
		if r["tool"] == "deploy.clear" {
			if _, ok := r["cleared_by"]; !ok {
				t.Fatalf("deploy.clear lost cleared_by beside policy: %v", r)
			}
		}
	}
}
