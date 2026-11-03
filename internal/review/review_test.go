package review_test

// Ported from tests/test_review.py (validate, classify, the review route). The gate's definition-release tests
// (test_the_gate_tiers_a_definition_release, test_a_malformed_definition_release_is_refused) are in internal/gate.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/authn"
	"github.com/jfillman/clearance/internal/definitions/deftest"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/review"
)

const img = "ghcr.io/jfillman/autopilot-agent-runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// Base is test_review.py's BASE definition.
const Base = `{"name": "gate-triage", "description": "Explains why a gate-api pipeline run failed.",
 "owner": "group:default/team-gate", "kind": "event",
 "identity": {"type": "workload", "serviceAccount": "autopilot-runs/gate-triage"},
 "profile": {"tierCeiling": "T1",
   "tools": ["glidepath.runs.list", "glidepath.run.get", "glidepath.logs.get", "glidepath.explain", "repo.file.get", "repo.pr.open"],
   "glidepath": {"apps": ["gate-api"]}, "repos": {"allow": ["jfillman/gate-api"]}, "models": ["claude-sonnet-5-5"],
   "network": "clearance+model", "compute": "small",
   "limits": {"ttlMinutes": 20, "toolCalls": 60, "githubCalls": 40, "openPrs": 1, "modelTokens": 400000, "children": 0}},
 "runtime": {"image": "` + img + `", "framework": "generic", "instructions": "Find out why."},
 "triggers": [{"type": "event", "source": "glidepath", "bindingKey": "gate-api.pipelinerun.finished",
   "match": {"subject.content.outcome": "failure"}, "maxPerHour": 4}]}`

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	v, err := pycompat.Decode(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

// Doc is a fresh copy of Base with top-level overrides.
func Doc(t *testing.T, over map[string]any) map[string]any {
	d := decode(t, Base)
	for k, v := range over {
		d[k] = v
	}
	return d
}

func prof(d map[string]any, kw map[string]any) map[string]any {
	raw, _ := json.Marshal(d)
	c, _ := pycompat.Decode(strings.NewReader(string(raw)))
	cm := c.(map[string]any)
	p := cm["profile"].(map[string]any)
	for k, v := range kw {
		p[k] = v
	}
	return cm
}

func rules(ps []review.Problem) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.Rule)
	}
	return out
}

func s(x string) *string { return &x }

func list(xs ...string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

var reg = deftest.Tools()

func validate(doc any, o review.Options) []string {
	return rules(review.Validate(doc, reg, parseDef, o))
}

func TestAGoodDefinitionHasNoProblems(t *testing.T) {
	if got := validate(Doc(t, nil), review.Options{Name: s("gate-triage"), Owner: s("group:default/team-gate"), Path: s("agents/gate-triage.yaml")}); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestValidationFindsWhatAPinOrACallWouldRefuse(t *testing.T) {
	cases := []struct {
		name string
		doc  any
		o    review.Options
		want []string
	}{
		{"not a mapping", "nope", review.Options{}, []string{"DF-SCHEMA"}},
		{"bad ceiling", prof(Doc(t, nil), map[string]any{"tierCeiling": "T9"}), review.Options{}, []string{"DF-SCHEMA"}},
		{"file name", Doc(t, nil), review.Options{Path: s("agents/other.yaml")}, []string{"DF-NAME"}},
		{"pin name", Doc(t, nil), review.Options{Name: s("x")}, []string{"DF-NAME"}},
		{"owner", Doc(t, nil), review.Options{Owner: s("group:default/x")}, []string{"DF-OWNER"}},
		{"identity", Doc(t, map[string]any{"identity": map[string]any{"type": "workload", "serviceAccount": "autopilot-runs/x"}}), review.Options{}, []string{"DF-IDENTITY"}},
		{"unknown tool", prof(Doc(t, nil), map[string]any{"tools": list("glidepath.runs.list", "no.such.tool")}), review.Options{}, []string{"DF-TOOL"}},
		{"tripwire", prof(Doc(t, nil), map[string]any{"tools": list("glidepath.runs.list", "k8s.exec")}), review.Options{}, []string{"DF-TRIPWIRE"}},
		{"no repos", prof(Doc(t, nil), map[string]any{"repos": map[string]any{"allow": []any{}}}), review.Options{}, []string{"DF-REPOS"}},
		{"model", Doc(t, nil), review.Options{Models: []string{"claude-haiku-5-5"}}, []string{"DF-MODEL"}},
		{"allowed image", Doc(t, nil), review.Options{ImageAllow: []string{"ghcr.io/jfillman/autopilot-agent-runtime@*"}}, []string{}},
		{"image not allowed", Doc(t, nil), review.Options{ImageAllow: []string{"ghcr.io/jfillman/runtime-*@*"}}, []string{"DF-IMAGE"}},
		{"no description", Doc(t, map[string]any{"description": " "}), review.Options{}, []string{"DF-DESCRIPTION"}},
		{"placeholder image", Doc(t, map[string]any{"runtime": map[string]any{"image": "x/y@sha256:" + strings.Repeat("0", 64)}}), review.Options{}, []string{"DF-IMAGE"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := validate(c.doc, c.o); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
	// repo.pr.open is T1, above a T0 ceiling (R007)
	if got := validate(prof(Doc(t, nil), map[string]any{"tierCeiling": "T0"}), review.Options{}); !contains(got, "DF-CEILING") {
		t.Fatal(got)
	}
	// a tag, not a digest: the schema may already refuse it
	d := Doc(t, nil)
	d["runtime"].(map[string]any)["image"] = "ghcr.io/x/y:latest"
	if got := validate(d, review.Options{}); !reflect.DeepEqual(got, []string{"DF-IMAGE"}) && !reflect.DeepEqual(got, []string{"DF-SCHEMA"}) {
		t.Fatal(got)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func classify(old, new map[string]any) (int, []review.Change) { return review.Classify(old, new, reg) }

func TestClassifyTiersAChangeByWhatTheAgentMayDoAfterIt(t *testing.T) {
	base := Doc(t, nil)
	limitsWith := func(k string, v int) map[string]any {
		l := map[string]any{}
		for kk, vv := range base["profile"].(map[string]any)["limits"].(map[string]any) {
			l[kk] = vv
		}
		l[k] = json.Number(strconv.Itoa(v))
		return l
	}
	tier, ch := classify(base, Doc(t, nil))
	if tier != 0 || len(ch) != 1 || ch[0].Change != "no change in authority" {
		t.Fatal(tier, ch)
	}
	d := Doc(t, nil)
	d["runtime"].(map[string]any)["instructions"] = "Be brief."
	if tier, _ := classify(base, d); tier != 0 {
		t.Fatal(tier)
	}
	cases := []struct {
		name string
		new  map[string]any
		want int
	}{
		{"fewer tools", prof(base, map[string]any{"tools": list("glidepath.runs.list", "glidepath.run.get", "repo.pr.open")}), 1},
		{"removed", nil, 1},
		{"more tokens", prof(base, map[string]any{"limits": limitsWith("modelTokens", 900000)}), 2},
		{"new image", Doc(t, map[string]any{"runtime": map[string]any{"image": strings.Replace(img, strings.Repeat("a", 64), strings.Repeat("b", 64), 1), "framework": "generic", "instructions": "Find out why."}}), 2},
		{"higher ceiling", prof(base, map[string]any{"tierCeiling": "T2"}), 3},
		{"new app", prof(base, map[string]any{"glidepath": map[string]any{"apps": list("gate-api", "flight-api")}}), 3},
		{"new owner", Doc(t, map[string]any{"owner": "group:default/other"}), 3},
		{"wider network", prof(base, map[string]any{"network": "allowlist"}), 3},
		{"narrow one, widen another", prof(base, map[string]any{"tierCeiling": "T2", "limits": limitsWith("toolCalls", 10)}), 3},
	}
	for _, c := range cases {
		if tier, _ := classify(base, c.new); tier != c.want {
			t.Errorf("%s: tier %d, want %d", c.name, tier, c.want)
		}
	}
	tier, ch = classify(base, prof(base, map[string]any{"limits": limitsWith("toolCalls", 10)}))
	if tier != 1 || !reflect.DeepEqual(ch, []review.Change{{"profile.limits.toolCalls", "60 -> 10", 1}}) {
		t.Fatal(tier, ch)
	}
	d = Doc(t, nil)
	d["triggers"].([]any)[0].(map[string]any)["maxPerHour"] = json.Number("12")
	tier, ch = classify(base, d)
	if tier != 2 || !strings.Contains(ch[0].Change, "maxPerHour 4 -> 12") {
		t.Fatal(tier, ch)
	}
	tools := append(list(), base["profile"].(map[string]any)["tools"].([]any)...)
	tier, ch = classify(base, prof(base, map[string]any{"tools": append(tools, "catalog.read")}))
	if tier != 2 || !reflect.DeepEqual(ch, []review.Change{{"profile.tools", "added catalog.read (T0)", 2}}) {
		t.Fatal(tier, ch)
	}
	tier, ch = classify(base, prof(base, map[string]any{"repos": map[string]any{"allow": list("jfillman/gate-api", "jfillman/baggage-api")}}))
	if tier != 3 || ch[0].Field != "profile.repos.allow" || ch[0].Change != "added jfillman/baggage-api" {
		t.Fatal(tier, ch)
	}
	if tier, _ := classify(nil, base); tier != 3 {
		t.Fatal("a new agent with a writing tool is tier 3", tier)
	}
	if tier, ch := classify(nil, prof(base, map[string]any{"tools": list("glidepath.runs.list"), "repos": map[string]any{}})); tier != 2 || ch[0].Change != "new agent (read tools only)" {
		t.Fatal(tier, ch)
	}
}

func TestTheReviewRoute(t *testing.T) {
	h := &review.Handler{Registry: reg, Parse: parseDef, Config: review.Config{
		Verifiers: []string{"app-*-cicd/pipeline-runner"}, Delegates: []string{"hangar-prod/app-backstage-prod/backstage"},
		ImageAllow: []string{"ghcr.io/jfillman/autopilot-agent-runtime@*"}}}
	mux := http.NewServeMux()
	h.Routes(mux)
	who := map[string]authn.Principal{
		"ci":    {ID: "app-gate-api-cicd/pipeline-runner", Kind: authn.KindServiceAccount},
		"dana":  {ID: "user:dana", Kind: authn.KindPerson},
		"tower": {ID: "hangar-prod/app-backstage-prod/backstage", Kind: authn.KindForeignWorkload},
		"svc":   {ID: "ns/svc", Kind: authn.KindServiceAccount},
	}
	post := func(token string, body any, hdr map[string]string) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/v1/definitions/review", strings.NewReader(string(raw)))
		if p, ok := who[token]; ok {
			r = r.WithContext(authn.WithPrincipal(context.Background(), p))
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
	if code, _ := post("", map[string]any{"doc": Doc(t, nil)}, nil); code != 401 {
		t.Fatal(code)
	}
	if code, _ := post("svc", map[string]any{"doc": Doc(t, nil)}, nil); code != 403 {
		t.Fatal(code)
	}
	// test_review.py accepts either answer ("... or r[\"tier\"] == 3"); repo.file.get is T0, so only repo.pr.open writes.
	code, out := post("ci", map[string]any{"doc": Doc(t, nil), "path": "agents/gate-triage.yaml"}, nil)
	want := map[string]any{"ok": true, "problems": []any{}, "tier": 3.0, "changes": []any{map[string]any{
		"field": "agent", "change": "new agent with writing tools repo.pr.open", "tier": 3.0}}}
	if code != 200 || !reflect.DeepEqual(out, want) {
		t.Fatal(code, out)
	}
	bad := Doc(t, nil)
	bad["runtime"].(map[string]any)["image"] = "docker.io/x/y@sha256:" + strings.Repeat("c", 64)
	_, out = post("dana", map[string]any{"doc": bad}, nil)
	if out["ok"] != false || len(out["problems"].([]any)) != 1 || out["problems"].([]any)[0].(map[string]any)["rule"] != "DF-IMAGE" || out["tier"] != nil {
		t.Fatal(out)
	}
	_, out = post("tower", map[string]any{"doc": Doc(t, nil), "old": Doc(t, nil)}, map[string]string{authn.OnBehalfOfHeader: "user:dana"})
	if out["tier"] != 0.0 {
		t.Fatal(out)
	}
	if code, _ := post("ci", map[string]any{}, nil); code != 400 {
		t.Fatal(code)
	}
	// strict decoding: an unknown field is refused
	if code, _ := post("ci", map[string]any{"doc": Doc(t, nil), "surprise": 1}, nil); code != 400 {
		t.Fatal(code)
	}
}
