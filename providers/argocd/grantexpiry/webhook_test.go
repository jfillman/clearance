package grantexpiry

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	agent "github.com/jfillman/clearance/providers/argocd/agent"
)

const argo = "system:serviceaccount:argocd-apps:argocd-application-controller"

type fakeLookup struct {
	grants map[string][]agent.Grant
	synced bool
}

func (f fakeLookup) Active(ns string) ([]agent.Grant, bool) {
	if !f.synced {
		return nil, false
	}
	return f.grants[ns], true
}

func handler(t *testing.T, mode Mode, l Lookup) *Handler {
	t.Helper()
	h, err := NewHandler(Config{Mode: mode, ArgoCDUser: argo, Now: func() time.Time { return now }}, l, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func reqFor(obj map[string]any, mutate func(r map[string]any)) map[string]any {
	r := map[string]any{"uid": "u-1", "operation": "UPDATE", "namespace": "prot", "name": "app-cm",
		"resource": map[string]any{"group": "", "version": "v1", "resource": "configmaps"},
		"userInfo": map[string]any{"username": argo}, "object": obj}
	if mutate != nil {
		mutate(r)
	}
	return r
}

func cmDoc(name, rendered string) map[string]any {
	md := map[string]any{"name": name, "namespace": "prot"}
	if rendered != "" {
		md["annotations"] = map[string]any{agent.AnnRendered: rendered}
	}
	return map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": md}
}

// post sends one AdmissionReview through ServeHTTP and returns the response.
func post(t *testing.T, h *Handler, req map[string]any) response {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": req})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		APIVersion string   `json:"apiVersion"`
		Kind       string   `json:"kind"`
		Response   response `json:"response"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.APIVersion != "admission.k8s.io/v1" || out.Kind != "AdmissionReview" || out.Response.UID != req["uid"] {
		t.Fatalf("not a review answer to the request: %s", rec.Body)
	}
	return out.Response
}

var expiredOnly = fakeLookup{synced: true, grants: map[string][]agent.Grant{"prot": {grant("g1", past, objs(cmKey, h1))}}}
var liveOnly = fakeLookup{synced: true, grants: map[string][]agent.Grant{"prot": {grant("g1", future, objs(cmKey, h1))}}}

func TestEnforceRefusesAnExpiredGrantWithTheAuditAnnotation(t *testing.T) {
	r := post(t, handler(t, Enforce, expiredOnly), reqFor(cmDoc("app-cm", h1), nil))
	if r.Allowed || r.Status == nil || r.Status.Code != 403 || !strings.Contains(r.Status.Message, "expired") {
		t.Fatalf("enforce must refuse an expired grant with a 403: %+v", r)
	}
	if a := r.AuditAnnotations[AuditKey]; !strings.HasPrefix(a, "prot/g1: ") {
		t.Fatalf("the audit annotation names the namespace and grant: %q", a)
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("enforce refuses; it does not warn: %v", r.Warnings)
	}
	if ok := post(t, handler(t, Enforce, liveOnly), reqFor(cmDoc("app-cm", h1), nil)); !ok.Allowed || ok.Status != nil || ok.AuditAnnotations != nil {
		t.Fatalf("enforce admits an unexpired listed object, silently: %+v", ok)
	}
}

func TestAuditAlwaysAllowsWarnsAndAnnotates(t *testing.T) {
	r := post(t, handler(t, Audit, expiredOnly), reqFor(cmDoc("app-cm", h1), nil))
	if !r.Allowed || r.Status != nil {
		t.Fatalf("audit must allow: %+v", r)
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "audit, not enforced") || len(r.Warnings[0]) > 250 {
		t.Fatalf("audit warns once, under 250 bytes: %v", r.Warnings)
	}
	if !strings.Contains(r.AuditAnnotations[AuditKey], "expired") {
		t.Fatalf("audit carries the expired-grant annotation: %v", r.AuditAnnotations)
	}
	// A would-refuse that is not the clock's (not listed): a warning, no expired-grant annotation.
	r = post(t, handler(t, Audit, liveOnly), reqFor(cmDoc("unlisted", h1), nil))
	if !r.Allowed || len(r.Warnings) != 1 || r.AuditAnnotations != nil {
		t.Fatalf("audit, an unlisted object: allowed with a warning and no expired-grant annotation: %+v", r)
	}
	// Nothing to say: no warning.
	if r := post(t, handler(t, Audit, liveOnly), reqFor(cmDoc("app-cm", h1), nil)); !r.Allowed || r.Warnings != nil {
		t.Fatalf("audit, a live grant: allowed and silent: %+v", r)
	}
	// Not synced and unreadable objects: audit still allows.
	for name, l := range map[string]Lookup{"not synced": fakeLookup{}} {
		if r := post(t, handler(t, Audit, l), reqFor(cmDoc("app-cm", h1), nil)); !r.Allowed || len(r.Warnings) != 1 {
			t.Fatalf("audit, %s: allowed with a warning: %+v", name, r)
		}
	}
}

func TestEnforceRefusesWhenTheCacheIsNotSynced(t *testing.T) {
	r := post(t, handler(t, Enforce, fakeLookup{}), reqFor(cmDoc("app-cm", h1), nil))
	if r.Allowed || !strings.Contains(r.Status.Message, "not synced") || r.AuditAnnotations != nil {
		t.Fatalf("enforce with no synced cache refuses (and it is not the clock's): %+v", r)
	}
}

func TestEnforceRefusesARequestWithNoReadableObject(t *testing.T) {
	r := post(t, handler(t, Enforce, liveOnly), reqFor(nil, func(r map[string]any) { delete(r, "object") }))
	if r.Allowed {
		t.Fatalf("enforce refuses a request it cannot read: %+v", r)
	}
}

// The handler's own scope check mirrors the configuration's matchConditions, field by field: each guard, with its
// field absent, leaves the request out of scope (allowed, not decided), exactly as a guarded match condition does.
func TestTheHandlersScopeGuardsEachMissingField(t *testing.T) {
	h := handler(t, Enforce, expiredOnly) // anything in scope is refused, so an allow proves out of scope
	cases := []struct {
		name    string
		mutate  func(r map[string]any)
		inScope bool
	}{
		{"in scope: Argo's UPDATE of a main resource", nil, true},
		{"in scope: Argo's CREATE", func(r map[string]any) { r["operation"] = "CREATE" }, true},
		{"no userInfo", func(r map[string]any) { delete(r, "userInfo") }, false},
		{"userInfo with no username", func(r map[string]any) { r["userInfo"] = map[string]any{} }, false},
		{"another user", func(r map[string]any) { r["userInfo"] = map[string]any{"username": "system:serviceaccount:default:x"} }, false},
		{"a subresource (scale)", func(r map[string]any) { r["subResource"] = "scale" }, false},
		{"an empty subResource is the main resource", func(r map[string]any) { r["subResource"] = "" }, true},
		{"no namespace (cluster-scoped)", func(r map[string]any) { delete(r, "namespace") }, false},
		{"DELETE", func(r map[string]any) { r["operation"] = "DELETE" }, false},
		{"no operation", func(r map[string]any) { delete(r, "operation") }, false},
		{"no resource: not excluded, so in scope", func(r map[string]any) { delete(r, "resource") }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := post(t, h, reqFor(cmDoc("app-cm", h1), c.mutate))
			if r.Allowed == c.inScope {
				t.Fatalf("in scope %v, but allowed=%v: %+v", c.inScope, r.Allowed, r)
			}
		})
	}
}

// Each resource the admission policy excludes is out of the handler's scope too; a normal resource is in it.
func TestTheExcludedResourcesAreNotDecided(t *testing.T) {
	h := handler(t, Enforce, expiredOnly)
	for _, x := range Excluded {
		r := post(t, h, reqFor(cmDoc("app-cm", h1), func(r map[string]any) {
			r["resource"] = map[string]any{"group": x.Group, "version": "v1", "resource": x.Resource}
		}))
		if !r.Allowed {
			t.Errorf("%s/%s is excluded and must not be decided: %+v", x.Group, x.Resource, r)
		}
	}
	for _, res := range [][2]string{{"", "configmaps"}, {"apps", "deployments"}, {"clearance.hangar.io", "other"}, {"events.k8s.io", "other"}, {"", "leases"}} {
		r := post(t, h, reqFor(cmDoc("app-cm", h1), func(r map[string]any) {
			r["resource"] = map[string]any{"group": res[0], "version": "v1", "resource": res[1]}
		}))
		if r.Allowed {
			t.Errorf("%s/%s is not excluded and must be decided: %+v", res[0], res[1], r)
		}
	}
}

func TestServeHTTPRefusesWhatIsNotAReview(t *testing.T) {
	h := handler(t, Enforce, liveOnly)
	for _, c := range []struct {
		method, ct, body string
		want             int
	}{
		{http.MethodGet, "", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "text/plain", "{}", http.StatusUnsupportedMediaType},
		{http.MethodPost, "application/json", "{}", http.StatusBadRequest},
		{http.MethodPost, "application/json", "not json", http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(c.method, "/validate", strings.NewReader(c.body))
		if c.ct != "" {
			req.Header.Set("Content-Type", c.ct)
		}
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s %s %q: %d, want %d", c.method, c.ct, c.body, rec.Code, c.want)
		}
	}
}

func TestNewHandlerRefusesABadConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no mode":       {ArgoCDUser: argo},
		"a bad mode":    {Mode: "warn", ArgoCDUser: argo},
		"no Argo user":  {Mode: Audit},
		"negative skew": {Mode: Enforce, ArgoCDUser: argo, Skew: -time.Second},
	} {
		if _, err := NewHandler(cfg, liveOnly, nil, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReadinessReportsTheModeAndRefusesAnotherMode(t *testing.T) {
	get := func(mode Mode, synced bool, q string) (int, string) {
		rec := httptest.NewRecorder()
		Ready(mode, func() bool { return synced })(rec, httptest.NewRequest(http.MethodGet, "/readyz"+q, nil))
		b, _ := io.ReadAll(rec.Body)
		return rec.Code, string(b)
	}
	if c, b := get(Enforce, true, "?mode=enforce"); c != 200 || !strings.Contains(b, "mode=enforce") {
		t.Fatalf("enforce pod, enforce rollout: %d %q", c, b)
	}
	if c, b := get(Audit, true, "?mode=enforce"); c != 503 || !strings.Contains(b, "mode=audit") {
		t.Fatalf("a pod still in audit is not Ready in an enforce rollout: %d %q", c, b)
	}
	if c, _ := get(Enforce, true, "?mode=audit"); c != 503 {
		t.Fatalf("an enforce pod is not Ready in an audit rollout: %d", c)
	}
	if c, b := get(Audit, true, ""); c != 200 || !strings.Contains(b, "mode=audit") {
		t.Fatalf("no mode asked: ready, the body says the mode: %d %q", c, b)
	}
	if c, _ := get(Enforce, false, "?mode=enforce"); c != 503 {
		t.Fatalf("a cache that is not synced is not Ready: %d", c)
	}
}

func TestMetricsExposeTheGrantTimesAndDecisions(t *testing.T) {
	g := grant("g1", future, objs(cmKey, h1))
	g.CheckedAt = past
	m := NewMetrics(func() []agent.Grant { return []agent.Grant{g} }, Enforce)
	m.SetSynced(func() bool { return true })
	h, err := NewHandler(Config{Mode: Enforce, ArgoCDUser: argo, Now: func() time.Time { return now }}, expiredOnly, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	post(t, h, reqFor(cmDoc("app-cm", h1), nil))
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	pt, _ := time.Parse(time.RFC3339, past)
	ft, _ := time.Parse(time.RFC3339, future)
	for _, want := range []string{
		`clearance_grant_expiry_decisions_total{mode="enforce",verdict="refuse",expired="true"} 1`,
		`clearance_grant_expiry_mode{mode="enforce"} 1`,
		`clearance_grant_expiry_cache_synced 1`,
		`clearance_grant_status_checked_timestamp_seconds{grant_namespace="prot",grant="g1"} ` + itoa(pt.Unix()),
		`clearance_grant_expires_timestamp_seconds{grant_namespace="prot",grant="g1"} ` + itoa(ft.Unix()),
		`clearance_grant_status_valid{grant_namespace="prot",grant="g1"} 1`,
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("metrics lack %q:\n%s", want, body)
		}
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
