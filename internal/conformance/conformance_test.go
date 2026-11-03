package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/conformance"
	"github.com/jfillman/clearance/internal/conformance/fakes"
)

type provider interface {
	Handler() http.Handler
	Close()
}

func run(t *testing.T, role string, p provider) *conformance.Report {
	t.Helper()
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(func() { p.Close(); srv.Close() })
	rep, err := conformance.Run(context.Background(), conformance.Options{Provider: srv.URL, Role: role,
		Timeout: 10 * time.Second, HoldWindow: 200 * time.Millisecond, PollInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	rep.Print(&out)
	t.Log("\n" + out.String())
	return rep
}

func ids(rep *conformance.Report) []string {
	var out []string
	for _, a := range rep.Assertions {
		out = append(out, a.ID)
	}
	return out
}

// TestConformance runs the suite against the four fakes: the good ones pass every assertion, each broken one
// fails the assertion its break violates, and the chain verifies at the end of every run.
func TestConformance(t *testing.T) {
	cases := []struct {
		name   string
		role   string
		p      func() provider
		failOn []string // empty: everything passes
	}{
		{"runtime", conformance.RoleRuntime, func() provider { return fakes.NewRuntime("fake-runtime", "1.0.0") }, nil},
		{"deployment", conformance.RoleDeployment, func() provider { return fakes.NewDeployment("fake-deploy", "1.0.0") }, nil},
		{"runtime acts on deny", conformance.RoleRuntime, func() provider {
			p := fakes.NewRuntime("fake-runtime-broken", "1.0.0")
			p.ActOnDeny = true
			return p
		}, []string{"runtime.deny-not-acted"}},
		{"deployment applies before clear", conformance.RoleDeployment, func() provider {
			p := fakes.NewDeployment("fake-deploy-broken", "1.0.0")
			p.ApplyBeforeClear = true
			return p
		}, []string{"deployment.hold", "deployment.release-once", "deployment.deny-never-applied",
			"deployment.expiry-never-applied"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rep := run(t, tc.role, tc.p())
			if got, want := ids(rep), conformance.Assertions[tc.role]; !slices.Equal(got, want) {
				t.Fatalf("assertions %v, want %v", got, want)
			}
			var failed []string
			for _, a := range rep.Failed() {
				failed = append(failed, a.ID)
			}
			if !slices.Equal(failed, tc.failOn) {
				t.Fatalf("failed %v, want %v", failed, tc.failOn)
			}
			if rep.Pass != (len(tc.failOn) == 0) {
				t.Fatalf("pass %v with failures %v", rep.Pass, failed)
			}
			if rep.Chain == nil || !rep.Chain.OK || rep.Chain.Records == 0 {
				t.Fatalf("chain %+v", rep.Chain)
			}
			if c := rep.Get("chain.verify"); c == nil || !c.Pass {
				t.Fatalf("chain.verify: %+v", c)
			}
		})
	}
}

// TestAssertionList pins the assertion ids to testdata/conformance/assertions.json, which the protocol document
// lists; a change to either is a change to the suite (SuiteVersion).
func TestAssertionList(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/conformance/assertions.json")
	if err != nil {
		t.Fatal(err)
	}
	var want struct {
		Suite      string              `json:"suite"`
		Assertions map[string][]string `json:"assertions"`
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if want.Suite != conformance.SuiteVersion {
		t.Fatalf("suite %q, want %q", want.Suite, conformance.SuiteVersion)
	}
	for role, list := range conformance.Assertions {
		if !slices.Equal(want.Assertions[role], list) {
			t.Fatalf("%s: assertions.json %v, harness %v", role, want.Assertions[role], list)
		}
	}
	if len(want.Assertions) != len(conformance.Assertions) {
		t.Fatalf("assertions.json roles %v", want.Assertions)
	}
	doc, err := os.ReadFile("../../docs/provider-protocol.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range conformance.Assertions {
		for _, id := range list {
			if !strings.Contains(string(doc), "`"+id+"`") {
				t.Errorf("docs/provider-protocol.md does not name %s", id)
			}
		}
	}
}

// TestUnreachableProvider: a provider that does not serve the control interface is one failed assertion, not an
// error.
func TestUnreachableProvider(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	rep, err := conformance.Run(context.Background(), conformance.Options{Provider: srv.URL, Role: conformance.RoleRuntime})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pass || len(rep.Assertions) != 1 || rep.Assertions[0].ID != "control.info" || rep.Assertions[0].Pass {
		t.Fatalf("report %+v", rep)
	}
}

// TestWrongRole: a runtime-only provider tested as a deployment provider fails control.info.
func TestWrongRole(t *testing.T) {
	p := fakes.NewRuntime("fake-runtime", "1.0.0")
	srv := httptest.NewServer(p.Handler())
	defer func() { p.Close(); srv.Close() }()
	rep, err := conformance.Run(context.Background(), conformance.Options{Provider: srv.URL, Role: conformance.RoleDeployment})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pass || rep.Get("control.info").Pass {
		t.Fatalf("report %+v", rep)
	}
}

func TestOptions(t *testing.T) {
	for _, o := range []conformance.Options{
		{Provider: "http://127.0.0.1:1", Role: "other"},
		{Provider: "ftp://x", Role: conformance.RoleRuntime},
		{Provider: "http://user:pw@x", Role: conformance.RoleRuntime},
	} {
		if _, err := conformance.Run(context.Background(), o); err == nil {
			t.Errorf("%+v: no error", o)
		}
	}
}

func TestDecodeApply(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"id": "a-1", "role": "runtime", "provider": "p",
			"core": map[string]any{"url": "http://127.0.0.1:1", "bearer": "x"}, "target": map[string]any{"url": "http://127.0.0.1:2"},
			"evaluation": map[string]any{"subject": map[string]any{}}}
	}
	enc := func(m map[string]any) *bytes.Reader {
		raw, _ := json.Marshal(m)
		return bytes.NewReader(raw)
	}
	if _, err := conformance.DecodeApply(enc(base())); err != nil {
		t.Fatal(err)
	}
	bad := []func(map[string]any){
		func(m map[string]any) { m["extra"] = 1 },
		func(m map[string]any) { m["id"] = "Bad ID" },
		func(m map[string]any) { m["role"] = "deployment" },
		func(m map[string]any) { m["core"] = map[string]any{"url": "file:///etc/passwd"} },
		func(m map[string]any) { m["target"] = map[string]any{"url": "http://x/?q=1"} },
		func(m map[string]any) { m["evaluation"] = "[]" },
		func(m map[string]any) { m["manifest"] = "x" },
		func(m map[string]any) { m["poll_interval_ms"] = -1 },
		func(m map[string]any) { delete(m, "provider") },
	}
	for i, edit := range bad {
		m := base()
		edit(m)
		if _, err := conformance.DecodeApply(enc(m)); err == nil {
			t.Errorf("case %d: accepted %v", i, m)
		}
	}
	if _, err := conformance.DecodeApply(strings.NewReader(`{"id":"a"} {}`)); err == nil {
		t.Error("trailing data accepted")
	}
	big := strings.NewReader(`{"manifest":"` + strings.Repeat("x", conformance.MaxControlBody) + `"}`)
	if _, err := conformance.DecodeApply(big); err != conformance.ErrTooLarge {
		t.Errorf("an oversized body: %v", err)
	}
}

func FuzzDecodeApply(f *testing.F) {
	f.Add([]byte(`{"id":"a-1","role":"deployment","provider":"p","core":{"url":"http://h"},"target":{"url":"http://t"},"change":{},"manifest":"m"}`))
	f.Add([]byte(`{"id":"a-1","role":"runtime","provider":"p","core":{"url":"http://h"},"target":{"url":"http://t"},"evaluation":{}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, err := conformance.DecodeApply(bytes.NewReader(raw))
		if err == nil && (!conformance.ValidID(a.ID) || (a.Role != conformance.RoleRuntime && a.Role != conformance.RoleDeployment)) {
			t.Fatalf("accepted %+v", a)
		}
	})
}
