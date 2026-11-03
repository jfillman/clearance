package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/conformance"
	"github.com/jfillman/clearance/internal/conformance/fakes"
)

func TestConformanceCommand(t *testing.T) {
	good := fakes.NewDeployment("fake-deploy", "1.0.0")
	broken := fakes.NewRuntime("fake-runtime-broken", "1.0.0")
	broken.ActOnDeny = true
	gs, bs := httptest.NewServer(good.Handler()), httptest.NewServer(broken.Handler())
	t.Cleanup(func() { good.Close(); broken.Close(); gs.Close(); bs.Close() })
	fast := []string{"--hold-window", "150ms", "--poll-interval", "20ms", "--timeout", "10s"}

	cases := []struct {
		name     string
		args     []string
		code     int
		stdout   []string
		withFile bool
	}{
		{"a conformant deployment provider", append([]string{"--provider", gs.URL, "--role", "deployment"}, fast...), 0,
			[]string{"PASS deployment.hold", "PASS deployment.outcome-digest", "PASS chain.verify", "0 failed"}, true},
		{"a runtime provider that acts on deny", append([]string{"--provider", bs.URL, "--role", "runtime"}, fast...), 1,
			[]string{"FAIL runtime.deny-not-acted", "PASS runtime.allow-acted-once", "1 failed"}, true},
		{"no role", []string{"--provider", gs.URL}, 2, nil, false},
		{"an unknown role", []string{"--provider", gs.URL, "--role", "both"}, 2, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"conformance"}, tc.args...)
			report := filepath.Join(t.TempDir(), "report.json")
			if tc.withFile {
				args = append(args, "--report", report)
			}
			var out, errb bytes.Buffer
			if code := cli.Main(context.Background(), args, &out, &errb); code != tc.code {
				t.Fatalf("exit %d, want %d\n%s%s", code, tc.code, out.String(), errb.String())
			}
			for _, s := range tc.stdout {
				if !strings.Contains(out.String(), s) {
					t.Errorf("stdout does not say %q:\n%s", s, out.String())
				}
			}
			if !tc.withFile {
				return
			}
			raw, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			var rep conformance.Report
			if err := json.Unmarshal(raw, &rep); err != nil {
				t.Fatal(err)
			}
			if rep.Suite != conformance.SuiteVersion || rep.Pass != (tc.code == 0) || rep.Chain == nil || !rep.Chain.OK {
				t.Fatalf("report %+v", rep)
			}
			if strings.Contains(string(raw), "bearer") {
				t.Fatal("the report carries a bearer")
			}
		})
	}
}
