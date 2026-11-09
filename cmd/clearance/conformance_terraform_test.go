package main

// G-TF-7: the Terraform gate passes the provider conformance suite (docs/provider-protocol.md). The adapter below is
// the test-only control interface in front of the real `clearance hold`, `release` and `report` (holdMain, releaseMain
// and reportMain, run in process exactly as the CLI runs them): a fake workspace whose `terraform show -json` is
// conformance.PlanJSON, a saved plan file that is the manifest the harness names, and the harness's fake target in
// place of `terraform apply`. Nothing in the binary serves the control interface.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/conformance"
	"github.com/jfillman/clearance/internal/conformance/fakes"
)

// lineWriter calls fn for each line written to it.
type lineWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	fn  func(line string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			w.buf.WriteString(line)
			return len(p), nil
		}
		w.fn(strings.TrimRight(line, "\n"))
	}
}

// terraformChange is the part of the registration `hold` is given: what a workflow passes as flags.
type terraformChange struct {
	App, Env, Repo, Head, Proposer, ProposerKind, Owner string
	PR                                                  int64
	Paths                                               []string
	Checks                                              map[string]string
	Subject                                             struct {
		Workspace struct{ Backend, Key, Name string }
		Resources []struct{ Actions []string }
	}
}

// terraformAdapter is the Terraform gate as a conformance provider.
func terraformAdapter(version string) *fakes.Adapter {
	var ad *fakes.Adapter
	ad = fakes.NewAdapter(conformance.Info{Name: terraformProviderName, Version: version, Flow: conformance.FlowTerraformPlan},
		func(ctx context.Context, a conformance.ApplyRequest, p fakes.Progress) {
			var ch terraformChange
			if err := json.Unmarshal(a.Change, &ch); err != nil {
				p.Failed("the change: " + err.Error())
				return
			}
			dir, err := os.MkdirTemp("", "tf-conformance-")
			if err != nil {
				p.Failed(err.Error())
				return
			}
			defer os.RemoveAll(dir)
			write := func(name string, b []byte) string {
				path := filepath.Join(dir, name)
				if err == nil {
					err = os.WriteFile(path, b, 0o600)
				}
				return path
			}
			changes := len(ch.Subject.Resources) > 0
			plan := write("tfplan", []byte(a.Manifest))
			planJSON := write("plan.json", conformance.PlanJSON(changes))
			tokenFile := write("token", []byte(a.Core.Bearer))
			if err != nil {
				p.Failed(err.Error())
				return
			}

			// terraform plan has run; clearance hold registers it and waits.
			argv := []string{"--plan", plan, "--json", planJSON, "--lock-file", "none", "--url", a.Core.URL, "--token-file", tokenFile,
				"--app", ch.App, "--env", ch.Env, "--repo", ch.Repo, "--head", ch.Head, "--pr", strconv.FormatInt(ch.PR, 10),
				"--proposer", ch.Proposer, "--proposer-kind", ch.ProposerKind, "--owner", ch.Owner,
				"--backend", ch.Subject.Workspace.Backend, "--state-key", ch.Subject.Workspace.Key,
				"--workspace", ch.Subject.Workspace.Name}
			for k, v := range ch.Checks {
				argv = append(argv, "--check", k+"="+v)
			}
			for _, path := range ch.Paths {
				argv = append(argv, "--path", path)
			}
			var id string
			out := &lineWriter{fn: func(line string) {
				// "<id> <state> tier <n>" is the first line, and "holding for people" follows while it waits.
				f := strings.Fields(line)
				if id == "" && len(f) >= 3 && strings.HasPrefix(f[0], "ch-") {
					id = f[0]
					p.ChangeID(id)
					if f[1] == "holding" {
						p.Holding()
					}
				}
			}}
			var stderr bytes.Buffer
			if code := holdMain(ctx, argv, nil, noToken, out, &stderr); code != exitCleared {
				p.Refused(fmt.Sprintf("hold exit %d: %s", code, strings.TrimSpace(stderr.String())))
				return
			}

			// The apply step runs only after release exits 0.
			rel := []string{"--plan", plan, "--clearance", id, "--url", a.Core.URL, "--token-file", tokenFile}
			stderr.Reset()
			if code := releaseMain(ctx, rel, nil, noToken, &bytes.Buffer{}, &stderr); code != exitCleared {
				p.Refused(fmt.Sprintf("release exit %d: %s", code, strings.TrimSpace(stderr.String())))
				return
			}
			// terraform apply -json tfplan: the fake target takes the plan.
			if _, err := ad.ApplyTarget(ctx, a, a.Manifest); err != nil {
				p.Failed("the target refused: " + err.Error())
				return
			}
			now := time.Now().UTC()
			ts := func(d time.Duration) string { return now.Add(d).Format("2006-01-02T15:04:05.000Z07:00") }
			log := fmt.Sprintf(`{"type":"apply_start","@timestamp":%q,"hook":{"resource":{"addr":"aws_instance.web"},"action":"update"}}
{"type":"apply_complete","@timestamp":%q,"hook":{"resource":{"addr":"aws_instance.web"},"action":"update"}}
{"type":"change_summary","@message":"Apply complete","@timestamp":%q}
`, ts(0), ts(time.Second), ts(time.Second))
			logPath := write("apply.jsonl", []byte(log))
			if err != nil {
				p.Failed(err.Error())
				return
			}
			rep := []string{"--plan", plan, "--apply-log", logPath, "--clearance", id, "--url", a.Core.URL, "--token-file", tokenFile}
			stderr.Reset()
			if code := reportMain(ctx, rep, nil, noToken, &bytes.Buffer{}, &stderr); code != exitCleared {
				p.Failed(fmt.Sprintf("report exit %d: %s", code, strings.TrimSpace(stderr.String())))
				return
			}
			p.Applied(nil)
		})
	return ad
}

// TestTerraformConformance: the gate holds a plan, releases it once a person clears it (or policy does), applies only
// the cleared plan file, and reports an outcome whose digest is the cleared plan's, named terraform-ci; a denied or
// expired plan is never applied.
func TestTerraformConformance(t *testing.T) {
	ad := terraformAdapter("0.0.0-conformance")
	srv := httptest.NewServer(ad.Handler())
	t.Cleanup(func() { ad.Close(); srv.Close() })
	rep, err := conformance.Run(context.Background(), conformance.Options{Provider: srv.URL, Role: conformance.RoleDeployment,
		Timeout: 30 * time.Second, HoldWindow: 300 * time.Millisecond, PollInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	rep.Print(&out)
	t.Log("\n" + out.String())
	if !rep.Pass {
		t.Fatalf("conformance failed: %v", rep.Failed())
	}
	if rep.Provider.Name != "terraform-ci" || rep.Provider.Version != "0.0.0-conformance" {
		t.Fatalf("provider %+v", rep.Provider)
	}
	if got, want := len(rep.Assertions), len(conformance.Assertions[conformance.RoleDeployment]); got != want {
		t.Fatalf("%d assertions, want %d", got, want)
	}
}
