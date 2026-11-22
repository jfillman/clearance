package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
)

func TestClassifyRender(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	bg := context.Background()
	signaled := func() error {
		cmd := exec.Command("sh", "-c", "kill -9 $$")
		err := cmd.Run()
		if err == nil {
			t.Skip("no shell to kill")
		}
		return fmt.Errorf("helm template: helm template: %w: ", err)
	}
	cases := []struct {
		name    string
		ctx     context.Context
		err     error
		lookup  chartLookupResult
		generic bool
		code    string
	}{
		{"netns refused", bg, fmt.Errorf("helm template: %w", &netnsError{errors.New("refusing")}), lookupResolved, false, CodeFaultSandbox},
		{"deadline", bg, fmt.Errorf("helm template: %w", context.DeadlineExceeded), lookupResolved, false, CodeFaultTimeout},
		{"the run's context ended", expired, errors.New("helm template: signal: killed"), lookupResolved, false, CodeFaultTimeout},
		{"tool not found", bg, fmt.Errorf("helm template: %w", &exec.Error{Name: "helm", Err: exec.ErrNotFound}), lookupResolved, false, CodeFaultTool},
		{"tool killed", bg, signaled(), lookupResolved, false, CodeFaultTool},
		{"no allow list", bg, errors.New("refused: CLEARANCE_CHART_REPOS is not set on the plugin sidecar, so no chart repository may be fetched (x)"), lookupNotAsked, false, CodeFaultConfig},
		{"not allowed", bg, errors.New("refused: the chart repository x is not one of the repositories this cluster's platform allows"), lookupNotAsked, false, CodeRenderRefused},
		{"symlink", bg, errors.New("refused: value file a.yaml resolves outside the repository"), lookupResolved, false, CodeRenderRefused},
		{"scratch I/O", bg, fmt.Errorf("helm template: %w", &fs.PathError{Op: "mkdirtemp", Path: "/tmp", Err: fs.ErrPermission}), lookupResolved, false, CodeFaultInternal},
		{"clone after the tag resolved", bg, errors.New("fetch the chart at v1: git clone: exit status 128"), lookupResolved, false, CodeDepChartFetch},
		{"clone with the host unreachable", bg, errors.New("fetch the chart at v1: git clone: exit status 128"), lookupUnreachable, false, CodeDepChartUnreachable},
		{"clone of a tag the remote lacks", bg, errors.New("fetch the chart at v1: git clone: exit status 128"), lookupNoRef, false, CodeRenderFetch},
		{"clone, no lookup", bg, errors.New("fetch the chart at v1: git clone: exit status 128"), lookupNotAsked, false, CodeRenderFetch},
		{"peel", bg, errors.New("peel the chart tag: exit status 1"), lookupResolved, false, CodeDepChartFetch},
		{"helm says no", bg, errors.New("helm template: helm template: exit status 1: Error: parse error"), lookupResolved, false, CodeRenderHelm},
		{"kustomize says no", bg, errors.New("kustomize build: kustomize build: exit status 1"), lookupResolved, false, CodeRenderKustomize},
		{"generic source", bg, errors.New("source 2: helm template: exit status 1"), lookupNotAsked, true, CodeRenderSources},
		{"generic fetch", bg, errors.New("source 1: fetch https://x at v1: exit status 128"), lookupNotAsked, true, CodeRenderSources},
		{"generic unsupported", bg, errors.New("unsupported by the Clearance plugin (source 1): plugin"), lookupNotAsked, true, CodeRenderSources},
		{"generic parameter", bg, errors.New("the sources parameter lists no source"), lookupNotAsked, true, CodeRenderSources},
		{"unknown, chart mode", bg, errors.New("something odd"), lookupResolved, false, CodeFaultInternal},
		{"already classified", bg, fmt.Errorf("wrapped: %w", newErr(CodeRenderTree, "x", nil)), lookupResolved, false, CodeRenderTree},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyRender(c.ctx, c.err, c.lookup, c.generic)
			if got.Code != c.code || got.Class != Codes[c.code] {
				t.Fatalf("got %s (%s), want %s", got.Code, got.Class, c.code)
			}
			if !errors.Is(got, c.err) && got.Err != nil && !errors.Is(got.Err, c.err) {
				t.Fatal("the detail does not wrap the error")
			}
		})
	}
}

func TestClassifyConfigAndCore(t *testing.T) {
	cases := []struct {
		name string
		got  *CmpError
		code string
	}{
		{"a sidecar setting", classifyConfig(errors.Join(errors.New("PARAM_APP is required"), errors.New("CLEARANCE_URL is required"))), CodeFaultConfig},
		{"the netns setting", classifyConfig(fmt.Errorf("%s is one of ...", NetnsEnv)), CodeFaultConfig},
		{"the lkg setting", classifyConfig(fmt.Errorf("%s is ...", LKGEnv)), CodeFaultConfig},
		{"a parameter", classifyConfig(errors.Join(errors.New("PARAM_APP is required"), errors.New(`path "../x" must be relative`))), CodeRenderParams},
		{"an Argo CD variable", classifyConfig(errors.New("ARGOCD_APP_NAME is required")), CodeRenderParams},
		{"the token", classifyCore(fmt.Errorf("%w: open /x: no such file", client.ErrToken)), CodeFaultToken},
		{"an unreadable answer", classifyCore(&client.ResponseError{Op: "registerChange", Status: 200, Err: errors.New("bad json")}), CodeFaultCoreResponse},
		{"a 403", classifyCore(&client.APIError{Op: "registerChange", Status: 403, Message: "not a verifier"}), CodeRefusedByCore},
		{"a 401", classifyCore(&client.APIError{Op: "registerChange", Status: 401, Message: "bad token"}), CodeRefusedByCore},
		{"anything else", classifyCore(errors.New("odd")), CodeFaultInternal},
	}
	for _, c := range cases {
		if c.got.Code != c.code || c.got.Class != Codes[c.code] {
			t.Errorf("%s: got %s, want %s", c.name, c.got.Code, c.code)
		}
	}
	for state, code := range map[string]string{"denied": CodeRefusedDenied, "expired": CodeRefusedExpired, "superseded": CodeRefusedSuperseded,
		"exception": CodeRefusedException, "degraded": CodeRefusedDegraded, "withdrawn": CodeRefusedState} {
		if got := stateCode(state); got != code || Codes[got] != ClassRefusal {
			t.Errorf("%s: %s", state, got)
		}
	}
}

// Every way Generate fails, end to end: the class, the code, whether it may fall back, and the message's shape (U1:
// one short first line that starts with the code, the change's link on a refusal of a change).
func TestGenerateErrorClasses(t *testing.T) {
	reason := "DG-POLICY: clearance.yaml loosens the baseline"
	cases := []struct {
		name   string
		setup  func(e *env)
		code   string
		linked bool
	}{
		{"helm missing", func(e *env) { e.exec.fail = map[string]error{"helm": toolMissing} }, CodeFaultTool, false},
		{"helm says no", func(e *env) { e.exec.fail = map[string]error{"helm": errors.New("exit status 1: Error: boom")} }, CodeRenderHelm, false},
		{"an empty render", func(e *env) { e.exec.render = []byte("# nothing\n") }, CodeRenderTree, false},
		{"a revision that is not a commit", func(e *env) {
			e.cfg.Revision = "main"
			e.core.answer = &client.Change{ID: "x", State: "cleared"}
		}, CodeRenderRevision, false},
		{"a repository not allowed", func(e *env) { e.cfg.AllowedRepos = []string{"https://git.example.test/other.git"} }, CodeRenderRefused, false},
		{"no allow list", func(e *env) { e.cfg.AllowedRepos = nil }, CodeFaultConfig, false},
		{"the chart host unreachable", func(e *env) {
			e.cfg.RenderCacheTTL = time.Minute // so the tag is looked up
			e.exec.fail = map[string]error{"git": errors.New("exit status 128: Could not resolve host")}
		}, CodeDepChartUnreachable, false},
		{"denied", func(e *env) {
			e.core.answer = &client.Change{ID: "ch-x", State: "denied", Tier: 3, DenyReason: &reason}
		}, CodeRefusedDenied, true},
		{"expired", func(e *env) { e.core.answer = &client.Change{ID: "ch-x", State: "expired", Tier: 1} }, CodeRefusedExpired, true},
		{"superseded", func(e *env) { e.core.answer = &client.Change{ID: "ch-x", State: "superseded", Tier: 1} }, CodeRefusedSuperseded, true},
		{"another state", func(e *env) { e.core.answer = &client.Change{ID: "ch-x", State: "withdrawn", Tier: 1} }, CodeRefusedState, true},
		{"an outage hold", func(e *env) { e.core.err = fmt.Errorf("%w: dial tcp: refused", client.ErrCoreUnavailable) }, CodeRefusedOutageHold, false},
		{"the core refuses", func(e *env) {
			e.core.err = &client.APIError{Op: "registerChange", Status: 403, Message: "x is not a verifier"}
		}, CodeRefusedByCore, false},
		{"a hold without the wait image", func(e *env) {
			e.cfg.WaitImage = ""
			e.core.answer = &client.Change{ID: "ch-held", State: "holding"}
		}, CodeFaultWaitImage, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			c.setup(e)
			_, objs, err := e.generate(t)
			if len(objs) != 0 {
				t.Fatal("an error with output")
			}
			ce := wantCode(t, err, c.code)
			if ce.Class != Codes[c.code] || ce.FallsBack() != (ce.Class == ClassFault || ce.Class == ClassDep) {
				t.Fatalf("%+v", ce)
			}
			lines := strings.Split(err.Error(), "\n")
			if lines[0] != ce.FirstLine() || !strings.HasPrefix(lines[0], c.code+": ") || len(lines[0]) > 120 {
				t.Fatalf("first line %q", lines[0])
			}
			if c.linked {
				if len(lines) < 2 || lines[1] != "hold: http://clearance.test/v1/clearances/"+strings.TrimPrefix(ce.Link, "http://clearance.test/v1/clearances/") || ce.Link == "" {
					t.Fatalf("no link to the change: %q", err.Error())
				}
			} else if ce.Link != "" {
				t.Fatalf("a link without a change: %s", ce.Link)
			}
		})
	}
	// The denial's reason stays in the detail.
	e := newEnv(t)
	e.core.answer = &client.Change{ID: "ch-x", State: "denied", Tier: 3, DenyReason: &reason}
	if _, _, err := e.generate(t); !strings.Contains(err.Error(), reason) {
		t.Fatal(err)
	}
}

func TestChangeLink(t *testing.T) {
	cfg := Config{CoreURL: "https://core.example.test/"}
	if got := ChangeLink(cfg, "ch-1"); got != "https://core.example.test/v1/clearances/ch-1" {
		t.Fatal(got)
	}
	cfg.LinkBase = "https://ui.example.test"
	if got := ChangeLink(cfg, "ch-1"); got != "https://ui.example.test/changes/ch-1" {
		t.Fatal(got)
	}
	for _, id := range []string{"", "a/b", "a b", "x?y", strings.Repeat("a", 129)} {
		if got := ChangeLink(cfg, id); got != "" {
			t.Errorf("%q linked as %s", id, got)
		}
	}
}

// Every code is in the install guide's table, with its class, and every code in the guide is one the plugin has.
func TestEveryErrorCodeIsDocumented(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "install-argocd-plugin.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for code, class := range Codes {
		if !strings.HasPrefix(code, "CMP-"+map[ErrClass]string{ClassFault: "FAULT", ClassDep: "DEP", ClassRender: "RENDER", ClassRefusal: "REFUSED"}[class]+"-") {
			t.Errorf("%s: the prefix does not name its class %s", code, class)
		}
		row := regexp.MustCompile("(?m)^\\| `" + regexp.QuoteMeta(code) + "` \\| " + string(class) + " \\|")
		if !row.MatchString(doc) {
			t.Errorf("%s (%s) has no row in the guide's error codes table", code, class)
		}
	}
	for _, m := range regexp.MustCompile("`(CMP-[A-Z-]+)`").FindAllStringSubmatch(doc, -1) {
		if _, ok := Codes[m[1]]; !ok {
			t.Errorf("the guide names %s, which the plugin does not have", m[1])
		}
	}
}
