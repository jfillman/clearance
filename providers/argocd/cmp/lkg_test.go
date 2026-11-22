package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/client"
)

// lkgEnv is cachedEnv with last-known-good on and the pre-render cache off, so a second run renders in full and a
// fault in it is what the test injects.
func lkgEnv(t *testing.T) *env {
	t.Helper()
	e := cachedEnv(t)
	e.cfg.LKG = true
	e.cfg.RenderCacheTTL = 0
	return e
}

// toolMissing is helm that cannot be started: a plugin fault.
var toolMissing = &exec.Error{Name: "helm", Err: exec.ErrNotFound}

// run is one Generate, its output, error and stderr.
func (e *env) run(t *testing.T) (string, error) {
	t.Helper()
	var out bytes.Buffer
	e.err.Reset()
	_, err := Generate(context.Background(), e.d, e.cfg, e.src, &out)
	if err != nil && out.Len() != 0 {
		t.Fatalf("an error with output: %v", err)
	}
	return out.String(), err
}

func wantCode(t *testing.T, err error, code string) *CmpError {
	t.Helper()
	ce, ok := asCmp(err)
	if !ok || ce.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	return ce
}

func TestLastKnownGoodServesAFaultForTheSameInputs(t *testing.T) {
	for name, after := range map[string]time.Duration{
		"within the tree cache's lifetime (no core call)": time.Minute,
		"after it (the core confirms the same change)":    10 * time.Minute,
	} {
		t.Run(name, func(t *testing.T) {
			e := lkgEnv(t)
			first := e.gen(t)
			calls := len(e.core.reqs)
			e.now = e.now.Add(after)
			e.exec.fail = map[string]error{"helm": toolMissing}
			out, err := e.run(t)
			if err != nil || out != first {
				t.Fatalf("a fault for unchanged inputs was not served the last-known-good: %v", err)
			}
			if !strings.Contains(e.err.String(), "LAST-KNOWN-GOOD served") || !strings.Contains(e.err.String(), CodeFaultTool) || !strings.Contains(e.err.String(), "lkg-serves=1") {
				t.Fatalf("the serve is not logged with its code and count:\n%s", e.err.String())
			}
			if n := e.d.Cache.LKGServes(); n != 1 {
				t.Fatalf("counted %d serves", n)
			}
			wantCalls := calls
			if after > e.cfg.CacheTTL {
				wantCalls++
			}
			if len(e.core.reqs) != wantCalls {
				t.Fatalf("%d core calls, want %d", len(e.core.reqs), wantCalls)
			}
			// A second fault is counted again.
			if _, err := e.run(t); err != nil || e.d.Cache.LKGServes() != 2 {
				t.Fatalf("%v, %d", err, e.d.Cache.LKGServes())
			}
		})
	}
}

func TestLastKnownGoodServesAPanic(t *testing.T) {
	e := lkgEnv(t)
	first := e.gen(t)
	inner := e.d.Exec
	e.d.Exec = func(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
		if name == "helm" {
			panic("a plugin bug")
		}
		return inner(ctx, dir, name, args...)
	}
	out, err := e.run(t)
	if err != nil || out != first || !strings.Contains(e.err.String(), CodeFaultPanic) {
		t.Fatalf("%v\n%s", err, e.err.String())
	}
	// Off, the same panic is a fault with its code, not a crash.
	e.cfg.LKG = false
	if _, err := e.run(t); err == nil {
		t.Fatal("served with last-known-good off")
	} else {
		wantCode(t, err, CodeFaultPanic)
	}
}

func TestLastKnownGoodMissesFailClosed(t *testing.T) {
	for name, change := range map[string]func(e *env){
		"a new gitops revision": func(e *env) { e.cfg.Revision = "1123456789abcdef0123456789abcdef01234567" },
		"a changed parameter":   func(e *env) { e.cfg.ValuesJSON = `{"x":1}` },
		"a changed value file":  func(e *env) { e.cfg.ValueFiles = append(e.cfg.ValueFiles, "more.yaml") },
		"a moved chart tag":     func(e *env) { e.exec.head = chartSHA2 },
		"another cluster":       func(e *env) { e.cfg.Cluster = "other-cluster" },
		"a non-commit revision": func(e *env) { e.cfg.Revision = "main" },
		"generic mode": func(e *env) {
			e.cfg.Sources = `[{"repoURL":"https://github.com/jfillman/airframe.git","targetRevision":"v0.3.168","path":"."}]`
			e.cfg.ChartRepo, e.cfg.ChartRev, e.cfg.ChartPath, e.cfg.ValueFiles, e.cfg.ValuesJSON = "", "", "", nil, ""
			e.d.Run = func(context.Context, string, []string, string, ...string) ([]byte, error) { return nil, toolMissing }
		},
		"last-known-good off": func(e *env) { e.cfg.LKG = false },
	} {
		t.Run(name, func(t *testing.T) {
			e := lkgEnv(t)
			e.gen(t)
			change(e)
			e.exec.fail = map[string]error{"helm": toolMissing}
			out, err := e.run(t)
			if err == nil || out != "" {
				t.Fatalf("%s was served the last-known-good", name)
			}
			if ce, ok := asCmp(err); !ok || ce.Class == ClassRefusal || ce.Class == ClassRender && name != "generic mode" {
				t.Fatalf("the error is not the fault: %v", err)
			}
			if e.d.Cache.LKGServes() != 0 {
				t.Fatal("a miss was counted as a serve")
			}
		})
	}
}

func TestOnlyAFaultOrAnUnavailableDependencyFallsBack(t *testing.T) {
	cases := []struct {
		name   string
		inject func(e *env)
		code   string
		serves bool
	}{
		{"a tool that cannot start (fault)", func(e *env) { e.exec.fail = map[string]error{"helm": toolMissing} }, CodeFaultTool, true},
		{"helm says no (render error)", func(e *env) {
			e.exec.fail = map[string]error{"helm": errors.New("exit status 1: Error: template: nope")}
		}, CodeRenderHelm, false},
		{"kustomize says no (render error)", func(e *env) {
			e.cfg.KustomizeDir = "configmap"
			os.MkdirAll(filepath.Join(e.src, "configmap"), 0o755)
			e.exec.fail = map[string]error{"kustomize": errors.New("exit status 1: accumulating resources")}
		}, CodeRenderKustomize, false},
		{"an empty render (render error)", func(e *env) { e.exec.render = []byte("# nothing\n") }, CodeRenderTree, false},
		{"git cannot reach the chart host (dependency)", func(e *env) {
			e.exec.fail = map[string]error{"git": errors.New("exit status 128: fatal: unable to access: Could not resolve host")}
		}, CodeDepChartUnreachable, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := lkgEnv(t)
			first := e.gen(t)
			if c.code == CodeRenderKustomize { // the first render had no kustomize directory: key the entry with it
				e.cfg.KustomizeDir = "configmap"
				os.MkdirAll(filepath.Join(e.src, "configmap"), 0o755)
				first = e.gen(t)
			}
			c.inject(e)
			out, err := e.run(t)
			if c.serves {
				if err != nil || out != first {
					t.Fatalf("not served: %v", err)
				}
				if !strings.Contains(e.err.String(), c.code) {
					t.Fatalf("the serve does not name %s:\n%s", c.code, e.err.String())
				}
				return
			}
			ce := wantCode(t, err, c.code)
			if ce.FallsBack() || e.d.Cache.LKGServes() != 0 {
				t.Fatalf("a %s fell back", ce.Class)
			}
		})
	}
}

func TestARefusalNeverFallsBackAndDropsTheLastKnownGood(t *testing.T) {
	for _, state := range []string{"denied", "expired", "superseded", "holding"} {
		t.Run(state, func(t *testing.T) {
			e := lkgEnv(t)
			e.gen(t)
			// The decision changes: the next full render is refused (or held).
			e.now = e.now.Add(10 * time.Minute)
			e.core.answer = &client.Change{ID: "ch-abc", State: state, Tier: 3}
			out, err := e.run(t)
			if state == "holding" {
				if err != nil || !strings.Contains(out, "clearance-awaiting-approval") {
					t.Fatalf("%v", err)
				}
			} else {
				ce := wantCode(t, err, stateCode(state))
				if ce.FallsBack() || ce.Link == "" {
					t.Fatalf("%+v", ce)
				}
			}
			// A fault now must not serve what was cleared before the decision.
			e.exec.fail = map[string]error{"helm": toolMissing}
			e.core.answer = &client.Change{ID: "ch-abc", State: "cleared", Tier: 1, ExpiresAt: e.now.Add(time.Hour).Format(time.RFC3339Nano)}
			if out, err := e.run(t); err == nil || out != "" {
				t.Fatal("a fault after a refusal was served the old render")
			}
			if e.d.Cache.LKGServes() != 0 {
				t.Fatal("counted")
			}
		})
	}
}

func TestTheCoreMustConfirmALastKnownGood(t *testing.T) {
	e := lkgEnv(t)
	e.gen(t)
	e.now = e.now.Add(10 * time.Minute) // past the tree cache: the core is asked
	e.exec.fail = map[string]error{"helm": toolMissing}
	e.core.answer = &client.Change{ID: "ch-abc", State: "denied", Tier: 3}
	if out, err := e.run(t); err == nil || out != "" {
		t.Fatal("served a change the core now denies")
	} else {
		wantCode(t, err, CodeFaultTool) // the fault stands; the remembered change was not confirmed
	}
	if !strings.Contains(e.err.String(), "the core did not confirm") {
		t.Fatal(e.err.String())
	}
}

func TestALastKnownGoodDuringACoreOutageFollowsTheOutagePolicy(t *testing.T) {
	for outage, serves := range map[string]bool{"allow-and-record": true, "hold": false} {
		t.Run(outage, func(t *testing.T) {
			e := lkgEnv(t)
			e.core.answer.Outage = outage
			first := e.gen(t)
			e.now = e.now.Add(10 * time.Minute)
			calls := 0
			e.d.Core = unreachable{&calls}
			e.exec.fail = map[string]error{"helm": toolMissing}
			out, err := e.run(t)
			if serves != (err == nil && out == first) {
				t.Fatalf("serves=%v: %v", serves, err)
			}
			if !serves {
				wantCode(t, err, CodeRefusedOutageHold)
			}
		})
	}
}

func TestAnUnreachableChartHostUsesTheCommitLastCleared(t *testing.T) {
	e := lkgEnv(t)
	first := e.gen(t)
	e.exec.fail = map[string]error{"git": errors.New("exit status 128: Could not resolve host")}
	out, err := e.run(t)
	if err != nil || out != first {
		t.Fatalf("%v\n%s", err, e.err.String())
	}
	if !strings.Contains(e.err.String(), "last cleared at, "+chartSHA[:19]) {
		t.Fatal(e.err.String())
	}
	// A pointer that does not hash to its key is ignored.
	tk := lkgTagKey(e.cfg)
	p := filepath.Join(e.d.Cache.Dir, lkgDir, tk+".tag")
	if err := os.WriteFile(p, []byte(strings.Repeat("a", 64)+" "+chartSHA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := e.run(t); err == nil || out != "" {
		t.Fatal("a tampered pointer was followed")
	} else {
		wantCode(t, err, CodeDepChartUnreachable)
	}
}

func TestATagTheRemoteDoesNotHaveIsARenderErrorAndNeverFallsBack(t *testing.T) {
	e := lkgEnv(t)
	e.gen(t)
	inner := e.d.Exec
	e.d.Exec = func(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
		if name == "git" && args[0] == "ls-remote" {
			return nil, nil // the remote answers, without the tag
		}
		if name == "git" && args[0] == "clone" {
			return nil, errors.New("exit status 128: Remote branch v0.3.168 not found")
		}
		return inner(ctx, dir, name, args...)
	}
	_, err := e.run(t)
	if ce := wantCode(t, err, CodeRenderFetch); ce.FallsBack() {
		t.Fatal("falls back")
	}
}

func TestThePreRenderCacheKeepsTheLastKnownGoodFresh(t *testing.T) {
	e := cachedEnv(t)
	e.cfg.LKG = true
	e.gen(t)
	key := lkgKey(func() Config { c := e.cfg; c.chartCommit = chartSHA; c.chartLooked = true; return c }())
	p := e.d.Cache.entryPath(lkgDir, key)
	old := e.now.Add(-48 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("no last-known-good entry: %v", err)
	}
	e.now = e.now.Add(time.Minute)
	e.gen(t) // a pre-render hit
	if st, _ := os.Stat(p); !st.ModTime().After(old) {
		t.Fatal("a pre-render hit did not mark the last-known-good used")
	}
}

func TestTheLastKnownGoodStoreHasItsOwnBounds(t *testing.T) {
	c := Cache{Dir: t.TempDir()}
	for _, sub := range []string{rendersDir, lkgDir} {
		os.MkdirAll(filepath.Join(c.Dir, sub), 0o700)
	}
	for i := 0; i < renderCacheMaxEntries+10; i++ {
		e := renderEntry{Key: fmt.Sprintf("%064d", i), ID: "ch", Tree: "t", App: "a", Env: "e", Cluster: "c", Stream: []byte("x")}
		c.PutRender(e, time.Now())
		c.PutLKG(e, time.Now())
	}
	count := func(sub string) int {
		ents, _ := os.ReadDir(filepath.Join(c.Dir, sub))
		n := 0
		for _, x := range ents {
			if strings.HasSuffix(x.Name(), ".json") {
				n++
			}
		}
		return n
	}
	if count(rendersDir) != renderCacheMaxEntries || count(lkgDir) != renderCacheMaxEntries+10 {
		t.Fatalf("renders %d, lkg %d", count(rendersDir), count(lkgDir))
	}
	c.pruneRenders(filepath.Join(c.Dir, lkgDir), 3, 0)
	if count(lkgDir) != 3 {
		t.Fatalf("lkg %d after pruning to 3", count(lkgDir))
	}
}

func TestParseLKG(t *testing.T) {
	for v, want := range map[string]bool{"": false, "off": false, "on": true, " on ": true} {
		if got, err := ParseLKG(v); err != nil || got != want {
			t.Errorf("%q: %v %v", v, got, err)
		}
	}
	for _, v := range []string{"true", "On", "1", "yes"} {
		if _, err := ParseLKG(v); err == nil || !strings.Contains(err.Error(), LKGEnv) {
			t.Errorf("%q accepted: %v", v, err)
		}
	}
}

func TestAPreRenderHitMovesTheTagPointerBack(t *testing.T) {
	e := cachedEnv(t)
	e.cfg.LKG = true
	e.gen(t) // cleared at chartSHA
	e.exec.head = chartSHA2
	e.gen(t) // the tag moved: cleared at chartSHA2, the pointer names it
	e.exec.head = chartSHA
	e.gen(t) // the tag is back: a pre-render hit at chartSHA
	if _, commit := e.d.Cache.lkgByTag(e.cfg); commit != chartSHA {
		t.Fatalf("the pointer names %s after the hit at %s", commit, chartSHA)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed pipe") }

func TestAWriteFailureWhileServingIsCoded(t *testing.T) {
	e := lkgEnv(t)
	e.gen(t)
	e.exec.fail = map[string]error{"helm": toolMissing}
	o, err := Generate(context.Background(), e.d, e.cfg, e.src, failWriter{})
	if o != "" {
		t.Fatalf("outcome %q", o)
	}
	wantCode(t, err, CodeFaultInternal)
}
