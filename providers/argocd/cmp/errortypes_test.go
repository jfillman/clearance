package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/argosrc"
)

// recordUnclassified makes classification's last resort visible: every error that reaches it is recorded, with how.
func recordUnclassified(t *testing.T) *[]string {
	t.Helper()
	var got []string
	old := unclassifiedLog
	unclassifiedLog = func(how, msg string) { got = append(got, how+": "+msg) }
	t.Cleanup(func() { unclassifiedLog = old })
	return &got
}

// Every error path that fails a render is classified by the type it was made with, not by its message's first words
// and not by the fallback (I-76). Each case drives a real producer through Generate, and asserts the code the
// message-matching code gave it before types, so no code changed.
func TestEveryRenderFailureCarriesAnExplicitClass(t *testing.T) {
	failRun := func(err error) func(*env) {
		return func(e *env) {
			e.d.Run = func(context.Context, string, []string, string, ...string) ([]byte, error) { return nil, err }
		}
	}
	generic := func(sources string) func(*env) {
		return func(e *env) {
			e.cfg.ChartRepo, e.cfg.ChartRev, e.cfg.ChartPath, e.cfg.ValueFiles = "", "", "", nil
			e.cfg.Sources = sources
		}
	}
	const repo = "https://github.com/jfillman/airframe.git"
	one := `[{"repoURL":"` + repo + `","targetRevision":"v1.0.0","path":"x"}]`
	cases := []struct {
		name  string
		setup func(e *env)
		code  string
	}{
		{"repository not allowed (Canonical)", func(e *env) { e.cfg.AllowedRepos = []string{"https://git.example.test/other.git"} }, CodeRenderRefused},
		{"no allow list (Canonical)", func(e *env) { e.cfg.AllowedRepos = nil }, CodeFaultConfig},
		{"repository is not a remote (Canonical)", func(e *env) { e.cfg.ChartRepo = "/etc" }, CodeRenderRefused},
		{"listed as OCI but is not (Canonical)", func(e *env) {
			e.cfg.AllowedRepos = []string{"oci://" + strings.TrimPrefix(repo, "https://")}
		}, CodeRenderRefused},
		{"helm template fails", func(e *env) { e.exec.fail = map[string]error{"helm": errors.New("exit status 1")} }, CodeRenderHelm},
		{"kustomize build fails", func(e *env) {
			e.cfg.KustomizeDir = "k"
			writeFile(t, filepath.Join(e.src, "k/kustomization.yaml"), "resources: []\n")
			e.exec.fail = map[string]error{"kustomize": errors.New("exit status 1")}
		}, CodeRenderKustomize},
		{"chart fetch fails, no lookup", func(e *env) { e.exec.fail = map[string]error{"git": errors.New("exit status 128")} }, CodeRenderFetch},
		{"value file leaves the repository", func(e *env) {
			if err := os.Symlink(outsideFile(t), filepath.Join(e.src, "leak.yaml")); err != nil {
				t.Fatal(err)
			}
			e.cfg.ValueFiles = []string{"leak.yaml"}
		}, CodeRenderRefused},
		{"generic: a source's fetch fails", func(e *env) { generic(one)(e); failRun(errors.New("exit status 128"))(e) }, CodeRenderSources},
		{"generic: two sources share a ref", func(e *env) {
			generic(`[{"repoURL":"` + repo + `","targetRevision":"v1.0.0","ref":"a"},{"repoURL":"` + repo + `","targetRevision":"v1.0.0","ref":"a"}]`)(e)
		}, CodeRenderSources},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := recordUnclassified(t)
			e := newEnv(t)
			c.setup(e)
			_, _, err := e.generate(t)
			ce := wantCode(t, err, c.code)
			if ce.Class != Codes[c.code] {
				t.Fatalf("class %s for %s", ce.Class, c.code)
			}
			if len(*got) != 0 {
				t.Fatalf("classified by its message or by the fallback: %v", *got)
			}
		})
	}
}

// The errors argosrc makes about the sources are typed at the source, so classifyRender needs no message to place them.
func TestArgosrcSourceErrorsAreTyped(t *testing.T) {
	got := recordUnclassified(t)
	run := func(context.Context, string, []string, string, ...string) ([]byte, error) {
		return nil, errors.New("x")
	}
	_, parseErr := argosrc.ParseSources("")
	_, unknownErr := argosrc.ParseSources(`[{"nope":1}]`)
	_, noName := argosrc.Render(context.Background(), argosrc.Options{Run: run, Work: t.TempDir()}, argosrc.Request{Sources: []argosrc.Source{{RepoURL: "x"}}})
	_, noSource := argosrc.Render(context.Background(), argosrc.Options{Run: run, Work: t.TempDir()}, argosrc.Request{AppName: "a"})
	for name, err := range map[string]error{"empty": parseErr, "unsupported": unknownErr, "no name": noName, "no source": noSource} {
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if ce := classifyRender(context.Background(), err, lookupNotAsked, true); ce.Code != CodeRenderSources {
			t.Errorf("%s: %s", name, ce.Code)
		}
	}
	if len(*got) != 0 {
		t.Fatalf("classified by its message or by the fallback: %v", *got)
	}
}

// The fallback still works: an error with no type and no known prefix is a plugin fault, CMP-FAULT-INTERNAL (and so
// may fall back to the last-known-good render), and its message is logged. A known prefix is still placed, and logged.
func TestTheFallbackStillClassifiesAndLogs(t *testing.T) {
	got := recordUnclassified(t)
	ce := classifyRender(context.Background(), errors.New("something nobody classified"), lookupResolved, false)
	if ce.Code != CodeFaultInternal || ce.Class != ClassFault || !ce.FallsBack() {
		t.Fatalf("%+v", ce)
	}
	if len(*got) != 1 || !strings.Contains((*got)[0], "fallback") || !strings.Contains((*got)[0], "something nobody classified") {
		t.Fatalf("no debug line naming the message: %v", *got)
	}
	*got = nil
	ce = classifyRender(context.Background(), errors.New("helm template: untyped"), lookupResolved, false)
	if ce.Code != CodeRenderHelm || len(*got) != 1 || !strings.Contains((*got)[0], "message prefix") {
		t.Fatalf("%s %v", ce.Code, *got)
	}
	// A typed error does not log, whatever its message says.
	*got = nil
	ce = classifyRender(context.Background(), renderErrf(kindHelm, "words that match nothing: %w", errors.New("x")), lookupResolved, false)
	if ce.Code != CodeRenderHelm || len(*got) != 0 {
		t.Fatalf("%s %v", ce.Code, *got)
	}
}

// No render-phase error is made with a bare fmt.Errorf or errors.New whose message starts with the words
// classifyRenderByMessage once matched: such an error would reach the last resort and, reworded, the fallback. New
// ones are made with renderErrf (the plugin) or srcErrorf and sourcesErr (argosrc).
func TestNoRenderErrorIsMadeUntypedWithAMatchedPrefix(t *testing.T) {
	check := func(dir string, prefixes ...string) {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		if len(files) == 0 {
			t.Fatalf("no sources in %s", dir)
		}
		fset := token.NewFileSet()
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			typed := map[ast.Node]bool{} // errors made inside sourcesErr(...) or renderErr(...)
			ast.Inspect(file, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "sourcesErr" || id.Name == "renderErr") {
						for _, a := range call.Args {
							typed[a] = true
						}
					}
				}
				return true
			})
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 || typed[call] {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || !(pkg.Name == "fmt" && sel.Sel.Name == "Errorf" || pkg.Name == "errors" && sel.Sel.Name == "New") {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				msg, _ := strconv.Unquote(lit.Value)
				for _, p := range prefixes {
					if strings.HasPrefix(msg, p) {
						t.Errorf("%s: an untyped error that starts %q: %s", fset.Position(call.Pos()), p, msg)
					}
				}
				return true
			})
		}
	}
	check(".", "refused:", "helm template:", "kustomize build:", "fetch the chart at", "peel the chart tag", "the chart tag ")
	check("../../../internal/argosrc", "source %d", "the sources", "the render ", "the Application")
}
