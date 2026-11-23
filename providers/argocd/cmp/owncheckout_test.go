package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/client"
	"github.com/jfillman/clearance/internal/argosrc"
)

// An Application switched to the plugin in sources mode whose own gitops repository is private (I-83): the sidecar
// holds no credential, so that repository must come from the checkout Argo CD hands the plugin.
const (
	privGitops  = "https://git.example.invalid/acme/gitops-private.git"
	pubChart    = "https://charts.example.invalid/acme/platform.git"
	pubChartSHA = "dddddddddddddddddddddddddddddddddddddddd"
)

// ownRun is git and helm for these sources: the chart repository fetches, the private one does not, and helm records
// the value files it was given.
type ownRun struct {
	t       *testing.T
	fetched []string
	values  []string // the contents of each --values file, in order
	render  []byte
}

func (g *ownRun) run(_ context.Context, dir string, _ []string, name string, args ...string) ([]byte, error) {
	switch name {
	case "git":
		switch {
		case indexOf2(args, "fetch") >= 0:
			repo := args[len(args)-2]
			g.fetched = append(g.fetched, repo)
			if repo != pubChart {
				return nil, errors.New("exit status 128: fatal: could not read Username for 'https://git.example.invalid': terminal prompts disabled")
			}
			os.MkdirAll(filepath.Join(dir, "chart/templates"), 0o755)
			os.WriteFile(filepath.Join(dir, "chart/Chart.yaml"), []byte("apiVersion: v2\nname: platform\nversion: 1.0.0\n"), 0o644)
			return nil, nil
		case indexOf2(args, "rev-parse") >= 0:
			return []byte(pubChartSHA + "\n"), nil
		}
		return nil, nil
	case "helm":
		for i, a := range args {
			if a == "--values" {
				b, err := os.ReadFile(args[i+1])
				if err != nil {
					g.t.Fatalf("helm was given %s: %v", args[i+1], err)
				}
				g.values = append(g.values, string(b))
			}
		}
		return g.render, nil
	}
	return nil, errors.New("unexpected " + name)
}

// ownEnv is a generic-mode run of an Application whose carrier is privGitops at main, at path carrierPath, with its
// files in the checkout Argo CD handed the plugin. refRev is the $appsrc ref source's targetRevision.
func ownEnv(t *testing.T, carrierPath, refRev string) (*env, *ownRun) {
	t.Helper()
	g := &ownRun{t: t, render: read(t, "head.yaml")}
	e := newEnv(t)
	e.d.Run = g.run
	root := e.src
	for f, v := range map[string]string{"hangar-prod/base.yaml": "a: base\n", "hangar-prod/prod/values.yaml": "a: prod\n", "apps/x/keep": ""} {
		p := filepath.Join(root, filepath.FromSlash(f))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(v), 0o644)
	}
	if carrierPath != "." {
		e.src = filepath.Join(root, filepath.FromSlash(carrierPath)) // Argo CD runs the plugin in the carrier's path
	}
	srcs := `[{"repoURL":"` + privGitops + `","targetRevision":"` + refRev + `","path":".","ref":"appsrc","directory":{"exclude":"*"}},` +
		`{"repoURL":"` + pubChart + `","targetRevision":"v1.0.0","path":"chart","helm":{"ignoreMissingValueFiles":true,` +
		`"valueFiles":["$appsrc/hangar-prod/base.yaml","$appsrc/hangar-prod/prod/values.yaml","$appsrc/hangar-prod/absent.yaml"]}}]`
	c := gateAPIConfig()
	c.ChartRepo, c.ChartRev, c.ChartPath, c.ValueFiles, c.ValuesJSON = "", "", "", nil, ""
	c.Sources = srcs
	// Argo CD spells the carrier's repository its own way; it is the same repository.
	c.SourceRepo, c.SourcePath, c.SourceRev = "https://GIT.example.invalid/acme/gitops-private", carrierPath, "main"
	c.AllowedRepos = []string{pubChart}
	e.cfg = c
	e.core.answer = &client.Change{ID: "ch-own", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(3600e9).Format("2006-01-02T15:04:05.999999999Z07:00")}
	return e, g
}

func TestThePrivateOwnRepositoryRendersFromArgoCDsCheckout(t *testing.T) {
	for _, carrierPath := range []string{".", "apps/x"} {
		t.Run(carrierPath, func(t *testing.T) {
			e, g := ownEnv(t, carrierPath, "main")
			o, objs, err := e.generate(t)
			if err != nil || o != Cleared || len(objs) == 0 {
				t.Fatalf("%q %d objects: %v", o, len(objs), err)
			}
			if len(g.fetched) != 1 || g.fetched[0] != pubChart {
				t.Fatalf("fetched %v, want only the chart's repository", g.fetched)
			}
			// $appsrc resolved against the checkout, in order, the absent one dropped
			if strings.Join(g.values, "|") != "a: base\n|a: prod\n" {
				t.Fatalf("helm got values %q", g.values)
			}
			if !strings.Contains(e.err.String(), "source 1 Directory") || !strings.Contains(e.err.String(), "(Argo CD's checkout)") {
				t.Fatalf("stderr %s", e.err.String())
			}
		})
	}
}

// The ref source at another revision than the carrier's is fetched, as before, and fails as before on a private
// repository: Argo CD's checkout is of the carrier's revision, not that one.
func TestTheOwnRepositoryAtAnotherRevisionIsStillFetched(t *testing.T) {
	e, g := ownEnv(t, ".", "release-1")
	o, _, err := e.generate(t)
	var ce *CmpError
	if err == nil || o != "" || !errors.As(err, &ce) || ce.Code != CodeRenderSources || !strings.Contains(err.Error(), "could not read Username") {
		t.Fatalf("%q %v", o, err)
	}
	if len(g.fetched) != 1 || !strings.Contains(g.fetched[0], "gitops-private") || len(e.core.reqs) != 0 {
		t.Fatalf("fetched %v, %d registrations", g.fetched, len(e.core.reqs))
	}
}

func TestOwnCheckouts(t *testing.T) {
	cfg := Config{SourceRepo: "https://Git.Example.invalid/acme/gitops/", SourcePath: "apps/x", SourceRev: "main", Revision: mergeSHA}
	srcs := []argosrc.Source{{RepoURL: "https://git.example.invalid/acme/gitops.git"}, {RepoURL: "https://git.example.invalid/acme/gitops.git"},
		{RepoURL: "https://git.example.invalid/acme/other.git"}, {RepoURL: "git.example.invalid/acme/gitops", Chart: "c"},
		{RepoURL: "ssh://git@git.example.invalid/acme/gitops.git"}}
	got := ownCheckouts(cfg, srcs, "/w/repo/apps/x")
	if len(got) != 1 || got[0].RepoURL != srcs[0].RepoURL || got[0].Dir != "/w/repo" || got[0].Commit != mergeSHA || got[0].TargetRevision != "main" {
		t.Fatalf("%+v", got)
	}
	for name, c := range map[string]Config{
		"a branch, not a commit": {SourceRepo: cfg.SourceRepo, SourcePath: "apps/x", Revision: "main"},
		"no source repository":   {SourcePath: "apps/x", Revision: mergeSHA},
		"another path":           {SourceRepo: cfg.SourceRepo, SourcePath: "apps/y", Revision: mergeSHA},
	} {
		if got := ownCheckouts(c, srcs, "/w/repo/apps/x"); got != nil {
			t.Errorf("%s: %+v", name, got)
		}
	}
	for _, c := range []struct{ dir, path, root string }{
		{"/w/r", "", "/w/r"}, {"/w/r", ".", "/w/r"}, {"/w/r/a/b", "a/b", "/w/r"}, {"/w/r/a/b", "./a/b/", "/w/r"}, {"/w/r/a/b", "/a/b", "/w/r"},
		{"/w/r/a/b", "x/b", ""}, {"/w/r/a", "../a", ""}, {"rel/a", "a", ""}, {"", ".", ""},
	} {
		root, ok := carrierRoot(c.dir, c.path)
		if root != c.root || ok != (c.root != "") {
			t.Errorf("carrierRoot(%q, %q) = %q %v, want %q", c.dir, c.path, root, ok, c.root)
		}
	}
}
