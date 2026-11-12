package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/client"
)

// genericRun answers git and helm for the generic mode the way the real tools would for gate-api's sources: the
// airframe chart (a git path) with the gitops repository as a `$gitops` ref source, rendering the recorded output.
type genericRun struct {
	t      *testing.T
	calls  [][]string
	repoOf map[string]string // checkout dir -> repository
	render []byte
	each   func(n int) []byte // when set, the n'th helm render (0-based) instead of render
	helms  int
}

const (
	airframeURL = "https://github.com/jfillman/airframe.git"
	gitopsURL   = "https://github.com/jfillman/gitops-gate-api.git"
	shaAirframe = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaGitops   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func (g *genericRun) run(_ context.Context, dir string, _ []string, name string, args ...string) ([]byte, error) {
	g.calls = append(g.calls, append([]string{name}, args...))
	switch name {
	case "git":
		for i, a := range args {
			switch a {
			case "fetch":
				repo := args[len(args)-2]
				g.repoOf[dir] = repo
				switch repo {
				case airframeURL:
					os.MkdirAll(filepath.Join(dir, "charts/airframe-application/templates"), 0o755)
					os.WriteFile(filepath.Join(dir, "charts/airframe-application/Chart.yaml"), []byte("apiVersion: v2\nname: airframe-application\nversion: 0.3.168\n"), 0o644)
				case gitopsURL:
					for _, f := range []string{"prod/values.yaml", "prod/release.yaml"} {
						b, err := os.ReadFile(filepath.Join(parity, "hangar-prod", f))
						if err != nil {
							g.t.Fatal(err)
						}
						os.MkdirAll(filepath.Join(dir, "hangar-prod", filepath.Dir(f)), 0o755)
						os.WriteFile(filepath.Join(dir, "hangar-prod", f), b, 0o644)
					}
				}
				return nil, nil
			case "rev-parse":
				if g.repoOf[dir] == airframeURL {
					return []byte(shaAirframe + "\n"), nil
				}
				return []byte(shaGitops + "\n"), nil
			case "init", "checkout":
				return nil, nil
			default:
				_ = i
			}
		}
	case "helm":
		g.helms++
		if g.each != nil {
			return g.each(g.helms - 1), nil
		}
		return g.render, nil
	}
	return nil, errors.New("unexpected " + name)
}

func genericConfig(t *testing.T) Config {
	injected := read(t, "injected.json")
	var vals any
	if err := json.Unmarshal(injected, &vals); err != nil {
		t.Fatal(err)
	}
	srcs, _ := json.Marshal([]map[string]any{
		{"repoURL": airframeURL, "path": "charts/airframe-application", "targetRevision": "v0.3.168", "helm": map[string]any{
			"valueFiles":              []string{"$gitops/hangar-prod/prod/values.yaml", "$gitops/hangar-prod/prod/release.yaml", "$gitops/hangar-prod/absent.yaml"},
			"ignoreMissingValueFiles": true, "valuesObject": vals}},
		{"repoURL": gitopsURL, "targetRevision": "main", "ref": "gitops"},
	})
	c := gateAPIConfig()
	c.ChartRepo, c.ChartRev, c.ChartPath, c.ValueFiles = "", "", "", nil
	c.Sources = string(srcs)
	c.KubeVersion, c.APIVersions = "1.34.2", []string{"v1", "apps/v1"}
	return c
}

// The generic mode, given gate-api's original sources, renders the same tree the Airframe-chart parameters do, with
// the release name, the namespace, the cluster's facts and the value files in the order Argo CD gives Helm.
func TestGenericModeRendersTheSameTreeAsTheChartParameters(t *testing.T) {
	want := tekton(t, "tekton.json")
	g := &genericRun{t: t, repoOf: map[string]string{}, render: read(t, "head.yaml")}
	e := newEnv(t)
	e.d.Run = g.run
	e.cfg = genericConfig(t)
	e.core.answer = &client.Change{ID: "ch-gen", State: "cleared", Tier: 1, Outage: "allow-and-record", ExpiresAt: e.now.Add(3600e9).Format("2006-01-02T15:04:05.999999999Z07:00")}
	o, objs, err := e.generate(t)
	if err != nil || o != Cleared {
		t.Fatal(o, err)
	}
	if got := e.core.reqs[0].TreeDigest; got != want.Tree {
		t.Fatalf("tree %s, the chart-parameter path and Tekton's render give %s", got, want.Tree)
	}
	if len(objs) != len(want.Objects) {
		t.Fatalf("%d objects", len(objs))
	}
	var helm []string
	for _, c := range g.calls {
		if c[0] == "helm" {
			helm = c
		}
	}
	line := strings.Join(helm, " ")
	for _, w := range []string{"template . --name-template gate-api-prod --namespace app-gate-api-prod --kube-version 1.34.2", "--include-crds",
		"--api-versions v1 --api-versions apps/v1"} {
		if !strings.Contains(line, w) {
			t.Fatalf("helm was run as %s", line)
		}
	}
	var vals []string
	for i, a := range helm {
		if a == "--values" {
			vals = append(vals, filepath.Base(helm[i+1]))
		}
	}
	if len(vals) != 3 || vals[0] != "values.yaml" || vals[1] != "release.yaml" || !strings.HasPrefix(vals[2], "values-") {
		t.Fatalf("values files %v", vals)
	}
	if !strings.Contains(e.err.String(), "source 1 Helm") || !strings.Contains(e.err.String(), shaAirframe[:19]) {
		t.Fatalf("the sources the render resolved to are logged: %s", e.err.String())
	}
}

// Something the generic mode cannot reproduce is a refusal, not a render of something else.
func TestGenericModeRefusesWhatItCannotReproduce(t *testing.T) {
	g := &genericRun{t: t, repoOf: map[string]string{}, render: read(t, "head.yaml")}
	e := newEnv(t)
	e.d.Run = g.run
	e.cfg = genericConfig(t)
	e.cfg.Sources = `[{"repoURL":"https://example.test/x.git","path":".","plugin":{"name":"other"}}]`
	o, objs, err := e.generate(t)
	if err == nil || o != "" || len(objs) != 0 || !strings.Contains(err.Error(), "another config management plugin") || len(e.core.reqs) != 0 {
		t.Fatalf("%q %v %v, %d registrations", o, objs, err, len(e.core.reqs))
	}
}

func TestParseConfigGenericMode(t *testing.T) {
	base := map[string]string{"ARGOCD_APP_NAME": "a-dev", "ARGOCD_APP_NAMESPACE": "ns", "ARGOCD_APP_REVISION": mergeSHA, "ARGOCD_APP_PROJECT_NAME": "proj",
		"ARGOCD_APP_SOURCE_REPO_URL": "https://github.com/o/r.git", "PARAM_APP": "a", "PARAM_ENV": "dev", "PARAM_CLUSTER": "c", "CLEARANCE_URL": "http://clearance.test",
		"PARAM_SOURCES": `[{"repoURL":"x"}]`, "KUBE_VERSION": "1.34.2", "KUBE_API_VERSIONS": "v1, apps/v1,,example.test/v1/Foo"}
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := ParseConfig(get(base))
	if err != nil || c.Sources == "" || c.Project != "proj" || c.KubeVersion != "1.34.2" || strings.Join(c.APIVersions, "|") != "v1|apps/v1|example.test/v1/Foo" {
		t.Fatal(c, err)
	}
	// Both modes at once is a configuration error: the plugin would have to pick, and a wrong pick renders a different tree.
	for _, k := range []string{"PARAM_CHARTREPO", "PARAM_CHARTPATH", "PARAM_VALUEFILES", "PARAM_VALUESJSON", "PARAM_KUSTOMIZEDIR"} {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		m[k] = "x"
		if _, err := ParseConfig(get(m)); err == nil || !strings.Contains(err.Error(), "PARAM_SOURCES") {
			t.Errorf("%s with PARAM_SOURCES: %v", k, err)
		}
	}
}

func TestClusterScopedKindsParameterCorrectsTheBuiltInGuess(t *testing.T) {
	// CloudNativePG's Cluster is namespaced though it is named Cluster*; Crossplane's Composition is cluster-scoped
	// though the built-in list has never heard of it.
	render := []byte("apiVersion: postgresql.cnpg.io/v1\nkind: Cluster\nmetadata: {name: pg}\n---\napiVersion: apiextensions.crossplane.io/v1\nkind: Composition\nmetadata: {name: c}\n")
	plain, err := Canonicalize(render, "dest", nil)
	if err != nil {
		t.Fatal(err)
	}
	fixed, err := Canonicalize(render, "dest", []string{"!Cluster", "Composition"})
	if err != nil {
		t.Fatal(err)
	}
	ns := func(tr *Tree, kind string) string {
		for k := range tr.Hashes {
			if k[1] == kind {
				return k[2]
			}
		}
		return "?"
	}
	if ns(plain, "Cluster") != "" || ns(plain, "Composition") != "dest" || ns(fixed, "Cluster") != "dest" || ns(fixed, "Composition") != "" {
		t.Fatalf("plain %q %q, fixed %q %q", ns(plain, "Cluster"), ns(plain, "Composition"), ns(fixed, "Cluster"), ns(fixed, "Composition"))
	}
	c, err := ParseConfig(func(k string) string {
		return map[string]string{"ARGOCD_APP_NAME": "a", "ARGOCD_APP_NAMESPACE": "n", "PARAM_APP": "a", "PARAM_ENV": "e", "PARAM_CLUSTER": "c", "CLEARANCE_URL": "http://clearance.test",
			"PARAM_CLUSTERSCOPEDKINDS": "Composition, !Cluster"}[k]
	})
	if err != nil || strings.Join(c.ExtraCluster, "|") != "Composition|!Cluster" {
		t.Fatal(c.ExtraCluster, err)
	}
}
