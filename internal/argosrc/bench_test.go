package argosrc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Source resolution, for the regression check in CI (the cmp-bench job in .github/workflows/cmp.yaml; docs/gate.md,
// "Benchmarks"). The runner is a fake: `git checkout` writes a fixture tree into the checkout and helm and kustomize
// answer a fixed document, so there is no network and no tool process, and what is timed is argosrc's own work (the
// source's type, the value files, the checks of the paths and symlinks, the arguments, the duplicate-object check).

const benchSHA = "cccccccccccccccccccccccccccccccccccccccc"

const benchDoc = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: bench\ndata:\n  a: b\n"

// benchRunner answers git, helm and kustomize for the fixture trees below.
func benchRunner(tree map[string]string) Runner {
	return func(_ context.Context, dir string, _ []string, name string, args ...string) ([]byte, error) {
		switch name {
		case "git":
			for _, a := range args {
				switch a {
				case "checkout":
					for rel, body := range tree {
						p := filepath.Join(dir, filepath.FromSlash(rel))
						if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
							return nil, err
						}
						if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
							return nil, err
						}
					}
					return nil, nil
				case "rev-parse":
					return []byte(benchSHA + "\n"), nil
				}
			}
			return nil, nil
		case "helm", "kustomize":
			return []byte(benchDoc), nil
		}
		return nil, errors.New("unexpected " + name)
	}
}

func benchRender(b *testing.B, tree map[string]string, req Request) {
	b.Helper()
	run := benchRunner(tree)
	work := b.TempDir()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		o := Options{Run: run, Work: filepath.Join(work, "w"), AllowLocalRepos: false}
		os.RemoveAll(o.Work)
		if err := os.MkdirAll(o.Work, 0o755); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		res, err := Render(context.Background(), o, req)
		if err != nil || len(res.Manifests) == 0 {
			b.Fatal(err)
		}
	}
}

// BenchmarkRenderHelmSource is a Helm source from a git path with two value files, parameters and inline values.
func BenchmarkRenderHelmSource(b *testing.B) {
	benchRender(b, map[string]string{
		"chart/Chart.yaml": chartYAML, "chart/values.yaml": "color: red\n", "chart/templates/cm.yaml": cmTemplate,
		"env/dev.yaml": "color: blue\n", "env/dev2.yaml": "size: l\n",
	}, Request{AppName: "demo", Namespace: "ns", KubeVersion: "1.34.2", APIVersions: []string{"v1", "apps/v1"},
		Sources: []Source{{RepoURL: "https://git.example.test/acme/charts.git", TargetRevision: "main", Path: "chart", Helm: &Helm{
			ValueFiles: []string{"../env/dev.yaml", "../env/dev2.yaml"}, Parameters: []HelmParameter{{Name: "extra", Value: "$ARGOCD_APP_NAME"}},
			Values: "list: [a, b]\n"}}}})
}

// BenchmarkRenderKustomizeSource is a Kustomize source with a name prefix, images, labels, a namespace and replicas:
// each is a `kustomize edit` step, then the build.
func BenchmarkRenderKustomizeSource(b *testing.B) {
	benchRender(b, map[string]string{
		"app/kustomization.yaml": "resources:\n- deploy.yaml\n", "app/deploy.yaml": benchDoc,
	}, Request{AppName: "k", Namespace: "ns", Sources: []Source{{RepoURL: "https://git.example.test/acme/gitops.git", TargetRevision: "main", Path: "app", Kustomize: &Kustomize{
		NamePrefix: "dev-", NameSuffix: "-x", Images: []string{"nginx=registry.example.test/nginx:$ARGOCD_APP_NAME"},
		CommonLabels: map[string]string{"env": "dev"}, CommonAnnotations: map[string]string{"note": "n"},
		Namespace: "kns", Replicas: []KustomizeRep{{Name: "dev-web-x", Count: []byte(`"3"`)}},
	}}}})
}

// BenchmarkRenderDirectorySource is a plain directory of manifests.
func BenchmarkRenderDirectorySource(b *testing.B) {
	tree := map[string]string{}
	for _, n := range []string{"a", "b", "c", "d"} {
		tree["manifests/"+n+".yaml"] = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + n + "\ndata:\n  a: b\n"
	}
	benchRender(b, tree, Request{AppName: "d", Namespace: "ns", Sources: []Source{{RepoURL: "https://git.example.test/acme/gitops.git", TargetRevision: "main", Path: "manifests"}}})
}

// BenchmarkParseSources is the generic mode's sources parameter read.
func BenchmarkParseSources(b *testing.B) {
	raw := `[{"repoURL":"https://git.example.test/acme/charts.git","path":"chart","targetRevision":"v1.0.0","helm":{"valueFiles":["$gitops/prod/values.yaml"],"ignoreMissingValueFiles":true,"valuesObject":{"a":1,"b":{"c":[1,2,3]}}}},{"repoURL":"https://git.example.test/acme/gitops.git","targetRevision":"main","ref":"gitops"}]`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseSources(raw); err != nil {
			b.Fatal(err)
		}
	}
}
