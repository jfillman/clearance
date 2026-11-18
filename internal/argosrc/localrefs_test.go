package argosrc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestChartDependenciesMustBeLocal(t *testing.T) {
	for name, tc := range map[string]struct {
		file, body string
		ok         bool
	}{
		"none":            {"Chart.yaml", "name: a\n", true},
		"vendored":        {"Chart.yaml", "dependencies:\n- name: s\n  repository: ''\n", true},
		"file inside":     {"Chart.yaml", "dependencies:\n- name: s\n  repository: file://../lib\n", true},
		"file outside":    {"Chart.yaml", "dependencies:\n- name: s\n  repository: file://../../../etc\n", false},
		"https":           {"Chart.yaml", "dependencies:\n- name: s\n  repository: https://evil.test/charts\n", false},
		"oci":             {"Chart.yaml", "dependencies:\n- name: s\n  repository: oci://evil.test/charts\n", false},
		"alias":           {"Chart.yaml", "dependencies:\n- name: s\n  repository: '@stable'\n", false},
		"requirements":    {"requirements.yaml", "dependencies:\n- name: s\n  repository: http://evil.test\n", false},
		"lock":            {"Chart.lock", "dependencies:\n- name: s\n  repository: https://evil.test\n", false},
		"upper-case file": {"Chart.yaml", "dependencies:\n- name: s\n  repository: FILE://../lib\n", true},
	} {
		root := t.TempDir()
		put(t, root, "lib/Chart.yaml", "name: lib\n")
		put(t, root, "app/"+tc.file, tc.body)
		err := checkChartDependencies(root, filepath.Join(root, "app"), 1)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "dependency") {
			t.Errorf("%s: unclear message %v", name, err)
		}
	}
}

func TestKustomizationReferencesMustBeLocal(t *testing.T) {
	for name, tc := range map[string]struct {
		k  string
		ok bool
	}{
		"local file":      {"resources:\n- cm.yaml\n", true},
		"local base":      {"resources:\n- ../base\n", true},
		"https base":      {"resources:\n- https://github.com/o/r//base?ref=v1\n", false},
		"git@":            {"resources:\n- git@github.com:o/r.git//base\n", false},
		"bare host":       {"resources:\n- github.com/o/r/base\n", false},
		"go-getter":       {"bases:\n- git::https://x.test/o/r\n", false},
		"component":       {"components:\n- https://x.test/o/c\n", false},
		"escape":          {"resources:\n- ../../../etc\n", false},
		"helmCharts":      {"helmCharts:\n- name: c\n  repo: https://x.test\n", false},
		"patch path":      {"patches:\n- path: https://x.test/p.yaml\n", false},
		"generator files": {"configMapGenerator:\n- name: c\n  files:\n  - k=https://x.test/f\n", false},
		"inline patch":    {"patchesStrategicMerge:\n- |-\n  apiVersion: v1\n  kind: ConfigMap\n  metadata: {name: x}\n", true},
	} {
		root := t.TempDir()
		put(t, root, "cm.yaml", "a: b\n")
		put(t, root, "base/kustomization.yaml", "resources: []\n")
		put(t, root, "app/cm.yaml", "a: b\n")
		put(t, root, "app/kustomization.yaml", tc.k)
		err := CheckLocalKustomization(root, filepath.Join(root, "app"))
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestKustomizationRecursesIntoLocalBasesAndStopsOnCycles(t *testing.T) {
	root := t.TempDir()
	put(t, root, "app/kustomization.yaml", "resources:\n- ../base\n")
	put(t, root, "base/kustomization.yaml", "resources:\n- ../app\n- ../leaf\n")
	put(t, root, "leaf/kustomization.yaml", "resources: []\n")
	if err := CheckLocalKustomization(root, filepath.Join(root, "app")); err != nil {
		t.Fatal(err)
	}
	put(t, root, "leaf/kustomization.yaml", "resources:\n- https://evil.test/o/r\n")
	if err := CheckLocalKustomization(root, filepath.Join(root, "app")); err == nil || !strings.Contains(err.Error(), "refuses remote") {
		t.Fatal(err)
	}
}
