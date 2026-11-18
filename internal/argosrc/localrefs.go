package argosrc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Two renderers reach the network on their own: `helm dependency build` pulls a chart's dependencies from the
// repositories its Chart.yaml names, and `kustomize build` clones a remote resource, base or component and pulls a
// Helm chart named in helmCharts. Both would take a repository from a file inside an allowed source, so the
// repository list the plugin enforces (cmp/repos.go) would not reach them. The plugin therefore resolves only what is
// local: a dependency or kustomization reference must be a path inside the source tree. A remote one is refused (a
// platform that needs it vendors the chart under charts/ or lists the base as a source). The same holds on the plain
// Argo CD path (the repo-server), which this plugin closes only for the Applications behind the gate.

// within resolves p (relative to base unless absolute) and reports whether it exists inside root, symlinks followed.
func within(root, base, p string) bool {
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return false
	}
	rr, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	return real == rr || strings.HasPrefix(real, rr+string(os.PathSeparator))
}

// checkChartDependencies refuses a chart whose dependencies (Chart.yaml, requirements.yaml, Chart.lock) name a
// repository other than "" (a vendored or in-file subchart) or a file:// path inside root.
func checkChartDependencies(root, chartDir string, pos int) error {
	for _, name := range []string{"Chart.yaml", "requirements.yaml", "Chart.lock"} {
		b, err := os.ReadFile(filepath.Join(chartDir, name))
		if err != nil {
			continue
		}
		var f struct {
			Dependencies []struct {
				Name       string `yaml:"name"`
				Repository string `yaml:"repository"`
			} `yaml:"dependencies"`
		}
		if err := yaml.Unmarshal(b, &f); err != nil {
			return fmt.Errorf("source %d: %s is not readable YAML: %w", pos, name, err)
		}
		for _, d := range f.Dependencies {
			r := strings.TrimSpace(d.Repository)
			if r == "" {
				continue
			}
			if rest, ok := strings.CutPrefix(strings.ToLower(r), "file://"); ok && rest != "" {
				if within(root, chartDir, r[len("file://"):]) {
					continue
				}
				return unsupported(pos, "a chart dependency outside the source", fmt.Sprintf("%s: dependency %q is %q, which is not a directory inside the source", name, d.Name, r))
			}
			return unsupported(pos, "a chart dependency from a remote repository", fmt.Sprintf("%s: dependency %q names the repository %q; the plugin builds only dependencies under file:// inside the source (vendor the chart under charts/)", name, d.Name, redactURL(r)))
		}
	}
	return nil
}

var kustomizationNames = []string{"kustomization.yaml", "kustomization.yml", "Kustomization"}

// CheckLocalKustomization walks the kustomization at dir (inside root) and every local directory it names, and refuses
// anything kustomize would fetch: a reference that is not an existing path inside root (a URL, a git@ or go-getter
// spelling, or a name that exists nowhere locally, which kustomize would try as a remote), and any helmCharts.
func CheckLocalKustomization(root, dir string) error {
	return walkKustomization(root, dir, map[string]bool{})
}

func walkKustomization(root, dir string, seen map[string]bool) error {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	if seen[real] {
		return nil
	}
	seen[real] = true
	var raw []byte
	for _, n := range kustomizationNames {
		if b, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
			raw = b
			break
		}
	}
	if raw == nil {
		return nil // no kustomization here: kustomize reports it
	}
	var k map[string]any
	if err := yaml.Unmarshal(raw, &k); err != nil {
		return fmt.Errorf("the kustomization in %s is not readable YAML: %w", filepath.Base(dir), err)
	}
	if hc, ok := k["helmCharts"]; ok && hc != nil {
		return fmt.Errorf("the kustomization in %s has helmCharts: kustomize would pull a chart from a repository; the plugin renders only local kustomizations", filepath.Base(dir))
	}
	var refs []string
	for _, key := range []string{"resources", "bases", "components", "crds", "transformers", "generators", "configurations", "patchesStrategicMerge"} {
		if l, ok := k[key].([]any); ok {
			for _, e := range l {
				if s, ok := e.(string); ok && !strings.Contains(s, "\n") { // a patchesStrategicMerge entry may be inline YAML
					refs = append(refs, s)
				}
			}
		}
	}
	for _, key := range []string{"patches", "patchesJson6902", "replacements"} {
		if l, ok := k[key].([]any); ok {
			for _, e := range l {
				if m, ok := e.(map[string]any); ok {
					if s, ok := m["path"].(string); ok {
						refs = append(refs, s)
					}
				}
			}
		}
	}
	if o, ok := k["openapi"].(map[string]any); ok {
		if s, ok := o["path"].(string); ok {
			refs = append(refs, s)
		}
	}
	for _, key := range []string{"configMapGenerator", "secretGenerator"} {
		if l, ok := k[key].([]any); ok {
			for _, e := range l {
				m, _ := e.(map[string]any)
				for _, fk := range []string{"files", "envs"} {
					if fl, ok := m[fk].([]any); ok {
						for _, f := range fl {
							if s, ok := f.(string); ok {
								if _, after, found := strings.Cut(s, "="); found {
									s = after
								}
								refs = append(refs, s)
							}
						}
					}
				}
				if s, ok := m["env"].(string); ok {
					refs = append(refs, s)
				}
			}
		}
	}
	for _, r := range refs {
		if strings.Contains(r, "://") || strings.Contains(r, "::") || strings.HasPrefix(r, "git@") || !within(root, dir, r) {
			return fmt.Errorf("the kustomization in %s refers to %q, which is not a path inside the source: the plugin refuses remote bases, resources and components (kustomize would fetch them)", filepath.Base(dir), redactURL(r))
		}
		p := r
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			if err := walkKustomization(root, p, seen); err != nil {
				return err
			}
		}
	}
	return nil
}
