package argosrc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"go.yaml.in/yaml/v3"
)

// helm renders a Helm source: `helm template . --name-template <release> --namespace <ns> ...` run in the chart's
// directory, with the arguments and the order Argo CD's helmTemplate and Cmd.template build (reposerver/repository,
// util/helm/cmd.go): value files in order, then the inline values (valuesObject over values) as one more file,
// `--api-versions`, and `--include-crds` unless skipCrds.
func (st *state) helm(ctx context.Context, pos int, req Request, s Source, env Env, root, appPath string, res *Result) ([]byte, error) {
	h := s.Helm
	if h == nil {
		h = &Helm{}
	}
	if h.Version != "" && h.Version != "3" {
		return nil, unsupported(pos, "helm.version", fmt.Sprintf("%q: only Helm 3 renders", h.Version))
	}
	kubeVersion := req.KubeVersion
	if h.KubeVersion != "" {
		kubeVersion = h.KubeVersion
	}
	kubeVersion, err := ParseKubeVersion(kubeVersion)
	if err != nil {
		return nil, fmt.Errorf("source %d: %w", pos, err)
	}
	apiVersions := req.APIVersions
	if len(h.APIVersions) > 0 {
		apiVersions = h.APIVersions
	}
	ns := req.Namespace
	if h.Namespace != "" {
		ns = h.Namespace
	}
	release := ReleaseName(req.AppName, h)

	files, err := st.valueFiles(ctx, pos, s, h, env, root, appPath)
	if err != nil {
		return nil, err
	}
	args := []string{"template", ".", "--name-template", release}
	if ns != "" {
		args = append(args, "--namespace", ns)
	}
	if kubeVersion != "" {
		args = append(args, "--kube-version", kubeVersion)
	}
	set, setStr := map[string]string{}, map[string]string{}
	for _, p := range h.Parameters {
		if p.ForceString {
			setStr[p.Name] = env.Subst(p.Value)
		} else {
			set[p.Name] = env.Subst(p.Value)
		}
	}
	for _, k := range sortedKeys(set) {
		args = append(args, "--set", k+"="+cleanSetParameter(set[k]))
	}
	for _, k := range sortedKeys(setStr) {
		args = append(args, "--set-string", k+"="+cleanSetParameter(setStr[k]))
	}
	for _, fp := range h.FileParameters {
		path, err := st.fileParameter(ctx, pos, fp.Path, env, root, appPath)
		if err != nil {
			return nil, err
		}
		args = append(args, "--set-file", fp.Name+"="+cleanSetParameter(path))
	}
	for _, f := range files {
		args = append(args, "--values", f)
		if b, err := os.ReadFile(f); err == nil {
			res.ValueDocs = append(res.ValueDocs, b)
		}
	}
	if inline, err := inlineValues(h); err != nil {
		return nil, fmt.Errorf("source %d: %w", pos, err)
	} else if len(inline) > 0 {
		f, err := os.CreateTemp(st.o.Work, "values-*.yaml")
		if err != nil {
			return nil, err
		}
		_, werr := f.Write(inline)
		if cerr := f.Close(); werr != nil || cerr != nil {
			return nil, fmt.Errorf("write the inline values: %v %v", werr, cerr)
		}
		args = append(args, "--values", f.Name())
		res.ValueDocs = append(res.ValueDocs, inline)
	}
	for _, v := range apiVersions {
		args = append(args, "--api-versions", v)
	}
	if !h.SkipCrds {
		args = append(args, "--include-crds")
	}
	if h.SkipSchemaValidation {
		args = append(args, "--skip-schema-validation")
	}
	if h.SkipTests {
		args = append(args, "--skip-tests")
	}
	// Argo CD removes a Chart.lock that `helm template` writes when there was none (cleanupChartLockFile).
	lock := filepath.Join(appPath, "Chart.lock")
	_, lockErr := os.Stat(lock)
	defer func() {
		if os.IsNotExist(lockErr) {
			os.Remove(lock)
		}
	}()
	out, err := st.o.Run(ctx, appPath, st.o.helmEnv(), "helm", args...)
	if err != nil && isMissingDependency(err) {
		// runHelmBuild: Argo CD builds the chart's dependencies once, then retries.
		if _, berr := st.o.Run(ctx, appPath, st.o.helmEnv(), "helm", "dependency", "build"); berr != nil {
			return nil, unsupported(pos, "a chart dependency that cannot be built here",
				"helm dependency build failed (the plugin holds no repository definitions or credentials): "+firstLine(berr.Error()))
		}
		out, err = st.o.Run(ctx, appPath, st.o.helmEnv(), "helm", args...)
	}
	if err != nil {
		return nil, fmt.Errorf("source %d: helm template: %w", pos, err)
	}
	return out, nil
}

func isMissingDependency(err error) bool {
	m := err.Error()
	return strings.Contains(m, "found in requirements.yaml, but missing in charts") ||
		strings.Contains(m, "found in Chart.yaml, but missing in charts/ directory")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// cleanSetParameter is cleanSetParameters: a comma is escaped for Helm unless the value is a `{...}` list.
func cleanSetParameter(v string) string {
	if strings.HasPrefix(v, "{") && strings.HasSuffix(v, "}") {
		return v
	}
	var b strings.Builder
	prev := rune(0)
	for _, r := range v {
		if r == ',' && prev != '\\' {
			b.WriteString(`\,`)
		} else {
			b.WriteRune(r)
		}
		prev = r
	}
	return b.String()
}

// inlineValues is ApplicationSourceHelm.ValuesYAML: valuesObject when set, else values. valuesObject is JSON, and
// JSON is YAML, so it is written as it is (Argo CD re-encodes it as block YAML; Helm reads the same values).
func inlineValues(h *Helm) ([]byte, error) {
	if len(h.ValuesObject) > 0 && !bytes.Equal(bytes.TrimSpace(h.ValuesObject), []byte("null")) {
		var probe any
		if err := json.Unmarshal(h.ValuesObject, &probe); err != nil {
			return nil, fmt.Errorf("helm.valuesObject is not JSON: %w", err)
		}
		return append(bytes.TrimSpace(h.ValuesObject), '\n'), nil
	}
	return []byte(h.Values), nil
}

// referenced is getReferencedSource: a path that begins with a `$ref` naming one of the Application's ref sources.
func (st *state) referenced(raw string) (refTarget, bool) {
	if !strings.HasPrefix(raw, "$") {
		return refTarget{}, false
	}
	r, ok := st.refs[strings.Split(raw, "/")[0]]
	return r, ok
}

// resolveRef is getResolvedRefValueFile: the first path segment ($ref) is replaced by the referenced repository's
// checkout, the rest is resolved inside it and may not leave it.
func (st *state) resolveRef(ctx context.Context, pos int, raw string, env Env, rt refTarget) (refRoot, resolved string, err error) {
	if rt.src.Chart != "" {
		return "", "", fmt.Errorf("source %d: source has a 'chart' field defined, but Helm charts are not supported for 'ref' sources", pos)
	}
	co, err := st.git(ctx, rt.index, rt.src.RepoURL, rt.src.TargetRevision)
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(raw, "/")
	parts[0] = ""
	p, err := resolveValueFile(co.dir, co.dir, env.Subst(strings.Join(parts, "/")))
	if err != nil {
		return "", "", fmt.Errorf("source %d: error resolving value file path: %w", pos, err)
	}
	return co.dir, p, nil
}

func isGlob(p string) bool { return strings.ContainsAny(p, "*?[") }

// valueFiles is getResolvedValueFiles: each listed file resolved (a `$ref/` one against the referenced source's
// checkout, others against the chart, or the repository root when written with a leading slash), globs expanded in
// lexical order with an explicitly listed file keeping the position it was listed at, duplicates dropped, a missing
// file dropped only with ignoreMissingValueFiles (otherwise it is passed on and Helm refuses it).
func (st *state) valueFiles(ctx context.Context, pos int, s Source, h *Helm, env Env, root, appPath string) ([]string, error) {
	if st.multi {
		for _, raw := range append(append([]string{}, h.ValueFiles...), fileParamPaths(h)...) {
			if !strings.HasPrefix(raw, "$") {
				continue
			}
			v := strings.Split(raw, "/")[0]
			if _, ok := st.refs[v]; !ok {
				if len(st.refs) == 0 {
					return nil, fmt.Errorf("source %d: source referenced %q, but no source has a 'ref' field defined", pos, v)
				}
				var keys []string
				for k := range st.refs {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				return nil, fmt.Errorf("source %d: source referenced %q, which is not one of the available sources (%s)", pos, v, strings.Join(keys, ", "))
			}
		}
	}
	type resolved struct{ path, root string }
	resolve := func(raw string) (resolved, bool, error) {
		if rt, ok := st.referenced(raw); ok && st.multi {
			r, p, err := st.resolveRef(ctx, pos, raw, env, rt)
			return resolved{p, r}, false, err
		}
		p, err := resolveValueFile(appPath, root, env.Subst(raw))
		return resolved{p, root}, false, err
	}
	explicit := map[string]bool{}
	for _, raw := range h.ValueFiles {
		if r, _, err := resolve(raw); err == nil && !isGlob(r.path) {
			explicit[r.path] = true
		}
	}
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, raw := range h.ValueFiles {
		r, _, err := resolve(raw)
		if err != nil {
			if IsUnsupported(err) {
				return nil, unsupported(pos, "a remote value file URL", raw)
			}
			return nil, fmt.Errorf("source %d: error resolving value file path: %w", pos, err)
		}
		if isGlob(r.path) {
			matches, err := doublestar.FilepathGlob(r.path)
			if err != nil {
				return nil, fmt.Errorf("source %d: error expanding glob pattern %q: %w", pos, raw, err)
			}
			if len(matches) == 0 {
				if h.IgnoreMissingValueFiles {
					continue
				}
				return nil, fmt.Errorf("source %d: values file glob %q matched no files", pos, raw)
			}
			for _, m := range matches {
				real, err := filepath.EvalSymlinks(m)
				rr, _ := filepath.EvalSymlinks(r.root)
				if err != nil || (real != rr && !strings.HasPrefix(real, rr+string(os.PathSeparator))) {
					return nil, fmt.Errorf("source %d: glob pattern %q matches a file outside the repository", pos, raw)
				}
				if !explicit[m] {
					add(m)
				}
			}
			continue
		}
		if _, err := os.Stat(r.path); os.IsNotExist(err) && h.IgnoreMissingValueFiles {
			continue
		}
		add(r.path)
	}
	return out, nil
}

func fileParamPaths(h *Helm) []string {
	var out []string
	for _, f := range h.FileParameters {
		out = append(out, f.Path)
	}
	return out
}

func (st *state) fileParameter(ctx context.Context, pos int, raw string, env Env, root, appPath string) (string, error) {
	if rt, ok := st.referenced(raw); ok && st.multi {
		_, p, err := st.resolveRef(ctx, pos, raw, env, rt)
		return p, err
	}
	p, err := resolveValueFile(appPath, root, env.Subst(raw))
	if err != nil {
		return "", fmt.Errorf("source %d: error resolving helm value file path: %w", pos, err)
	}
	return p, nil
}

// ReleaseIDFromValues is releaseTracking.releaseId of the value documents Helm merged, last one winning.
func ReleaseIDFromValues(docs [][]byte) string {
	id := ""
	for _, raw := range docs {
		var v struct {
			ReleaseTracking struct {
				ReleaseID string `yaml:"releaseId"`
			} `yaml:"releaseTracking"`
		}
		if yaml.Unmarshal(raw, &v) == nil && v.ReleaseTracking.ReleaseID != "" {
			id = v.ReleaseTracking.ReleaseID
		}
	}
	return id
}
