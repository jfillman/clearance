package argosrc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Options are the renderer's collaborators.
type Options struct {
	Run             Runner
	Work            string // a scratch directory the renderer may fill; the caller removes it
	AllowLocalRepos bool   // tests only: a local path or file:// as a repository
}

// Request is everything Argo CD knows about the Application besides its sources.
type Request struct {
	AppName     string   // the Application's name: the Helm release name unless a source sets one
	Namespace   string   // spec.destination.namespace
	Project     string   // spec.project (ARGOCD_APP_PROJECT_NAME)
	KubeVersion string   // the destination cluster's Kubernetes version (KUBE_VERSION in a plugin)
	APIVersions []string // the destination cluster's API versions, [group/]version[/kind] (KUBE_API_VERSIONS)
	Sources     []Source

	// KustomizeBuildOptions is argocd-cm's kustomize.buildOptions, the cluster-wide flags Argo CD adds to
	// `kustomize build`. A plugin cannot read argocd-cm, so the Application's onboarding passes it here.
	KustomizeBuildOptions string
}

// Provenance records what each source resolved to: a git commit, or the digest of the packaged chart.
type Provenance struct {
	Position  int    `json:"position"` // 1-based
	Type      string `json:"type"`     // Helm, Kustomize, Directory or Ref (a reference only: nothing rendered)
	Repo      string `json:"repo"`
	Chart     string `json:"chart,omitempty"`
	Requested string `json:"requested"`
	Resolved  string `json:"resolved"`
}

// Result is a render.
type Result struct {
	Manifests  []byte // every rendered document, in source order, separated by "---"
	Sources    []Provenance
	ValueDocs  [][]byte // the Helm value files' and inline values' contents, in Helm's merge order
	HelmRender bool     // at least one source was rendered by Helm
}

// refTarget is a source another source's value files may name ("$ref/path").
type refTarget struct {
	index int
	src   Source
}

type checkout struct{ dir, commit string }

// state is one Render: the sources, the ref sources by name, and the git checkouts made so far (one per repository
// and requested revision, so every use of a ref source sees the one commit).
type state struct {
	o     Options
	multi bool
	refs  map[string]refTarget
	cos   map[[2]string]checkout
}

func (st *state) git(ctx context.Context, pos int, repo, rev string) (checkout, error) {
	k := [2]string{repo, rev}
	if c, ok := st.cos[k]; ok {
		return c, nil
	}
	dir, commit, err := st.o.fetchGit(ctx, pos, repo, rev)
	if err != nil {
		return checkout{}, err
	}
	c := checkout{dir, commit}
	st.cos[k] = c
	return c, nil
}

// Render renders every source of the Application as Argo CD's repo-server does and returns their documents.
// An *UnsupportedError means the renderer refused a feature it cannot reproduce.
func Render(ctx context.Context, o Options, req Request) (*Result, error) {
	if o.Run == nil || o.Work == "" {
		return nil, errors.New("argosrc: Options.Run and Options.Work are required")
	}
	if req.AppName == "" {
		return nil, errors.New("the Application's name is required")
	}
	if len(req.Sources) == 0 {
		return nil, errors.New("the Application has no source")
	}
	st := &state{o: o, multi: len(req.Sources) > 1, refs: map[string]refTarget{}, cos: map[[2]string]checkout{}}
	for i, s := range req.Sources {
		if s.Ref == "" {
			continue
		}
		if _, dup := st.refs["$"+s.Ref]; dup {
			return nil, fmt.Errorf("source %d: ref %q is used by two sources", i+1, s.Ref)
		}
		st.refs["$"+s.Ref] = refTarget{index: i + 1, src: s}
	}
	res := &Result{}
	var out bytes.Buffer
	for i, s := range req.Sources {
		pos := i + 1
		if s.Plugin != nil {
			return nil, unsupported(pos, "another config management plugin", fmt.Sprintf("plugin %q", s.Plugin.Name))
		}
		if s.TagPrefix != "" {
			return nil, unsupported(pos, "tagPrefix", "Argo CD resolves the tag list; the plugin pins an exact revision")
		}
		if strings.HasPrefix(s.RepoURL, "oci://") {
			return nil, unsupported(pos, "an oci:// artifact source", "only OCI Helm charts (a repoURL without a scheme, and a chart) are rendered")
		}
		// A source that only provides value files: GenerateManifest skips it (reposerver/repository, "ref only source").
		if st.multi && s.Path == "" && s.Chart == "" && s.Ref != "" {
			co, err := st.git(ctx, pos, s.RepoURL, s.TargetRevision)
			if err != nil {
				return nil, err
			}
			res.Sources = append(res.Sources, Provenance{Position: pos, Type: "Ref", Repo: s.RepoURL, Requested: s.TargetRevision, Resolved: co.commit})
			continue
		}
		var root, appPath, revision string
		var prov Provenance
		if s.Chart != "" {
			dir, digest, err := o.fetchChart(ctx, pos, s.RepoURL, s.Chart, s.TargetRevision)
			if err != nil {
				return nil, err
			}
			root, appPath, revision = dir, dir, s.TargetRevision
			prov = Provenance{Position: pos, Repo: s.RepoURL, Chart: s.Chart, Requested: s.TargetRevision, Resolved: digest}
		} else {
			co, err := st.git(ctx, pos, s.RepoURL, s.TargetRevision)
			if err != nil {
				return nil, err
			}
			p, err := sourcePath(co.dir, orDot(s.Path))
			if err != nil {
				return nil, fmt.Errorf("source %d: %w", pos, err)
			}
			root, appPath, revision = co.dir, p, co.commit
			prov = Provenance{Position: pos, Repo: s.RepoURL, Requested: s.TargetRevision, Resolved: co.commit}
		}
		if _, err := os.Stat(filepath.Join(appPath, ".argocd-source.yaml")); err == nil {
			return nil, unsupported(pos, ".argocd-source.yaml", "parameter overrides in the repository")
		}
		if matches, _ := filepath.Glob(filepath.Join(appPath, ".argocd-source-*.yaml")); len(matches) > 0 {
			return nil, unsupported(pos, ".argocd-source-<app>.yaml", "parameter overrides in the repository")
		}
		typ, err := sourceType(s, appPath)
		if err != nil {
			return nil, fmt.Errorf("source %d: %w", pos, err)
		}
		prov.Type = typ
		env := sourceEnv(req, s, revision)
		var docs []byte
		switch typ {
		case "Helm":
			docs, err = st.helm(ctx, pos, req, s, env, root, appPath, res)
			res.HelmRender = true
		case "Kustomize":
			docs, err = st.kustomize(ctx, pos, req, s, env, root, appPath)
		default:
			docs, err = st.directory(pos, s, root, appPath)
		}
		if err != nil {
			return nil, err
		}
		res.Sources = append(res.Sources, prov)
		if len(bytes.TrimSpace(docs)) > 0 {
			out.Write(bytes.TrimSpace(docs))
			out.WriteString("\n---\n")
		}
	}
	res.Manifests = out.Bytes()
	if err := noDuplicates(res.Manifests); err != nil {
		return nil, err
	}
	return res, nil
}

func orDot(p string) string {
	if p == "" {
		return "."
	}
	return p
}

// sourceType is GetAppSourceType: the explicit one (a helm, kustomize or directory section), else what the
// directory holds (discovery.AppType: a Chart.yaml or a kustomization file at its root, the last one in file-name
// order winning, else a plain directory).
func sourceType(s Source, appPath string) (string, error) {
	var types []string
	if s.Kustomize != nil {
		types = append(types, "Kustomize")
	}
	if s.Helm != nil {
		types = append(types, "Helm")
	}
	if s.Directory != nil {
		types = append(types, "Directory")
	}
	if len(types) > 1 {
		return "", fmt.Errorf("multiple application sources defined: %s", strings.Join(types, ","))
	}
	if len(types) == 1 {
		return types[0], nil
	}
	ents, err := os.ReadDir(appPath) // sorted by name, as filepath.Walk visits them
	if err != nil {
		return "", err
	}
	typ := "Directory"
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, "Chart.yaml") {
			typ = "Helm"
		}
		if n == "kustomization.yaml" || n == "kustomization.yml" || n == "Kustomization" {
			typ = "Kustomize"
		}
	}
	return typ, nil
}

// noDuplicates refuses an Application whose sources render two objects of one identity (Argo CD reports it as a
// ComparisonError); collapsing them silently would hash a tree Argo CD does not apply. Documents are read as nodes so
// that a mapping repeating a key (which Argo CD's reader accepts, the last one winning) is not a reason to stop here;
// the plugin's stamping reader decides about that.
func noDuplicates(manifests []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(manifests))
	seen := map[string]bool{}
	var dups []string
	add := func(m *yaml.Node) {
		md := nodeField(m, "metadata")
		name, ns := nodeScalar(md, "name"), nodeScalar(md, "namespace")
		av, kind := nodeScalar(m, "apiVersion"), nodeScalar(m, "kind")
		if kind == "" || name == "" {
			return
		}
		group := ""
		if i := strings.Index(av, "/"); i >= 0 {
			group = av[:i]
		}
		k := group + "|" + kind + "|" + ns + "|" + name
		if seen[k] {
			dups = append(dups, kind+"/"+name)
		}
		seen[k] = true
	}
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("the render is not YAML: %w", err)
		}
		m := &doc
		if m.Kind == yaml.DocumentNode && len(m.Content) == 1 {
			m = m.Content[0]
		}
		if m.Kind != yaml.MappingNode {
			continue
		}
		if items := nodeField(m, "items"); items != nil && items.Kind == yaml.SequenceNode && strings.HasSuffix(nodeScalar(m, "kind"), "List") {
			for _, it := range items.Content {
				if it.Kind == yaml.MappingNode {
					add(it)
				}
			}
			continue
		}
		add(m)
	}
	if len(dups) > 0 {
		sort.Strings(dups)
		return fmt.Errorf("the sources render the same object more than once: %s", strings.Join(dups, ", "))
	}
	return nil
}

// nodeField is a mapping's value for key (the last one when the key repeats), or nil.
func nodeField(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	var out *yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			out = m.Content[i+1]
		}
	}
	return out
}

func nodeScalar(m *yaml.Node, key string) string {
	if v := nodeField(m, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}
