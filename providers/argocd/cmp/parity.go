package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/jfillman/clearance/internal/argosrc"
	"github.com/jfillman/clearance/internal/gate/render"
)

// `clearance-cmp parity` is G-ARGO-10b's parity suite: for each Application it renders the Application's original
// sources with the plugin's generic renderer and compares the result, object by object and hash by hash, with what
// Argo CD's own repo-server renders for the same Application at the same revisions (`argocd app manifests`).
// Both sides go through the one canonicalisation and hashing the plugin stamps with (Canonicalize), so "identical"
// means the plugin would stamp, and the agent recompute, exactly the objects Argo CD applies.
//
// Read-only: the Applications are read from a file, Argo CD's render is asked for (argocd --core uses the caller's
// kube credentials and the repo-server; it syncs nothing), the repositories are only fetched.

// Parity statuses.
const (
	StatusIdentical     = "identical"      // same objects, same hashes, same tree
	StatusDiffers       = "differs"        // the first difference is in Detail
	StatusUnsupported   = "unsupported"    // the plugin refuses a feature the Application uses (named in Detail)
	StatusNotComparable = "not-comparable" // the Application is already rendered by a plugin: there is no original to compare
	StatusError         = "error"          // a render failed on a side (Detail says which)
)

// AppResult is one Application's parity result.
type AppResult struct {
	Instance      string               `json:"instance"` // which Argo CD, e.g. "hangar-dev/argocd"
	Name          string               `json:"name"`
	Status        string               `json:"status"`
	Detail        string               `json:"detail,omitempty"`
	Objects       int                  `json:"objects"`
	PluginTree    string               `json:"pluginTree,omitempty"`
	ArgoTree      string               `json:"argoTree,omitempty"`
	Sources       []argosrc.Provenance `json:"sources,omitempty"`
	ScopeMismatch []string             `json:"scopeMismatch,omitempty"` // kinds the plugin's cluster-scope list gets wrong for this cluster
	RenderMillis  int64                `json:"renderMillis,omitempty"`  // the plugin side's render (fetching included): the sidecar has 80 s
}

// Report is a parity run.
type Report struct {
	Results []AppResult    `json:"results"`
	Counts  map[string]int `json:"counts"`
	Tools   []string       `json:"tools,omitempty"` // the renderer's helm, kustomize and git versions: they must be Argo CD's
}

// Argo renders an Application the way Argo CD does and returns the manifests as a YAML stream.
type Argo interface {
	Manifests(ctx context.Context, app string, prov []argosrc.Provenance) ([]byte, error)
}

// ClusterInfo is what Argo CD knows of the destination cluster (`argocd cluster get -o json`).
type ClusterInfo struct {
	ServerVersion string `json:"serverVersion"`
	Info          struct {
		ServerVersion string   `json:"serverVersion"`
		APIVersions   []string `json:"apiVersions"`
	} `json:"info"`
}

// Version is the cluster's Kubernetes version as Argo CD hands it to a render.
func (c ClusterInfo) Version() string {
	if c.Info.ServerVersion != "" {
		return c.Info.ServerVersion
	}
	return c.ServerVersion
}

// Application is the part of an Application resource the parity run reads.
type Application struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Project     string            `json:"project"`
		Source      *json.RawMessage  `json:"source"`
		Sources     []json.RawMessage `json:"sources"`
		Destination struct {
			Namespace string `json:"namespace"`
		} `json:"destination"`
	} `json:"spec"`
}

// SourcesJSON is the Application's original sources as the plugin's `sources` parameter carries them.
func (a Application) SourcesJSON() string {
	if len(a.Spec.Sources) > 0 {
		b, _ := json.Marshal(a.Spec.Sources)
		return string(b)
	}
	if a.Spec.Source != nil {
		return "[" + string(*a.Spec.Source) + "]"
	}
	return ""
}

// ReadApplications reads `kubectl get applications -o json` (a List, or one Application).
func ReadApplications(b []byte) ([]Application, error) {
	var list struct {
		Items []Application `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	if list.Items != nil {
		return list.Items, nil
	}
	var one Application
	if err := json.Unmarshal(b, &one); err != nil || one.Metadata.Name == "" {
		return nil, errors.New("the file is neither an Application list nor an Application")
	}
	return []Application{one}, nil
}

// ParityOpts are what a parity run knows besides the Applications.
type ParityOpts struct {
	Run           argosrc.Runner
	Argo          Argo
	Cluster       ClusterInfo
	Scopes        map[string]bool // kind -> cluster-scoped, from the cluster's discovery (optional)
	Instance      string
	KustomizeOpts string // argocd-cm kustomize.buildOptions
	Only          string // only Applications whose name contains this
	Parallel      int
	Timeout       time.Duration
	SavePlugin    string // keep the plugin's rendered manifests per Application here (debugging a difference)
	Progress      io.Writer
}

// CompareApp renders one Application with the plugin and with Argo CD and compares them.
func CompareApp(ctx context.Context, o ParityOpts, app Application) AppResult {
	run, argo, cluster, scopes, instance, kustomizeOpts := o.Run, o.Argo, o.Cluster, o.Scopes, o.Instance, o.KustomizeOpts
	res := AppResult{Instance: instance, Name: app.Metadata.Name}
	raw := app.SourcesJSON()
	srcs, err := argosrc.ParseSources(raw)
	if err != nil {
		return fail(res, err)
	}
	for _, s := range srcs {
		if s.Plugin != nil {
			res.Status, res.Detail = StatusNotComparable, fmt.Sprintf("a source is rendered by the %q plugin", s.Plugin.Name)
			return res
		}
	}
	ns := app.Spec.Destination.Namespace
	tmp, err := os.MkdirTemp("", "clearance-parity-")
	if err != nil {
		return fail(res, err)
	}
	defer os.RemoveAll(tmp)
	req := argosrc.Request{AppName: app.Metadata.Name, Namespace: ns, Project: orDefault(app.Spec.Project, "default"), KubeVersion: cluster.Version(),
		APIVersions: cluster.Info.APIVersions, Sources: srcs, KustomizeBuildOptions: kustomizeOpts}
	started := time.Now()
	pr, perr := argosrc.Render(ctx, argosrc.Options{Run: run, Work: tmp}, req)
	res.RenderMillis = time.Since(started).Milliseconds()
	if perr != nil {
		if argosrc.IsUnsupported(perr) {
			res.Status, res.Detail = StatusUnsupported, perr.Error()
			return res
		}
		return fail(res, fmt.Errorf("plugin render: %w", perr))
	}
	res.Sources = pr.Sources
	if o.SavePlugin != "" {
		os.WriteFile(filepath.Join(o.SavePlugin, app.Metadata.Name+".yaml"), pr.Manifests, 0o644)
	}
	am, aerr := argo.Manifests(ctx, app.Metadata.Name, pr.Sources)
	if aerr != nil {
		return fail(res, fmt.Errorf("argo render: %w", aerr))
	}
	am = stripTracking(am)
	// What the plugin would stamp is the raw render: a render it cannot read is a refusal whatever Argo CD does.
	pt, perr := Canonicalize(pr.Manifests, ns, nil)
	at, aerr2 := Canonicalize(am, ns, nil)
	if perr == nil {
		// `argocd app manifests` hides the data of a core Secret; the plugin's side is hidden the same way, to compare.
		pm, herr := hideSecretData(pr.Manifests)
		if herr != nil {
			return fail(res, herr)
		}
		if !bytes.Equal(pm, pr.Manifests) {
			if pt, perr = Canonicalize(pm, ns, nil); perr != nil {
				return fail(res, fmt.Errorf("plugin tree: %w", perr))
			}
		}
	}
	switch {
	case perr != nil && aerr2 != nil && perr.Error() == aerr2.Error():
		res.Status, res.Detail = StatusIdentical, "both renders hold no stampable objects: "+perr.Error()
		return res
	case perr != nil && aerr2 == nil:
		// Argo CD renders it, the plugin will not stamp it: a refusal (fail closed), not a silent difference.
		res.Status, res.Detail = StatusUnsupported, "the plugin refuses to stamp what Argo CD renders: "+perr.Error()
		return res
	case perr != nil:
		return fail(res, fmt.Errorf("plugin tree: %w", perr))
	case aerr2 != nil:
		return fail(res, fmt.Errorf("argo tree: %w", aerr2))
	}
	res.Objects, res.PluginTree, res.ArgoTree = len(at.Hashes), pt.Root, at.Root
	res.ScopeMismatch = scopeAudit(at, scopes)
	if diff := compareTrees(at, pt); diff != "" {
		res.Status, res.Detail = StatusDiffers, diff
		// A difference that is the render disagreeing with itself is the chart's (time or randomness in its output),
		// not the renderer's: render again and say so.
		if pr2, err := argosrc.Render(ctx, argosrc.Options{Run: run, Work: tmp}, req); err == nil {
			if pm2, herr := hideSecretData(pr2.Manifests); herr == nil {
				if pt2, err := Canonicalize(pm2, ns, nil); err == nil && pt2.Root != pt.Root {
					res.Detail = "non-deterministic render (two renders by the plugin differ from each other: " + compareTrees(pt, pt2) + "); against Argo CD: " + diff
				}
			}
		}
		if nullAnnotations(at, pt) {
			res.Detail += " [the chart renders `annotations: null` where Argo CD's tracking replaces it: see docs/gate.md, Rendering any source]"
		}
		return res
	}
	if pt.Root != at.Root {
		res.Status, res.Detail = StatusDiffers, "the objects and their hashes agree but the tree digests differ"
		return res
	}
	res.Status = StatusIdentical
	return res
}

func fail(r AppResult, err error) AppResult {
	r.Status, r.Detail = StatusError, err.Error()
	return r
}

// compareTrees names the first difference between Argo CD's tree and the plugin's, by identity and JSON pointer.
func compareTrees(argo, plugin *Tree) string {
	var keys []render.Key
	seen := map[render.Key]bool{}
	for k := range argo.Hashes {
		keys = append(keys, k)
		seen[k] = true
	}
	for k := range plugin.Hashes {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		for x := range keys[i] {
			if keys[i][x] != keys[j][x] {
				return keys[i][x] < keys[j][x]
			}
		}
		return false
	})
	var msgs []string
	for _, k := range keys {
		id := k[1] + "/" + k[3]
		if k[2] != "" {
			id = k[2] + "/" + id
		}
		ah, aok := argo.Hashes[k]
		ph, pok := plugin.Hashes[k]
		switch {
		case aok && !pok:
			msgs = append(msgs, "only Argo CD renders "+id)
		case !aok && pok:
			msgs = append(msgs, "only the plugin renders "+id)
		case ah != ph:
			ptrs := render.DiffPointers(argo.Set[k].Value, plugin.Set[k].Value, "")
			p := "(no leaf difference found)"
			if len(ptrs) > 0 {
				p = ptrs[0]
				if len(ptrs) > 1 {
					p += fmt.Sprintf(" (+%d more)", len(ptrs)-1)
				}
			}
			msgs = append(msgs, id+" differs at "+p)
		}
	}
	if len(msgs) == 0 {
		return ""
	}
	if len(msgs) > 3 {
		return strings.Join(msgs[:3], "; ") + fmt.Sprintf("; and %d more", len(msgs)-3)
	}
	return strings.Join(msgs, "; ")
}

// nullAnnotations is whether a difference between the trees is a chart rendering `metadata.annotations: null` (the
// plugin hashes the null, the object Argo CD applies has a map).
func nullAnnotations(argo, plugin *Tree) bool {
	for k, d := range plugin.Set {
		md, _ := d.Value.(map[string]any)["metadata"].(map[string]any)
		if v, present := md["annotations"]; present && v == nil && argo.Hashes[k] != plugin.Hashes[k] {
			return true
		}
	}
	return false
}

// scopeAudit lists the kinds whose scope the plugin guesses wrongly for this cluster (Argo CD asks the cluster's
// discovery; the plugin has a list), given the cluster's truth as kind -> cluster-scoped.
func scopeAudit(t *Tree, truth map[string]bool) []string {
	if truth == nil {
		return nil
	}
	bad := map[string]bool{}
	for _, k := range t.Keys {
		cluster, known := truth[k[1]]
		if known && cluster != isClusterScoped(k[1], nil) {
			bad[k[1]] = true
		}
	}
	var out []string
	for k := range bad {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// hideSecretData is diff.HideSecretData as `argocd app manifests` applies it to a core Secret: every value of data
// and stringData becomes "++++++++" (the API server does this for the CLI; it is never applied to what is stamped).
func hideSecretData(b []byte) ([]byte, error) {
	if !bytes.Contains(b, []byte("Secret")) {
		return b, nil // nothing to hide: leave the render byte for byte as it is
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var out bytes.Buffer
	hid := false
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return b, nil // not readable as YAML 1.2: Canonicalize will say so
		}
		if m == nil {
			continue
		}
		if m["kind"] == "Secret" && m["apiVersion"] == "v1" {
			// stringData is folded into data, every value hidden, and an empty result is shown as null.
			_, hasData := m["data"]
			sd, hasString := m["stringData"].(map[string]any)
			if d, ok := m["data"].(map[string]any); ok || hasString || hasData {
				if d == nil {
					d = map[string]any{}
				}
				for k := range d {
					d[k] = "++++++++"
				}
				for k := range sd {
					d[k] = "++++++++"
				}
				delete(m, "stringData")
				if len(d) == 0 {
					m["data"] = nil
				} else {
					m["data"] = d
				}
				hid = true
			}
		}
		j, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		out.WriteString("---\n")
		out.Write(j)
		out.WriteString("\n")
	}
	if !hid {
		return b, nil
	}
	return out.Bytes(), nil
}

// stripTracking removes Argo CD's resource-tracking annotation from `argocd app manifests` output: the repo-server
// adds it after a plugin has rendered, so it is not part of what the plugin hashes.
func stripTracking(b []byte) []byte {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var out bytes.Buffer
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return b // leave what cannot be read for Canonicalize to refuse
		}
		if m == nil {
			continue
		}
		if md, ok := m["metadata"].(map[string]any); ok {
			if ann, ok := md["annotations"].(map[string]any); ok {
				delete(ann, "argocd.argoproj.io/tracking-id")
				if len(ann) == 0 {
					delete(md, "annotations")
				}
			}
		}
		j, err := json.Marshal(m)
		if err != nil {
			return b
		}
		out.WriteString("---\n")
		out.Write(j)
		out.WriteString("\n")
	}
	return out.Bytes()
}

// -- Argo CD's side ---------------------------------------------------------------------------------------------

// dirArgo reads Argo CD's manifests from files captured earlier: <dir>/<application>.yaml.
type dirArgo struct{ dir string }

func (d dirArgo) Manifests(_ context.Context, app string, _ []argosrc.Provenance) ([]byte, error) {
	return os.ReadFile(filepath.Join(d.dir, app+".yaml"))
}

// cliArgo asks Argo CD: `argocd --core app manifests <app> --source git` with every git source pinned to the commit
// the plugin side resolved, so both sides render the same revisions.
type cliArgo struct {
	bin  string
	env  []string
	save string // when set, the raw output is kept here
	run  func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)
}

func (c cliArgo) Manifests(ctx context.Context, app string, prov []argosrc.Provenance) ([]byte, error) {
	args := []string{"--core", "app", "manifests", app, "--source", "git"}
	if len(prov) == 1 {
		// A revision is always passed: without one the CLI prints the controller's target objects (hooks removed,
		// cluster-scoped namespaces cleared), not what the repo-server renders.
		rev := prov[0].Resolved
		if prov[0].Chart != "" {
			rev = prov[0].Requested
		}
		if rev != "" {
			args = append(args, "--revision", rev)
		}
	} else {
		for _, p := range prov {
			rev := p.Resolved
			if p.Chart != "" {
				rev = p.Requested
			}
			args = append(args, "--revisions", rev, "--source-positions", fmt.Sprint(p.Position))
		}
	}
	out, err := c.run(ctx, c.env, c.bin, args...)
	if err != nil {
		return nil, err
	}
	if c.save != "" {
		if err := os.WriteFile(filepath.Join(c.save, app+".yaml"), out, 0o644); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func execArgo(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var out, eb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &eb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(eb.String())
		if i := strings.LastIndex(msg, `"msg":"`); i >= 0 {
			msg = msg[i+7:]
			if j := strings.Index(msg, `"`); j >= 0 {
				msg = msg[:j]
			}
		}
		if len(msg) > 400 {
			msg = msg[:400] + "..."
		}
		return nil, fmt.Errorf("%s: %w: %s", name, err, msg)
	}
	return out.Bytes(), nil
}

// parityRun is OSRun for an operator's laptop: git may use the operator's own system credential helper to read the
// private repositories Argo CD reads (the sidecar has no credential; this command never prints or stores one).
func parityRun(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	return OSRun(ctx, dir, append([]string{"GIT_CONFIG_NOSYSTEM=0"}, env...), name, args...)
}

// -- the command ------------------------------------------------------------------------------------------------

func parityMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("parity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apps := fs.String("apps", "", "`kubectl get applications -o json` output (required)")
	instance := fs.String("instance", "", "a label for this Argo CD (e.g. hangar-dev/argocd)")
	clusterFile := fs.String("cluster-info", "", "`argocd cluster get <server> -o json` output: the cluster's version and API versions")
	scopesFile := fs.String("scopes", "", "lines of `Kind true|false` (cluster-scoped?) from the cluster's discovery, for the scope audit")
	argoDir := fs.String("argo-dir", "", "read Argo CD's manifests from <dir>/<application>.yaml instead of asking `argocd`")
	argocd := fs.String("argocd", "argocd", "the argocd CLI (used with --core and KUBECONFIG, whose namespace is the Argo CD's)")
	kubeconfig := fs.String("kubeconfig", "", "KUBECONFIG for the argocd CLI (its current namespace is the Argo CD's)")
	savePlugin := fs.String("save-plugin", "", "keep the plugin's rendered manifests per Application in this directory")
	save := fs.String("save-argo", "", "keep Argo CD's raw manifests per Application in this directory")
	kopts := fs.String("kustomize-build-options", "", "argocd-cm kustomize.buildOptions of that Argo CD")
	only := fs.String("only", "", "only the Applications whose name contains this")
	par := fs.Int("parallel", 4, "Applications rendered at once")
	format := fs.String("format", "text", "text, md or json")
	timeout := fs.Duration("timeout", 10*time.Minute, "per Application")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *apps == "" {
		fmt.Fprintln(stderr, "parity: --apps is required")
		return 2
	}
	b, err := os.ReadFile(*apps)
	if err != nil {
		fmt.Fprintln(stderr, "parity:", err)
		return 2
	}
	list, err := ReadApplications(b)
	if err != nil {
		fmt.Fprintln(stderr, "parity:", err)
		return 2
	}
	var cluster ClusterInfo
	if *clusterFile != "" {
		cb, err := os.ReadFile(*clusterFile)
		if err == nil {
			err = json.Unmarshal(cb, &cluster)
		}
		if err != nil {
			fmt.Fprintln(stderr, "parity: --cluster-info:", err)
			return 2
		}
	}
	var scopes map[string]bool
	if *scopesFile != "" {
		sb, err := os.ReadFile(*scopesFile)
		if err != nil {
			fmt.Fprintln(stderr, "parity: --scopes:", err)
			return 2
		}
		scopes = map[string]bool{}
		for _, l := range strings.Split(string(sb), "\n") {
			if f := strings.Fields(l); len(f) == 2 {
				scopes[f[0]] = f[1] == "true"
			}
		}
	}
	var argo Argo
	if *argoDir != "" {
		argo = dirArgo{*argoDir}
	} else {
		var env []string
		if *kubeconfig != "" {
			env = append(env, "KUBECONFIG="+*kubeconfig)
		}
		if *save != "" {
			if err := os.MkdirAll(*save, 0o755); err != nil {
				fmt.Fprintln(stderr, "parity:", err)
				return 2
			}
		}
		argo = cliArgo{bin: *argocd, env: env, save: *save, run: execArgo}
	}
	if *savePlugin != "" {
		if err := os.MkdirAll(*savePlugin, 0o755); err != nil {
			fmt.Fprintln(stderr, "parity:", err)
			return 2
		}
	}
	tools := toolVersions(context.Background(), parityRun)
	rep := RunParity(context.Background(), ParityOpts{Run: parityRun, Argo: argo, Cluster: cluster, Scopes: scopes, Instance: *instance, KustomizeOpts: *kopts,
		Only: *only, Parallel: *par, Timeout: *timeout, SavePlugin: *savePlugin, Progress: stderr}, list)
	rep.Tools = tools
	switch *format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
	case "md":
		io.WriteString(stdout, rep.Markdown())
	default:
		io.WriteString(stdout, rep.Text())
	}
	if rep.Counts[StatusDiffers] > 0 || rep.Counts[StatusError] > 0 {
		return 1
	}
	return 0
}

// toolVersions asks the tools the renderer runs for their versions.
func toolVersions(ctx context.Context, run argosrc.Runner) []string {
	var out []string
	for _, c := range [][]string{{"helm", "version", "--short"}, {"kustomize", "version"}, {"git", "--version"}} {
		b, err := run(ctx, ".", nil, c[0], c[1:]...)
		if err != nil {
			out = append(out, c[0]+": not available")
			continue
		}
		out = append(out, c[0]+" "+strings.TrimSpace(string(b)))
	}
	return out
}

// RunParity compares every Application, o.Parallel at a time.
func RunParity(ctx context.Context, o ParityOpts, apps []Application) *Report {
	var todo []Application
	for _, a := range apps {
		if o.Only == "" || strings.Contains(a.Metadata.Name, o.Only) {
			todo = append(todo, a)
		}
	}
	rep := &Report{Results: make([]AppResult, len(todo)), Counts: map[string]int{}}
	parallel := max(o.Parallel, 1)
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, a := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, o.Timeout)
			defer cancel()
			r := CompareApp(cctx, o, a)
			mu.Lock()
			rep.Results[i] = r
			if o.Progress != nil {
				fmt.Fprintf(o.Progress, "%-14s %s %s\n", r.Status, o.Instance, r.Name)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	for _, r := range rep.Results {
		rep.Counts[r.Status]++
	}
	return rep
}

func (r *Report) summary() string {
	var parts []string
	for _, s := range []string{StatusIdentical, StatusDiffers, StatusUnsupported, StatusNotComparable, StatusError} {
		parts = append(parts, fmt.Sprintf("%s %d", s, r.Counts[s]))
	}
	objs := 0
	for _, x := range r.Results {
		if x.Status == StatusIdentical {
			objs += x.Objects
		}
	}
	return fmt.Sprintf("%d Applications: %s; %d objects hash-identical", len(r.Results), strings.Join(parts, ", "), objs)
}

// Text is the report for a terminal: the counts, then every Application that is not identical.
func (r *Report) Text() string {
	var b strings.Builder
	b.WriteString(r.summary() + "\n")
	if len(r.Tools) > 0 {
		b.WriteString("tools: " + strings.Join(r.Tools, "; ") + "\n")
	}
	for _, x := range r.Results {
		if x.Status != StatusIdentical {
			fmt.Fprintf(&b, "%s %s/%s: %s\n", x.Status, x.Instance, x.Name, x.Detail)
		}
		if len(x.ScopeMismatch) > 0 {
			fmt.Fprintf(&b, "scope %s/%s: kinds the plugin scopes wrongly: %s\n", x.Instance, x.Name, strings.Join(x.ScopeMismatch, ", "))
		}
	}
	return b.String()
}

// Markdown is the report for docs and a PR body.
func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString(r.summary() + ".\n\n")
	if len(r.Tools) > 0 {
		b.WriteString("Renderer tools: " + strings.Join(r.Tools, "; ") + ".\n\n")
	}
	b.WriteString("| Instance | Applications | identical | differs | unsupported | not comparable | error |\n|---|---|---|---|---|---|---|\n")
	byInst := map[string]*Report{}
	var order []string
	for _, x := range r.Results {
		if byInst[x.Instance] == nil {
			byInst[x.Instance] = &Report{Counts: map[string]int{}}
			order = append(order, x.Instance)
		}
		byInst[x.Instance].Counts[x.Status]++
		byInst[x.Instance].Results = append(byInst[x.Instance].Results, x)
	}
	for _, i := range order {
		c := byInst[i].Counts
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d |\n", i, len(byInst[i].Results), c[StatusIdentical], c[StatusDiffers], c[StatusUnsupported], c[StatusNotComparable], c[StatusError])
	}
	var rest []AppResult
	for _, x := range r.Results {
		if x.Status != StatusIdentical || len(x.ScopeMismatch) > 0 {
			rest = append(rest, x)
		}
	}
	if len(rest) > 0 {
		b.WriteString("\n| Application | Status | Detail |\n|---|---|---|\n")
		for _, x := range rest {
			d := x.Detail
			if len(x.ScopeMismatch) > 0 {
				d += " [scope: " + strings.Join(x.ScopeMismatch, ", ") + "]"
			}
			fmt.Fprintf(&b, "| %s/%s | %s | %s |\n", x.Instance, x.Name, x.Status, strings.ReplaceAll(strings.TrimSpace(d), "|", "\\|"))
		}
	}
	return b.String()
}
