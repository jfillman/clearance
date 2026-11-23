package argosrc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// kustomize renders a Kustomize source: the same `kustomize edit` commands, in the same order, that Argo CD runs in
// the source's directory for the Application's kustomize options (util/kustomize Build), then `kustomize build`.
// The directory is the renderer's own checkout, so the edits never touch anything shared.
//
// Not rendered, and refused: kustomize.patches (Argo CD rewrites kustomization.yaml itself), kustomize.version (a
// different binary), and any build option that is not on the allow list (checkBuildOptions).
func (st *state) kustomize(ctx context.Context, pos int, req Request, s Source, env Env, root, appPath string) ([]byte, error) {
	k := s.Kustomize
	if k == nil {
		k = &Kustomize{}
	}
	if k.Version != "" {
		return nil, unsupported(pos, "kustomize.version", fmt.Sprintf("%q: the plugin has one kustomize binary", k.Version))
	}
	if len(k.Patches) > 0 {
		return nil, unsupported(pos, "kustomize.patches", "Argo CD edits kustomization.yaml to add them; the plugin does not reproduce that")
	}
	buildOpts, err := checkBuildOptions(pos, req.KustomizeBuildOptions)
	if err != nil {
		return nil, err
	}
	netEnv, err := st.renderEnv(false) // kustomize fetches remote bases itself (git, HTTP): the network is off for it
	if err != nil {
		return nil, err
	}
	edit := func(args ...string) error {
		_, err := st.o.Run(ctx, appPath, netEnv, "kustomize", append([]string{"edit"}, args...)...)
		if err != nil {
			return srcErrorf("kustomize %s: %w", pos, strings.Join(args[:2], " "), err)
		}
		return nil
	}
	if k.NamePrefix != "" {
		if err := edit("set", "nameprefix", "--", k.NamePrefix); err != nil {
			return nil, err
		}
	}
	if k.NameSuffix != "" {
		if err := edit("set", "namesuffix", "--", k.NameSuffix); err != nil {
			return nil, err
		}
	}
	if len(k.Images) > 0 {
		args := []string{"set", "image"}
		for _, im := range k.Images {
			args = append(args, env.Subst(im))
		}
		if err := edit(args...); err != nil {
			return nil, err
		}
	}
	if len(k.Replicas) > 0 {
		args := []string{"set", "replicas"}
		for _, r := range k.Replicas {
			n, err := replicaCount(r.Count)
			if err != nil {
				return nil, srcErrorf("%w", pos, err)
			}
			args = append(args, fmt.Sprintf("%s=%d", r.Name, n))
		}
		if err := edit(args...); err != nil {
			return nil, err
		}
	}
	if len(k.CommonLabels) > 0 {
		args := []string{"add", "label"}
		if k.ForceCommonLabels {
			args = append(args, "--force")
		}
		if k.LabelWithoutSelector {
			args = append(args, "--without-selector")
		}
		if k.LabelIncludeTemplates {
			args = append(args, "--include-templates")
		}
		labels := map[string]string{}
		for n, v := range k.CommonLabels {
			labels[n] = env.Subst(v)
		}
		for _, n := range sortedKeys(labels) {
			args = append(args, n+":"+labels[n])
		}
		if err := edit(args...); err != nil {
			return nil, err
		}
	}
	if len(k.CommonAnnotations) > 0 {
		args := []string{"add", "annotation"}
		if k.ForceCommonAnnotations {
			args = append(args, "--force")
		}
		ann := map[string]string{}
		for n, v := range k.CommonAnnotations {
			if k.CommonAnnotationsEnvsubst {
				v = env.Subst(v)
			}
			ann[n] = v
		}
		for _, n := range sortedKeys(ann) {
			args = append(args, n+":"+ann[n])
		}
		if err := edit(args...); err != nil {
			return nil, err
		}
	}
	if k.Namespace != "" {
		if err := edit("set", "namespace", "--", k.Namespace); err != nil {
			return nil, err
		}
	}
	if len(k.Components) > 0 {
		found := k.Components
		if k.IgnoreMissingComponents {
			found = nil
			for _, c := range k.Components {
				if _, err := os.Stat(filepath.Join(appPath, c)); err == nil {
					found = append(found, c)
				}
			}
		}
		if len(found) > 0 {
			if err := edit(append([]string{"add", "component"}, found...)...); err != nil {
				return nil, err
			}
		}
	}
	args := []string{"build", appPath}
	args = append(args, buildOpts...)
	out, err := st.o.Run(ctx, root, netEnv, "kustomize", args...)
	if err != nil {
		return nil, srcErrorf("kustomize build: %w", pos, err)
	}
	return out, nil
}

// replicaCount is KustomizeReplica.GetIntCount: a number, or a string holding one.
func replicaCount(raw json.RawMessage) (int, error) {
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if n, err := strconv.Atoi(s); err == nil {
			return n, nil
		}
		return 0, fmt.Errorf("expected integer value for count. Received: %s", s)
	}
	return 0, fmt.Errorf("expected integer value for count. Received: %s", string(raw))
}

// buildOptionSpec is one allowed `kustomize build` option. values is the set of values it accepts; nil means a
// boolean flag (bare, or =true / =false).
type buildOptionSpec struct {
	values map[string]bool
}

// allowedBuildOptions is the whole set of kustomize build options the plugin passes on (kustomize 5.8.1). The build
// options arrive as a plugin parameter, which the Application's author controls, so this is an allow list: an option
// is here only when it cannot widen what kustomize reads or runs. Everything else is refused, notably
// --load-restrictor LoadRestrictionsNone (reads files outside the kustomization, such as the verifier token),
// --enable-alpha-plugins and --enable-exec (run code in the sidecar), --enable-helm and --helm-* (chart inflation),
// --mount, --network and --network-name (container function runtimes), --env (passes environment through) and
// --output (writes a file). Adding to this list is a security decision.
var allowedBuildOptions = map[string]buildOptionSpec{
	"--reorder":                {values: map[string]bool{"legacy": true, "none": true}},
	"--enable-managedby-label": {},
	"--load-restrictor":        {values: map[string]bool{"LoadRestrictionsRootOnly": true}}, // the default
}

// checkBuildOptions parses the build options (--flag, --flag=value and --flag value forms) and returns the tokens to
// pass to `kustomize build`, unchanged. Anything that is not an allow-listed option with an allowed value is an
// UnsupportedError naming it; nothing runs.
func checkBuildOptions(pos int, raw string) ([]string, error) {
	toks := strings.Fields(raw)
	var out []string
	refuse := func(tok, why string) error {
		return unsupported(pos, "kustomize build option "+strconv.Quote(tok),
			why+"; only allow-listed options are accepted ("+allowedBuildOptionList()+")")
	}
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		name, val, hasVal := strings.Cut(tok, "=")
		spec, ok := allowedBuildOptions[name]
		if !ok || !strings.HasPrefix(tok, "--") {
			return nil, refuse(tok, "it is not an allowed option")
		}
		if spec.values == nil { // boolean
			if hasVal && val != "true" && val != "false" {
				return nil, refuse(tok, "a boolean option takes only true or false")
			}
			out = append(out, tok)
			continue
		}
		if !hasVal {
			if i+1 >= len(toks) {
				return nil, refuse(tok, "the option needs a value")
			}
			i++
			val = toks[i]
			out = append(out, tok, val)
		} else {
			out = append(out, tok)
		}
		if !spec.values[val] {
			return nil, refuse(tok+" "+val, "the value is not allowed")
		}
	}
	return out, nil
}

func allowedBuildOptionList() string {
	var parts []string
	for _, n := range sortedSpecNames() {
		spec := allowedBuildOptions[n]
		if spec.values == nil {
			parts = append(parts, n)
			continue
		}
		var vs []string
		for v := range spec.values {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		parts = append(parts, n+" "+strings.Join(vs, "|"))
	}
	return strings.Join(parts, ", ")
}

func sortedSpecNames() []string {
	var ns []string
	for n := range allowedBuildOptions {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return ns
}
