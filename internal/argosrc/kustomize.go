package argosrc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// kustomize renders a Kustomize source: the same `kustomize edit` commands, in the same order, that Argo CD runs in
// the source's directory for the Application's kustomize options (util/kustomize Build), then `kustomize build`.
// The directory is the renderer's own checkout, so the edits never touch anything shared.
//
// Not rendered, and refused: kustomize.patches (Argo CD rewrites kustomization.yaml itself), kustomize.version (a
// different binary), and a build option that turns on Helm chart inflation (a network fetch with its own
// repositories and credentials).
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
	if strings.Contains(req.KustomizeBuildOptions, "--enable-helm") || strings.Contains(req.KustomizeBuildOptions, "--helm-") {
		return nil, unsupported(pos, "kustomize with Helm chart inflation", "kustomize.buildOptions enables --enable-helm")
	}
	edit := func(args ...string) error {
		_, err := st.o.Run(ctx, appPath, nil, "kustomize", append([]string{"edit"}, args...)...)
		if err != nil {
			return fmt.Errorf("source %d: kustomize %s: %w", pos, strings.Join(args[:2], " "), err)
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
				return nil, fmt.Errorf("source %d: %w", pos, err)
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
	args = append(args, strings.Fields(req.KustomizeBuildOptions)...)
	out, err := st.o.Run(ctx, root, nil, "kustomize", args...)
	if err != nil {
		return nil, fmt.Errorf("source %d: kustomize build: %w", pos, err)
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
