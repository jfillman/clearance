// Command cmp-spike is the G-ARGO-1 spike's Config Management Plugin. It is NOT the G-ARGO-4 plugin: it registers
// nothing with a core, it keeps no cache, and it exists only to answer three questions on a real Argo CD 3.5
// repo-server: what a plugin source in a multi-source Application can see (spike a), whether a stamped
// clearance.hangar.io/rendered annotation survives to admission (spike b), and what a non-zero exit shows (G-ARGO-4's
// denial path).
//
// Modes (plugin parameter "mode"):
//
//	chart-here   the plugin source is the chart directory; value files come from the "valueFiles" parameter,
//	             which may name $appsrc/... paths the way a Helm source does
//	values-here  the plugin source is the values (gitops) repo; the chart is cloned from the "chartRepo"
//	             parameter at "chartRevision" (a tag), path "chartPath"
//	deny         exit 1 with a message, the way G-ARGO-4 refuses a tier-3 denial or an outage hold
//
// Every object is canonicalised (JSON with sorted keys, server-populated fields dropped), hashed, and stamped with
// clearance.hangar.io/rendered and clearance.hangar.io/grant; the tree root is the sha256 of the sorted
// "<apiVersion>/<kind>/<namespace>/<name> <hash>" lines. A ConfigMap carries what the plugin
// saw, so the spike can read it back from the cluster.
// The diag ConfigMap is named clearance-cmp-diag-<application>.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	annRendered = "clearance.hangar.io/rendered"
	annGrant    = "clearance.hangar.io/grant"
	annTree     = "clearance.hangar.io/tree"
)

func param(name string) string { return os.Getenv("PARAM_" + strings.ToUpper(name)) }

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "clearance-cmp-spike:", err)
		os.Exit(1)
	}
}

func run(out io.Writer) error {
	mode := param("mode")
	diag := map[string]any{"mode": mode}
	cwd, _ := os.Getwd()
	diag["cwd"] = cwd
	diag["files"] = listFiles(cwd, 2)
	env := []string{}
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		if strings.HasPrefix(k, "ARGOCD_") || strings.HasPrefix(k, "PARAM_") || strings.HasPrefix(k, "KUBE_") {
			env = append(env, e)
		}
	}
	sort.Strings(env)
	diag["env"] = env

	var chartDir string
	var valueFiles []string
	switch mode {
	case "deny":
		return errors.New("tier 3 change denied by policy (spike): DG-POLICY; nothing syncs")
	case "chart-here":
		chartDir = "."
		resolved := map[string]string{}
		for _, f := range splitList(param("valueFiles")) {
			p := f
			if strings.HasPrefix(f, "$") {
				// What a Helm source would do: $ref/... is the root of the ref source. Look for any trace of it.
				ref, rest, _ := strings.Cut(strings.TrimPrefix(f, "$"), "/")
				candidates := []string{filepath.Join(cwd, "..", ref, rest), filepath.Join("/tmp", ref, rest), os.ExpandEnv(f)}
				found := ""
				for _, c := range candidates {
					if _, err := os.Stat(c); err == nil {
						found = c
						break
					}
				}
				resolved[f] = found
				if found == "" {
					continue
				}
				p = found
			}
			if _, err := os.Stat(p); err == nil {
				valueFiles = append(valueFiles, p)
			}
		}
		diag["refResolution"] = resolved
	case "values-here":
		tmp, err := os.MkdirTemp("", "chart-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		repo, rev := param("chartRepo"), param("chartRevision")
		if repo == "" || rev == "" {
			return errors.New("values-here needs chartRepo and chartRevision")
		}
		cmd := exec.Command("git", "clone", "--quiet", "--depth", "1", "--branch", rev, repo, tmp)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("clone chart: %w", err)
		}
		head, _ := exec.Command("git", "-C", tmp, "rev-parse", "HEAD").Output()
		diag["chartCommit"] = strings.TrimSpace(string(head))
		chartDir = filepath.Join(tmp, param("chartPath"))
		for _, f := range splitList(param("valueFiles")) {
			if _, err := os.Stat(f); err == nil {
				valueFiles = append(valueFiles, f)
			}
		}
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	diag["valueFilesUsed"] = valueFiles

	args := []string{"template", envOr("ARGOCD_APP_NAME", "spike"), chartDir, "--namespace", envOr("ARGOCD_APP_NAMESPACE", "default")}
	for _, f := range valueFiles {
		args = append(args, "-f", f)
	}
	if v := param("valuesJson"); v != "" {
		f, err := os.CreateTemp("", "values-*.json")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if _, err := f.WriteString(v); err != nil {
			return err
		}
		f.Close()
		args = append(args, "-f", f.Name())
	}
	var rendered bytes.Buffer
	cmd := exec.Command("helm", args...)
	cmd.Stdout, cmd.Stderr = &rendered, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("helm template: %w", err)
	}

	objs, err := decodeAll(rendered.Bytes())
	if err != nil {
		return err
	}
	// Spike only: the scratch Argo CD is namespaced and cannot own a Namespace; the real argocd-apps can.
	if drop := splitList(param("dropKinds")); len(drop) > 0 {
		kept := objs[:0]
		for _, o := range objs {
			k, _ := o["kind"].(string)
			if !contains(drop, k) {
				kept = append(kept, o)
			}
		}
		objs = kept
	}
	grant := param("grant")
	lines := []string{}
	hashes := map[string]string{}
	for _, o := range objs {
		h, err := objectHash(o)
		if err != nil {
			return err
		}
		key := objectKey(o)
		lines = append(lines, key+" "+h)
		hashes[key] = h
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n") + "\n"))
	tree := "sha256:" + hex.EncodeToString(sum[:])
	for _, o := range objs {
		md := ensureMap(o, "metadata")
		ann := ensureMap(md, "annotations")
		ann[annRendered] = hashes[objectKey(o)]
		ann[annTree] = tree
		if grant != "" {
			ann[annGrant] = grant
		}
	}
	diag["tree"] = tree
	diag["objects"] = lines
	diagJSON, _ := json.Marshal(diag)
	objs = append(objs, map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "clearance-cmp-diag-" + envOr("ARGOCD_APP_NAME", "spike")},
		"data":     map[string]any{"diag.json": string(diagJSON)},
	})
	for _, o := range objs {
		b, err := json.Marshal(o)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "---\n%s\n", b)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func splitList(v string) []string {
	out := []string{}
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func listFiles(root string, depth int) []string {
	out := []string{}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if strings.Count(rel, string(filepath.Separator)) >= depth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == ".git" {
			return filepath.SkipDir
		}
		out = append(out, rel)
		return nil
	})
	if len(out) > 200 {
		out = append(out[:200], "...")
	}
	return out
}

func decodeAll(b []byte) ([]map[string]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	out := []map[string]any{}
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		if len(m) == 0 {
			continue
		}
		out = append(out, m)
	}
}

func ensureMap(m map[string]any, k string) map[string]any {
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	v := map[string]any{}
	m[k] = v
	return v
}

func objectKey(o map[string]any) string {
	md, _ := o["metadata"].(map[string]any)
	ns, _ := md["namespace"].(string)
	name, _ := md["name"].(string)
	return fmt.Sprintf("%v/%v/%s/%s", o["apiVersion"], o["kind"], ns, name)
}

// objectHash is the canonical hash: a deep copy without status, server-populated metadata and the clearance
// annotations, marshalled by encoding/json (map keys sorted).
func objectHash(o map[string]any) (string, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		return "", err
	}
	delete(c, "status")
	if md, ok := c["metadata"].(map[string]any); ok {
		for _, k := range []string{"creationTimestamp", "resourceVersion", "uid", "generation", "managedFields", "selfLink"} {
			delete(md, k)
		}
		if ann, ok := md["annotations"].(map[string]any); ok {
			delete(ann, annRendered)
			delete(ann, annGrant)
			delete(ann, annTree)
			if len(ann) == 0 {
				delete(md, "annotations")
			}
		}
	}
	cb, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cb)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
