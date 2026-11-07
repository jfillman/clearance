package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Exec runs a program and returns its stdout; a failure carries its stderr.
type Exec func(ctx context.Context, dir, name string, args ...string) ([]byte, error)

// OSExec is Exec on the real machine. No shell is involved: arguments are never parsed by one.
func OSExec(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	// The sidecar's environment carries no credential for these tools: git and helm get a bare one.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1"}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 2000 {
			msg = msg[:2000] + "..."
		}
		return nil, fmt.Errorf("%s %s: %w: %s", name, firstArg(args), err, msg)
	}
	return out.Bytes(), nil
}

func firstArg(a []string) string {
	if len(a) > 0 {
		return a[0]
	}
	return ""
}

// Rendered is what the customer's render produced.
type Rendered struct {
	Manifests  []byte
	ChartRepo  string
	ChartTag   string
	ChartMerge string // the peeled commit of the tag ("" when the chart is in the source directory)
}

// Render fetches the chart at its pinned tag (recording the peeled commit, not the tag, which a repository can
// move), then runs `helm template <Application> <chart> --namespace <destination>` with the gitops repository's
// value files and the platform's injected values last (as Glidepath's clearance-gate does), and, when asked,
// `kustomize build` of a directory beside it. srcDir is the plugin's source directory (the gitops repository).
func Render(ctx context.Context, run Exec, cfg Config, srcDir string) (*Rendered, error) {
	out := &Rendered{ChartRepo: cfg.ChartRepo, ChartTag: cfg.ChartRev}
	tmp, err := os.MkdirTemp("", "clearance-cmp-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	chart := srcDir
	if cfg.ChartRepo != "" {
		dest := filepath.Join(tmp, "chart")
		if _, err := run(ctx, tmp, "git", "clone", "--quiet", "--depth", "1", "--branch", cfg.ChartRev, "--", cfg.ChartRepo, dest); err != nil {
			return nil, fmt.Errorf("fetch the chart at %s: %w", cfg.ChartRev, err)
		}
		sha, err := run(ctx, dest, "git", "rev-parse", "HEAD^{commit}")
		if err != nil {
			return nil, fmt.Errorf("peel the chart tag: %w", err)
		}
		out.ChartMerge = strings.TrimSpace(string(sha))
		if !sha40.MatchString(out.ChartMerge) {
			return nil, fmt.Errorf("the chart tag %s peeled to %q, not a commit", cfg.ChartRev, out.ChartMerge)
		}
		chart = dest
	}
	chart = filepath.Join(chart, filepath.FromSlash(cfg.ChartPath))

	args := []string{"template", cfg.AppName, chart, "--namespace", cfg.Destination}
	for _, f := range cfg.ValueFiles {
		p := filepath.Join(srcDir, filepath.FromSlash(f))
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() { // a missing one is skipped (ignoreMissingValueFiles)
			args = append(args, "-f", p)
		}
	}
	if cfg.ValuesJSON != "" {
		p := filepath.Join(tmp, "injected.json")
		if err := os.WriteFile(p, []byte(cfg.ValuesJSON), 0o600); err != nil {
			return nil, err
		}
		args = append(args, "-f", p)
	}
	helm, err := run(ctx, srcDir, "helm", args...)
	if err != nil {
		return nil, fmt.Errorf("helm template: %w", err)
	}
	out.Manifests = helm
	if cfg.KustomizeDir != "" {
		if st, err := os.Stat(filepath.Join(srcDir, filepath.FromSlash(cfg.KustomizeDir))); err == nil && st.IsDir() {
			k, err := run(ctx, srcDir, "kustomize", "build", filepath.Join(srcDir, filepath.FromSlash(cfg.KustomizeDir)))
			if err != nil {
				return nil, fmt.Errorf("kustomize build: %w", err)
			}
			out.Manifests = append(append(append([]byte{}, helm...), []byte("\n---\n")...), k...)
		}
	}
	return out, nil
}

// releaseFromValues is releaseTracking.releaseId of the value files (the last file that sets it wins, as Helm merges
// them): the release id for an app whose chart renders no hangar.io/release-id (no Rollout). "" when none sets one.
// Not part of the rendered objects, so the tree digest does not bind it: the stamp built from it is only claimed.
func releaseFromValues(cfg Config, srcDir string) string {
	id := ""
	for _, f := range cfg.ValueFiles {
		raw, err := os.ReadFile(filepath.Join(srcDir, filepath.FromSlash(f)))
		if err != nil {
			continue
		}
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
