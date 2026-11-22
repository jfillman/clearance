package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/jfillman/clearance/internal/argosrc"
)

// Exec runs a program and returns its stdout; a failure carries its stderr.
type Exec func(ctx context.Context, dir, name string, args ...string) ([]byte, error)

// OSExec is Exec on the real machine. No shell is involved: arguments are never parsed by one.
func OSExec(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	return OSRun(ctx, dir, nil, name, args...)
}

// OSRun is OSExec with extra environment (the generic renderer's: Helm's cache directories, git's allowed protocols).
//
// Every step runs under the render's limits (limits.go) and, where the kernel has it, the filesystem sandbox
// (fssandbox.go): it is started through this binary's shim, which sets the resource limits and the Landlock rules and
// then execs the tool. Its stdout is capped, its stderr kept to its first 64 KiB, and the render's scratch directory is
// measured after it. A bound it goes over is a *LimitError.
func OSRun(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	b := budgetFrom(ctx)
	lim := DefaultLimits()
	if b != nil {
		lim = b.lim
	}
	// The step's own scratch, under the render's root: its TMPDIR, and the network-off files.
	scratch, err := os.MkdirTemp(workDir(ctx), "clearance-step-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	if argosrc.NetworkOffFor(name, args) { // helm template and kustomize build read files only (argosrc/sandbox.go)
		off, err := argosrc.NetworkOffEnv(scratch)
		if err != nil {
			return nil, err
		}
		env = append(append([]string{}, env...), off...)
	}
	// The sidecar's environment carries no credential for these tools: git and helm get a bare one. GOMEMLIMIT makes
	// the Go tools (helm, kustomize) collect before they reach the memory bound rather than fail at it.
	fullEnv := append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1",
		"TMPDIR=" + scratch, "GOMEMLIMIT=" + strconv.FormatInt(lim.Memory/4*3, 10)}, env...)
	tool, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, firstArg(args), err)
	}
	landlock, err := fsSandboxFor(name)
	if err != nil {
		return nil, err
	}
	self, selfErr := shimPath()
	if selfErr != nil && landlock {
		if err := fsShimRefused(name, selfErr); err != errRetryBare {
			return nil, err
		}
		landlock = false
	}
	var (
		out  *capWriter
		errb *headWriter
		ps   *os.ProcessState
	)
	// A render step runs in a user+network namespace of its own when the mode and the kernel allow (netns.go).
	run := func(isolated, landlock bool) error {
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		out, errb = &capWriter{max: lim.Output, over: cancel}, &headWriter{max: 64 << 10}
		var cmd *exec.Cmd
		if selfErr == nil {
			spec, err := buildSpec(lim, landlock, tool, dir, scratch, b).env()
			if err != nil {
				return err
			}
			cmd = exec.CommandContext(sctx, self, append([]string{shimArg, tool}, args...)...)
			cmd.Env = append(append([]string{}, fullEnv...), spec)
		} else {
			cmd = exec.CommandContext(sctx, tool, args...)
			cmd.Env = fullEnv
		}
		cmd.Dir = dir
		cmd.Stdout, cmd.Stderr = out, errb
		cmd.WaitDelay = 2 * time.Second // a killed step's children cannot hold its pipes open past this
		if isolated {
			ok, err := sandboxStart(cmd, name, args)
			if err != nil {
				return err
			}
			isolated = ok
		}
		err := cmd.Start()
		if err != nil && isolated && startFailedForNetns(err) {
			return noteStartRefused(name, err)
		}
		if err == nil {
			err = cmd.Wait()
		}
		ps = cmd.ProcessState
		if err != nil && landlock && ps != nil && ps.ExitCode() == shimFailCode && strings.HasPrefix(errb.String(), shimLandlockPrefix) {
			return fsShimRefused(name, errors.New(strings.TrimSpace(strings.TrimPrefix(errb.String(), "clearance-cmp sandbox: "))))
		}
		return err
	}
	isolated := true
	for attempt := 0; attempt < 3; attempt++ {
		err = run(isolated, landlock)
		if err != errRetryBare {
			break
		}
		// try mode: the kernel refused the namespace, or Landlock, after a good probe. Once each, at most.
		if NetnsState() != "on" {
			isolated = false
		}
		if FSSandboxState() != "on" {
			landlock = false
		}
	}
	step := name + " " + firstArg(args)
	if err != nil {
		var ne *netnsError
		if errors.As(err, &ne) {
			return nil, err
		}
		if le := stepLimit(lim, step, out, errb.String(), ps, ctx.Err() == nil, selfErr == nil); le != nil {
			return nil, le
		}
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 2000 {
			msg = msg[:2000] + "..."
		}
		return nil, fmt.Errorf("%s: %w: %s", step, err, msg)
	}
	if b != nil {
		if n := dirSize(b.root); n > lim.Temp {
			return nil, &LimitError{Limit: LimitTemp, Setting: EnvMaxTemp, Bound: FormatSize(lim.Temp), Step: step,
				Detail: fmt.Sprintf("left the render's scratch directory at %s", FormatSize(n))}
		}
	}
	return out.buf, nil
}

// stepLimit says which bound, if any, stopped a failed step. limited is whether the shim set the kernel limits.
func stepLimit(lim Limits, step string, out *capWriter, stderr string, ps *os.ProcessState, ctxLive, limited bool) *LimitError {
	if out != nil && out.full {
		return &LimitError{Limit: LimitOutput, Setting: EnvMaxOutput, Bound: FormatSize(lim.Output), Step: step,
			Detail: fmt.Sprintf("wrote more than %s to stdout", FormatSize(lim.Output))}
	}
	if !limited || ps == nil {
		return nil
	}
	cpu, rss := stepUsage(ps)
	switch signalLimit(ps) {
	case LimitCPU:
		return &LimitError{Limit: LimitCPU, Setting: EnvMaxCPU, Bound: lim.CPU.String(), Step: step,
			Detail: fmt.Sprintf("used %.1fs of CPU", cpu)}
	case LimitTemp:
		return &LimitError{Limit: LimitTemp, Setting: EnvMaxTemp, Bound: FormatSize(lim.Temp), Step: step,
			Detail: "tried to write a file larger than the bound"}
	case "killed":
		if ctxLive && cpu >= lim.CPU.Seconds() {
			return &LimitError{Limit: LimitCPU, Setting: EnvMaxCPU, Bound: lim.CPU.String(), Step: step,
				Detail: fmt.Sprintf("used %.1fs of CPU", cpu)}
		}
	}
	low := strings.ToLower(stderr)
	switch {
	// The Go runtime ("fatal error: runtime: cannot allocate memory", "out of memory allocating heap arena map"), git
	// and C tools ("malloc failed"), and a thread stack (it counts against RLIMIT_DATA: "pthread_create failed").
	case strings.Contains(low, "out of memory") || strings.Contains(low, "cannot allocate memory") || strings.Contains(low, "malloc failed") ||
		strings.Contains(low, "pthread_create failed"):
		d := "ran out of memory"
		if rss > 0 {
			d += fmt.Sprintf(" (peak resident %s)", FormatSize(rss&^(1<<20-1)))
		}
		return &LimitError{Limit: LimitMemory, Setting: EnvMaxMemory, Bound: FormatSize(lim.Memory), Step: step, Detail: d}
	case strings.Contains(low, "file too large"):
		return &LimitError{Limit: LimitTemp, Setting: EnvMaxTemp, Bound: FormatSize(lim.Temp), Step: step,
			Detail: "tried to write a file larger than the bound"}
	}
	return nil
}

// shimPath is this binary, which the shim is. Off Linux there is none.
func shimPath() (string, error) {
	if !shimSupported {
		return "", errors.New("the sandbox shim is Linux only")
	}
	selfOnce.Do(func() { selfExe, selfErr = os.Executable() })
	return selfExe, selfErr
}

var (
	selfOnce sync.Once
	selfExe  string
	selfErr  error
)

var errRetryBare = errors.New("retry without a network namespace")

func firstArg(a []string) string {
	if len(a) > 0 {
		return a[0]
	}
	return ""
}

// Rendered is what the customer's render produced.
type Rendered struct {
	Generic    bool                 // rendered from the Application's original sources (PARAM_SOURCES)
	Sources    []argosrc.Provenance // what each source resolved to (generic only)
	Release    string               // releaseTracking.releaseId of the value files (generic only; legacy reads the files itself)
	Manifests  []byte
	ChartRepo  string
	ChartTag   string
	ChartFetch string // the chart cache: hit, miss (fetched and kept) or off
	ChartMerge string // the peeled commit of the tag ("" when the chart is in the source directory)
}

// Render fetches the chart at its pinned tag (recording the peeled commit, not the tag, which a repository can
// move), then runs `helm template <Application> <chart> --namespace <destination>` with the gitops repository's
// value files and the platform's injected values last (as Glidepath's clearance-gate does), and, when asked,
// `kustomize build` of a directory beside it. srcDir is the plugin's source directory (the gitops repository).
func Render(ctx context.Context, run Exec, cfg Config, srcDir string) (*Rendered, error) {
	out := &Rendered{ChartRepo: cfg.ChartRepo, ChartTag: cfg.ChartRev}
	tmp, err := os.MkdirTemp(workDir(ctx), "clearance-cmp-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	chart := srcDir
	if cfg.ChartRepo != "" {
		dest := filepath.Join(tmp, "chart")
		// The chart cache (fetchcache.go) answers by the commit the tag resolves to now; a cfg.chartCommit hint is
		// what Generate already resolved for its own cache key.
		hint := cfg.chartCommit
		if hint == "" && !cfg.chartLooked && cfg.ChartCache.enabled() {
			hint = resolveChart(ctx, run, cfg.ChartRepo, cfg.ChartRev)
		}
		commit, how, err := cfg.ChartCache.Fetch(ctx, run, cfg.ChartRepo, cfg.ChartRev, hint, dest)
		if err != nil {
			return nil, err
		}
		out.ChartMerge, out.ChartFetch = commit, how
		chart = dest
	}
	chart = filepath.Join(chart, filepath.FromSlash(cfg.ChartPath))
	// Helm and Kustomize follow symlinks, and git keeps them: a link to a host file (a service-account token) would
	// put that file into the render. Every tree they read must resolve inside the repository it came from.
	chartRoot := srcDir
	if cfg.ChartRepo != "" {
		chartRoot = filepath.Join(tmp, "chart")
	}
	if err := argosrc.CheckSymlinksIn(chart, chartRoot); err != nil {
		return nil, fmt.Errorf("refused: the chart: %w", err)
	}

	args := []string{"template", cfg.AppName, chart, "--namespace", cfg.Destination}
	for _, f := range cfg.ValueFiles {
		p := filepath.Join(srcDir, filepath.FromSlash(f))
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() { // a missing one is skipped (ignoreMissingValueFiles)
			if real, err := filepath.EvalSymlinks(p); err != nil || !strings.HasPrefix(real+"/", realDir(srcDir)+"/") {
				return nil, fmt.Errorf("refused: value file %s resolves outside the repository", f)
			}
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
			if err := argosrc.CheckSymlinksIn(filepath.Join(srcDir, filepath.FromSlash(cfg.KustomizeDir)), srcDir); err != nil {
				return nil, fmt.Errorf("refused: kustomize %s: %w", cfg.KustomizeDir, err)
			}
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

// SourcesRequest is the generic renderer's request for this run: the Application as Argo CD itself would describe it
// to its own repo-server (name, destination namespace, project, the cluster's version and API versions).
func SourcesRequest(cfg Config) (argosrc.Request, error) {
	srcs, err := argosrc.ParseSources(cfg.Sources)
	if err != nil {
		return argosrc.Request{}, err
	}
	return argosrc.Request{AppName: cfg.AppName, Namespace: cfg.Destination, Project: cfg.Project, KubeVersion: cfg.KubeVersion,
		APIVersions: cfg.APIVersions, Sources: srcs, KustomizeBuildOptions: cfg.KustomizeBuildOptions}, nil
}

// RenderSources is the generic mode (G-ARGO-10b): render the Application's original sources as Argo CD would.
func RenderSources(ctx context.Context, run argosrc.Runner, cfg Config) (*Rendered, error) {
	req, err := SourcesRequest(cfg)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(workDir(ctx), "clearance-cmp-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	res, err := argosrc.Render(ctx, argosrc.Options{Run: run, Work: tmp}, req)
	if err != nil {
		return nil, err
	}
	return &Rendered{Manifests: res.Manifests, Generic: true, Sources: res.Sources, Release: argosrc.ReleaseIDFromValues(res.ValueDocs)}, nil
}

// realDir is dir with its symlinks resolved ("\x00", which no path starts with, when that fails).
func realDir(dir string) string {
	r, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "\x00"
	}
	return r
}
