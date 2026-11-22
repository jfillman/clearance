package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// The filesystem sandbox of the render steps (hardening W-34: X6). The sidecar mounts one secret, the clearance token
// (a projected service-account token that lets its holder register changes as a verifier), and every step it runs
// (git, helm, kustomize) runs as the same user. A chart or a kustomization is tenant input, and Helm templates and
// Kustomize plugins read files: without a sandbox, `{{ .Files }}`-style tricks, a symlink the containment checks miss,
// or a tool bug would put the token into a rendered object or a log.
//
// Every step is therefore started through a small shim (this binary, re-executed with shimArg) that, before it execs
// the real tool, applies:
//   - Landlock (Linux 5.13+, unprivileged: no capability, no user namespace, no node change; containerd's and Docker's
//     default seccomp profiles allow its three system calls): the step may read only the system directories, its tool's
//     own directory, HOME, the plugin's source directory, and its render's own scratch directory (the only place it may
//     write); everything else, the token's directory and the service-account directory included, answers EACCES. It
//     also stops the step from ptrace-reading the plugin's memory. The rules are inherited by everything the step starts.
//   - the per-step resource limits (limits.go): RLIMIT_CPU, RLIMIT_DATA and RLIMIT_FSIZE, set before the tool's first
//     instruction.
//
// CLEARANCE_CMP_FS_SANDBOX is try (default), require or off, as the network namespace's setting (netns.go): try uses
// Landlock when the kernel has it and otherwise renders without it, saying so once; require refuses to render
// without it; off never applies it. The resource limits do not depend on it.
const FSSandboxEnv = "CLEARANCE_CMP_FS_SANDBOX"

// shimArg is argv[1] of the shim; shimSpecEnv carries its instructions (removed before the tool runs).
const (
	shimArg     = "__clearance-sandbox-exec"
	shimSpecEnv = "CLEARANCE_CMP_SANDBOX_SPEC"
	// shimFailCode is the shim's exit code when it could not set up the sandbox (the tool never ran).
	shimFailCode = 125
	// shimLandlockPrefix starts the shim's setup-channel message when Landlock itself refused (try mode then runs the
	// step without it). It is read from that channel only, never from the tool's stderr.
	shimLandlockPrefix = "clearance-cmp sandbox: landlock: "
)

// ParseFSSandbox reads the setting's value; anything but the three exact values is an error.
func ParseFSSandbox(v string) (string, error) {
	switch v {
	case "", NetnsTry:
		return NetnsTry, nil
	case NetnsRequire, NetnsOff:
		return v, nil
	}
	return "", fmt.Errorf("%s is one of %q, %q or %q, got %q", FSSandboxEnv, NetnsTry, NetnsRequire, NetnsOff, v)
}

// sandboxSpec is what the shim applies before exec.
type sandboxSpec struct {
	CPU      uint64   `json:"cpu,omitempty"`   // RLIMIT_CPU, seconds
	Data     uint64   `json:"data,omitempty"`  // RLIMIT_DATA, bytes
	FSize    uint64   `json:"fsize,omitempty"` // RLIMIT_FSIZE, bytes
	Landlock bool     `json:"landlock,omitempty"`
	RX       []string `json:"rx,omitempty"` // read and execute beneath
	RO       []string `json:"ro,omitempty"` // read beneath
	RW       []string `json:"rw,omitempty"` // read, write, create and remove beneath
	Dev      []string `json:"dev,omitempty"`
	ErrFD    int      `json:"errfd,omitempty"` // the setup-error channel's fd (setupFD), 0 none
}

// systemRX are the directories a step may read and execute from: the tools, their libraries and their configuration
// (certificates, passwd, git's and ssh's system files). Nothing under /var or /run, where Kubernetes mounts secrets.
var systemRX = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"}

// systemRO are read only: the Go runtime and git read a few files under them.
var systemRO = []string{"/proc", "/sys"}

var fsb struct {
	sync.Mutex
	mode   string
	token  string // the token file, which no root may contain
	probed bool
	usable bool
	abi    int // the kernel's Landlock ABI, once probed usable
	cause  error
	warned bool
}

// fsWarn is where the one-line fallback notice goes.
var fsWarn io.Writer = os.Stderr

// landlockProbe is the availability check; a test replaces it. It returns the kernel's ABI.
var landlockProbe = probeLandlock

// probeLandlock asks the kernel for its Landlock ABI, then installs a ruleset for real in a disposable child (the shim
// running `true`): a seccomp profile that allows creating a ruleset but not restrict_self, or a kernel that refuses the
// rules, is found here, before any render, and not by every render under require.
func probeLandlock() (int, error) {
	abi, err := landlockABI()
	if err != nil {
		return 0, err
	}
	self, err := shimPath()
	if err != nil {
		return 0, fmt.Errorf("landlock: %w", err)
	}
	tru, err := exec.LookPath("true")
	if err != nil {
		return abi, nil // nothing to probe with: the ABI answer stands, and a step's own setup failure still reports
	}
	spec := sandboxSpec{Landlock: true, RX: append(append([]string{}, systemRX...), filepath.Dir(tru)), Dev: []string{"/dev"}}
	env, err := spec.env()
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(self, shimArg, tru)
	cmd.Env = []string{env}
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("landlock: installing a ruleset failed in a probe (%v): %s", err, strings.TrimSpace(string(out)))
	}
	return abi, nil
}

// SetFSSandbox sets the mode and the token path to keep out, and forgets any earlier probe.
func SetFSSandbox(mode, tokenFile string) {
	fsb.Lock()
	defer fsb.Unlock()
	fsb.mode, fsb.token, fsb.probed, fsb.usable, fsb.cause, fsb.warned = mode, tokenFile, false, false, nil, false
}

func fsModeLocked() string {
	if fsb.mode == "" {
		return NetnsTry
	}
	return fsb.mode
}

func fsProbeLocked() {
	if fsb.probed {
		return
	}
	fsb.probed = true
	abi, err := landlockProbe()
	if err != nil {
		fsb.cause = err
		return
	}
	fsb.usable, fsb.abi = true, abi
}

// FSSandboxState is what the summary line and doctor report: on, off or unavailable.
func FSSandboxState() string {
	fsb.Lock()
	defer fsb.Unlock()
	if fsModeLocked() == NetnsOff {
		return "off"
	}
	fsProbeLocked()
	if fsb.usable {
		return "on"
	}
	return "unavailable"
}

// fsSandboxABI is the kernel's Landlock ABI once the probe found it usable (0 otherwise).
func fsSandboxABI() int {
	fsb.Lock()
	defer fsb.Unlock()
	return fsb.abi
}

// fsSandboxCause is why the probe said unavailable (nil when it did not).
func fsSandboxCause() error {
	fsb.Lock()
	defer fsb.Unlock()
	return fsb.cause
}

// fsSandboxFor says whether this step gets Landlock: an error in require mode when it cannot.
func fsSandboxFor(name string) (bool, error) {
	fsb.Lock()
	defer fsb.Unlock()
	if fsModeLocked() == NetnsOff {
		return false, nil
	}
	fsProbeLocked()
	if fsb.usable {
		return true, nil
	}
	if fsModeLocked() == NetnsRequire {
		return false, errNoFSSandbox(name, fsb.cause)
	}
	fsWarnOnceLocked(fsb.cause)
	return false, nil
}

// fsShimRefused handles a shim that reported Landlock refused after a good probe: require stops, try remembers it,
// warns, and the caller runs the step again without Landlock.
func fsShimRefused(name string, cause error) error {
	fsb.Lock()
	defer fsb.Unlock()
	if fsModeLocked() == NetnsRequire {
		return errNoFSSandbox(name, cause)
	}
	fsb.probed, fsb.usable, fsb.cause = true, false, cause
	fsWarnOnceLocked(cause)
	return errRetryBare
}

func fsWarnOnceLocked(cause error) {
	if fsb.warned {
		return
	}
	fsb.warned = true
	fmt.Fprintf(fsWarn, "clearance: WARNING render steps run WITHOUT the filesystem sandbox (%v): helm, kustomize and git can read "+
		"every file this user can, the clearance token included. Run on a kernel with Landlock (Linux 5.13+, lsm= includes landlock) "+
		"and set %s=%s (docs/install-argocd-plugin.md)\n", cause, FSSandboxEnv, NetnsRequire)
}

func errNoFSSandbox(name string, cause error) error {
	return &netnsError{fmt.Errorf("refusing to run %s: the filesystem sandbox is unavailable (%v) and %s=%s. It needs Landlock: "+
		"Linux 5.13 or later with landlock in the kernel's active LSMs, and a seccomp profile that allows landlock_create_ruleset, "+
		"landlock_add_rule and landlock_restrict_self (containerd's and Docker's RuntimeDefault do). Set %s=%s to render without it",
		name, cause, FSSandboxEnv, NetnsRequire, FSSandboxEnv, NetnsTry)}
}

// tokenUnder reports whether the token file lies in dir or beneath it (by resolved paths when they resolve).
func tokenUnder(token, dir string) bool {
	if token == "" || dir == "" {
		return false
	}
	t, d := resolved(token), resolved(dir)
	return t == d || strings.HasPrefix(t, strings.TrimSuffix(d, "/")+"/")
}

func resolved(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	// Resolve the deepest part that exists (a token not yet written, /etc being /private/etc), and keep the rest.
	rest := ""
	for q := filepath.Clean(p); ; {
		if r, err := filepath.EvalSymlinks(q); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(q)
		if parent == q {
			return filepath.Clean(p)
		}
		rest = filepath.Join(filepath.Base(q), rest)
		q = parent
	}
}

// systemRootsHolding is the list of fixed roots a step may read that would contain the token: a configuration the
// sandbox cannot protect, which ParseConfig refuses.
func systemRootsHolding(token string) []string {
	var hit []string
	for _, d := range append(append(append([]string{}, systemRX...), systemRO...), "/dev", os.Getenv("HOME")) {
		if d != "" && d != "/" && tokenUnder(token, d) {
			hit = append(hit, d)
		}
	}
	return hit
}

// buildSpec is the shim's instructions for one step: the limits, and with Landlock the roots it may use. A root that
// would contain the token file is left out, whatever it is (ParseConfig refuses the fixed ones at start).
func buildSpec(lim Limits, landlock bool, tool, dir, scratch string, b *budget) sandboxSpec {
	s := sandboxSpec{CPU: uint64((lim.CPU + 999_999_999) / 1_000_000_000), Data: uint64(lim.Memory), FSize: uint64(lim.Temp), Landlock: landlock}
	if !landlock {
		return s
	}
	fsb.Lock()
	token := fsb.token
	fsb.Unlock()
	keep := func(list []string, p ...string) []string {
		for _, d := range p {
			if d != "" && !tokenUnder(token, d) {
				list = append(list, d)
			}
		}
		return list
	}
	s.RX = keep(s.RX, systemRX...)
	s.RX = keep(s.RX, filepath.Dir(tool))
	s.RO = keep(s.RO, systemRO...)
	s.RO = keep(s.RO, os.Getenv("HOME"), dir)
	s.RW = keep(s.RW, scratch)
	if b != nil {
		s.RO = keep(s.RO, b.src)
		s.RW = keep(s.RW, b.root)
	} else {
		// A step outside a render (the chart tag lookup before it, the parity tool, a test) has no render root: it may use
		// the system's temporary directory, unless the token is in it.
		s.RW = keep(s.RW, os.TempDir())
	}
	s.Dev = keep(s.Dev, "/dev")
	return s
}

func (s sandboxSpec) env() (string, error) {
	b, err := json.Marshal(s)
	return shimSpecEnv + "=" + string(b), err
}

// maybeShim runs the shim when this process was started as one; it never returns then. main and TestMain call it first.
func maybeShim() {
	if len(os.Args) > 1 && os.Args[1] == shimArg {
		os.Exit(shimMain(os.Args[2:]))
	}
}

// shimMain is the shim: args are the tool's resolved path and its arguments.
func shimMain(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "clearance-cmp sandbox: no command")
		return shimFailCode
	}
	raw := os.Getenv(shimSpecEnv)
	var spec sandboxSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		fmt.Fprintln(os.Stderr, "clearance-cmp sandbox: bad spec:", err)
		return shimFailCode
	}
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, shimSpecEnv+"=") {
			env = append(env, kv)
		}
	}
	err := shimExec(spec, args[0], args, env) // returns only on failure
	fmt.Fprintln(os.Stderr, err)
	return shimFailCode
}
