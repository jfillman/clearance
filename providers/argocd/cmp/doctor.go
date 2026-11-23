package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/jfillman/clearance/client"
)

// `clearance-cmp doctor` is the install preflight (docs/install-argocd-plugin.md, "Run doctor first"): it reads the
// sidecar's own environment, checks every setting and everything the plugin needs from its pod, prints one line per
// check and exits non-zero when any check fails. It never prints the token, registers nothing with the core (its one
// authenticated call is a read of a change that does not exist) and writes only a probe file inside the cache
// directory.

// Doctor levels.
const (
	levelOK   = "ok"
	levelWarn = "warn"
	levelFail = "fail"
)

// DefaultPluginDir is where the cmp-server of the repo-server's copyutil binary creates the plugin socket.
const DefaultPluginDir = "/home/argocd/cmp-server/plugins"

// cmpServerBinary is what copyutil puts in the shared var-files volume and the sidecar's command runs.
const cmpServerBinary = "/var/run/argocd/argocd-cmp-server"

// perRunVars are what Argo CD sets for one `generate` run, not on the container: a doctor run has none of them, so
// a placeholder stands in (the rules are ParseConfig's; the per-run values are not the sidecar's to get right).
var perRunVars = map[string]string{
	"ARGOCD_APP_NAME": "doctor", "ARGOCD_APP_NAMESPACE": "doctor", "PARAM_APP": "doctor", "PARAM_ENV": "doctor", "PARAM_CLUSTER": "doctor",
}

// Check is one line of the report.
type Check struct {
	Level string // ok, warn or fail
	Name  string
	Msg   string
	Fix   string // what to do about a warn or a fail
}

// DoctorEnv is everything the checks touch, so a test can hand them a fake environment.
type DoctorEnv struct {
	Get       func(string) string
	LookPath  func(string) (string, error)
	Run       func(ctx context.Context, name string, args ...string) (string, error) // a tool's combined output
	PluginDir string
	CmpServer string // path of argocd-cmp-server
	Timeout   time.Duration
	FreeBytes func(dir string) (int64, bool) // free space of the volume holding dir; false when it cannot be read
	ReadFile  func(string) ([]byte, error)   // the container's cgroup files (doctor_limits.go); nil is os.ReadFile
}

func osDoctorEnv() DoctorEnv {
	return DoctorEnv{Get: os.Getenv, LookPath: exec.LookPath, PluginDir: DefaultPluginDir, CmpServer: cmpServerBinary, Timeout: 10 * time.Second, FreeBytes: freeBytes,
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			return strings.TrimSpace(string(out)), err
		}}
}

func doctorMain(args []string, stdout, stderr io.Writer) int {
	env := osDoctorEnv()
	fs := flag.NewFlagSet("clearance-cmp doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&env.PluginDir, "plugin-dir", env.PluginDir, "the directory the cmp-server creates the plugin socket in")
	fs.DurationVar(&env.Timeout, "timeout", env.Timeout, "how long one network call or tool version command may take")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: clearance-cmp doctor [--plugin-dir DIR] [--timeout DURATION]\n\n"+
			"Checks the sidecar's settings and what the plugin needs from its pod, using this process's environment.\n"+
			"Prints one line per check (ok, warn or fail, with the fix); exits 1 if any check fails.")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	if env.Timeout <= 0 {
		fmt.Fprintln(stderr, "clearance-cmp doctor: --timeout must be a positive duration")
		return 2
	}
	return RunDoctor(context.Background(), env, stdout)
}

// RunDoctor runs every check, prints the report and returns the exit code: 0 with no failure, 1 otherwise.
func RunDoctor(ctx context.Context, env DoctorEnv, out io.Writer) int {
	checks := Doctor(ctx, env)
	var n = map[string]int{}
	for _, c := range checks {
		n[c.Level]++
		line := fmt.Sprintf("%-5s %-14s %s", c.Level, c.Name, c.Msg)
		if c.Fix != "" && c.Level != levelOK {
			line += "  fix: " + c.Fix
		}
		fmt.Fprintln(out, line)
	}
	fmt.Fprintf(out, "doctor: %d ok, %d warn, %d fail\n", n[levelOK], n[levelWarn], n[levelFail])
	if n[levelFail] > 0 {
		return 1
	}
	return 0
}

// Doctor runs every check and returns them in order.
func Doctor(ctx context.Context, env DoctorEnv) []Check {
	var out []Check
	add := func(level, name, msg, fix string) { out = append(out, Check{level, name, msg, fix}) }
	cfg := doctorSettings(env, add)
	tokenOK := doctorToken(env, cfg, add)
	doctorCore(ctx, env, cfg, tokenOK, add)
	doctorRepos(cfg, add)
	doctorCache(cfg, add)
	doctorCaches(env, add)
	doctorTools(ctx, env, add)
	doctorNetns(env, add)
	doctorFSSandbox(env, add)
	doctorLimits(env, cfg, add)
	doctorMetrics(env, add)
	doctorSocket(env, add)
	return out
}

// doctorSettings reports every problem ParseConfig would report, not only the first. The per-run variables Argo CD
// sets (ARGOCD_APP_*, PARAM_*) are given placeholders when absent, and the two settings ParseConfig stops at the first
// error for (the namespace mode and the durations) are checked one by one here and blanked for the call.
func doctorSettings(env DoctorEnv, add func(level, name, msg, fix string)) Config {
	good := true
	bad := func(name, msg, fix string) { add(levelFail, name, msg, fix); good = false }
	blank := map[string]bool{}
	if _, err := ParseNetns(env.Get(NetnsEnv)); err != nil {
		bad("setting", err.Error(), "set "+NetnsEnv+" to try, require or off, or remove it")
		blank[NetnsEnv] = true
	}
	if _, err := ParseFSSandbox(env.Get(FSSandboxEnv)); err != nil {
		bad("setting", err.Error(), "set "+FSSandboxEnv+" to try, require or off, or remove it")
		blank[FSSandboxEnv] = true
	}
	if _, err := ParseLKG(env.Get(LKGEnv)); err != nil {
		bad("setting", err.Error(), "set "+LKGEnv+" to off or on, or remove it (off)")
		blank[LKGEnv] = true
	}
	for _, d := range []string{"CLEARANCE_CMP_CACHE_TTL", "CLEARANCE_WAIT_TIMEOUT", "CLEARANCE_CMP_CALL_TIMEOUT"} {
		if v := env.Get(d); v != "" {
			if p, err := time.ParseDuration(v); err != nil || p <= 0 {
				bad("setting", fmt.Sprintf("%s is a positive duration, got %q", d, v), "write it like 2m or 30s, or remove it")
				blank[d] = true
			}
		}
	}
	for _, n := range []string{"CLEARANCE_CMP_CHART_CACHE_MAX_BYTES", "CLEARANCE_CMP_CHART_CACHE_MAX_ENTRIES"} {
		if v := strings.TrimSpace(env.Get(n)); v != "" {
			if p, err := strconv.ParseInt(v, 10, 64); err != nil || p < 0 {
				bad("setting", fmt.Sprintf("%s is a non-negative integer (0 turns the cache off), got %q", n, v), "write a whole number of bytes or entries, 0 to turn the chart cache off, or remove it")
				blank[n] = true
			}
		}
	}
	if v := strings.TrimSpace(env.Get("CLEARANCE_CMP_RENDER_CACHE_TTL")); v != "" && v != "0" && v != "0s" {
		if p, err := time.ParseDuration(v); err != nil || p <= 0 {
			bad("setting", fmt.Sprintf("CLEARANCE_CMP_RENDER_CACHE_TTL is a positive duration (0 turns the cache off), got %q", v), "write it like 15m, 0 to turn the render cache off, or remove it")
			blank["CLEARANCE_CMP_RENDER_CACHE_TTL"] = true
		}
	}
	get := func(k string) string {
		if blank[k] {
			return ""
		}
		if v := env.Get(k); v != "" {
			return v
		}
		return perRunVars[k]
	}
	cfg, err := ParseConfig(get)
	if err != nil {
		for _, e := range flatten(err) {
			bad("setting", e.Error(), settingFix(e.Error()))
		}
	}
	if good {
		add(levelOK, "settings", "every sidecar setting is present and well formed (the per-run ARGOCD_APP_* and PARAM_* variables are set by Argo CD for each render and are not checked here)", "")
	}
	if cfg.WaitImage == "" {
		add(levelWarn, "wait-image", "CLEARANCE_WAIT_IMAGE is not set: a change held for people cannot get its PreSync wait Job", "set CLEARANCE_WAIT_IMAGE to the clearance-wait image")
	}
	return cfg
}

func settingFix(msg string) string {
	switch {
	case strings.HasPrefix(msg, "CLEARANCE_URL is required"):
		return "set CLEARANCE_URL to the Clearance core's http(s) URL, e.g. https://clearance.example.test"
	case strings.Contains(msg, "CLEARANCE_URL"):
		return "CLEARANCE_URL is the core's http(s) URL, with no credentials, query or fragment"
	case strings.Contains(msg, "CLEARANCE_CHART_REPOS"):
		return "CLEARANCE_CHART_REPOS lists repository URLs (git, https, ssh, or oci://registry/path), separated by commas or spaces"
	case strings.Contains(msg, "CLEARANCE_WAIT_HOST_ALIAS"):
		return "write it ip=host[,host], or remove it"
	case strings.Contains(msg, "CLEARANCE_CMP_LINK_BASE"):
		return "CLEARANCE_CMP_LINK_BASE is the web UI's base URL (https://clearance.example.test), or remove it to link the core's record"
	case strings.Contains(msg, "CLEARANCE_WAIT_IMAGE"):
		return "give an image reference such as registry.example.test/clearance-wait:v1"
	}
	return "fix the setting named in the message"
}

// flatten splits an errors.Join into its parts.
func flatten(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, e := range j.Unwrap() {
			out = append(out, flatten(e)...)
		}
		return out
	}
	return []error{err}
}

// doctorToken checks the file, never its content: exists, readable, not empty, one line of printable characters, and
// not world-readable.
// It returns whether the token is usable (a regular, bounded, non-empty, single-token file), so no later check reads a
// file this check rejected.
func doctorToken(env DoctorEnv, cfg Config, add func(level, name, msg, fix string)) bool {
	p := cfg.TokenFile
	if p == "" {
		p = orDefault(env.Get("CLEARANCE_TOKEN_FILE"), "/var/run/secrets/tokens/clearance")
	}
	const name = "token"
	st, err := os.Stat(p)
	if err != nil {
		add(levelFail, name, fmt.Sprintf("%s does not exist or cannot be read (%v)", p, errReason(err)),
			"mount a projected service-account token with audience clearance at that path (docs/install-argocd-plugin.md), or point CLEARANCE_TOKEN_FILE at it")
		return false
	}
	if !st.Mode().IsRegular() {
		add(levelFail, name, p+" is not a regular file", "mount the projected token as a file")
		return false
	}
	f, err := os.Open(p)
	if err != nil {
		add(levelFail, name, fmt.Sprintf("%s is not readable by this user (%v)", p, errReason(err)), "the sidecar runs as uid 999: make the token readable by it (projected volume defaultMode 0444 or 0440 with fsGroup 999)")
		return false
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, client.MaxTokenBytes+1))
	if err != nil {
		add(levelFail, name, fmt.Sprintf("%s cannot be read (%v)", p, errReason(err)), "check the volume mount")
		return false
	}
	tok := strings.TrimSpace(string(raw))
	switch {
	case len(raw) > client.MaxTokenBytes:
		add(levelFail, name, fmt.Sprintf("%s is over %d bytes", p, client.MaxTokenBytes), "it should hold one service-account token")
		return false
	case tok == "":
		add(levelFail, name, p+" is empty", "the kubelet writes a projected token shortly after the pod starts; check the serviceAccountToken source and its path")
		return false
	case strings.ContainsFunc(tok, func(r rune) bool { return r < 0x21 || r == 0x7f }):
		add(levelFail, name, p+" holds whitespace or control characters inside the token", "it should hold exactly one token")
		return false
	}
	if st.Mode().Perm()&0o004 != 0 {
		add(levelWarn, name, fmt.Sprintf("%s is non-empty and readable, and world-readable (mode %04o)", p, st.Mode().Perm()),
			"a projected token is 0644 by default; set the volume's defaultMode to 0440 with the pod's fsGroup 999 so only the sidecar's user reads it")
		return true
	}
	add(levelOK, name, fmt.Sprintf("%s is non-empty and readable (mode %04o); its content is never printed", p, st.Mode().Perm()), "")
	return true
}

func errReason(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// doctorCore checks that the core answers and accepts the token. The only authenticated call that cannot change
// anything is a read of a change that does not exist (GET /v1/clearances/{id}). The core authenticates every route
// that is not on its short unauthenticated list in middleware (authn.Middleware, internal/server/server.go) before
// the handler runs, so a rejected token is a 401 there and a 404 from the handler means the token was accepted. That
// read cannot show the principal may act on a real change (the handler looks the change up before it checks who is
// asking), nor that it is a registered verifier: that is checked when the plugin registers a change, and the report
// says so.
func doctorCore(ctx context.Context, env DoctorEnv, cfg Config, tokenOK bool, add func(level, name, msg, fix string)) {
	const name = "core"
	if !validCoreURL(cfg.CoreURL) {
		add(levelFail, name, "not checked: CLEARANCE_URL is missing or not valid", "fix CLEARANCE_URL first")
		return
	}
	shown := redact(cfg.CoreURL)
	if u, err := url.Parse(cfg.CoreURL); err == nil && u.Scheme == "http" {
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			add(levelWarn, "core-tls", shown+" is plain http: the verifier token crosses the network unencrypted", "terminate TLS at the core's route and use an https URL")
		}
	}
	// /healthz needs no token, so reachability is judged without sending one.
	opt := client.Options{CAFile: cfg.CAFile, BaseURL: cfg.CoreURL, Timeout: env.Timeout, Retries: -1, BreakerThreshold: -1, UserAgent: "clearance-argocd-cmp-doctor"}
	anon, err := client.New(opt)
	if err != nil {
		add(levelFail, name, err.Error(), "fix CLEARANCE_URL")
		return
	}
	opt.Token = client.FileToken(cfg.TokenFile)
	cl, _ := client.New(opt)
	hctx, cancel := context.WithTimeout(ctx, env.Timeout)
	defer cancel()
	if _, err := anon.Healthz(hctx); err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) {
			add(levelFail, name, fmt.Sprintf("%s answered /healthz with HTTP %d: this is not a Clearance core, or its route is wrong", shown, ae.Status),
				"CLEARANCE_URL must reach the core's own service or route (not the web UI or another service)")
			return
		}
		add(levelFail, name, fmt.Sprintf("%s is not reachable: %v", shown, err),
			"check the URL, DNS (or hostAliases) and the NetworkPolicy and egress from the repo-server pod; the core's NetworkPolicy must allow the repo-server's namespace")
		return
	}
	add(levelOK, name, shown+" is reachable (GET /healthz)", "")
	if !tokenOK {
		add(levelFail, "core-auth", "not checked: there is no usable token file (see the token check)", "fix the token first")
		return
	}
	actx, acancel := context.WithTimeout(ctx, env.Timeout)
	defer acancel()
	_, err = cl.Clearance(actx, "clearance-cmp-doctor-probe")
	var ae *client.APIError
	switch {
	case errors.As(err, &ae) && ae.Status == 404:
		add(levelOK, "core-auth", "the core accepted the token (an authenticated read of a change that does not exist answered 404). Whether this principal is on the core's verifiers list is checked when the plugin registers a change, not here", "")
	case errors.As(err, &ae) && ae.Status == 401:
		add(levelFail, "core-auth", "the core rejected the token (HTTP 401: "+ae.Message+")",
			"the token's audience must be the core's CLEARANCE_AUDIENCE (default clearance) and its service account must be one the core can authenticate (TokenReview for the same cluster, or CLEARANCE_FOREIGN_* for another)")
	case errors.As(err, &ae) && ae.Status == 403:
		add(levelFail, "core-auth", "the core authenticated the token and refused it (HTTP 403: "+ae.Message+")",
			"the core reads a change only for a registered provider or the verifier that registered it; the plugin needs the verifier path: list this pod's service account (<namespace>/<serviceaccount>) in the core's verifiers (CLEARANCE_VERIFIERS)")
	case err != nil:
		add(levelFail, "core-auth", "the authenticated read failed: "+err.Error(), "see the core's log; the core must answer GET /v1/clearances/{id}")
	default:
		add(levelWarn, "core-auth", "the core answered 200 for a change that should not exist", "check CLEARANCE_URL points at a real core")
	}
}

func validCoreURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil
}

// doctorRepos applies NormalizeRepo, the rule Canonical uses, to every entry.
func doctorRepos(cfg Config, add func(level, name, msg, fix string)) {
	const name = "chart-repos"
	if len(cfg.AllowedRepos) == 0 {
		add(levelFail, name, "CLEARANCE_CHART_REPOS is empty: the plugin fetches no chart, and every gated Application shows a comparison error",
			"list the repositories charts may come from (there is no wildcard and no default)")
		return
	}
	seen := map[string]string{}
	bad := 0
	for _, r := range cfg.AllowedRepos {
		k, err := NormalizeRepo(r, hasOCIScheme(r))
		if err != nil {
			bad++
			add(levelFail, name, "entry "+err.Error(), "a repository entry is https://host/path, ssh://host/path, git@host:owner/repo, git://host/path or oci://host/path: no local path, file://, option, query or .. segment")
			continue
		}
		if prev, dup := seen[k]; dup {
			add(levelWarn, name, fmt.Sprintf("%s and %s are the same repository (%s)", redact(prev), redact(r), k), "list it once")
			continue
		}
		seen[k] = r
		add(levelOK, name, fmt.Sprintf("%s is allowed as %s", redact(r), k), "")
	}
	if bad > 0 {
		add(levelFail, name, "the plugin refuses to start with an entry that is not a repository URL", "fix or remove the entries above")
	}
}

// doctorCache writes and removes one probe file in the cache directory (created if missing, as the cache does).
func doctorCache(cfg Config, add func(level, name, msg, fix string)) {
	const name = "cache"
	dir := orDefault(cfg.CacheDir, "/tmp/clearance-cmp-cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		add(levelFail, name, fmt.Sprintf("%s cannot be created (%v)", dir, errReason(err)), "the root filesystem is read-only: mount a writable emptyDir at /tmp (renders use it too) or point CLEARANCE_CMP_CACHE_DIR at one")
		return
	}
	f, err := os.CreateTemp(dir, ".doctor-probe-*")
	if err != nil {
		add(levelFail, name, fmt.Sprintf("%s is not writable (%v)", dir, errReason(err)), "mount a writable emptyDir there, owned by the sidecar's user (uid 999)")
		return
	}
	_, werr := f.WriteString("clearance-cmp doctor probe\n")
	cerr := f.Close()
	rerr := os.Remove(f.Name())
	if werr != nil || cerr != nil || rerr != nil {
		add(levelFail, name, fmt.Sprintf("%s: the probe file could not be written or removed", dir), "check the volume is writable and has space")
		return
	}
	add(levelOK, name, dir+" is writable", "")
}

// doctorMetrics checks the metrics settings (metrics.go): off when CLEARANCE_CMP_METRICS_DIR is unset; otherwise the
// directory must take a probe file, as each run's record needs, and a store already there must parse.
func doctorMetrics(env DoctorEnv, add func(level, name, msg, fix string)) {
	const name = "metrics"
	dir, addr := strings.TrimSpace(env.Get(MetricsDirEnv)), strings.TrimSpace(env.Get(MetricsAddrEnv))
	if addr != "" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			add(levelFail, name, fmt.Sprintf("%s=%q is not host:port (%v)", MetricsAddrEnv, addr, err), "set it to an address such as :9464, on the metrics container only")
			return
		}
	}
	if dir == "" {
		if addr != "" {
			add(levelFail, name, MetricsAddrEnv+" is set but "+MetricsDirEnv+" is not: the metrics server has no store to serve", "set "+MetricsDirEnv+" to the directory the plugin sidecar records into")
			return
		}
		add(levelOK, name, "off: "+MetricsDirEnv+" is not set, runs record nothing (and nothing listens)", "")
		return
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		add(levelFail, name, fmt.Sprintf("%s cannot be created (%v)", dir, errReason(err)), "mount a writable emptyDir there, shared with the metrics container")
		return
	}
	f, err := os.CreateTemp(dir, ".doctor-probe-*")
	if err != nil {
		add(levelFail, name, fmt.Sprintf("%s is not writable (%v)", dir, errReason(err)), "mount a writable emptyDir there, owned by the sidecar's user (uid 999)")
		return
	}
	_, werr := f.WriteString("clearance-cmp doctor probe\n")
	cerr := f.Close()
	if rerr := os.Remove(f.Name()); werr != nil || cerr != nil || rerr != nil {
		add(levelFail, name, fmt.Sprintf("%s: the probe file could not be written or removed", dir), "check the volume is writable and has space")
		return
	}
	if _, err := readStore(dir); err != nil {
		add(levelWarn, name, fmt.Sprintf("%s is writable, but its store does not read (%v): the next run starts it again and counts a reset", dir, err), "nothing to do unless it keeps happening; then check nothing else writes "+MetricsStoreFile)
		return
	}
	msg := "on: each run records into " + dir
	if addr != "" {
		msg += "; `clearance-cmp metrics` serves it on " + addr
	}
	add(levelOK, name, msg, "")
}

// doctorTools prints each tool's version; a missing tool fails.
func doctorTools(ctx context.Context, env DoctorEnv, add func(level, name, msg, fix string)) {
	for _, t := range []struct {
		bin  string
		args []string
	}{{"git", []string{"--version"}}, {"helm", []string{"version", "--template", "{{.Version}}"}}, {"kustomize", []string{"version"}}} {
		path, err := env.LookPath(t.bin)
		if err != nil {
			add(levelFail, t.bin, t.bin+" is not on PATH", "run the clearance-cmp image: it ships git, helm and kustomize")
			continue
		}
		tctx, cancel := context.WithTimeout(ctx, env.Timeout)
		out, err := env.Run(tctx, path, t.args...)
		cancel()
		if err != nil {
			add(levelFail, t.bin, fmt.Sprintf("%s did not report a version (%v)", path, err), "reinstall the tool or use the clearance-cmp image")
			continue
		}
		add(levelOK, t.bin, fmt.Sprintf("%s %s", path, firstLine(out)), "")
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(line)
}

// doctorNetns reports the private network namespace probe: on, unavailable or off.
func doctorNetns(env DoctorEnv, add func(level, name, msg, fix string)) {
	const name = "netns"
	mode, err := ParseNetns(env.Get(NetnsEnv))
	if err != nil {
		add(levelFail, name, err.Error(), "set "+NetnsEnv+" to try, require or off")
		return
	}
	SetNetns(mode)
	switch state := NetnsState(); {
	case state == "on":
		add(levelOK, name, "on: renders run in a private network namespace (mode "+mode+")", "")
	case state == "off":
		add(levelOK, name, "off: "+NetnsEnv+"=off, renders run without a private network namespace", "")
	case mode == NetnsRequire:
		ns.Lock()
		cause := ns.cause
		ns.Unlock()
		add(levelFail, name, fmt.Sprintf("unavailable and %s=require: every render would be refused (%v)", NetnsEnv, cause),
			"give the container a seccomp profile that allows unshare/clone with CLONE_NEWUSER|CLONE_NEWNET, or set "+NetnsEnv+"=try")
	default:
		ns.Lock()
		cause := ns.cause
		ns.Unlock()
		add(levelWarn, name, fmt.Sprintf("unavailable: renders run WITHOUT a private network namespace (%v)", cause),
			"optional hardening: a Localhost seccomp profile allowing unshare/clone with CLONE_NEWUSER|CLONE_NEWNET, then "+NetnsEnv+"=require")
	}
}

// doctorSocket checks the plugin socket directory and the cmp-server binary the sidecar command runs. Outside the
// sidecar neither exists, which is a warning, not a failure.
func doctorSocket(env DoctorEnv, add func(level, name, msg, fix string)) {
	const name = "plugin-socket"
	st, err := os.Stat(env.PluginDir)
	if err != nil || !st.IsDir() {
		add(levelWarn, name, fmt.Sprintf("%s does not exist: fine outside the sidecar; in the sidecar the cmp-server cannot create its socket", env.PluginDir),
			"mount the repo-server's plugins emptyDir at "+DefaultPluginDir)
	} else {
		add(levelOK, name, env.PluginDir+" exists (not written to: doctor creates nothing outside the cache directory)", "")
	}
	if _, err := os.Stat(env.CmpServer); err != nil {
		add(levelWarn, "cmp-server", env.CmpServer+" is not there: fine outside the sidecar; in the sidecar it is copied in by the repo-server's copyutil init container",
			"mount the repo-server's var-files volume at /var/run/argocd and use it as the container command")
		return
	}
	add(levelOK, "cmp-server", env.CmpServer+" is present", "")
}

// doctorCaches reports the chart fetch cache and the pre-render cache from the same settings ParseConfig reads. The
// chart cache lives under the cache directory, so its byte bound must fit the volume that holds it.
func doctorCaches(env DoctorEnv, add func(level, name, msg, fix string)) {
	num := func(name string, def int64) int64 {
		if v := strings.TrimSpace(env.Get(name)); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
				return n
			}
		}
		return def
	}
	dir := orDefault(env.Get("CLEARANCE_CMP_CACHE_DIR"), "/tmp/clearance-cmp-cache")
	maxBytes, maxEntries := num("CLEARANCE_CMP_CHART_CACHE_MAX_BYTES", 512<<20), num("CLEARANCE_CMP_CHART_CACHE_MAX_ENTRIES", 32)
	switch {
	case maxBytes == 0 || maxEntries == 0:
		add(levelOK, "chart-cache", "off: CLEARANCE_CMP_CHART_CACHE_MAX_BYTES or _MAX_ENTRIES is 0, every render clones the chart", "")
	default:
		msg := fmt.Sprintf("on, under %s/charts: at most %s and %d entries", dir, humanBytes(maxBytes), maxEntries)
		free, known := int64(0), false
		if env.FreeBytes != nil {
			free, known = env.FreeBytes(dir)
		}
		switch {
		case !known:
			add(levelOK, "chart-cache", msg+" (free space of the volume could not be read)", "")
		case free < maxBytes:
			add(levelWarn, "chart-cache", fmt.Sprintf("%s; the volume holding the cache dir has only %s free, less than the byte bound", msg, humanBytes(free)),
				"size the emptyDir at /tmp (sizeLimit) to at least the bound plus room for renders, or lower CLEARANCE_CMP_CHART_CACHE_MAX_BYTES; a full volume never fails a render, it only loses cache hits")
		default:
			add(levelOK, "chart-cache", fmt.Sprintf("%s; the volume has %s free", msg, humanBytes(free)), "")
		}
	}
	v := strings.TrimSpace(env.Get("CLEARANCE_CMP_RENDER_CACHE_TTL"))
	ttl := 15 * time.Minute
	if d, err := time.ParseDuration(v); v != "" && err == nil && d > 0 {
		ttl = d
	}
	treeTTL := 2 * time.Minute
	if d, err := time.ParseDuration(env.Get("CLEARANCE_CMP_CACHE_TTL")); err == nil && d > 0 {
		treeTTL = d
	}
	if v == "0" || v == "0s" {
		add(levelOK, "render-cache", fmt.Sprintf("off: CLEARANCE_CMP_RENDER_CACHE_TTL is 0, every render runs helm; the cleared-tree cache (CLEARANCE_CMP_CACHE_TTL) is %s", treeTTL), "")
	} else {
		add(levelOK, "render-cache", fmt.Sprintf("on: a rendered stream is reused for up to %s (never past the clearance's expiry); the cleared-tree cache TTL is %s", ttl, treeTTL), "")
	}
	doctorLKG(env, dir, add)
}

// doctorLKG reports the last-known-good fallback (lkg.go): on or off, and how many renders it has served from this
// cache directory. A count above zero means the plugin faulted, or a dependency was down, and Argo CD was given a
// remembered render: look for "LAST-KNOWN-GOOD served" on the sidecar's stderr.
func doctorLKG(env DoctorEnv, dir string, add func(level, name, msg, fix string)) {
	on, err := ParseLKG(env.Get(LKGEnv))
	if err != nil {
		return // reported with the settings
	}
	if !on {
		add(levelOK, "last-known-good", "off ("+LKGEnv+"): a plugin fault or an unreachable chart host fails the render", "")
		return
	}
	n := Cache{Dir: dir}.LKGServes()
	msg := fmt.Sprintf("on: a plugin fault or an unavailable dependency serves the render last cleared for the exact same inputs, after the core confirms it; served %d so far from %s", n, dir)
	if n > 0 {
		add(levelWarn, "last-known-good", msg, "the plugin faulted or a dependency was down: read the LAST-KNOWN-GOOD lines on the sidecar's stderr, fix the cause")
		return
	}
	add(levelOK, "last-known-good", msg, "")
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d KiB", n>>10)
}
