package personcli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/jfillman/clearance/internal/observe"
)

// The write commands (docs/cli.md, Writes): clear, deny, resolve, break-glass. They go to the Clearance core
// (CLEARANCE_URL) with the person's own ID token, send X-Clearance-Via: cli, show what will happen first (read from
// clearance-api) and ask for confirmation. The core decides everything: who may, what tier, how fresh the sign-in
// must be. The CLI only shows, asks and sends once; it never retries a write.

// via is the surface a CLI write claims (recorded as `surface` on the evidence record, claimed).
var viaHeaders = map[string]string{"X-Clearance-Via": "cli"}

// coreClient is an authenticated client for the Clearance core, the write phase's server.
func (s *session) coreClient() (*Client, error) {
	if s.cfg.URL == "" {
		return nil, fail(ExitUsage, "no Clearance core URL: set --url, CLEARANCE_URL or url in %s", cfgHint(s.e))
	}
	tok, _, err := s.token()
	if err != nil {
		return nil, err
	}
	return &Client{Base: s.cfg.URL, Token: tok, HTTP: s.e.HTTP, UserAgent: "clearance-cli/" + s.e.Version, Name: "the Clearance core"}, nil
}

// interactive is whether a person can answer a prompt: stdin is a terminal that nothing else has read.
func (s *session) interactive() bool { return s.e.StdinTTY && !s.tokenStdin && !s.stdinUsed }

// readLine reads one line of the answer from stdin.
func (s *session) readLine() string {
	line, _ := bufio.NewReader(s.e.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

// confirm asks before a write. yes (--yes) skips the question; strict (tier 3, break-glass) refuses to go on without a
// terminal even then, because a script must not clear the most consequential changes unattended. want, when set, is
// the text the person must type back instead of y.
func (s *session) confirm(yes, strict bool, question, want string) *exitError {
	if strict && !s.interactive() {
		return fail(ExitUsage, "this needs an interactive confirmation on a terminal (--yes is not honored here, and --token-stdin leaves no terminal)")
	}
	if yes && want == "" {
		return nil
	}
	if !s.interactive() {
		return fail(ExitUsage, "not a terminal: pass --yes to confirm")
	}
	if want != "" {
		fmt.Fprintf(s.e.Stderr, "%s\nType %s to go on: ", question, want)
		if s.readLine() != want {
			return fail(ExitError, "cancelled: nothing was sent")
		}
		return nil
	}
	fmt.Fprintf(s.e.Stderr, "%s [y/N] ", question)
	if a := strings.ToLower(s.readLine()); a != "y" && a != "yes" {
		return fail(ExitError, "cancelled: nothing was sent")
	}
	return nil
}

// preview reads the change from clearance-api and prints what a write will act on (to stderr: stdout is the
// answer). It returns the change as the api gave it.
func (s *session) preview(ctx context.Context, id string) (map[string]any, error) {
	if s.cfg.APIURL == "" {
		return nil, fail(ExitUsage, "no clearance-api URL to show the change from: set --api, CLEARANCE_API_URL or api_url in %s", cfgHint(s.e))
	}
	c, err := s.client(false)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := c.Get(ctx, "/v1/clearances/"+url.PathEscape(id), nil, &m); err != nil {
		return nil, err
	}
	showChangeTo(s.e.Stderr, s.e, m)
	fmt.Fprintln(s.e.Stderr)
	return m, nil
}

func tierOf(m map[string]any) int {
	n, _ := strconv.Atoi(str(m, "tier"))
	return n
}

// ChangesClear is `clearance changes clear <id> [--reason R] [--yes]`.
func (e *Env) ChangesClear(ctx context.Context, args []string) int {
	var reason string
	var yes bool
	s, pos, ee := e.begin("changes clear", "<change-id> [--reason R] [--yes]", args, func(fs *flag.FlagSet) {
		fs.StringVar(&reason, "reason", "", "a note recorded with your approval (optional, at most 4000 characters)")
		fs.BoolVar(&yes, "yes", false, "do not ask for confirmation (not honored for a tier 3 change without a terminal)")
	})
	if ee != nil {
		return e.finish("changes clear", ee)
	}
	if len(pos) != 1 {
		return e.finish("changes clear", s.usageErr())
	}
	return e.finish("changes clear", func() error {
		core, err := s.coreClient()
		if err != nil {
			return err
		}
		m, err := s.preview(ctx, pos[0])
		if err != nil {
			return err
		}
		if st := str(m, "state"); st != "holding" {
			return fail(ExitError, "this change is %s: only a holding change is cleared", st)
		}
		tier := tierOf(m)
		q := fmt.Sprintf("Clear %s (%s / %s, tier %d) as yourself?", str(m, "id"), str(m, "app"), str(m, "env"), tier)
		if reason != "" {
			q += fmt.Sprintf("\nYour note: %s", reason)
		}
		if ee := s.confirm(yes, tier >= 3, q, ""); ee != nil {
			return ee
		}
		var body any
		if reason != "" {
			body = map[string]any{"reason": reason}
		}
		var raw json.RawMessage
		if err := core.Post(ctx, "/v1/clearances/"+url.PathEscape(pos[0])+"/clear", body, viaHeaders, &raw); err != nil {
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, raw, ""); wrote || err != nil {
			return err
		}
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		fmt.Fprintf(e.Stdout, "approved %s: the change is %s, %s (record %s)\n", str(out, "id"), str(out, "state"), needs(out), str(out, "audit_seq"))
		return nil
	}())
}

// ChangesDeny is `clearance changes deny <id> --reason R [--yes]`.
func (e *Env) ChangesDeny(ctx context.Context, args []string) int {
	var reason string
	var yes bool
	s, pos, ee := e.begin("changes deny", "<change-id> --reason R [--yes]", args, func(fs *flag.FlagSet) {
		fs.StringVar(&reason, "reason", "", "why (required, recorded)")
		fs.BoolVar(&yes, "yes", false, "do not ask for confirmation")
	})
	if ee != nil {
		return e.finish("changes deny", ee)
	}
	if len(pos) != 1 || strings.TrimSpace(reason) == "" {
		if len(pos) == 1 {
			fmt.Fprintln(e.Stderr, "a reason is required: --reason \"why\"")
		}
		return e.finish("changes deny", s.usageErr())
	}
	return e.finish("changes deny", func() error {
		core, err := s.coreClient()
		if err != nil {
			return err
		}
		m, err := s.preview(ctx, pos[0])
		if err != nil {
			return err
		}
		if st := str(m, "state"); st != "holding" {
			return fail(ExitError, "this change is %s: only a holding change is denied", st)
		}
		q := fmt.Sprintf("Deny %s (%s / %s, tier %d)?\nReason recorded: %s", str(m, "id"), str(m, "app"), str(m, "env"), tierOf(m), reason)
		if ee := s.confirm(yes, false, q, ""); ee != nil {
			return ee
		}
		var raw json.RawMessage
		if err := core.Post(ctx, "/v1/clearances/"+url.PathEscape(pos[0])+"/deny", map[string]any{"reason": reason}, viaHeaders, &raw); err != nil {
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, raw, ""); wrote || err != nil {
			return err
		}
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		fmt.Fprintf(e.Stdout, "denied %s (record %s)\n", str(out, "id"), str(out, "audit_seq"))
		return nil
	}())
}

// -- exceptions resolve ----------------------------------------------------------------------------------------------

// MaxBulk is the most items the bulk endpoint takes in one call; a larger selection is sent as several.
const MaxBulk = 200

// maxSelection bounds one invocation (a fat-fingered --all-matching is not 50 000 writes).
const maxSelection = 2000

// resolvable are the exception kinds a person resolves (the core skips the others).
var resolvable = []string{"out-of-band", "drift", "untraced-apply", "digest-mismatch"}

// parseSeqs reads a --from-file: one seq per line (blank lines and #-comments ignored), a JSON array of seqs, or
// `exceptions list -o jsonl` / `-o json` output (an object with a seq, or {items: [...]}).
func parseSeqs(b []byte) ([]int64, error) {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 {
		return nil, nil
	}
	var out []int64
	seq := func(v any) error {
		switch x := v.(type) {
		case float64:
			if x != float64(int64(x)) || x < 0 {
				return fmt.Errorf("%v is not a seq", x)
			}
			out = append(out, int64(x))
		case map[string]any:
			f, ok := x["seq"].(float64)
			if !ok || f < 0 || f != float64(int64(f)) {
				return fmt.Errorf("an item has no seq")
			}
			out = append(out, int64(f))
		default:
			return fmt.Errorf("%v is not a seq", v)
		}
		return nil
	}
	switch b[0] {
	case '[':
		var l []any
		if err := json.Unmarshal(b, &l); err != nil {
			return nil, err
		}
		for _, v := range l {
			if err := seq(v); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] == '{' {
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				return nil, fmt.Errorf("line %d: %v", n+1, err)
			}
			if items, ok := m["items"].([]any); ok {
				for _, it := range items {
					if err := seq(it); err != nil {
						return nil, fmt.Errorf("line %d: %v", n+1, err)
					}
				}
				continue
			}
			if err := seq(m); err != nil {
				return nil, fmt.Errorf("line %d: %v", n+1, err)
			}
			continue
		}
		v, err := strconv.ParseInt(strings.Fields(line)[0], 10, 64)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("line %d: %q is not a seq", n+1, line)
		}
		out = append(out, v)
	}
	return out, nil
}

// uniq keeps the first of each seq, in order.
func uniq(xs []int64) []int64 {
	seen := map[int64]bool{}
	out := xs[:0:0]
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// ExceptionsResolve is `clearance exceptions resolve`: one or more seqs (arguments, --from-file, or --all-matching
// the exceptions list's filters) get a person's resolution, through the bulk endpoint in calls of at most 200.
func (e *Env) ExceptionsResolve(ctx context.Context, args []string) int {
	var as, cause, note, file, scope, kind, tool, app, since, until string
	var allMatching, plan, yes bool
	usage := "<seq>... | --from-file F | --all-matching [--scope S --kind K --tool T --app A --since T --until T]  --as still-live|reverted|ratified|declared-break-glass [--cause C] [--note N] [--plan] [--yes]"
	s, pos, ee := e.begin("exceptions resolve", usage, args, func(fs *flag.FlagSet) {
		fs.StringVar(&as, "as", "", "the resolution: "+strings.Join(observe.ResolutionStates, ", "))
		fs.StringVar(&cause, "cause", "", "why it was reverted (only with --as reverted): "+strings.Join(observe.RevertCauses, ", "))
		fs.StringVar(&note, "note", "", "free text recorded beside it (at most 4 KiB)")
		fs.StringVar(&file, "from-file", "", "seqs from a file (one per line, a JSON array, or `exceptions list -o jsonl` output); - is stdin")
		fs.BoolVar(&allMatching, "all-matching", false, "every exception the filters below match (at most 2000)")
		fs.StringVar(&scope, "scope", "", "with --all-matching: app, target, cluster or environment")
		fs.StringVar(&kind, "kind", "", "with --all-matching: exception kind (default: "+strings.Join(resolvable, ", ")+")")
		fs.StringVar(&tool, "tool", "deploy.exception", "with --all-matching: the record tool")
		fs.StringVar(&app, "app", "", "with --all-matching: only this app")
		fs.StringVar(&since, "since", "", "with --all-matching: since an RFC 3339 time, a date, or a span such as 24h or 7d")
		fs.StringVar(&until, "until", "", "with --all-matching: until (RFC 3339)")
		fs.BoolVar(&plan, "plan", false, "print the requests that would be sent and send nothing (needs no core URL)")
		fs.BoolVar(&yes, "yes", false, "do not ask for confirmation")
	})
	if ee != nil {
		return e.finish("exceptions resolve", ee)
	}
	return e.finish("exceptions resolve", func() error {
		if !slices.Contains(observe.ResolutionStates, as) {
			return fail(ExitUsage, "--as is one of %s", strings.Join(observe.ResolutionStates, ", "))
		}
		switch {
		case as == "reverted" && !slices.Contains(observe.RevertCauses, cause):
			return fail(ExitUsage, "--as reverted needs --cause, one of %s", strings.Join(observe.RevertCauses, ", "))
		case as != "reverted" && cause != "":
			return fail(ExitUsage, "--cause is only for --as reverted")
		case len(note) > 4096:
			return fail(ExitUsage, "--note is at most 4096 bytes")
		}
		sources := 0
		for _, b := range []bool{len(pos) > 0, file != "", allMatching} {
			if b {
				sources++
			}
		}
		if sources != 1 {
			return fail(ExitUsage, "name what to resolve in exactly one way: seqs as arguments, --from-file, or --all-matching")
		}
		var seqs []int64
		switch {
		case len(pos) > 0:
			for _, p := range pos {
				n, err := strconv.ParseInt(p, 10, 64)
				if err != nil || n < 0 {
					return fail(ExitUsage, "%q is not a seq", p)
				}
				seqs = append(seqs, n)
			}
		case file != "":
			var b []byte
			var err error
			if file == "-" {
				s.stdinUsed = true
				b, err = io.ReadAll(io.LimitReader(e.Stdin, 4<<20))
			} else {
				b, err = os.ReadFile(file)
			}
			if err != nil {
				return fail(ExitUsage, "--from-file: %v", err)
			}
			if seqs, err = parseSeqs(b); err != nil {
				return fail(ExitUsage, "--from-file: %v", err)
			}
		default:
			st, err := sinceTime(since, e.Now(), false)
			if err != nil {
				return fail(ExitUsage, "%v", err)
			}
			c, cerr := s.client(false)
			if cerr != nil {
				return cerr
			}
			q := url.Values{}
			setIf(q, "kind", kind)
			setIf(q, "tool", tool)
			setIf(q, "app", app)
			setIf(q, "since", st)
			setIf(q, "until", until)
			_, rows, err := fetchList(ctx, c, "/v1/exceptions", q, listFlags{limit: 200, all: true})
			if err != nil {
				return err
			}
			for _, r := range rows {
				if !scopeMatches(r, scope) || (kind == "" && !slices.Contains(resolvable, exceptionKind(r))) {
					continue
				}
				if n, ok := r["seq"].(float64); ok {
					seqs = append(seqs, int64(n))
				}
			}
			if len(rows) >= maxSelection {
				fmt.Fprintf(e.Stderr, "warning: the filters matched at least %d exceptions and only these were read; narrow them or run again\n", maxSelection)
			}
		}
		seqs = uniq(seqs)
		if len(seqs) == 0 {
			fmt.Fprintln(e.Stdout, "nothing matches: nothing to resolve")
			return nil
		}
		if len(seqs) > maxSelection {
			return fail(ExitUsage, "%d seqs is over the limit of %d for one run: narrow the selection", len(seqs), maxSelection)
		}
		type call struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			Body   any    `json:"body"`
		}
		var calls []call
		one := func(extra map[string]any) map[string]any {
			m := map[string]any{"state": as}
			if cause != "" {
				m["cause"] = cause
			}
			if note != "" {
				m["note"] = note
			}
			for k, v := range extra {
				m[k] = v
			}
			return m
		}
		if len(pos) == 1 {
			calls = []call{{"POST", fmt.Sprintf("/v1/observations/%d/resolution", seqs[0]), one(nil)}}
		} else {
			for i := 0; i < len(seqs); i += MaxBulk {
				calls = append(calls, call{"POST", "/v1/observations/resolutions", one(map[string]any{"items": seqs[i:min(i+MaxBulk, len(seqs))]})})
			}
		}
		if plan {
			doc, _ := json.Marshal(map[string]any{"count": len(seqs), "calls": calls})
			if wrote, err := emit(e.Stdout, s.format, doc, "calls"); wrote || err != nil {
				return err
			}
			fmt.Fprintf(e.Stdout, "plan: resolve %d as %s%s in %d call(s) to %s; nothing is sent\n", len(seqs), as, causeNote(cause), len(calls), orNone(s.cfg.URL))
			for i, c := range calls {
				b, _ := json.Marshal(c.Body)
				fmt.Fprintf(e.Stdout, "  %d. %s %s\n     %s\n", i+1, c.Method, c.Path, b)
			}
			return nil
		}
		core, err := s.coreClient()
		if err != nil {
			return err
		}
		q := fmt.Sprintf("Resolve %d exception(s) as %s%s in %d call(s) to the Clearance core?\nSeqs: %s", len(seqs), as, causeNote(cause), len(calls), seqList(seqs))
		if note != "" {
			q += "\nNote: " + note
		}
		if ee := s.confirm(yes, false, q, ""); ee != nil {
			return ee
		}
		var answers []json.RawMessage
		var recorded, skipped, failed int
		for i, c := range calls {
			var raw json.RawMessage
			if err := core.Post(ctx, c.Path, c.Body, viaHeaders, &raw); err != nil {
				if i > 0 || len(answers) > 0 {
					fmt.Fprintf(e.Stderr, "%d of %d call(s) were already recorded (%d resolutions) before this one failed; the rest were not sent\n", i, len(calls), recorded)
				}
				return err
			}
			answers = append(answers, raw)
			var a struct {
				Recorded []json.RawMessage `json:"recorded"`
				Skipped  []struct {
					Seq    int64  `json:"seq"`
					Reason string `json:"reason"`
				} `json:"skipped"`
				Failed []json.RawMessage `json:"failed"`
				Seq    *int64            `json:"seq"`
			}
			_ = json.Unmarshal(raw, &a)
			if a.Seq != nil { // the single route's answer is one record
				recorded++
			}
			recorded += len(a.Recorded)
			skipped += len(a.Skipped)
			failed += len(a.Failed)
			if s.format == FormatTable {
				for _, sk := range a.Skipped {
					fmt.Fprintf(e.Stdout, "skipped %d: %s\n", sk.Seq, sk.Reason)
				}
			}
		}
		if s.format != FormatTable {
			doc := json.RawMessage(answers[0])
			if len(answers) > 1 || len(pos) != 1 {
				doc, _ = json.Marshal(answers)
			}
			if _, err := emit(e.Stdout, s.format, doc, ""); err != nil {
				return err
			}
			return nil
		}
		fmt.Fprintf(e.Stdout, "resolved: %d recorded, %d skipped, %d refused, in %d call(s)\n", recorded, skipped, failed, len(calls))
		return nil
	}())
}

func causeNote(c string) string {
	if c == "" {
		return ""
	}
	return " (" + c + ")"
}

func orNone(s string) string {
	if s == "" {
		return "(no core URL set)"
	}
	return s
}

func seqList(seqs []int64) string {
	const show = 20
	var parts []string
	for i, n := range seqs {
		if i == show {
			parts = append(parts, fmt.Sprintf("... and %d more", len(seqs)-show))
			break
		}
		parts = append(parts, strconv.FormatInt(n, 10))
	}
	return strings.Join(parts, " ")
}

// -- break-glass ------------------------------------------------------------------------------------------------------

// BreakglassOpen is `clearance breakglass open`: always interactive, and the person types the environment back.
func (e *Env) BreakglassOpen(ctx context.Context, args []string) int {
	var cluster, env, app, ttl, reason string
	s, pos, ee := e.begin("breakglass open", "--cluster C --env E [--app A] --ttl 30m --reason R", args, func(fs *flag.FlagSet) {
		fs.StringVar(&cluster, "cluster", "", "the protected cluster")
		fs.StringVar(&env, "env", "", "the protected environment")
		fs.StringVar(&app, "app", "", "narrow the window to one app (optional)")
		fs.StringVar(&ttl, "ttl", "", "how long the window stays open, a Go duration (1m to the deployment's maximum, never over 4h)")
		fs.StringVar(&reason, "reason", "", "why (required: it is recorded, names you, and is read in the break-glass report)")
	})
	if ee != nil {
		return e.finish("breakglass open", ee)
	}
	if len(pos) > 0 || cluster == "" || env == "" || ttl == "" || strings.TrimSpace(reason) == "" {
		return e.finish("breakglass open", s.usageErr())
	}
	return e.finish("breakglass open", func() error {
		core, err := s.coreClient()
		if err != nil {
			return err
		}
		scope := cluster + "/" + env
		q := fmt.Sprintf("BREAK GLASS on %s%s for %s.\nIt is recorded under your name with this reason: %q\nIt clears nothing; changes made inside the window are listed as exceptions in its report.",
			scope, map[bool]string{true: " (app " + app + ")"}[app != ""], ttl, reason)
		if ee := s.confirm(false, true, q, scope); ee != nil {
			return ee
		}
		body := map[string]any{"reason": reason, "ttl": ttl, "cluster": cluster, "env": env}
		if app != "" {
			body["app"] = app
		}
		var raw json.RawMessage
		if err := core.Post(ctx, "/v1/breakglass", body, viaHeaders, &raw); err != nil {
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, raw, ""); wrote || err != nil {
			return err
		}
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		fmt.Fprintf(e.Stdout, "break-glass %s is open on %s until %s; close it early with `%s breakglass close %s`\n",
			str(out, "id"), scope, str(out, "expires_at"), e.prog(), str(out, "id"))
		return nil
	}())
}

// BreakglassClose is `clearance breakglass close <id>`.
func (e *Env) BreakglassClose(ctx context.Context, args []string) int {
	var yes bool
	s, pos, ee := e.begin("breakglass close", "<window-id> [--yes]", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&yes, "yes", false, "do not ask for confirmation")
	})
	if ee != nil {
		return e.finish("breakglass close", ee)
	}
	if len(pos) != 1 {
		return e.finish("breakglass close", s.usageErr())
	}
	return e.finish("breakglass close", func() error {
		core, err := s.coreClient()
		if err != nil {
			return err
		}
		if ee := s.confirm(yes, false, fmt.Sprintf("Close break-glass window %s now? It is reconciled at once.", pos[0]), ""); ee != nil {
			return ee
		}
		var raw json.RawMessage
		if err := core.Post(ctx, "/v1/breakglass/"+url.PathEscape(pos[0])+"/close", nil, viaHeaders, &raw); err != nil {
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, raw, ""); wrote || err != nil {
			return err
		}
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		fmt.Fprintf(e.Stdout, "break-glass %s is %s\n", str(out, "id"), str(out, "state"))
		return nil
	}())
}

// BreakglassList is `clearance breakglass list`: the windows open now (an admin reads them).
func (e *Env) BreakglassList(ctx context.Context, args []string) int {
	var cluster string
	s, pos, ee := e.begin("breakglass list", "[--cluster C]", args, func(fs *flag.FlagSet) {
		fs.StringVar(&cluster, "cluster", "", "only this cluster")
	})
	if ee != nil {
		return e.finish("breakglass list", ee)
	}
	if len(pos) > 0 {
		return e.finish("breakglass list", s.usageErr())
	}
	return e.finish("breakglass list", func() error {
		core, err := s.coreClient()
		if err != nil {
			return err
		}
		q := url.Values{}
		setIf(q, "cluster", cluster)
		var raw json.RawMessage
		if err := core.Get(ctx, "/v1/breakglass", q, &raw); err != nil {
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, raw, "items"); wrote || err != nil {
			return err
		}
		var l struct {
			Items []map[string]any `json:"items"`
		}
		_ = json.Unmarshal(raw, &l)
		if len(l.Items) == 0 {
			fmt.Fprintln(e.Stdout, "no break-glass window is open")
			return nil
		}
		var tr [][]string
		for _, w := range l.Items {
			tr = append(tr, []string{str(w, "id"), str(w, "cluster") + "/" + str(w, "env"), str(w, "app"), str(w, "person"), str(w, "expires_at"), clean(str(w, "reason"))})
		}
		table(e.Stdout, []string{"ID", "SCOPE", "APP", "OPENED BY", "EXPIRES", "REASON"}, tr)
		return nil
	}())
}
