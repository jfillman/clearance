package personcli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// sinceTime reads --since: an RFC 3339 time or date, or a span back from now (30m, 24h, 7d).
func sinceTime(v string, now time.Time, plus bool) (string, error) {
	if v == "" {
		return "", nil
	}
	if m := regexp.MustCompile(`^(\d+)([mhd])$`).FindStringSubmatch(v); m != nil {
		n, _ := strconv.Atoi(m[1])
		d := map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
		t := now.UTC().Add(-time.Duration(n) * d)
		if plus { // the gate's changes are stamped +00:00 (compared as text)
			return t.Format("2006-01-02T15:04:05") + "+00:00", nil
		}
		return t.Format("2006-01-02T15:04:05Z"), nil
	}
	if _, err := time.Parse(time.RFC3339, v); err == nil {
		return v, nil
	}
	if _, err := time.Parse("2006-01-02", v); err == nil {
		return v, nil
	}
	return "", fmt.Errorf("--since is an RFC 3339 time, a date, or a span such as 30m, 24h or 7d, not %q", v)
}

type listFlags struct {
	limit int
	all   bool
}

func (l *listFlags) register(fs *flag.FlagSet) {
	fs.IntVar(&l.limit, "limit", 50, "most items per page, 1 to 200")
	fs.BoolVar(&l.all, "all", false, "follow the cursor and read every page (at most 2000 items)")
}

func (l *listFlags) check() *exitError {
	if l.limit < 1 || l.limit > 200 {
		return fail(ExitUsage, "--limit is 1 to 200")
	}
	return nil
}

// page is a list answer: items and the cursor of the next page.
type page struct {
	Items []json.RawMessage `json:"items"`
	Next  any               `json:"next"`
}

// fetchList reads one page, or with all follows the cursor, and returns the document as {items, next} verbatim.
func fetchList(ctx context.Context, c *Client, path string, q url.Values, l listFlags) (json.RawMessage, []map[string]any, error) {
	q.Set("limit", strconv.Itoa(l.limit))
	var all []json.RawMessage
	var next any
	for {
		var raw json.RawMessage
		if err := c.Get(ctx, path, q, &raw); err != nil {
			return nil, nil, err
		}
		var p page
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, nil, fmt.Errorf("unexpected answer from %s: %v", path, err)
		}
		all, next = append(all, p.Items...), p.Next
		if !l.all || p.Next == nil || len(p.Items) == 0 || len(all) >= 2000 {
			break
		}
		q.Set("after", fmt.Sprint(p.Next))
		if f, ok := p.Next.(float64); ok {
			q.Set("after", strconv.FormatInt(int64(f), 10))
		}
	}
	if all == nil {
		all = []json.RawMessage{}
	}
	doc, _ := json.Marshal(map[string]any{"items": all, "next": next})
	rows := make([]map[string]any, 0, len(all))
	for _, it := range all {
		var m map[string]any
		if json.Unmarshal(it, &m) == nil {
			rows = append(rows, m)
		}
	}
	return doc, rows, nil
}

func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func clock(m map[string]any, k string) string {
	s := str(m, k)
	if len(s) >= 19 {
		return strings.Replace(s[:19], "T", " ", 1)
	}
	return s
}

// needs is "owner 0/1, outside 0/1": the approvals held against the requirement, for display only (the gate decides).
func needs(c map[string]any) string {
	req := sub(c, "requirement")
	if req == nil {
		return "-"
	}
	have := map[string]int{}
	if aps, ok := c["approvals"].([]any); ok {
		for _, a := range aps {
			if m, ok := a.(map[string]any); ok {
				have[str(m, "role")]++
			}
		}
	}
	var parts []string
	for _, role := range []string{"owner", "outside"} {
		if n, _ := req[role].(float64); n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d/%d", role, have[role], int(n)))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func changeRows(rows []map[string]any, withNeeds bool) ([]string, [][]string) {
	head := []string{"ID", "APP", "ENV", "TIER", "STATE", "PROPOSER", "UPDATED"}
	if withNeeds {
		head = append(head, "NEEDS")
	}
	var out [][]string
	for _, c := range rows {
		r := []string{str(c, "id"), str(c, "app"), str(c, "env"), str(c, "tier"), str(c, "state"), str(c, "proposer"), clock(c, "updated_at")}
		if withNeeds {
			r = append(r, needs(c))
		}
		out = append(out, r)
	}
	return head, out
}

// Awaiting is `clearance inbox`: the holding changes the caller may clear now (GET /v1/clearances?awaiting=me).
func (e *Env) Awaiting(ctx context.Context, args []string) int {
	var lf listFlags
	s, pos, ee := e.begin("inbox", "[--limit N] [--all]", args, lf.register)
	if ee != nil {
		return e.finish("inbox", ee)
	}
	if len(pos) > 0 {
		return e.finish("inbox", s.usageErr())
	}
	return e.finish("inbox", func() error {
		if err := lf.check(); err != nil {
			return err
		}
		c, err := s.client(false)
		if err != nil {
			return err
		}
		doc, rows, err := fetchList(ctx, c, "/v1/clearances", url.Values{"awaiting": {"me"}}, lf)
		if err != nil {
			if ae, ok := err.(*APIError); ok && ae.Status == 400 && strings.Contains(ae.Message, "awaiting") {
				return fail(ExitError, "this clearance-api does not support awaiting=me (it predates the person CLI release)")
			}
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, doc, "items"); wrote || err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Fprintln(e.Stdout, "nothing is waiting on you")
			return nil
		}
		head, tr := changeRows(rows, true)
		table(e.Stdout, head, tr)
		return nil
	}())
}

// ChangesList is `clearance changes list`.
func (e *Env) ChangesList(ctx context.Context, args []string) int {
	var lf listFlags
	var app, env, state, tier, since string
	s, pos, ee := e.begin("changes list", "[--app A] [--env E] [--state S] [--tier N] [--since T] [--limit N] [--all]", args, func(fs *flag.FlagSet) {
		lf.register(fs)
		fs.StringVar(&app, "app", "", "only this app")
		fs.StringVar(&env, "env", "", "only this environment")
		fs.StringVar(&state, "state", "", "holding, cleared, denied, expired, superseded, degraded or exception")
		fs.StringVar(&tier, "tier", "", "only this tier (0 to 3)")
		fs.StringVar(&since, "since", "", "updated since: an RFC 3339 time, a date, or a span such as 24h or 7d")
	})
	if ee != nil {
		return e.finish("changes list", ee)
	}
	if len(pos) > 0 {
		return e.finish("changes list", s.usageErr())
	}
	return e.finish("changes list", func() error {
		if err := lf.check(); err != nil {
			return err
		}
		st, err := sinceTime(since, e.Now(), true)
		if err != nil {
			return fail(ExitUsage, "%v", err)
		}
		c, cerr := s.client(false)
		if cerr != nil {
			return cerr
		}
		q := url.Values{}
		setIf(q, "app", app)
		setIf(q, "env", env)
		setIf(q, "state", state)
		setIf(q, "tier", tier)
		setIf(q, "since", st)
		doc, rows, err := fetchList(ctx, c, "/v1/clearances", q, lf)
		if err != nil {
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, doc, "items"); wrote || err != nil {
			return err
		}
		head, tr := changeRows(rows, false)
		table(e.Stdout, head, tr)
		return nil
	}())
}

// ChangesShow is `clearance changes show <id>`: why this tier, the approvals, what the grant binds to, the outcome
// and the attestation summary.
func (e *Env) ChangesShow(ctx context.Context, args []string) int {
	s, pos, ee := e.begin("changes show", "<change-id>", args, nil)
	if ee != nil {
		return e.finish("changes show", ee)
	}
	if len(pos) != 1 {
		return e.finish("changes show", s.usageErr())
	}
	return e.finish("changes show", func() error {
		c, err := s.client(false)
		if err != nil {
			return err
		}
		var raw json.RawMessage
		if err := c.Get(ctx, "/v1/clearances/"+url.PathEscape(pos[0]), nil, &raw); err != nil {
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, raw, ""); wrote || err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		showChange(e, m)
		return nil
	}())
}

func showChange(e *Env, m map[string]any) {
	w := e.Stdout
	rows := [][2]string{
		{"change", str(m, "id")},
		{"app", fmt.Sprintf("%s / %s  (cluster %s)", str(m, "app"), str(m, "env"), str(m, "cluster"))},
		{"state", fmt.Sprintf("%s  (tier %s)", str(m, "state"), str(m, "tier"))},
		{"target", str(m, "target")},
		{"proposer", fmt.Sprintf("%s (%s)", str(m, "proposer"), str(m, "proposer_kind"))},
		{"owner group", str(m, "owner")},
		{"updated", str(m, "updated_at")},
		{"expires", str(m, "expires_at")},
	}
	if v := str(m, "deny_reason"); v != "" {
		rows = append(rows, [2]string{"denied", fmt.Sprintf("%s: %s", str(m, "denied_by"), v)})
	}
	if v := str(m, "cleared_by"); v != "" {
		rows = append(rows, [2]string{"cleared by", v})
	}
	kv(w, rows)
	fmt.Fprintln(w, "\nwhy this tier")
	if rs, _ := m["reasons"].([]any); len(rs) == 0 {
		fmt.Fprintln(w, "  (no reasons recorded)")
	} else {
		for _, r := range rs {
			if rm, ok := r.(map[string]any); ok {
				fmt.Fprintf(w, "  tier %s  %s  %s\n", str(rm, "tier"), clean(str(rm, "rule")), clean(str(rm, "subject")))
			}
		}
	}
	fmt.Fprintf(w, "\nneeds   %s\n", needs(m))
	if req := sub(m, "requirement"); req != nil {
		fmt.Fprintf(w, "        owner group %s; outside groups %s\n", str(req, "ownerGroup"), join(req["outsideGroups"]))
	}
	fmt.Fprintln(w, "approvals")
	if aps, _ := m["approvals"].([]any); len(aps) == 0 {
		fmt.Fprintln(w, "  (none yet)")
	} else {
		for _, a := range aps {
			if am, ok := a.(map[string]any); ok {
				via := ""
				if v := str(am, "via"); v != "" {
					via = "  via " + v
				}
				fmt.Fprintf(w, "  %-8s %s  %s%s\n", str(am, "role"), clean(str(am, "person")), clock(am, "at"), clean(via))
			}
		}
	}
	fmt.Fprintln(w, "\nbinds to")
	rows = [][2]string{{"  head", str(m, "head")}, {"  tree", str(m, "tree_digest")}}
	if sj := sub(m, "subject"); sj != nil {
		rows = append(rows, [2]string{"  subject", fmt.Sprintf("%s %s", str(sj, "kind"), str(sj, "name"))})
		if d := sub(sj, "digests"); d != nil {
			for k, v := range d {
				rows = append(rows, [2]string{"  digest " + k, fmt.Sprint(v)})
			}
		}
	}
	kv(w, rows)
	if oc := sub(m, "outcome"); oc != nil {
		fmt.Fprintf(w, "\noutcome  applied=%s matched=%s at %s (record %s)\n", str(oc, "applied"), str(oc, "matched"), str(oc, "at"), str(oc, "seq"))
	} else {
		fmt.Fprintln(w, "\noutcome  none reported")
	}
	if at := sub(m, "attestation"); at != nil {
		log := "not logged"
		if v := str(at, "rekor_log_index"); v != "" {
			log = "Rekor #" + v
		}
		fmt.Fprintf(w, "attestation  signed %s (%s, %s); `%s attest verify %s` checks it\n", clock(at, "created_at"), str(at, "backend"), log, e.prog(), str(m, "id"))
	} else {
		fmt.Fprintln(w, "attestation  none yet")
	}
}

// ChangesHistory is `clearance changes history <id>`: the change's deploy.* records in chain order
// (GET /v1/clearances/{id}/records, from the change-history API).
func (e *Env) ChangesHistory(ctx context.Context, args []string) int {
	var lf listFlags
	s, pos, ee := e.begin("changes history", "<change-id> [--limit N] [--all]", args, lf.register)
	if ee != nil {
		return e.finish("changes history", ee)
	}
	if len(pos) != 1 {
		return e.finish("changes history", s.usageErr())
	}
	return e.finish("changes history", func() error {
		if err := lf.check(); err != nil {
			return err
		}
		c, err := s.client(false)
		if err != nil {
			return err
		}
		doc, rows, err := fetchList(ctx, c, "/v1/clearances/"+url.PathEscape(pos[0])+"/records", url.Values{}, lf)
		if err != nil {
			if isMissingRoute(err) {
				return fail(ExitNotFound, "this clearance-api has no change history (GET /v1/clearances/{id}/records); it predates the change-history API release")
			}
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, doc, "items"); wrote || err != nil {
			return err
		}
		var tr [][]string
		for _, r := range rows {
			rec := sub(r, "record")
			tr = append(tr, []string{str(r, "seq"), clock(r, "ts"), str(r, "tool"), str(r, "principal"), strings.TrimSpace(str(rec, "decision") + " " + str(rec, "result"))})
		}
		table(e.Stdout, []string{"SEQ", "TIME", "TOOL", "PRINCIPAL", "RESULT"}, tr)
		return nil
	}())
}

func exceptionKind(r map[string]any) string {
	if ex := sub(r, "exception"); ex != nil {
		return str(ex, "kind")
	}
	return ""
}

func scopeMatches(r map[string]any, scope string) bool {
	if scope == "" {
		return true
	}
	if str(r, "app") == scope || str(r, "target") == scope {
		return true
	}
	if d := sub(r, "destination"); d != nil && (str(d, "cluster") == scope || str(d, "environment") == scope) {
		return true
	}
	return false
}

// ExceptionsList is `clearance exceptions list`.
func (e *Env) ExceptionsList(ctx context.Context, args []string) int {
	var lf listFlags
	var scope, kind, tool, app, since, until string
	s, pos, ee := e.begin("exceptions list", "[--scope S] [--kind K] [--tool T] [--app A] [--since T] [--until T] [--limit N] [--all]", args, func(fs *flag.FlagSet) {
		lf.register(fs)
		fs.StringVar(&scope, "scope", "", "only records whose app, target, cluster or environment is this (filtered here, after the read)")
		fs.StringVar(&kind, "kind", "", "deploy.exception kind: out-of-band, drift, untraced-apply, digest-mismatch, attempted-refused, monitoring-protection")
		fs.StringVar(&tool, "tool", "", "narrow to one tool (deploy.exception, deploy.degraded, breakglass.open, ...)")
		fs.StringVar(&app, "app", "", "only this app")
		fs.StringVar(&since, "since", "", "since: an RFC 3339 time, a date, or a span such as 24h or 7d")
		fs.StringVar(&until, "until", "", "until (RFC 3339)")
	})
	if ee != nil {
		return e.finish("exceptions list", ee)
	}
	if len(pos) > 0 {
		return e.finish("exceptions list", s.usageErr())
	}
	return e.finish("exceptions list", func() error {
		if err := lf.check(); err != nil {
			return err
		}
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
		doc, rows, err := fetchList(ctx, c, "/v1/exceptions", q, lf)
		if err != nil {
			return err
		}
		if scope != "" {
			var kept []map[string]any
			var raws []json.RawMessage
			for _, r := range rows {
				if scopeMatches(r, scope) {
					kept = append(kept, r)
					b, _ := json.Marshal(r)
					raws = append(raws, b)
				}
			}
			rows = kept
			if raws == nil {
				raws = []json.RawMessage{}
			}
			var p page
			_ = json.Unmarshal(doc, &p)
			doc, _ = json.Marshal(map[string]any{"items": raws, "next": p.Next})
		}
		if wrote, err := emit(e.Stdout, s.format, doc, "items"); wrote || err != nil {
			return err
		}
		var tr [][]string
		for _, r := range rows {
			tr = append(tr, []string{str(r, "seq"), clock(r, "ts"), str(r, "tool"), exceptionKind(r), str(r, "app"), str(r, "target"), str(r, "principal")})
		}
		table(e.Stdout, []string{"SEQ", "TIME", "TOOL", "KIND", "APP", "TARGET", "PRINCIPAL"}, tr)
		return nil
	}())
}

// EvidenceList is `clearance evidence`: the evidence records the caller may see.
func (e *Env) EvidenceList(ctx context.Context, args []string) int {
	var lf listFlags
	var tool, app, cov, since, until, principal, agent string
	s, pos, ee := e.begin("evidence", "[--tool T] [--app A] [--coverage STATE[,STATE]] [--since T] [--until T] [--principal P] [--agent A] [--limit N] [--all]", args, func(fs *flag.FlagSet) {
		lf.register(fs)
		fs.StringVar(&tool, "tool", "", "only this tool (repo.pr.open, deploy.clear, ...)")
		fs.StringVar(&app, "app", "", "only this app")
		fs.StringVar(&cov, "coverage", "", "only these coverage states (authorized-and-verified, observed-not-attributed, out-of-band-detected, coverage-unavailable, break-glass, attempted-refused)")
		fs.StringVar(&since, "since", "", "since: an RFC 3339 time, a date, or a span such as 24h or 7d")
		fs.StringVar(&until, "until", "", "until (RFC 3339)")
		fs.StringVar(&principal, "principal", "", "only this principal")
		fs.StringVar(&agent, "agent", "", "only this agent")
	})
	if ee != nil {
		return e.finish("evidence", ee)
	}
	if len(pos) > 0 {
		return e.finish("evidence", s.usageErr())
	}
	return e.finish("evidence", func() error {
		if err := lf.check(); err != nil {
			return err
		}
		st, err := sinceTime(since, e.Now(), false)
		if err != nil {
			return fail(ExitUsage, "%v", err)
		}
		c, cerr := s.client(false)
		if cerr != nil {
			return cerr
		}
		q := url.Values{}
		setIf(q, "tool", tool)
		setIf(q, "app", app)
		setIf(q, "coverage", cov)
		setIf(q, "since", st)
		setIf(q, "until", until)
		setIf(q, "principal", principal)
		setIf(q, "agent", agent)
		doc, rows, err := fetchList(ctx, c, "/v1/evidence", q, lf)
		if err != nil {
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, doc, "items"); wrote || err != nil {
			return err
		}
		var tr [][]string
		for _, r := range rows {
			tr = append(tr, []string{str(r, "seq"), clock(r, "ts"), str(r, "tool"), str(r, "principal"), str(r, "decision"), str(r, "coverage"), str(r, "app"), str(r, "target")})
		}
		table(e.Stdout, []string{"SEQ", "TIME", "TOOL", "PRINCIPAL", "DECISION", "COVERAGE", "APP", "TARGET"}, tr)
		return nil
	}())
}

// Coverage is `clearance coverage [scope]`. Exit codes: 0 covered (every feed healthy), 2 degraded, 3 blind or
// unavailable (the statement could not be read, or no scope has any coverage). 1, 4 and 5 are as everywhere.
func (e *Env) Coverage(ctx context.Context, args []string) int {
	var from, to string
	s, pos, ee := e.begin("coverage", "[scope] [--from T] [--to T]", args, func(fs *flag.FlagSet) {
		fs.StringVar(&from, "from", "", "window start (RFC 3339; default 24 hours ago)")
		fs.StringVar(&to, "to", "", "window end (RFC 3339; default now)")
	})
	if ee != nil {
		return e.finish("coverage", ee)
	}
	if len(pos) > 1 {
		return e.finish("coverage", s.usageErr())
	}
	code := ExitOK
	err := func() error {
		c, err := s.client(false)
		if err != nil {
			return err
		}
		q := url.Values{}
		if len(pos) == 1 {
			q.Set("scope", pos[0])
		}
		setIf(q, "from", from)
		setIf(q, "to", to)
		var raw json.RawMessage
		if err := c.Get(ctx, "/v1/coverage", q, &raw); err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		var sts []map[string]any
		if sc, ok := m["scopes"].([]any); ok {
			for _, x := range sc {
				if xm, ok := x.(map[string]any); ok {
					sts = append(sts, xm)
				}
			}
		} else {
			sts = []map[string]any{m}
		}
		code = coverageCode(sts)
		if wrote, err := emit(e.Stdout, s.format, raw, ""); wrote || err != nil {
			return err
		}
		if len(pos) == 1 {
			fmt.Fprintf(e.Stdout, "%s: %s%s\n%s\n", str(m, "scope"), str(m, "state"), map[bool]string{true: " (clean)", false: ""}[m["clean"] == true], clean(str(m, "text")))
			return nil
		}
		var tr [][]string
		for _, st := range sts {
			tr = append(tr, []string{str(st, "scope"), str(st, "state"), str(st, "clean")})
		}
		if len(tr) == 0 {
			fmt.Fprintln(e.Stdout, "no scope has been observed in the window")
			return nil
		}
		table(e.Stdout, []string{"SCOPE", "STATE", "CLEAN"}, tr)
		return nil
	}()
	if err != nil {
		ee := mapError(err)
		if ee.code == ExitUnavailable || ee.code == ExitNotFound || ee.code == ExitError {
			code = 3
		} else {
			code = ee.code
		}
		fmt.Fprintf(e.Stderr, "%s coverage: %s\n", e.prog(), ee.msg)
	}
	return code
}

// coverageCode is the worst of the statements' states: healthy 0, degraded 2, blind 3 (and none: 3).
func coverageCode(sts []map[string]any) int {
	if len(sts) == 0 {
		return 3
	}
	code := 0
	for _, st := range sts {
		switch str(st, "state") {
		case "healthy":
		case "degraded":
			code = max(code, 2)
		default:
			code = max(code, 3)
		}
	}
	return code
}
