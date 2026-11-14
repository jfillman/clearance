package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/statement"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/verify"
)

// The hosted verify page (P-3): the first Clearance route reachable without an identity, and so a separate listener
// (CLEARANCE_VERIFY_LISTEN), off unless it is set, with its own handler, its own limits and none of the authenticated API's
// routes. It serves a statement's PUBLIC summary and the seven checks, server-rendered with no script, to anyone who holds
// the statement's id (128 random bits). It is read-only: no request to it writes a record, a cookie or a file, and it
// makes no request of its own (it reads this core's store and nothing else).
//
// Nothing recipient-specific is on it: no record id, no proof, no exception row, no person, firm, repository or
// cluster. Those are the statement's recipient detail, which the subscriber opens to a named recipient through the
// packet routes (P-1) and which the recipient pulls under its credential.

// StatementOptions are the deployment's statement and verify-page settings (core.Config reads them from the environment).
type StatementOptions struct {
	// IndependentWitnesses are the names of the log's witnesses the deployment asserts it does not run. None (the default,
	// and the lab): no witness is independent, and check 4 says so.
	IndependentWitnesses []string
	// LogKeys are the log's public keys (signed-note vkeys, the file `clearance packet --ledger-log-keys` takes) and
	// WitnessPolicy the witness policy: the trust inputs of checks 3 and 4. Without them those checks are NOT CHECKED.
	LogKeys       []byte
	WitnessPolicy []byte
	// PublicBaseURL, when set (an https URL, no path), is printed in the page's `clearance verify` command. The page never
	// uses the request's Host header for anything.
	PublicBaseURL string
	// The verify listener's limits: requests a minute for one client and its burst, for the whole listener and its burst, the
	// number of trusted proxy hops in front of it (0: the connection's address), and how many verifications may run at once.
	ClientPerMinute, ClientBurst, GlobalPerMinute, GlobalBurst, TrustedProxyHops, MaxChecks int
}

// Defaults of the verify listener's limits.
const (
	DefaultVerifyClientPerMinute = 30
	DefaultVerifyClientBurst     = 10
	DefaultVerifyGlobalPerMinute = 600
	DefaultVerifyGlobalBurst     = 100
	DefaultVerifyMaxChecks       = 2
	// maxPageBytes caps a rendered page.
	maxPageBytes = 256 << 10
	// resultTTL is how long the result of checks 1 to 6 (which rest on immutable data and this deployment's trust inputs) is
	// kept before they are run again; failedResultTTL for a run that could not complete.
	resultTTL       = 10 * time.Minute
	failedResultTTL = 15 * time.Second
	resultCacheSize = 128
	verifyHandlerTO = 10 * time.Second
)

func (s *Server) statementOpts() StatementOptions {
	o := s.opt.Statements
	if o.ClientPerMinute <= 0 {
		o.ClientPerMinute = DefaultVerifyClientPerMinute
	}
	if o.ClientBurst <= 0 {
		o.ClientBurst = DefaultVerifyClientBurst
	}
	if o.GlobalPerMinute <= 0 {
		o.GlobalPerMinute = DefaultVerifyGlobalPerMinute
	}
	if o.GlobalBurst <= 0 {
		o.GlobalBurst = DefaultVerifyGlobalBurst
	}
	if o.MaxChecks <= 0 {
		o.MaxChecks = DefaultVerifyMaxChecks
	}
	return o
}

// stmtResult is checks 1 to 6 for one statement, run once. done is closed when it is ready.
type stmtResult struct {
	done   chan struct{}
	rep    *verify.Report
	doc    *statement.Document
	err    error
	at     time.Time
	digest string
}

type stmtResults struct {
	mu    sync.Mutex
	by    map[string]*stmtResult
	order []string
	sem   chan struct{}
}

// result is the checks' result for e, run at most once at a time and kept for resultTTL. A run is started only for an id the
// chain holds a statement of, so nothing an anonymous caller invents can cost more than a map miss. busy is true when
// every verification slot is taken: the caller answers 503 and the next try finds the result.
func (s *Server) result(ctx context.Context, e *stmtEntry) (res *stmtResult, busy bool) {
	c := &s.stmtRes
	c.mu.Lock()
	if c.by == nil {
		c.by = map[string]*stmtResult{}
		c.sem = make(chan struct{}, s.statementOpts().MaxChecks)
	}
	now := s.opt.Clock()
	if r := c.by[e.id]; r != nil && r.digest == e.digest {
		ttl := resultTTL
		if r.err != nil {
			ttl = failedResultTTL
		}
		select {
		case <-r.done:
			if now.Sub(r.at) < ttl {
				c.mu.Unlock()
				return r, false
			}
		default: // still running: wait for it
			c.mu.Unlock()
			select {
			case <-r.done:
				return r, false
			case <-ctx.Done():
				return nil, true
			}
		}
	}
	sem := c.sem
	select {
	case sem <- struct{}{}:
	default:
		c.mu.Unlock()
		return nil, true
	}
	r := &stmtResult{done: make(chan struct{}), digest: e.digest}
	if _, ok := c.by[e.id]; !ok {
		for len(c.order) >= resultCacheSize {
			delete(c.by, c.order[0])
			c.order = c.order[1:]
		}
		c.order = append(c.order, e.id)
	}
	c.by[e.id] = r
	c.mu.Unlock()
	go func() {
		defer func() { <-sem }()
		defer close(r.done)
		defer func() {
			if p := recover(); p != nil {
				r.err = errors.New("the verification failed unexpectedly")
				s.log.Error("statement: the checks panicked", "statement", e.id)
			}
		}()
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		r.rep, r.doc, r.err = s.runStatementChecks(cctx, e)
		r.at = s.opt.Clock()
	}()
	select {
	case <-r.done:
		return r, false
	case <-ctx.Done():
		return nil, true
	}
}

// runStatementChecks runs the seven checks on the stored statement, with the verifier's own code (internal/verify) and
// this deployment's own trust inputs: the keys the core published, the log keys and witness policy it was configured with.
// Check 7 is a placeholder here; the caller fills it from the current state.
func (s *Server) runStatementChecks(ctx context.Context, e *stmtEntry) (*verify.Report, *statement.Document, error) {
	_, issuer, err := s.opt.Gate.Credentials()
	if err != nil {
		return nil, nil, errors.New("no issuer")
	}
	rows, err := s.opt.Store.SigningKeys(ctx, s.opt.Clock().Add(-KeysWindow-token.MaxAccessLifetime))
	if err != nil {
		return nil, nil, err
	}
	ks := token.KeySet{}
	for _, k := range rows {
		var j token.JWK
		if json.Unmarshal(k.JWK, &j) == nil {
			if pub, err := j.Public(); err == nil {
				ks[j.Kid] = pub
			}
		}
	}
	opt := s.statementOpts()
	so := verify.StatementOptions{Keys: ks, KeysSrc: "the keys this core publishes (GET /v1/keys)", Issuer: issuer, IndependentWitnesses: opt.IndependentWitnesses, Options: verify.Options{Now: s.opt.Clock}}
	so.LogKeys, so.LogKeysSrc = opt.LogKeys, "this deployment's configured log keys"
	so.WitnessPolicy, so.WitnessPolicySrc = opt.WitnessPolicy, "this deployment's configured witness policy"
	so.RecipientKeys, so.RecipientKeysSrc = map[string][]byte{}, map[string]string{}
	for _, p := range s.opt.Providers {
		if p.Assurance() && len(p.Keys) > 0 {
			so.RecipientKeys[p.Name] = []byte(strings.Join(p.Keys, "\n"))
			so.RecipientKeysSrc[p.Name] = "registered with this core"
		}
	}
	pk, err := s.opt.Store.Packet(ctx, e.packetID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// The statement's packet is gone: checks 3 to 6 have nothing to run on and say so.
	case err != nil:
		return nil, nil, err
	default:
		b := s.bundles.get(pk.ID, pk.Digest)
		if b == nil {
			if b, err = packet.LoadBundle(pk.Bundle); err != nil {
				return nil, nil, err
			}
			s.bundles.put(b)
		}
		so.PacketFiles = b.Files
	}
	so.Live = &verify.Live{State: statement.StateValid, AsOf: s.opt.Clock()}
	rep := verify.VerifyStatement(e.envelope, e.id, so)
	var doc *statement.Document
	if len(rep.Checks) == 7 && rep.Checks[1].Status == verify.Pass {
		var env struct {
			Payload string `json:"payload"`
		}
		if json.Unmarshal(e.envelope, &env) == nil {
			if raw, err := base64.StdEncoding.DecodeString(env.Payload); err == nil {
				doc, _ = statement.Parse(raw)
			}
		}
	}
	return rep, doc, nil
}

// VerifyHandler is the public handler. It is built even when no listener serves it, so tests drive it; the core mounts it
// only on CLEARANCE_VERIFY_LISTEN.
func (s *Server) VerifyHandler() http.Handler {
	o := s.statementOpts()
	lim := newLimiter(o.ClientPerMinute, o.ClientBurst, o.GlobalPerMinute, o.GlobalBurst, o.TrustedProxyHops, s.opt.Clock)
	h := &verifyPage{s: s, lim: lim, base: o.PublicBaseURL}
	inner := http.TimeoutHandler(http.HandlerFunc(h.serve), verifyHandlerTO, "The request took too long.\n")
	// The security headers are set on the connection's own writer first, so the timeout's 503 carries them too.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurity(w)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		inner.ServeHTTP(w, r)
	})
}

// VerifyHTTPServer is the public listener's http.Server: small header and body limits, short timeouts.
func (s *Server) VerifyHTTPServer(addr string) *http.Server {
	return &http.Server{Addr: addr, Handler: s.VerifyHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelWarn)}
}

type verifyPage struct {
	s    *Server
	lim  *limiter
	base string
}

// setSecurity sets the headers every answer of the listener carries, errors included.
func setSecurity(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", cspHeader)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Permissions-Policy", "interest-cohort=()")
	// The page is about a revocable object: a copy kept anywhere could outlive a revocation, so nothing is stored (max-age 0
	// in effect). The cost is bounded by the limiter and by the result cache; the benefit is that a revoked statement is
	// revoked on the next load, whoever holds the earlier copy.
	h.Set("Cache-Control", "no-store")
}

func (v *verifyPage) plain(w http.ResponseWriter, status int, body string) {
	setSecurity(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// notFound is the one answer to every id that is not a statement: malformed, unknown, or any path the listener does not
// serve. Same status, headers and body, so it is no oracle.
func (v *verifyPage) notFound(w http.ResponseWriter) {
	v.plain(w, http.StatusNotFound, "No such statement.\n")
}

func (v *verifyPage) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		v.plain(w, http.StatusMethodNotAllowed, "GET only.\n")
		return
	}
	if r.URL.Path == "/healthz" {
		v.plain(w, http.StatusOK, "ok\n")
		return
	}
	// The limit comes first and covers every other path, including the ones that do not exist: guessing costs budget.
	if ok, wait := v.lim.allow(v.lim.clientOf(r)); !ok {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		v.plain(w, http.StatusTooManyRequests, "Too many requests. Try again shortly.\n")
		return
	}
	id, part, ok := route(r.URL.Path)
	if !ok {
		v.notFound(w)
		return
	}
	// The listener takes no parameter at all: any query is refused the same way whatever the id is.
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.ContentLength > 0 || len(r.Header.Values("Content-Length")) > 1 {
		v.plain(w, http.StatusBadRequest, "This page takes no parameters.\n")
		return
	}
	ctx := r.Context()
	if !statement.ValidID(id) {
		// The same lookup an unknown id costs, so a malformed id and an unknown one take the same work.
		_, _, _ = v.s.lookupStatement(ctx, "st-00000000000000000000000000000000")
		v.notFound(w)
		return
	}
	live, found, err := v.s.lookupStatement(ctx, id)
	switch {
	case err != nil:
		v.s.log.ErrorContext(ctx, "verify page: the store could not be read", "error", err.Error())
		v.plain(w, http.StatusServiceUnavailable, "The current state could not be read. Try again shortly.\n")
		return
	case !found:
		v.notFound(w)
		return
	}
	switch part {
	case "statement.json":
		v.statementJSON(w, r, live.entry)
	case "status.json":
		v.statusJSON(w, live)
	default:
		v.page(w, r, live)
	}
}

// route splits /s/{id}, /s/{id}/statement.json and /s/{id}/status.json. Anything else is not served.
func route(path string) (id, part string, ok bool) {
	rest, found := strings.CutPrefix(path, "/s/")
	if !found || len(rest) > 64 {
		return "", "", false
	}
	id, part, _ = strings.Cut(rest, "/")
	switch part {
	case "", "statement.json", "status.json":
		return id, part, id != "" && !strings.Contains(rest, "//") && !strings.HasSuffix(rest, "/")
	}
	return "", "", false
}

func (v *verifyPage) statementJSON(w http.ResponseWriter, r *http.Request, e *stmtEntry) {
	setSecurity(w)
	etag := `"` + e.digest + `"`
	// The document is immutable; whether it is still current is the status, which is never cached. So the document may be
	// revalidated cheaply and nothing about its validity rides on a cached copy.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+e.id+`.json"`)
	_, _ = w.Write(e.envelope)
}

// statusJSON is the signed current state, as of the read.
func (v *verifyPage) statusJSON(w http.ResponseWriter, live stmtLive) {
	signer, _, err := v.s.opt.Gate.Credentials()
	if err != nil {
		v.plain(w, http.StatusServiceUnavailable, "No signer.\n")
		return
	}
	e := live.entry
	st := statement.Status{Type: statement.StatusSchema, ID: e.id, State: e.state(), SupersededBy: e.supersededBy, AsOf: pycompat.ISO(v.s.opt.Clock().UTC().Truncate(time.Second))}
	if e.revoked {
		st.RevokedAt = e.revokedAt
	}
	if e.state() == statement.StateRevoked {
		st.SupersededBy = "" // revoked wins; a revoked statement is not "superseded"
	}
	payload, err := st.Canonical()
	if err == nil {
		var env token.Envelope
		if env, err = token.SignDSSE(context.Background(), signer, statement.StatusPayloadType, payload); err == nil {
			var raw []byte
			if raw, err = json.Marshal(env); err == nil {
				setSecurity(w)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, _ = w.Write(raw)
				return
			}
		}
	}
	v.plain(w, http.StatusServiceUnavailable, "The status could not be signed.\n")
}

// ---- the page ----

type checkRow struct {
	N      int
	Name   string
	Status string
	Class  string
	Says   string
	What   string
}

type tableRow struct{ State, Count string }

type pageData struct {
	ID, Word, Class, Sentence     string
	AsOf, Checked                 string
	Doc                           *statement.Document
	Checks                        []checkRow
	ByCoverage, ByClass, Verdicts []tableRow
	Scopes                        []statement.ScopeHealth
	Blind                         []blindRow
	Successor                     string
	Superseded, Revoked, HaveDoc  bool
	Limitation                    string
	Command                       string
	Base                          string
	Insurer                       *insurerView
	SharePct, AgentPct            string
	Telemetry                     []telemetryRow
	CleanWindow                   bool
	BlindTotal                    int64
	LedgerWords                   string
}

type blindRow struct {
	Kind, Scope, From, To string
	Seconds               int64
}

type telemetryRow struct {
	Scope int
	Pct   string
}

type insurerView struct {
	*statement.Insurer
	SharePct, AgentPct string
}

// what each check proves, and what it does not, in one line each.
var checkWhat = [7]string{
	"The statement names the issuer and a key that issuer published signed it. It does not show the issuer is trustworthy.",
	"The signature holds over the exact bytes read: nothing in the statement was changed after it was signed.",
	"The statement is cut from one packet, cites its records by digest, and every one of them is proven to be in the log under a checkpoint the log signed. It does not show the records are complete before the log began.",
	"A witness the issuer does not run has countersigned that checkpoint, so the log cannot be rewritten or shortened without that witness noticing. Without it the statement says so.",
	"The totals and counts are recomputed from the records themselves, by the same code the offline verifier runs, and equal what the statement prints.",
	"Every coverage state, exception class and observed scope is listed (a state left out would read as none), and the exceptions and health equal the records'. Blind windows are printed, never filled in.",
	"The issuer's current state, read when this page was made: neither revoked nor replaced by a correction.",
}

var statusSays = map[verify.Status]string{
	verify.Pass:            "Checked and passed.",
	verify.Fail:            "Checked and FAILED.",
	verify.NotChecked:      "Not checked: an input this page needs was missing.",
	verify.SelfVouched:     "Passed only on the issuer's own word.",
	verify.NotCheckpointed: "Not under a witnessed checkpoint.",
	verify.NotWitnessed:    "NOT YET INDEPENDENTLY WITNESSED: a witness the issuer does not run has not yet seen this log.",
}

func statusClass(s verify.Status) string {
	switch s {
	case verify.Pass:
		return "ok"
	case verify.Fail:
		return "bad"
	}
	return "warn"
}

func (v *verifyPage) page(w http.ResponseWriter, r *http.Request, live stmtLive) {
	e := live.entry
	res, busy := v.s.result(r.Context(), e)
	if busy || res == nil {
		w.Header().Set("Retry-After", "2")
		v.plain(w, http.StatusServiceUnavailable, "The checks are busy. Try again in a moment.\n")
		return
	}
	if res.err != nil || res.rep == nil || len(res.rep.Checks) != 7 {
		v.plain(w, http.StatusServiceUnavailable, "The checks could not be run. Try again shortly.\n")
		return
	}
	asOf := v.s.opt.Clock()
	rep := &verify.Report{Packet: e.id, Checks: slices.Clone(res.rep.Checks)}
	st := e.state()
	rep.Checks[6] = verify.CheckCurrent(e.id, verify.StatementOptions{Live: &verify.Live{State: st, SupersededBy: e.supersededBy, RevokedAt: e.revokedAt, AsOf: asOf}, Options: verify.Options{Now: v.s.opt.Clock}})
	if res.rep.Checks[1].Status != verify.Pass {
		// The signature did not verify: nothing in the statement is shown, and the live state is not vouched for either.
		rep.Checks[6].Status = verify.NotChecked
	}
	d := pageData{ID: e.id, Doc: res.doc, HaveDoc: res.doc != nil, Base: v.base,
		AsOf: asOf.UTC().Format(time.RFC3339), Checked: res.at.UTC().Format(time.RFC3339), Superseded: st == statement.StateSuperseded, Revoked: st == statement.StateRevoked}
	d.Word, d.Class, d.Sentence = pageWord(rep)
	d.Successor = e.supersededBy
	for i, c := range rep.Checks {
		says := statusSays[c.Status]
		if i == 6 {
			says = c.Detail // check 7's words are the verifier's own and carry no name
		}
		d.Checks = append(d.Checks, checkRow{N: i + 1, Name: strings.TrimPrefix(c.Name, fmt.Sprintf("%d. ", i+1)), Status: string(c.Status), Class: statusClass(c.Status), Says: says, What: checkWhat[i]})
		if i == 3 && c.Status == verify.NotWitnessed {
			d.Limitation = "not yet independently witnessed"
		}
	}
	if doc := res.doc; doc != nil {
		for _, c := range doc.Summary.ByCoverage {
			d.ByCoverage = append(d.ByCoverage, tableRow{c.State, fmt.Sprint(c.Count)})
		}
		for _, c := range doc.Summary.Exceptions.ByClass {
			d.ByClass = append(d.ByClass, tableRow{c.State, fmt.Sprint(c.Count)})
		}
		for _, c := range doc.Summary.Receipts.ByVerdict {
			d.Verdicts = append(d.Verdicts, tableRow{c.State, fmt.Sprint(c.Count)})
		}
		d.Scopes = doc.Summary.Health.Scopes
		d.BlindTotal = doc.Summary.Health.BlindSeconds
		for _, b := range doc.Summary.Health.BlindWindows {
			sc := "all scopes"
			if b.Index > 0 {
				sc = fmt.Sprintf("scope %d", b.Index)
			}
			d.Blind = append(d.Blind, blindRow{Kind: b.Kind, Scope: sc, From: b.From, To: b.To, Seconds: b.Seconds})
		}
		d.CleanWindow = doc.Summary.Health.WindowVerified && len(d.Blind) == 0
		l := doc.Summary.Ledger
		d.LedgerWords = fmt.Sprintf("ledger %s: %d record(s) under a checkpoint, %d recorded after it", l.State, l.Checkpointed, l.NotCheckpointed)
		if in := doc.Insurer; in != nil {
			iv := &insurerView{Insurer: in, SharePct: permille(in.SharePerMille), AgentPct: permille(in.AgentSharePerMille)}
			d.Insurer = iv
			for _, t := range in.Telemetry {
				d.Telemetry = append(d.Telemetry, telemetryRow{t.Index, permille(&t.PerMille)})
			}
		}
	}
	d.Command = "clearance verify --statement " + e.id + ".json --statement-keys <the issuer's keys> --statement-issuer <the issuer> --log-keys <log keys> --witness-policy <policy> --status status.json --packet <packet the subscriber opened to you>"
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, d); err != nil || buf.Len() > maxPageBytes {
		v.s.log.ErrorContext(r.Context(), "verify page: the page could not be rendered", "statement", e.id)
		v.plain(w, http.StatusInternalServerError, "The page could not be rendered.\n")
		return
	}
	setSecurity(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func permille(p *int) string {
	if p == nil {
		return "none in the period"
	}
	return fmt.Sprintf("%d.%d%%", *p/10, *p%10)
}

// pageWord is the one word, its colour class and a sentence: VERIFIED, INCOMPLETE, FAILED, SUPERSEDED or REVOKED.
func pageWord(rep *verify.Report) (word, class, sentence string) {
	c7 := rep.Checks[6]
	switch {
	case c7.Status == verify.Fail && strings.HasPrefix(c7.Detail, "REVOKED"):
		return "REVOKED", "bad", "The issuer withdrew this statement. Do not rely on it."
	case c7.Status == verify.Fail && strings.HasPrefix(c7.Detail, "SUPERSEDED"):
		return "SUPERSEDED", "warn", "A correction replaced this statement. Read the newer one."
	}
	switch rep.ExitCode() {
	case 0:
		return "VERIFIED", "ok", "All seven checks passed."
	case 1:
		return "FAILED", "bad", "This statement does not verify. Do not rely on it."
	}
	return "INCOMPLETE", "warn", "Nothing failed, but not every check could be completed. The checks below say which."
}

const pageCSS = `:root{--bg:#fff;--fg:#14171a;--mut:#4b5560;--ok:#0b6b2e;--warn:#8a5a00;--bad:#a01212;--line:#d5dae0}
@media (prefers-color-scheme:dark){:root{--bg:#101316;--fg:#e8ecef;--mut:#a3adb7;--ok:#5fd48a;--warn:#f0b954;--bad:#ff8c8c;--line:#2d343b}}
body{background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;margin:0 auto;max-width:56rem;padding:1rem 1rem 3rem}
h1{font-size:1rem;color:var(--mut);margin:0 0 .5rem;font-weight:600}h2{font-size:1.1rem;margin:2rem 0 .5rem}
.word{font-size:2.6rem;font-weight:800;letter-spacing:.02em;margin:.2rem 0}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:.3rem .5rem;text-align:left;vertical-align:top}
.mut{color:var(--mut)}code{font-family:ui-monospace,monospace;font-size:.9em;overflow-wrap:anywhere}details{border:1px solid var(--line);border-radius:6px;padding:.5rem 1rem;margin:1rem 0}
summary{cursor:pointer;font-weight:600}.box{border:1px solid var(--line);border-radius:6px;padding:.5rem 1rem;margin:1rem 0}`

var cspHeader = func() string {
	sum := sha256.Sum256([]byte(pageCSS))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

var pageTmpl = template.Must(template.New("page").Funcs(template.FuncMap{"css": func() template.CSS { return template.CSS(pageCSS) }}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow">
<title>Verification statement</title><style>{{css}}</style></head><body>
<h1>Verification statement <code>{{.ID}}</code></h1>
<p class="word {{.Class}}" role="status">{{.Word}}</p>
<p>{{.Sentence}}{{if .Successor}} Its successor is <a href="/s/{{.Successor}}">{{.Successor}}</a>.{{end}}</p>
<p class="mut">State read {{.AsOf}} (UTC). Checks 1 to 6 were run at {{.Checked}}. A revoked or replaced statement shows here as soon as the issuer does it.</p>
{{if .Limitation}}<p class="box warn"><strong>Limitation: {{.Limitation}}.</strong> The log's checkpoint has been countersigned only by witnesses the issuer runs, or by ones whose independence is not established. Everything else may be correct; this one assurance is not yet in place.</p>{{end}}
<details><summary>The seven checks</summary>
<table><tbody>{{range .Checks}}<tr><td>{{.N}}</td><td><strong>{{.Name}}</strong><br><span class="mut">{{.What}}</span></td><td class="{{.Class}}"><strong>{{.Status}}</strong><br>{{.Says}}</td></tr>{{end}}</tbody></table>
</details>
{{if .HaveDoc}}{{with .Doc}}
<h2>What the statement says</h2>
<table><tbody>
<tr><th>Period</th><td>{{.Period.From}} to {{.Period.To}}</td></tr>
<tr><th>Scope, as the subscriber prints it</th><td>{{.Scope.Label}} ({{.Scope.Observed}} observed scope(s))</td></tr>
<tr><th>Policy version</th><td>{{.PolicyVersion}}</td></tr>
<tr><th>Profile</th><td>{{.Profile}}</td></tr>
<tr><th>Issued</th><td>{{.IssuedAt}}</td></tr>
<tr><th>Records the counts rest on</th><td>{{.Cited.Count}}</td></tr>
</tbody></table>
{{end}}
<h2>Counts by coverage state</h2>
<table><tbody>{{range .ByCoverage}}<tr><td>{{.State}}</td><td>{{.Count}}</td></tr>{{end}}<tr><th>Total records</th><th>{{.Doc.Summary.TotalRecords}}</th></tr></tbody></table>
<h2>Exceptions by class</h2>
<table><tbody>{{range .ByClass}}<tr><td>{{.State}}</td><td>{{.Count}}</td></tr>{{end}}<tr><th>Total</th><th>{{.Doc.Summary.Exceptions.Total}}</th></tr><tr><th>Unresolved</th><th>{{.Doc.Summary.Exceptions.Unresolved}}</th></tr></tbody></table>
<h2>Observation health</h2>
{{if .CleanWindow}}<p>Every observed scope's feeds were healthy for the whole period.</p>{{else}}<p class="warn"><strong>Not every part of the period could be seen.</strong> {{.BlindTotal}} second(s) in all.</p>{{end}}
<table><thead><tr><th>Scope</th><th>State</th><th>Cleared and verified</th><th>Seen, not cleared</th><th>Could not see (s)</th></tr></thead><tbody>
{{range .Scopes}}<tr><td>{{.Index}}</td><td>{{.State}}{{if not .Collector}} (no collector){{end}}</td><td>{{.Cleared}}</td><td>{{.Seen}}</td><td>{{.BlindSeconds}}</td></tr>{{else}}<tr><td colspan="5">No observed scope.</td></tr>{{end}}
</tbody></table>
{{if .Blind}}<h2>Blind windows</h2><p>Stretches of the period something could not be seen or decided.</p>
<table><thead><tr><th>Kind</th><th>Scope</th><th>From</th><th>To</th><th>Seconds</th></tr></thead><tbody>{{range .Blind}}<tr><td>{{.Kind}}</td><td>{{.Scope}}</td><td>{{.From}}</td><td>{{.To}}</td><td>{{.Seconds}}</td></tr>{{end}}</tbody></table>{{end}}
<h2>Verification result and receipts</h2>
<p>{{.LedgerWords}}.</p>
<table><tbody>{{range .Verdicts}}<tr><td>Receipts, {{.State}}</td><td>{{.Count}}</td></tr>{{end}}<tr><th>Receipts attached</th><th>{{.Doc.Summary.Receipts.Count}}</th></tr></tbody></table>
<p class="mut">The firms that signed them are in the recipient detail, which the subscriber opens to a named recipient.</p>
{{with .Insurer}}<h2>Insurer profile</h2>
<table><tbody>
<tr><th>Critical changes cleared</th><td>{{.CriticalChanges}}</td></tr>
<tr><th>Of those, cleared by two independent people</th><td>{{.WithTwoApprovers}} ({{.SharePct}})</td></tr>
<tr><th>Unresolved exceptions</th><td>{{len .Unresolved}}</td></tr>
<tr><th>Changes proposed by an agent</th><td>{{.AgentChanges}} of {{.Changes}} ({{.AgentPct}})</td></tr>
</tbody></table>
{{if .Unresolved}}<table><thead><tr><th>Unresolved exception, class</th><th>Disposition</th></tr></thead><tbody>{{range .Unresolved}}<tr><td>{{.Class}}</td><td>{{.Disposition}}</td></tr>{{end}}</tbody></table>{{end}}
{{end}}
{{if .Telemetry}}<h2>Telemetry coverage per scope</h2><table><tbody>{{range .Telemetry}}<tr><td>Scope {{.Scope}}</td><td>{{.Pct}} of the period could be seen</td></tr>{{end}}</tbody></table>{{end}}
<h2>Questionnaire mapping</h2>
<p class="mut">Each line says what this statement is evidence for. It is evidence toward the objective, not a claim that the objective is met.</p>
<table><tbody>{{range .Doc.Mapping}}<tr><td><strong>{{.Framework}} {{.Ref}}</strong></td><td>{{.Objective}}<br><span class="mut">{{.Evidence}}</span></td></tr>{{end}}</tbody></table>
{{else}}<p class="box bad">The statement's signature did not verify, so nothing it says is shown.</p>{{end}}
<h2>Check it yourself</h2>
<p><a href="/s/{{.ID}}/statement.json">The signed statement</a> and <a href="/s/{{.ID}}/status.json">its current status</a> (signed) download from this page. Run the same seven checks alone, without Clearance:</p>
<p><code>{{.Command}}</code></p>
<p class="mut">The records, proofs and exception rows are the recipient detail. They are not on this page; the subscriber opens them to a named recipient.</p>
</body></html>
`))
