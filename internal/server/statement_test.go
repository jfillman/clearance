package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/ledger"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/statement"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
	"github.com/jfillman/clearance/internal/verify"
)

// P-3 fixtures: a lab chain with a real witnessed checkpoint (and, when asked, a second witness that is not the lab's),
// built into a packet and published to a real core over HTTP; statements issued through the real authenticated routes and
// read through the real public handler, over a real socket.

type p3opts struct {
	// independent: a second witness, which the deployment declares it does not run, countersigns the checkpoint.
	independent bool
	// blind: the scope's collector stops reporting a day into the period.
	blind bool
	// limits for the public listener (zero: the defaults).
	stmt func(*server.StatementOptions)
	// issuer is the token issuer the statements print ("": clearance).
	issuer string
	// noPage: the verify handler is not built (the listener is off).
	noPage bool
}

type p3lab struct {
	f        *fixture
	coreKey  *token.KeySigner
	vkey     string
	policy   []byte
	dir      string
	bundle   *packet.Bundle
	pid      string
	verifier *httptest.Server
	independ []string
}

const p3Scope = "aws-lab-sentinel"

func p3Keys(t *testing.T, name string) (note.Signer, note.Verifier, string, string) {
	t.Helper()
	skey, vk, cosig, err := ledger.GenerateKey(name)
	if err != nil {
		t.Fatal(err)
	}
	s, v, err := f_note.NewEd25519SignerVerifier(skey)
	if err != nil {
		t.Fatal(err)
	}
	return s, v, vk, cosig
}

func p3Witness(t *testing.T, name string, log note.Verifier) (cosig, url string) {
	t.Helper()
	wskey, _, wcosig, err := ledger.GenerateKey(name)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := f_note.NewSignerForCosignatureV1(wskey)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.NewWitness(ws, []note.Verifier{log}, "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(w.ServeHTTP))
	t.Cleanup(srv.Close)
	return wcosig, srv.URL
}

func p3Health(ts string, interval int) store.Event {
	h := map[string]any{"state": "healthy", "interval_seconds": json.Number(fmt.Sprint(interval)),
		"checks": []any{map[string]any{"name": "trail-enabled", "ok": true}}}
	return store.Event{"ts": ts, "tool": "observation.health", "boundary": "deployment", "coverage": "observed-not-attributed", "scope": p3Scope,
		"source": map[string]any{"name": "cloudtrail"}, "health": h, "principal": nil, "agent": nil, "decision": "allow", "args_sha256": p2hex('0'), "result": "health"}
}

func p3Person(sub string) map[string]any {
	return map[string]any{"sub": sub, "iss": "https://idp.example", "person": sub, "role": "approver", "at": "2026-10-12T08:00:00Z", "kind": "person"}
}

func p3Lab(t *testing.T, o p3opts) *p3lab {
	t.Helper()
	logSigner, logVer, vkey, _ := p3Keys(t, "p3-test-ledger")
	labCosig, labURL := p3Witness(t, "lab-witness", logVer)
	policy := fmt.Sprintf("witness lab %s %s\nquorum lab\n", labCosig, labURL)
	var indep []string
	if o.independent {
		indCosig, indURL := p3Witness(t, "indep-witness", logVer)
		policy = fmt.Sprintf("witness lab %s %s\nwitness ind %s %s\ngroup both all lab ind\nquorum both\n", labCosig, labURL, indCosig, indURL)
		indep = []string{"indep-witness"}
	}
	cfg := config(t, "")
	s := signer(t)
	cfg.Signer, cfg.TokenIssuer, cfg.TokenTTL = s, orDefault(o.issuer, "clearance"), 15*time.Minute
	cfg.Statements = server.StatementOptions{LogKeys: []byte(vkey + "\n"), WitnessPolicy: policy2(policy), IndependentWitnesses: indep,
		ClientPerMinute: 6000, ClientBurst: 1000, GlobalPerMinute: 60000, GlobalBurst: 10000, TrustedProxyHops: 1}
	if o.stmt != nil {
		o.stmt(&cfg.Statements)
	}
	f := newFixture(t, cfg)
	l := &p3lab{f: f, coreKey: s, vkey: vkey, policy: []byte(policy), independ: indep}

	start := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	interval := 5184000
	if o.blind {
		interval = 3600 // the collector's last report holds an hour, then the scope is blind
	}
	f.p2add(t, p3Health("2026-10-09T23:00:00Z", interval))
	for i := 0; i < 12; i++ {
		id := fmt.Sprintf("ch-%016x", i)
		tier := i % 4
		at := start.Add(time.Duration(i) * 20 * time.Hour)
		subj := map[string]any{"kind": "manifest-tree", "name": "gate-api/prod", "digests": map[string]any{"sha256": p2hex('b'), "gitCommit": p2hex('a')[:40]}}
		f.p2add(t, p2event(at.Format(time.RFC3339), "deploy.request", "gate-api", map[string]any{"change": p2change(id, "gate-api", tier, "holding"), "subject": subj}))
		clear := map[string]any{"change": p2change(id, "gate-api", tier, "cleared"), "subject": subj, "cleared_by": "policy", "approvals": []any{}}
		if tier == 3 {
			clear["cleared_by"], clear["approvals"] = "approvals", []any{p3Person("alice-sentinel"), p3Person("bob-sentinel")}
		}
		f.p2add(t, p2event(at.Add(time.Minute).Format(time.RFC3339), "deploy.clear", "gate-api", clear))
	}
	// An out-of-band change in the scope that nobody resolved: an unresolved exception.
	obs := f.p2add(t, store.Event{"ts": "2026-10-15T10:00:00Z", "tool": "observation", "boundary": "deployment", "coverage": "observed-not-attributed", "scope": p3Scope,
		"source":   map[string]any{"name": "cloudtrail", "event_id": "e-1"},
		"resource": map[string]any{"kind": "instance", "name": "i-sentinel"}, "actor": map[string]any{"subject": "arn:aws:iam::111:user/ops-sentinel"},
		"action": map[string]any{"verb": "write", "api": "RunInstances", "succeeded": true}, "principal": nil, "agent": nil, "decision": "allow", "args_sha256": p2hex('0'), "result": "observed"})
	f.p2add(t, store.Event{"ts": "2026-10-15T10:01:00Z", "tool": "assessment", "boundary": "deployment", "coverage": "out-of-band-detected", "scope": p3Scope,
		"about":       map[string]any{"seq": json.Number(fmt.Sprint(obs))},
		"attribution": map[string]any{"signal": "grant-lookup"}, "principal": nil, "agent": nil, "decision": "allow", "args_sha256": p2hex('0'), "result": "assessed"})

	// The ledger: every record under a checkpoint the log signed and every witness countersigned.
	skey := logSigner
	cfgL := ledger.Config{
		Log: ledger.LogConfig{Dir: t.TempDir(), Key: ledger.LogKey{Signer: skey, Verifiers: []note.Verifier{logVer}}, Policy: []byte(policy),
			CheckpointInterval: 200 * time.Millisecond, WitnessTimeout: 2 * time.Second, BatchAge: 20 * time.Millisecond},
		Tier3Wait: true, StallAfter: 3 * time.Second, PollEvery: 50 * time.Millisecond,
	}
	ctx := context.Background()
	lst, ok := f.core.Store.(store.Ledger)
	if !ok {
		t.Fatal("the memory store keeps no ledger")
	}
	svc, err := ledger.Open(ctx, cfgL, f.core.Store, lst, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := f.core.Store.Head(ctx)
	deadline := time.Now().Add(30 * time.Second)
	for svc.Status(ctx).Witnessed != head+1 {
		if time.Now().After(deadline) {
			t.Fatalf("not witnessed in time: %+v", svc.Status(ctx))
		}
		svc.Step(ctx)
		time.Sleep(60 * time.Millisecond)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = svc.Close(cctx)

	now := time.Date(2026, 11, 9, 6, 0, 0, 0, time.UTC)
	res, err := packet.Build(ctx, f.core.Store, packet.Params{From: start.Add(-24 * time.Hour), To: now.Add(-6 * time.Hour), Now: now, Version: "test",
		Scopes: []string{p3Scope}, LogKeys: []string{vkey}, WitnessPolicy: l.policy})
	if err != nil {
		t.Fatal(err)
	}
	l.dir = filepath.Join(t.TempDir(), "packet")
	if _, err := packet.Write(ctx, l.dir, res, []string{"json"}, nil); err != nil {
		t.Fatal(err)
	}
	if l.bundle, err = packet.PackDir(l.dir); err != nil {
		t.Fatal(err)
	}
	l.pid = l.bundle.ID
	f.do("POST", "/v1/packets", "user:admin", l.bundle.JSON).want(t, 200, "")
	if !o.noPage {
		l.verifier = httptest.NewServer(f.core.Server.VerifyHandler())
		t.Cleanup(l.verifier.Close)
	}
	return l
}

// indep is the --independent-witness argument a stranger would give: the independent witness's name and its key as the policy lists it.
func (l *p3lab) indep(t *testing.T) string {
	t.Helper()
	for _, ln := range strings.Split(string(l.policy), "\n") {
		if f := strings.Fields(ln); len(f) >= 3 && f[0] == "witness" && f[1] == "ind" {
			return "indep-witness=" + f[2]
		}
	}
	t.Fatal("no independent witness in the policy")
	return ""
}

// statementWriter writes a record the way the core's issue and revoke do: as the core, with the tool and the statement marked as fields it verified.
func statementWriter() evidence.Writer {
	w := evidence.Core("test")
	w.Verified = map[string]bool{"tool": true, "statement": true, "packet": true, "ts": true, "decision": true, "target": true, "principal": true, "args_sha256": true, "result": true}
	return w
}

func policy2(p string) []byte { return []byte(p) }

func orDefault(v, d string) string {
	if v != "" {
		return v
	}
	return d
}

func (l *p3lab) issue(t *testing.T, body map[string]any) server.StatementIssued {
	t.Helper()
	a := l.f.do("POST", "/v1/statements", "user:admin", body).want(t, 200, "")
	raw, _ := json.Marshal(a.body)
	var out server.StatementIssued
	if err := json.Unmarshal(raw, &out); err != nil || !statement.ValidID(out.ID) {
		t.Fatalf("%v %v", out, err)
	}
	return out
}

func (l *p3lab) req(extra ...map[string]any) map[string]any {
	b := map[string]any{"packet": l.pid, "scope": "Production change management", "policy_version": "gate-1.4"}
	for _, e := range extra {
		for k, v := range e {
			b[k] = v
		}
	}
	return b
}

type page struct {
	status int
	h      http.Header
	body   string
}

func (l *p3lab) get(t *testing.T, path string) page {
	t.Helper()
	return l.getWith(t, "GET", path, nil)
}

func (l *p3lab) getWith(t *testing.T, method, path string, hdr map[string]string) page {
	t.Helper()
	req, err := http.NewRequest(method, l.verifier.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hdr["X-Forwarded-For"]; !ok {
		req.Header.Set("X-Forwarded-For", "198.51.100.1") // the visitor the one trusted proxy saw
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return page{resp.StatusCode, resp.Header, string(raw)}
}

func (p page) word() string {
	m := regexp.MustCompile(`<p class="word [a-z]+" role="status">([A-Z ,]+)</p>`).FindStringSubmatch(p.body)
	if m == nil {
		return ""
	}
	return m[1]
}

var checkNames = verify.StatementChecks

// checkRow is one check's status as the page prints it, found by the check's name.
func (p page) checkStatus(t *testing.T, i int) string {
	t.Helper()
	name := strings.TrimPrefix(checkNames[i], fmt.Sprintf("%d. ", i+1))
	m := regexp.MustCompile(`<td>` + fmt.Sprint(i+1) + `</td><td><strong>` + regexp.QuoteMeta(template(name)) + `</strong>.*?<td class="[a-z]+"><strong>([A-Z ,-]+)</strong>`).FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("check %d (%s) is not on the page", i+1, name)
	}
	return m[1]
}

// template is html/template's escaping of the characters the check names hold.
func template(s string) string {
	return strings.NewReplacer("'", "&#39;", "&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;").Replace(s)
}

// sentinels are values from the lab chain that must never reach the public page: a recipient, a person, a repository, a
// cluster, a scope's real name, an actor, a resource and an approver's issuer.
var sentinels = []string{"gate-api", "hangar-prod", p3Scope, "alice-sentinel", "bob-sentinel", "ops-sentinel", "i-sentinel", "idp.example",
	"lab-auditor", "lab-grc-hub", "user:admin", "lab-witness", "p3-test-ledger", "cloudtrail", "RunInstances", "ch-0000"}

func (l *p3lab) coreKeysFile(t *testing.T) string {
	t.Helper()
	resp, err := http.Get(l.f.srv.URL + "/v1/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return writeTemp(t, "keys.json", raw)
}

func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// offline runs `clearance verify --statement` with every trust input a stranger holds, minus the ones named in drop.
func (l *p3lab) offline(t *testing.T, id string, extra []string, drop ...string) (int, string) {
	t.Helper()
	st := l.get(t, "/s/"+id+"/statement.json")
	status := l.get(t, "/s/"+id+"/status.json")
	if st.status != 200 || status.status != 200 {
		t.Fatalf("download: %d %d", st.status, status.status)
	}
	args := map[string][]string{
		"statement":        {writeTemp(t, "statement.json", []byte(st.body))},
		"statement-keys":   {writeTemp(t, "keys.json", []byte(l.get(t, "/s/"+id+"/keys.json").body))},
		"statement-issuer": {"clearance"},
		"log-keys":         {writeTemp(t, "log.pub", []byte(l.vkey+"\n"))},
		"witness-policy":   {writeTemp(t, "policy.txt", l.policy)},
		"packet":           {l.dir},
		"status":           {writeTemp(t, "status.json", []byte(status.body))},
	}
	for _, d := range drop {
		delete(args, d)
	}
	var argv []string
	for k, v := range args {
		argv = append(argv, "--"+k, v[0])
	}
	argv = append(argv, extra...)
	argv = append(argv, "--no-seen")
	var out, errb bytes.Buffer
	code := verify.Main(argv, &out, &errb)
	return code, out.String() + errb.String()
}

func pageSecurityHeaders(t *testing.T, p page) {
	t.Helper()
	h := p.h
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("headers: %v", h)
	}
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %s", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "script-src") || strings.Contains(csp, "*") {
		t.Errorf("CSP is not strict: %s", csp)
	}
	if h.Get("Set-Cookie") != "" {
		t.Errorf("a cookie: %v", h)
	}
	if cc := h.Get("Cache-Control"); !strings.Contains(cc, "no-store") && !strings.Contains(cc, "no-cache") {
		t.Errorf("cache-control %q", cc)
	}
}

// TestP3StatementGate is the P-3 gate: one command, `go test ./internal/server -run TestP3StatementGate -count=1`. A
// verification statement is issued for a lab change and verifies on the page handler, driven through the real HTTP server,
// with JavaScript-free HTML and every check reported individually; check 4 prints the "not yet independently witnessed"
// limitation in the lab configuration and passes when an independent witness is configured; a revoked statement shows revoked;
// a blind window is printed; and the statement verifies offline with `clearance verify --statement`.
func TestP3StatementGate(t *testing.T) {
	// --- the lab configuration: the only witness is the lab's own ---
	lab := p3Lab(t, p3opts{})
	st := lab.issue(t, lab.req())
	if !st.Created || st.State != "valid" || st.Links.Page != "/s/"+st.ID {
		t.Fatalf("%+v", st)
	}
	began := time.Now()
	pg := lab.get(t, st.Links.Page)
	if took := time.Since(began); took > 2*time.Second {
		t.Errorf("the first load of the page took %s: the card says under two seconds", took)
	}
	if pg.status != 200 || !strings.HasPrefix(pg.h.Get("Content-Type"), "text/html") {
		t.Fatalf("%d %v", pg.status, pg.h)
	}
	pageSecurityHeaders(t, pg)
	for i := range checkNames {
		got := pg.checkStatus(t, i)
		want := "PASS"
		if i == 3 {
			want = "NOT INDEPENDENTLY WITNESSED"
		}
		if got != want {
			t.Errorf("check %d: %q, want %q", i+1, got, want)
		}
	}
	if pg.word() != "INCOMPLETE" || !strings.Contains(pg.body, "not yet independently witnessed") {
		t.Errorf("word %q; the limitation is not printed", pg.word())
	}
	for _, want := range []string{"<details>", "Counts by coverage state", "Questionnaire mapping", "SOC 2 CC8.1", "ISO/IEC 27001:2022 A.8.32", "NIST SP 800-53 Rev. 5 CM-3", "NIST SP 800-53 Rev. 5 CM-5", "SIG", "authorized-and-verified", "out-of-band", "State read"} {
		if !strings.Contains(strings.ReplaceAll(pg.body, "&amp;", "&"), want) && !strings.Contains(pg.body, template(want)) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(strings.ToLower(pg.body), "<script") || regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(pg.body) || strings.Contains(pg.body, "http://") || strings.Contains(pg.body, "https://") {
		t.Error("the page carries script, an event handler or an external reference")
	}
	for _, s := range sentinels {
		if strings.Contains(pg.body, s) {
			t.Errorf("the public page names %q", s)
		}
	}
	// The one inline style is the one the CSP hashes.
	m := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindStringSubmatch(pg.body)
	if m == nil {
		t.Fatal("no style")
	}
	sum := sha256.Sum256([]byte(m[1]))
	if !strings.Contains(pg.h.Get("Content-Security-Policy"), "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Error("the CSP does not hash the page's style")
	}

	// Offline: every input the stranger holds, exit 2 (the lab says so), then each missing input is NOT CHECKED, never a pass.
	code, out := lab.offline(t, st.ID, nil)
	if code != 2 || !strings.Contains(out, "NOT INDEPENDENTLY WITNESSED") || strings.Count(out, "[PASS]") != 6 {
		t.Fatalf("lab offline: exit %d\n%s", code, out)
	}
	for _, c := range []struct {
		drop string
		idx  []int
	}{{"packet", []int{3, 4, 5, 6}}, {"status", []int{7}}, {"log-keys", []int{3}}, {"statement-keys", []int{1, 2}}} {
		code, out := lab.offline(t, st.ID, nil, c.drop)
		if code != 2 {
			t.Errorf("without --%s: exit %d, want 2\n%s", c.drop, code, out)
		}
		if strings.Count(out, "[PASS]") == 7 {
			t.Errorf("without --%s everything passed", c.drop)
		}
	}

	// A revoked statement shows revoked, on the page and offline (exit 1), and nothing else about it changes.
	rv := lab.f.do("POST", "/v1/statements/"+st.ID+"/revoke", "user:admin", map[string]any{"reason": "test"}).want(t, 200, "")
	if rv.body["created"] != true || rv.body["state"] != "revoked" {
		t.Fatalf("%v", rv.body)
	}
	pg = lab.get(t, "/s/"+st.ID)
	if pg.word() != "REVOKED" || pg.checkStatus(t, 6) != "FAIL" || !strings.Contains(pg.body, "REVOKED, as of") {
		t.Errorf("revoked statement: word %q", pg.word())
	}
	if code, out := lab.offline(t, st.ID, nil); code != 1 || !strings.Contains(out, "REVOKED") {
		t.Errorf("revoked offline: exit %d\n%s", code, out)
	}
	n := len(lab.f.toolRecords(server.ToolStatementRevoke))
	lab.f.do("POST", "/v1/statements/"+st.ID+"/revoke", "user:admin", map[string]any{"reason": "again"}).want(t, 200, "")
	if m := len(lab.f.toolRecords(server.ToolStatementRevoke)); m != n || n != 1 {
		t.Errorf("a second revocation wrote a record (%d, %d)", n, m)
	}

	// --- an independent witness is configured: all seven pass, on the page and offline ---
	ind := p3Lab(t, p3opts{independent: true})
	is := ind.issue(t, ind.req())
	pg = ind.get(t, is.Links.Page)
	for i := range checkNames {
		want := "PASS"
		if i == 3 {
			want = "PASS, INDEPENDENCE DECLARED"
		}
		if got := pg.checkStatus(t, i); got != want {
			t.Errorf("independent: check %d is %q, want %q", i+1, got, want)
		}
	}
	// The page never presents the witness's independence as verified: the word may be VERIFIED only with the declaration in the
	// summary (outside the checks' <details>), naming the witness and the command that confirms it.
	summary := pg.body[:strings.Index(pg.body, "<details>")]
	if pg.word() != "VERIFIED, WITNESS INDEPENDENCE DECLARED" || !strings.Contains(pg.body, `class="word warn"`) || strings.Contains(pg.body, "not yet independently witnessed") ||
		!strings.Contains(summary, "Declared by the issuer, not verified here") || !strings.Contains(summary, "indep-witness") ||
		!strings.Contains(summary, "ISSUER DECLARES independent") || !strings.Contains(pg.body, "--independent-witness &lt;name&gt;=&lt;key&gt;") {
		t.Errorf("independent: word %q; the declaration is not in the summary:\n%s", pg.word(), summary)
	}
	if code, out := ind.offline(t, is.ID, []string{"--independent-witness", ind.indep(t)}); code != 0 || strings.Count(out, "[PASS]") != 7 || !strings.Contains(out, "VERIFIED") {
		t.Fatalf("independent offline: exit %d\n%s", code, out)
	}
	// Without naming the independent witness itself, the stranger has only the issuer's word for it: not exit 0.
	if code, out := ind.offline(t, is.ID, nil); code != 2 || !strings.Contains(out, "[SELF-VOUCHED]") {
		t.Errorf("independent, unpinned: exit %d\n%s", code, out)
	}
	// A witness the stranger names that did not countersign is not independence.
	if code, _ := ind.offline(t, is.ID, []string{"--independent-witness", "someone-else=" + strings.SplitN(ind.indep(t), "=", 2)[1]}); code != 2 {
		t.Errorf("a named witness that did not sign: exit %d", code)
	}

	// --- a blind window is printed ---
	bl := p3Lab(t, p3opts{blind: true})
	bs := bl.issue(t, bl.req())
	pg = bl.get(t, bs.Links.Page)
	for _, want := range []string{"Blind windows", "Not every part of the period could be seen", "feed-blind", "scope 1"} {
		if !strings.Contains(pg.body, want) {
			t.Errorf("blind page lacks %q", want)
		}
	}
	if pg.checkStatus(t, 5) != "PASS" {
		t.Errorf("a blind period is printed, not a failure: check 6 is %q", pg.checkStatus(t, 5))
	}
}

func TestP3StatementIsIssuedOnceAndRecordedBeforeItIsServed(t *testing.T) {
	l := p3Lab(t, p3opts{})
	// A write that fails before the commit is not served and not recorded; the retry is the first.
	l.f.core.Server.FailAtomicForTest("before")
	l.f.do("POST", "/v1/statements", "user:admin", l.req()).want(t, 503, "")
	if n := len(l.f.toolRecords(server.ToolStatementIssue)); n != 0 {
		t.Fatalf("%d records after a failed write", n)
	}
	a := l.issue(t, l.req())
	// The same request again, from several callers at once, is one statement and one record.
	var wg sync.WaitGroup
	ids := make([]string, 8)
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids[i] = l.f.do("POST", "/v1/statements", "user:admin", l.req()).body["id"].(string)
		}()
	}
	wg.Wait()
	for _, id := range ids {
		if id != a.ID {
			t.Fatalf("%s is not %s", id, a.ID)
		}
	}
	if n := len(l.f.toolRecords(server.ToolStatementIssue)); n != 1 {
		t.Fatalf("%d issue records for one statement", n)
	}
	// A write that commits and then reports failure: the retry finds it and writes nothing.
	l.f.core.Server.FailAtomicForTest("after")
	l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"policy_version": "gate-1.5"})).want(t, 503, "")
	if n := len(l.f.toolRecords(server.ToolStatementIssue)); n != 2 {
		t.Fatalf("%d records", n)
	}
	l.f.core.Server.ResetStatementIndexForTest()
	b := l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"policy_version": "gate-1.5"})).want(t, 200, "")
	if b.body["created"] != false || len(l.f.toolRecords(server.ToolStatementIssue)) != 2 {
		t.Fatalf("the retry wrote a second record: %v", b.body)
	}
	// The record holds the signed statement and no credential, and names the person who issued it.
	rec := l.f.toolRecords(server.ToolStatementIssue)[0]
	raw, _ := json.Marshal(rec)
	if !strings.Contains(string(raw), `"principal":"user:admin"`) || strings.Contains(string(raw), "Bearer") || strings.Contains(string(raw), "credential") {
		t.Errorf("record: %s", raw)
	}
	// The id is 128 random bits: fixed shape, never derived from the packet or a counter.
	if !regexp.MustCompile(`^st-[0-9a-f]{32}$`).MatchString(a.ID) || strings.Contains(a.ID, l.pid[3:11]) || a.ID == b.body["id"] {
		t.Errorf("ids %s %v", a.ID, b.body["id"])
	}
}

func TestP3IssuingAndRevokingAreAdminGatedAndValidated(t *testing.T) {
	l := p3Lab(t, p3opts{})
	l.f.do("POST", "/v1/statements", "", l.req()).want(t, 401, "")
	l.f.do("POST", "/v1/statements", "user:dana", l.req()).want(t, 403, "")
	l.f.do("POST", "/v1/statements/st-00000000000000000000000000000000/revoke", "user:dana", map[string]any{"reason": "x"}).want(t, 403, "")
	for name, body := range map[string]map[string]any{
		"unknown field":      l.req(map[string]any{"extra": 1}),
		"scope with markup":  l.req(map[string]any{"scope": "<script>alert(1)</script>"}),
		"scope with a URL":   l.req(map[string]any{"scope": "see http://example.invalid"}),
		"scope too long":     l.req(map[string]any{"scope": strings.Repeat("a", 121)}),
		"policy with space":  l.req(map[string]any{"policy_version": "a b"}),
		"policy with markup": l.req(map[string]any{"policy_version": "\"><b>"}),
		"packet not an id":   l.req(map[string]any{"packet": "../../etc/passwd"}),
		"bad profile":        l.req(map[string]any{"profile": "score"}),
		"bad supersedes":     l.req(map[string]any{"supersedes": "st-1"}),
	} {
		if a := l.f.do("POST", "/v1/statements", "user:admin", body); a.status != 400 {
			t.Errorf("%s: %d %v", name, a.status, a.body)
		}
	}
	l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"packet": "pk-" + strings.Repeat("0", 32)})).want(t, 404, "")
	l.f.do("POST", "/v1/statements", "user:admin", "{not json").want(t, 400, "")
	l.f.do("POST", "/v1/statements", "user:admin", strings.Repeat("a", 5000)).want(t, 413, "")
	l.f.do("POST", "/v1/statements/st-00000000000000000000000000000000/revoke", "user:admin", map[string]any{"reason": "x"}).want(t, 404, "")
	l.f.do("POST", "/v1/statements/not-an-id/revoke", "user:admin", map[string]any{"reason": "x"}).want(t, 404, "")
	st := l.issue(t, l.req())
	l.f.do("POST", "/v1/statements/"+st.ID+"/revoke", "user:admin", map[string]any{"reason": ""}).want(t, 400, "")
	l.f.do("POST", "/v1/statements/"+st.ID+"/revoke", "user:admin", map[string]any{"reason": "x", "more": 1}).want(t, 400, "")
	if n := len(l.f.toolRecords(server.ToolStatementIssue)) + len(l.f.toolRecords(server.ToolStatementRevoke)); n != 1 {
		t.Errorf("%d records: a refused request wrote one", n)
	}
}

func TestP3ACorrectionSupersedesAndAPublicReadNeverWrites(t *testing.T) {
	l := p3Lab(t, p3opts{})
	old := l.issue(t, l.req())
	nw := l.issue(t, l.req(map[string]any{"policy_version": "gate-1.5", "supersedes": old.ID}))
	if nw.Supersedes != old.ID {
		t.Fatalf("%+v", nw)
	}
	pg := l.get(t, "/s/"+old.ID)
	if pg.word() != "SUPERSEDED" || !strings.Contains(pg.body, `href="/s/`+nw.ID+`"`) {
		t.Errorf("superseded: word %q", pg.word())
	}
	if w := l.get(t, "/s/"+nw.ID).word(); w != "INCOMPLETE" {
		t.Error("the successor does not show a result")
	}
	if code, out := l.offline(t, old.ID, nil); code != 1 || !strings.Contains(out, "SUPERSEDED by "+nw.ID) {
		t.Errorf("superseded offline: exit %d\n%s", code, out)
	}
	l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"policy_version": "gate-1.6", "supersedes": old.ID})).want(t, 409, "")
	l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"supersedes": "st-" + strings.Repeat("1", 32)})).want(t, 404, "")

	// Reading, any number of times and in any way, appends nothing.
	head, _, _ := l.f.core.Store.Head(context.Background())
	for i := 0; i < 5; i++ {
		l.get(t, "/s/"+old.ID)
		l.get(t, "/s/"+nw.ID+"/status.json")
		l.get(t, "/s/"+nw.ID+"/statement.json")
		l.get(t, "/s/st-"+strings.Repeat("a", 32))
		l.get(t, "/s/garbage")
	}
	if h2, _, _ := l.f.core.Store.Head(context.Background()); h2 != head {
		t.Fatalf("anonymous reads grew the chain from %d to %d", head, h2)
	}

	// A revoked statement cannot be superseded.
	l.f.do("POST", "/v1/statements/"+nw.ID+"/revoke", "user:admin", map[string]any{"reason": "withdrawn"}).want(t, 200, "")
	l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"policy_version": "gate-1.7", "supersedes": nw.ID})).want(t, 409, "")
}

func TestP3ThePublicRouteIsNoOracleAndTakesNothing(t *testing.T) {
	l := p3Lab(t, p3opts{})
	st := l.issue(t, l.req())
	unknown := "/s/st-" + strings.Repeat("a", 32)
	ref := l.get(t, unknown)
	if ref.status != 404 {
		t.Fatalf("%d", ref.status)
	}
	// Malformed ids, traversal, oversize, odd paths and the other statement routes' shapes: one answer, byte for byte.
	for _, p := range []string{"/s/garbage", "/s/", "/s", "/", "/s/" + st.ID + "/", "/s/" + st.ID + "//statement.json", "/s/" + st.ID + "/other", "/s/../etc/passwd",
		"/s/%2e%2e/x", "/s/ST-" + strings.Repeat("A", 32), "/s/st-" + strings.Repeat("a", 31), "/s/st-" + strings.Repeat("a", 33), "/s/st-" + strings.Repeat("g", 32),
		"/s/" + strings.Repeat("a", 5000), "/s/" + st.ID + "%2fstatement.json", "/s/%2e%2e/%2e%2e/etc/passwd", "/s/%2e%2e%2f" + st.ID, "/s/" + st.ID[:5] + "%2d" + st.ID[6:], "/s//" + st.ID, "/s/" + st.ID + "%2f", "/s%2f" + st.ID, "/v1/statements", "/v1/keys", "/readyz", "/access/v1/evaluation", "/s/st-" + strings.Repeat("a", 32) + "/statement.json",
		"/s/st-" + strings.Repeat("a", 32) + "/status.json"} {
		got := l.get(t, p)
		if got.status != 404 || got.body != ref.body {
			t.Errorf("%s: %d %q (want the one 404)", p, got.status, got.body)
		}
		if got.h.Get("Content-Type") != ref.h.Get("Content-Type") || got.h.Get("Content-Security-Policy") != ref.h.Get("Content-Security-Policy") || got.h.Get("Cache-Control") != ref.h.Get("Cache-Control") {
			t.Errorf("%s: the headers differ from the unknown id's", p)
		}
	}
	// A parameter, of any name, is refused whether or not the id is a statement.
	for _, p := range []string{"/s/" + st.ID + "?a=1", "/s/" + st.ID + "?", "/s/" + st.ID + "?x", unknown + "?a=1", "/s/garbage?a=1", "/s/" + st.ID + "/status.json?fresh=1"} {
		if got := l.get(t, p); got.status != 400 && got.status != 404 {
			t.Errorf("%s: %d", p, got.status)
		}
	}
	if a, b := l.get(t, "/s/"+st.ID+"?a=1"), l.get(t, unknown+"?a=1"); a.status != 400 || b.status != 400 || a.body != b.body {
		t.Errorf("a parameter is refused differently for a real id (%d) and an unknown one (%d)", a.status, b.status)
	}
	// Methods: only GET and HEAD.
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		if got := l.getWith(t, m, "/s/"+st.ID, nil); got.status != 405 || got.h.Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %d %v", m, got.status, got.h)
		}
	}
	if h := l.getWith(t, "HEAD", "/s/"+st.ID, nil); h.status != 200 || h.body != "" {
		t.Errorf("HEAD: %d %q", h.status, h.body)
	}
	// Nothing the request says is reflected: not a header, not the path, not the host.
	got := l.getWith(t, "GET", "/s/"+st.ID, map[string]string{"Host": "evil.invalid", "X-Forwarded-Host": "evil2.invalid", "Referer": "http://evil3.invalid", "User-Agent": "reflect-me-ua", "Cookie": "a=reflect-me-cookie"})
	for _, s := range []string{"evil", "reflect-me"} {
		if strings.Contains(got.body, s) {
			t.Errorf("the page reflects %q", s)
		}
	}
	if bad := l.get(t, "/s/<script>alert(1)</script>"); strings.Contains(bad.body, "script") {
		t.Errorf("the 404 reflects the path: %q", bad.body)
	}
	// The statement's own downloads: immutable, revalidated, and the status is signed and never cached.
	sj := l.get(t, "/s/"+st.ID+"/statement.json")
	if sj.status != 200 || sj.h.Get("Content-Type") != "application/json; charset=utf-8" || !strings.Contains(sj.h.Get("Cache-Control"), "no-cache") || sj.h.Get("ETag") == "" {
		t.Fatalf("%d %v", sj.status, sj.h)
	}
	if nm := l.getWith(t, "GET", "/s/"+st.ID+"/statement.json", map[string]string{"If-None-Match": sj.h.Get("ETag")}); nm.status != 304 || nm.body != "" {
		t.Errorf("revalidation: %d", nm.status)
	}
	ss := l.get(t, "/s/"+st.ID+"/status.json")
	if ss.status != 200 || ss.h.Get("Cache-Control") != "no-store" {
		t.Errorf("status: %d %v", ss.status, ss.h)
	}
	pageSecurityHeaders(t, ss)
	for _, s := range sentinels {
		if strings.Contains(sj.body, s) || strings.Contains(ss.body, s) {
			t.Errorf("a downloadable names %q", s)
		}
	}
	// The statement's signed payload is exactly the public summary: decode it and look for anything recipient-level.
	var env struct{ Payload string }
	_ = json.Unmarshal([]byte(sj.body), &env)
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	for _, s := range append(sentinels, "record_seq", "exception_seqs", "approvers", "recipient") {
		if strings.Contains(string(payload), s) {
			t.Errorf("the signed payload names %q", s)
		}
	}
	// The method that is not GET never reaches a handler that writes: the chain is unchanged.
	if len(l.f.toolRecords(server.ToolStatementIssue)) != 1 {
		t.Error("a public request wrote a statement")
	}
}

func TestP3TheLimitsAnswer429WithoutLockoutAndWriteNothing(t *testing.T) {
	l := p3Lab(t, p3opts{stmt: func(o *server.StatementOptions) { o.ClientPerMinute, o.ClientBurst = 60, 4 }})
	st := l.issue(t, l.req())
	head, _, _ := l.f.core.Store.Head(context.Background())
	var got429 page
	n429 := 0
	for i := 0; i < 12; i++ {
		p := l.get(t, "/s/"+st.ID)
		if p.status == 429 {
			n429++
			got429 = p
		}
	}
	if n429 < 6 || got429.h.Get("Retry-After") == "" {
		t.Fatalf("%d refusals, %v", n429, got429.h)
	}
	pageSecurityHeaders(t, got429)
	// A request for a path that does not exist costs the same budget: guessing is not free.
	for i := 0; i < 6; i++ {
		_ = l.get(t, "/s/st-"+strings.Repeat("b", 32))
	}
	if p := l.get(t, "/s/st-"+strings.Repeat("c", 32)); p.status != 429 {
		t.Errorf("a guess after the burst: %d", p.status)
	}
	// Not a lockout: the bucket refills, and the health probe is never limited.
	if p := l.get(t, "/healthz"); p.status != 200 {
		t.Errorf("healthz %d", p.status)
	}
	time.Sleep(1200 * time.Millisecond)
	if p := l.get(t, "/s/"+st.ID); p.status != 200 {
		t.Errorf("after the refill: %d", p.status)
	}
	if h2, _, _ := l.f.core.Store.Head(context.Background()); h2 != head {
		t.Errorf("refusals wrote records: %d to %d", head, h2)
	}

}

func TestP3ARevocationOnAnotherReplicaIsSeenWithinASecond(t *testing.T) {
	l := p3Lab(t, p3opts{})
	st := l.issue(t, l.req())
	if w := l.get(t, "/s/"+st.ID).word(); w != "INCOMPLETE" {
		t.Fatalf("%q", w)
	}
	// Another replica (or a restart that lost the index) wrote the revocation: the record is in the chain and nothing in
	// this process knew. The page reads the chain's tail, so it shows revoked at once and never serves a cached "valid".
	if err := l.f.core.Store.Atomic(context.Background(), func(tx store.Tx) error {
		_, err := tx.Append(context.Background(), store.Event{"ts": time.Now().UTC().Format(time.RFC3339), "task_id": nil, "session": nil, "parent": nil,
			"principal": "user:admin", "agent": nil, "tool": server.ToolStatementRevoke, "tier": nil, "decision": "allow", "rule": nil,
			"target": "statement:" + st.ID, "args_sha256": p2hex('0'), "boundary": "deployment", "result": "revoked elsewhere",
			"statement": map[string]any{"id": st.ID, "reason": "elsewhere"}}, statementWriter())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond) // the background read of the tail runs about once a second
	if w := l.get(t, "/s/"+st.ID).word(); w != "REVOKED" {
		t.Errorf("after another replica revoked: %q", w)
	}
	// And a restart rebuilds the same answer from the chain.
	l.f.core.Server.ResetStatementIndexForTest()
	if w := l.get(t, "/s/"+st.ID).word(); w != "REVOKED" {
		t.Errorf("after a restart: %q", w)
	}
	// A store that cannot be read fails closed: not "valid", not "revoked", an error.
	l.f.core.Server.ResetStatementIndexForTest()
	l.f.core.Server.BreakReadsForTest()
	if p := l.get(t, "/s/"+st.ID); p.status != 503 || strings.Contains(p.body, "VERIFIED") {
		t.Errorf("an unreadable store: %d", p.status)
	}
}

// offlineMutations: what a verifier does with a statement or a packet that was changed. Each is a check that fails (exit 1), not
// a pass and not a crash.
func TestP3TheVerifierFailsWhatWasAlteredAndNeverPassesWhatItCouldNotCheck(t *testing.T) {
	l := p3Lab(t, p3opts{independent: true})
	st := l.issue(t, l.req())
	good, out := l.offline(t, st.ID, []string{"--independent-witness", l.indep(t)})
	if good != 0 {
		t.Fatalf("the baseline does not pass: %d\n%s", good, out)
	}
	stmt := l.get(t, "/s/"+st.ID+"/statement.json").body
	var env map[string]any
	_ = json.Unmarshal([]byte(stmt), &env)
	payload, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
	run := func(name string, envelope []byte, packetDir string, extra ...string) (int, string) {
		t.Helper()
		status := l.get(t, "/s/"+st.ID+"/status.json").body
		args := []string{"--statement", writeTemp(t, "s.json", envelope), "--statement-keys", l.coreKeysFile(t), "--statement-issuer", "clearance",
			"--log-keys", writeTemp(t, "l", []byte(l.vkey+"\n")), "--witness-policy", writeTemp(t, "p", l.policy), "--packet", packetDir,
			"--status", writeTemp(t, "st", []byte(status)), "--independent-witness", l.indep(t), "--no-seen"}
		var o, e bytes.Buffer
		c := verify.Main(append(args, extra...), &o, &e)
		return c, o.String() + e.String()
	}

	// A statement whose bytes were changed: the signature fails.
	tampered := bytes.Replace(payload, []byte(`"Production change management"`), []byte(`"Production change management!"`), 1)
	env2 := map[string]any{"payloadType": env["payloadType"], "payload": base64.StdEncoding.EncodeToString(tampered), "signatures": env["signatures"]}
	b, _ := json.Marshal(env2)
	if c, o := run("tampered", b, l.dir); c != 1 || !strings.Contains(o, "[FAIL] 2.") {
		t.Errorf("a changed statement: %d\n%s", c, o)
	}
	// Garbage, and an envelope of the wrong type, and one signed by a key the verifier does not hold.
	for name, body := range map[string][]byte{"garbage": []byte("not json"), "empty": nil, "wrong type": []byte(`{"payloadType":"x","payload":"e30=","signatures":[{"keyid":"k","sig":"AA=="}]}`), "huge": bytes.Repeat([]byte("a"), statement.MaxEnvelopeBytes+10)} {
		if c, o := run(name, body, l.dir); c == 0 {
			t.Errorf("%s passed:\n%s", name, o)
		}
	}
	other := signer(t)
	re, err := token.SignDSSE(context.Background(), other, statement.PayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := json.Marshal(re)
	if c, o := run("other key", rb, l.dir); c != 1 || !strings.Contains(o, "[FAIL] 1.") {
		t.Errorf("a statement signed by another key: %d\n%s", c, o)
	}
	// A wrong issuer name for the keys the verifier holds.
	if c, o := run("issuer", []byte(stmt), l.dir, "--statement-issuer", "someone-else"); c != 1 {
		t.Errorf("another issuer: %d\n%s", c, o)
	}
	// An issuer that signs a statement whose counts are not the packet's (a buggy or dishonest issuer, with the real key).
	doc, err := statement.Parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	resign := func(d *statement.Document) []byte {
		pl, err := d.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		e, err := token.SignDSSE(context.Background(), l.coreKey, statement.PayloadType, pl)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(e)
		return raw
	}
	clone := func() *statement.Document {
		var d statement.Document
		raw, _ := json.Marshal(doc)
		_ = json.Unmarshal(raw, &d)
		return &d
	}
	d := clone()
	d.Summary.ByCoverage[0].Count++
	d.Summary.TotalRecords++
	if c, o := run("counts", resign(d), l.dir); c != 1 || !strings.Contains(o, "[FAIL] 5.") {
		t.Errorf("counts that do not recompute: %d\n%s", c, o)
	}
	d = clone()
	d.Summary.Exceptions.ByClass = d.Summary.Exceptions.ByClass[1:]
	if c, o := run("class", resign(d), l.dir); c != 1 || !strings.Contains(o, "[FAIL] 6.") {
		t.Errorf("an omitted exception class: %d\n%s", c, o)
	}
	d = clone()
	d.Summary.Exceptions.Unresolved = 0
	if c, o := run("unresolved", resign(d), l.dir); c != 1 || !strings.Contains(o, "[FAIL] 6.") {
		t.Errorf("an unresolved exception hidden: %d\n%s", c, o)
	}
	d = clone()
	d.Summary.Health.BlindSeconds += 100
	if c, o := run("health", resign(d), l.dir); c != 1 || !strings.Contains(o, "[FAIL] 6.") {
		t.Errorf("health that does not match: %d\n%s", c, o)
	}
	d = clone()
	d.Cited.Count--
	if c, o := run("cited", resign(d), l.dir); c != 1 || !strings.Contains(o, "[FAIL] 3.") {
		t.Errorf("cited records that are not the packet's: %d\n%s", c, o)
	}
	d = clone()
	d.Checkpoint.Root = strings.Repeat("0", 64)
	if c, o := run("checkpoint", resign(d), l.dir); c != 1 || !strings.Contains(o, "[FAIL] 3.") {
		t.Errorf("another checkpoint: %d\n%s", c, o)
	}
	d = clone()
	d.Packet.Digest = strings.Repeat("0", 64)
	if c, _ := run("packet", resign(d), l.dir); c != 1 {
		t.Errorf("another packet: %d", c)
	}

	// A packet that was changed after the statement: its manifest, its records and its proofs each fail check 3.
	for name, mutate := range map[string]func(dir string){
		"a record": func(dir string) {
			p := filepath.Join(dir, "evidence", "records.jsonl")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, bytes.Replace(b, []byte("gate-api"), []byte("gate-apx"), 1), 0o644)
		},
		"the proofs": func(dir string) {
			p := filepath.Join(dir, "evidence", "proofs.json")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, bytes.Replace(b, []byte(`"path":["`), []byte(`"path":["00`), 1), 0o644)
		},
		"packet.json": func(dir string) {
			p := filepath.Join(dir, "packet.json")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, bytes.Replace(b, []byte(`"total_records":`), []byte(`"total_records":1`), 1), 0o644)
		},
	} {
		cp := filepath.Join(t.TempDir(), "p")
		if err := copyDir(l.dir, cp); err != nil {
			t.Fatal(err)
		}
		mutate(cp)
		if c, o := run(name, []byte(stmt), cp); c != 1 {
			t.Errorf("a packet with %s changed: exit %d\n%s", name, c, o)
		}
	}
	// A stale status is not a current one, and a status for another statement is refused.
	other2 := l.issue(t, l.req(map[string]any{"policy_version": "gate-9"}))
	os2 := l.get(t, "/s/"+other2.ID+"/status.json").body
	if c, o := run("status", []byte(stmt), l.dir, "--status", writeTemp(t, "other-status", []byte(os2))); c != 1 || !strings.Contains(o, "[FAIL] 7.") {
		t.Errorf("another statement's status: %d\n%s", c, o)
	}
	if c, o := run("stale", []byte(stmt), l.dir, "--status-max-age", "1ns"); c != 2 || !strings.Contains(o, "[NOT CHECKED] 7.") {
		t.Errorf("a stale status: %d\n%s", c, o)
	}
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
}

func TestP3TheInsurerProfilePrintsItsFiveFigures(t *testing.T) {
	l := p3Lab(t, p3opts{})
	st := l.issue(t, l.req(map[string]any{"profile": "insurer"}))
	pg := l.get(t, "/s/"+st.ID)
	for _, want := range []string{"Insurer profile", "Critical changes cleared", "cleared by two independent people", "Unresolved exceptions", "Changes proposed by an agent", "Telemetry coverage per scope", "Privileged change", "Separation of duties", "Unauthorized-change detection"} {
		if !strings.Contains(pg.body, want) {
			t.Errorf("the insurer page lacks %q", want)
		}
	}
	// Three tier 3 changes in the lab, each cleared by two distinct people: 3 of 3, and one unresolved out-of-band exception.
	if !strings.Contains(pg.body, "<td>3</td>") || !strings.Contains(pg.body, "3 (100.0%)") || !strings.Contains(pg.body, "<td>out-of-band</td><td>none-recorded</td>") {
		t.Errorf("the figures are not the lab's:\n%s", pg.body)
	}
	for _, s := range sentinels {
		if strings.Contains(pg.body, s) {
			t.Errorf("the insurer page names %q", s)
		}
	}
	if pg.checkStatus(t, 4) != "PASS" || pg.checkStatus(t, 5) != "PASS" {
		t.Error("the insurer figures do not recompute")
	}
	// A standard statement of the same packet carries none of them.
	std := l.get(t, "/s/"+l.issue(t, l.req()).ID)
	if strings.Contains(std.body, "Insurer profile") {
		t.Error("a standard statement carries the insurer figures")
	}
}
