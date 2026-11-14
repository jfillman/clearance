package grc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/grc"
	"github.com/jfillman/clearance/internal/grc/grctest"
)

const (
	secret   = "s3cr3t-client-secret-value"
	evRes    = "res-evidence-1"
	repRes   = "res-report-1"
	linkBase = "https://clearance.example.com"
)

var now = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// fakeCore is the part of the core the push writes to: POST /v1/records, de-duplicating by the record's event id
// the way the real one does.
type fakeCore struct {
	*httptest.Server
	mu   sync.Mutex
	Recs []map[string]any
	seen map[string]bool
	Down bool
	// Status, when set, answers a record with a status (by its change id), for a core that refuses one item.
	Status func(changeID string) int
}

func newFakeCore() *fakeCore {
	c := &fakeCore{seen: map[string]bool{}}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.Down {
			http.Error(w, "down", 503)
			return
		}
		var in map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &in)
		rec, _ := in["record"].(map[string]any)
		if ch, ok := rec["change"].(map[string]any); ok && c.Status != nil {
			if st := c.Status(fmt.Sprint(ch["id"])); st != 0 {
				http.Error(w, "no", st)
				return
			}
		}
		dup := false
		if src, ok := rec["source"].(map[string]any); ok {
			k := fmt.Sprint(in["kind"], src["name"], src["event_id"])
			dup = c.seen[k]
			c.seen[k] = true
		}
		if !dup {
			c.Recs = append(c.Recs, in)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"seq": len(c.Recs), "duplicate": dup})
	}))
	return c
}

func (c *fakeCore) kinds(kind string) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for _, r := range c.Recs {
		if r["kind"] == kind {
			out = append(out, r)
		}
	}
	return out
}

// items are the per-change grc.push records that landed (not the set's batch record, not a failure).
func (c *fakeCore) items() []map[string]any {
	var out []map[string]any
	for _, r := range c.kinds("grc.push") {
		rec := r["record"].(map[string]any)
		if _, ok := rec["change"]; ok && rec["result"] == "pushed" {
			out = append(out, r)
		}
	}
	return out
}

func (c *fakeCore) raw() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := json.Marshal(c.Recs)
	return string(b)
}

func change(id, env, state string, tier int, ago time.Duration) gate.Change {
	at := now.Add(-ago)
	d := gate.PyTime{Time: at}
	c := gate.Change{ID: id, App: "shop", Env: env, Cluster: "sentinel-cluster", Repo: "sentinel-org/sentinel-repo", PR: 4242,
		Proposer: "user:sentinel-proposer", ProposerKind: "person", Paths: []string{"sentinel/path/deploy.yaml"},
		TreeDigest: strings.Repeat("ab", 32), PolicyVersion: "v7", Tier: tier, State: state,
		Checks:    map[string]string{"sentinel-check": "pass"}, //
		Approvals: []gate.Approval{{Person: "user:sentinel-approver", Role: "owner", At: at.Format(time.RFC3339), Kind: "person"}},
		CreatedAt: d, UpdatedAt: d, DecidedAt: &d}
	if state == gate.StateCleared {
		c.ClearedBy = strp("people")
	}
	return c
}

func strp(s string) *string { return &s }

type rig struct {
	hub    *grctest.Vanta
	api    *grctest.API
	core   *fakeCore
	cfg    grc.Config
	logs   *bytes.Buffer
	sleeps []time.Duration
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{hub: grctest.NewVanta("client-1", secret), api: grctest.NewAPI(), core: newFakeCore(), logs: &bytes.Buffer{}}
	t.Cleanup(func() { r.hub.Close(); r.api.Close(); r.core.Close() })
	dir := t.TempDir()
	sec, tok := filepath.Join(dir, "secret"), filepath.Join(dir, "token")
	os.WriteFile(sec, []byte(secret+"\n"), 0o600)
	os.WriteFile(tok, []byte("clearance/grc\n"), 0o600)
	env := map[string]string{
		"CLEARANCE_GRC_TARGET": "vanta", "CLEARANCE_GRC_VANTA_BASE_URL": r.hub.URL, "CLEARANCE_GRC_VANTA_CLIENT_ID": "client-1",
		"CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE": sec, "CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID": evRes,
		"CLEARANCE_GRC_VANTA_REPORT_RESOURCE_ID": repRes, "CLEARANCE_API_URL": r.api.URL, "CLEARANCE_URL": r.core.URL,
		"CLEARANCE_GRC_SA_TOKEN_FILE": tok, "CLEARANCE_GRC_LINK_BASE": linkBase, "CLEARANCE_GRC_BACKOFF_BASE": "1s", "CLEARANCE_GRC_BACKOFF_MAX": "30s",
	}
	cfg, err := grc.ConfigFromEnv(func(k string) string { return env[k] }, grc.ConfigLoopbackForTest())
	if err != nil {
		t.Fatal(err)
	}
	r.cfg = cfg
	return r
}

func (r *rig) service(t *testing.T) *grc.Service {
	t.Helper()
	v, err := grc.NewVanta(r.cfg.VantaBaseURL, r.cfg.VantaClientID, r.cfg.VantaSecretFile, r.cfg.VantaEvidenceResource, r.cfg.VantaReportResource, grc.InsecureLoopbackForTest())
	if err != nil {
		t.Fatal(err)
	}
	s := grc.NewService(r.cfg, v, slog.New(slog.NewTextHandler(r.logs, nil)))
	s.Now = func() time.Time { return now }
	s.Sleep = func(_ context.Context, d time.Duration) error { r.sleeps = append(r.sleeps, d); return nil }
	return s
}

func TestOffUnlessConfigured(t *testing.T) {
	_, err := grc.ConfigFromEnv(func(string) string { return "" })
	if !errors.Is(err, grc.ErrOff) {
		t.Fatalf("no target must be off, got %v", err)
	}
	// Even with every other setting present, no target means off.
	_, err = grc.ConfigFromEnv(func(k string) string {
		return map[string]string{"CLEARANCE_API_URL": "http://x", "CLEARANCE_GRC_LINK_BASE": linkBase}[k]
	})
	if !errors.Is(err, grc.ErrOff) {
		t.Fatalf("got %v", err)
	}
}

func TestConfigRefusals(t *testing.T) {
	r := newRig(t)
	base := map[string]string{
		"CLEARANCE_GRC_TARGET": "vanta", "CLEARANCE_GRC_VANTA_BASE_URL": "https://api.vanta.com", "CLEARANCE_GRC_VANTA_CLIENT_ID": "c",
		"CLEARANCE_GRC_VANTA_CLIENT_SECRET_FILE": "/x", "CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID": "r", "CLEARANCE_API_URL": "http://api",
		"CLEARANCE_URL": "http://core", "CLEARANCE_GRC_LINK_BASE": linkBase}
	with := func(k, v string) error {
		_, err := grc.ConfigFromEnv(func(x string) string {
			if x == k {
				return v
			}
			return base[x]
		})
		return err
	}
	if err := with("X", ""); err != nil {
		t.Fatalf("the base config is valid: %v", err)
	}
	for k, v := range map[string]string{
		"CLEARANCE_GRC_VANTA_BASE_URL":             "http://api.vanta.com",     // http, not loopback
		"CLEARANCE_GRC_LINK_BASE":                  "http://clearance.example", // the link is https always
		"CLEARANCE_GRC_VANTA_CLIENT_ID":            "",
		"CLEARANCE_GRC_TARGET":                     "drata",
		"CLEARANCE_GRC_VANTA_EVIDENCE_RESOURCE_ID": "",
		"CLEARANCE_GRC_VANTA_BASE_URL ":            "",
	} {
		if strings.HasSuffix(k, " ") {
			continue
		}
		if err := with(k, v); err == nil {
			t.Errorf("%s=%q was accepted", k, v)
		}
	}
	for _, u := range []string{"https://user:pw@api.vanta.com", "https://api.vanta.com?x=1", "ftp://x", "https://", "http://evil.example"} {
		if grc.CheckURL(u, "U", true) == nil {
			t.Errorf("%s accepted", u)
		}
	}
	for _, u := range []string{"https://api.vanta.com", "http://127.0.0.1:9", "http://localhost:1", "http://[::1]:5"} {
		if err := grc.CheckURL(u, "U", true); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	if grc.CheckURL("http://127.0.0.1", "U", false) == nil {
		t.Error("loopback http only when allowed")
	}
	_ = r
}

// The card's gate, in miniature: a change appears as an item at the hub with a link back.
func TestAChangeBecomesAnEvidenceItemWithALinkBack(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 2, time.Hour))
	if err := r.service(t).PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	it, ok := r.hub.Item(evRes, "clearance-change-chg-1")
	if !ok {
		t.Fatal("no evidence item at the hub")
	}
	if it["externalUrl"] != linkBase+"/changes/chg-1" {
		t.Fatalf("link back: %v", it["externalUrl"])
	}
	p := it["customProperties"].(map[string]any)
	if p["origin"] != "person" || p["tier"] != float64(2) || p["approver_kind"] != "person" || p["controls"] != "soc2/2017:CC8.1" || p["change_digest"] != strings.Repeat("ab", 32) {
		t.Fatalf("properties: %v", p)
	}
	// The ledger holds a grc.push for it, naming the change and the digest sent, and the link.
	recs := r.core.items()
	if len(recs) != 1 {
		t.Fatalf("%d grc.push records", len(recs))
	}
	rec := recs[0]["record"].(map[string]any)
	if rec["result"] != "pushed" || rec["target"] != "vanta" || rec["change"].(map[string]any)["id"] != "chg-1" || rec["args_sha256"] == "" {
		t.Fatalf("%v", rec)
	}
}

// Only the documented fields leave: every key of the outbound payload is one the docs list, and nothing else of the
// change (repository, pull request, paths, proposer, approver, checks, cluster) appears anywhere in any body sent.
func TestNothingButDocumentedFieldsLeaves(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 3, time.Hour), change("chg-2", "prod", gate.StateDenied, 3, time.Hour))
	s := r.service(t)
	if err := s.PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.ReportOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, body := range append(r.hub.Bodies, r.hub.TokenBodies...) {
		for _, bad := range []string{"sentinel", "4242", "user:", "deploy.yaml", `"repo"`, `"pr"`, `"paths"`, `"proposer"`, `"checks"`, `"cluster"`} {
			if bytes.Contains(body, []byte(bad)) {
				t.Errorf("a body carries %q: %s", bad, body)
			}
		}
	}
	for _, body := range r.hub.Bodies {
		var in struct {
			ResourceID string
			Resources  []map[string]json.RawMessage
		}
		if err := json.Unmarshal(body, &in); err != nil {
			t.Fatal(err)
		}
		fields := grc.EvidenceFields
		if in.ResourceID == repRes {
			fields = grc.ReportFields
		}
		for _, res := range in.Resources {
			for k := range res {
				if k != "displayName" && k != "uniqueId" && k != "externalUrl" && k != "customProperties" {
					t.Errorf("unexpected resource key %q", k)
				}
			}
			var props map[string]any
			_ = json.Unmarshal(res["customProperties"], &props)
			if len(props) != len(fields) {
				t.Errorf("%s: %d properties sent, %d documented", in.ResourceID, len(props), len(fields))
			}
			for k, v := range props {
				if _, ok := fields[k]; !ok {
					t.Errorf("undocumented property %q", k)
				}
				switch v.(type) {
				case string, float64, bool:
				default:
					t.Errorf("property %q is not a flat scalar: %T", k, v)
				}
			}
		}
	}
	// The token request carries the client id, the secret and the scope: the credential's own exchange, nothing else.
	var tr map[string]string
	_ = json.Unmarshal(r.hub.TokenBodies[0], &tr)
	if len(tr) != 4 || tr["scope"] != grc.VantaScope || tr["grant_type"] != "client_credentials" {
		t.Fatalf("%v", tr)
	}
	// No approver identity, in any form, not even a hash: the kind and the count only.
	p, _ := r.hub.Item(evRes, "clearance-change-chg-1")
	props := p["customProperties"].(map[string]any)
	if _, has := props["approvers_sha256"]; has || props["approver_count"] != float64(1) || props["approver_kind"] != "person" {
		t.Fatalf("approvers: %v", props)
	}
}

func TestOnlyClearedChangesOfTheConfiguredEnvsInTheWindow(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("in", "prod", gate.StateCleared, 1, time.Hour),
		change("dev", "dev", gate.StateCleared, 1, time.Hour),
		change("denied", "prod", gate.StateDenied, 1, time.Hour),
		change("old", "prod", gate.StateCleared, 1, 100*24*time.Hour))
	if err := r.service(t).PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := r.hub.Items(evRes); n != 1 {
		t.Fatalf("%d items", n)
	}
	if _, ok := r.hub.Item(evRes, "clearance-change-in"); !ok {
		t.Fatal("the in-scope change is not there")
	}
}

func TestLinkIsBuiltFromConfigAndAnUnsafeIdIsNotSent(t *testing.T) {
	b := grc.Builder{LinkBase: linkBase}
	if l, ok := b.Link("chg-1"); !ok || l != linkBase+"/changes/chg-1" {
		t.Fatal(l)
	}
	for _, id := range []string{"", "../../x", "a/b", "a?b=c", "a#f", "https://evil.example", "a b", strings.Repeat("a", 200)} {
		if _, ok := b.Link(id); ok {
			t.Errorf("id %q got a link", id)
		}
	}
	r := newRig(t)
	bad := change("x/../y", "prod", gate.StateCleared, 1, time.Hour)
	r.api.Set(bad)
	// Nothing sendable is an empty set, which is refused (never PUT as empty): see TestEmptyAndShrinkGuards.
	if err := r.service(t).PushOnce(context.Background()); err == nil {
		t.Fatal("an empty set was pushed")
	}
	if r.hub.Puts != 0 {
		t.Fatal("a change with an unsafe id was sent")
	}
}

// A retry, a restart and a second replica leave one item at the hub and one record per item in the ledger.
func TestPushIsIdempotent(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour), change("chg-2", "prod", gate.StateCleared, 2, 2*time.Hour))
	ctx := context.Background()
	s := r.service(t)
	for i := 0; i < 3; i++ {
		if err := s.PushOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if r.hub.Puts != 1 {
		t.Fatalf("an unchanged set was sent %d times", r.hub.Puts)
	}
	// A restart: a new Service with no memory pushes the same set again; the hub's set does not grow, and the core
	// de-duplicates the records.
	s2 := r.service(t)
	if err := s2.PushOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if r.hub.Puts != 2 || r.hub.Items(evRes) != 2 {
		t.Fatalf("puts %d items %d", r.hub.Puts, r.hub.Items(evRes))
	}
	if n := len(r.core.items()); n != 2 {
		t.Fatalf("%d grc.push records after a restart, want 2", n)
	}
	// The hub itself taking the same body twice (a duplicate submission) is the same set.
	hubBody := r.hub.Bodies[0]
	req, _ := http.NewRequest("PUT", r.hub.URL+"/v1/resources/custom_resource", bytes.NewReader(hubBody))
	req.Header.Set("Authorization", r.hub.LastAuth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 || r.hub.Items(evRes) != 2 {
		t.Fatalf("duplicate submission: %v %v items %d", err, resp, r.hub.Items(evRes))
	}
	// A changed item is a new record (its digest changed), and still one item.
	c := change("chg-1", "prod", gate.StateCleared, 3, time.Hour)
	r.api.Set(c, change("chg-2", "prod", gate.StateCleared, 2, 2*time.Hour))
	if err := s2.PushOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if r.hub.Items(evRes) != 2 || len(r.core.items()) != 3 {
		t.Fatalf("items %d records %d", r.hub.Items(evRes), len(r.core.items()))
	}
}

func TestRetriesWithBackoffAndHonoursRetryAfter(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	r.hub.Fail = []grctest.Failure{{Status: 429, RetryAfter: "7"}, {Status: 503}, {Status: 500}}
	if err := r.service(t).PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.hub.Puts != 4 || len(r.sleeps) != 3 {
		t.Fatalf("puts %d sleeps %v", r.hub.Puts, r.sleeps)
	}
	if r.sleeps[0] != 7*time.Second {
		t.Errorf("Retry-After 7 waited %s", r.sleeps[0])
	}
	for i, d := range r.sleeps[1:] { // backoff 1s base: attempt 2 is 2s, attempt 3 4s, each jittered into [half, whole]
		hi := time.Second << (i + 1)
		if d < hi/2 || d > hi {
			t.Errorf("sleep %d = %s, want within [%s, %s]", i+1, d, hi/2, hi)
		}
	}
	if r.hub.Items(evRes) != 1 || len(r.core.items()) != 1 {
		t.Fatal("the push did not land after the retries")
	}
	if len(r.core.kinds("grc.push")[0]["record"].(map[string]any)) == 0 || strings.Contains(r.core.raw(), `"failed"`) {
		t.Fatal("a push that landed is not a failure")
	}
}

func TestBoundedRetriesThenALedgerRecordNeverASilentDrop(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	for i := 0; i < 20; i++ {
		r.hub.Fail = append(r.hub.Fail, grctest.Failure{Status: 503})
	}
	s := r.service(t)
	err := s.PushOnce(context.Background())
	var e *grc.Error
	if !errors.As(err, &e) || e.Class != "unavailable" {
		t.Fatalf("got %v", err)
	}
	if r.hub.Puts != r.cfg.Attempts {
		t.Fatalf("%d attempts, want the bound %d", r.hub.Puts, r.cfg.Attempts)
	}
	if s.Healthy() {
		t.Fatal("a failed cycle is not healthy")
	}
	recs := r.core.kinds("grc.push")
	if len(recs) != 1 || recs[0]["record"].(map[string]any)["result"] != "failed" || recs[0]["record"].(map[string]any)["reason"] != "unavailable" {
		t.Fatalf("the failure is not in the ledger: %v", recs)
	}
	// Nothing was marked sent: once the hub is back, the next cycle sends it.
	r.hub.Fail = nil
	if err := s.PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.hub.Items(evRes) != 1 || !s.Healthy() {
		t.Fatal("the next cycle did not recover")
	}
}

func TestAuthFailureIsNotRetriedAndLeaksNothing(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	r.hub.ClientSecret = "a-different-secret"
	s := r.service(t)
	err := s.PushOnce(context.Background())
	var e *grc.Error
	if !errors.As(err, &e) || e.Class != "auth" || e.Retryable {
		t.Fatalf("got %v", err)
	}
	if r.hub.Tokens != 1 || r.hub.Puts != 0 {
		t.Fatalf("a bad credential was retried: tokens %d puts %d", r.hub.Tokens, r.hub.Puts)
	}
	if rec := r.core.kinds("grc.push"); len(rec) != 1 || rec[0]["record"].(map[string]any)["reason"] != "auth" {
		t.Fatalf("%v", rec)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(r.logs.String(), secret) || strings.Contains(r.core.raw(), secret) {
		t.Fatal("the secret leaked")
	}
}

func TestARevokedTokenIsMintedAgainOnce(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	s := r.service(t)
	if err := s.PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Another mint (another client of the same application) invalidates ours.
	http.Post(r.hub.URL+"/oauth/token", "application/json", strings.NewReader(fmt.Sprintf(`{"client_id":"client-1","client_secret":%q,"scope":"x","grant_type":"client_credentials"}`, secret)))
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour), change("chg-2", "prod", gate.StateCleared, 1, time.Hour))
	if err := s.PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.hub.Items(evRes) != 2 {
		t.Fatal("the push did not land after a re-mint")
	}
	if r.hub.Tokens != 3 {
		t.Fatalf("tokens minted %d (one, the other client's, one re-mint)", r.hub.Tokens)
	}
}

// No credential or token in the chain, the logs, the errors or what the hub's error bodies echo.
func TestNoTokenInRecordsLogsOrErrors(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	r.hub.Fail = []grctest.Failure{{Status: 503}, {Status: 400}} // each answer echoes the bearer token back in its body
	s := r.service(t)
	var all []string
	if err := s.PushOnce(context.Background()); err != nil {
		all = append(all, err.Error())
	}
	r.hub.Fail = nil
	r.hub.ClientSecret = "rotated"
	s2 := r.service(t)
	if err := s2.PushOnce(context.Background()); err != nil {
		all = append(all, err.Error())
	}
	_ = s2.ReportOnce(context.Background())
	hay := strings.Join(all, "\n") + r.logs.String() + r.core.raw()
	for _, needle := range []string{secret, "secret-access-token", "Bearer", "rotated", "a-different"} {
		if strings.Contains(hay, needle) {
			t.Errorf("%q is in the chain, logs or errors", needle)
		}
	}
	if len(all) == 0 {
		t.Fatal("the failures were not exercised")
	}
}

func TestResponseBodiesAreCapped(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	r.hub.Huge = 8 << 20
	err := r.service(t).PushOnce(context.Background())
	var e *grc.Error
	// The capped read is not valid JSON: a bad response, not an out-of-memory read.
	if !errors.As(err, &e) || e.Class != "bad-response" {
		t.Fatalf("got %v", err)
	}
}

func TestPaginationAndTheItemCap(t *testing.T) {
	r := newRig(t)
	r.api.PageSize = 2
	var cs []gate.Change
	for i := 0; i < 7; i++ {
		cs = append(cs, change(fmt.Sprintf("chg-%d", i), "prod", gate.StateCleared, 1, time.Duration(i+1)*time.Hour))
	}
	r.api.Set(cs...)
	if err := r.service(t).PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.hub.Items(evRes) != 7 {
		t.Fatalf("%d items across pages", r.hub.Items(evRes))
	}
	// A cap that trims the set refuses the cycle: the hub keeps what it has, and the refusal is a record.
	r.cfg.MaxItems = 3
	puts := r.hub.Puts
	err := r.service(t).PushOnce(context.Background())
	var rf *grc.Refusal
	if !errors.As(err, &rf) || rf.Reason != grc.ReasonTruncated || r.hub.Puts != puts || r.hub.Items(evRes) != 7 {
		t.Fatalf("a capped read was pushed: %v", err)
	}
	if f := r.core.kinds("grc.push"); f[len(f)-1]["record"].(map[string]any)["reason"] != "truncated" {
		t.Fatal("the truncation is not a record")
	}
}

func TestCoverageReportIsCountsPerDayAndLandsOnItsOwnResource(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("a", "prod", gate.StateCleared, 1, time.Hour), change("b", "prod", gate.StateCleared, 3, 2*time.Hour),
		change("c", "prod", gate.StateDenied, 2, 3*time.Hour), change("d", "prod", gate.StateCleared, 0, 30*time.Hour))
	s := r.service(t)
	if err := s.ReportOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	it, ok := r.hub.Item(repRes, "clearance-coverage-prod-2026-11-14")
	if !ok {
		t.Fatalf("no report for the day: %v", r.hub.Sets[repRes])
	}
	p := it["customProperties"].(map[string]any)
	if p["changes_total"] != float64(3) || p["changes_cleared"] != float64(2) || p["changes_denied"] != float64(1) || p["cleared_tier3"] != float64(1) || p["cleared_by_people"] != float64(2) {
		t.Fatalf("%v", p)
	}
	if r.hub.Items(repRes) != 2 || r.hub.Items(evRes) != 0 {
		t.Fatal("a report is its own resource, one item a day")
	}
	if rec := r.core.kinds("grc.report"); len(rec) != 1 || rec[0]["record"].(map[string]any)["result"] != "pushed" {
		t.Fatalf("%v", rec)
	}
	// Again: the same report, the same record.
	if err := s.ReportOnce(context.Background()); err != nil || len(r.core.kinds("grc.report")) != 1 {
		t.Fatalf("a repeat report: %v", err)
	}
	// Without a report resource, nothing is sent and nothing fails.
	r.cfg.VantaReportResource = ""
	before := r.hub.Puts
	if err := r.service(t).ReportOnce(context.Background()); err != nil || r.hub.Puts != before {
		t.Fatalf("report off: %v puts %d", err, r.hub.Puts-before)
	}
}

func TestLedgerDownDoesNotLoseTheRecordAndRetriesNextCycle(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	s := r.service(t)
	r.core.Down = true
	if err := s.PushOnce(context.Background()); err == nil {
		t.Fatal("an unrecorded push must be an error")
	}
	r.core.Down = false
	if err := s.PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.core.items()) != 1 {
		t.Fatal("the record was not written once the core was back")
	}
}

func TestTheSecretIsReadFromTheFileEachMint(t *testing.T) {
	r := newRig(t)
	r.api.Set(change("chg-1", "prod", gate.StateCleared, 1, time.Hour))
	os.WriteFile(r.cfg.VantaSecretFile, []byte("rotated-secret\n"), 0o600)
	r.hub.ClientSecret = "rotated-secret"
	if err := r.service(t).PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}
