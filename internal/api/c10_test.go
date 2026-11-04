package api

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// -- the signed grant feed ----------------------------------------------------------------------------------------

// signedFeed is a feed row as the core writes it, signed with a throwaway key, listing tokens issued with it.
func signedFeed(t *testing.T, cluster string, seq int64, ids ...string) (store.Feed, *token.KeySigner) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := token.NewKeySigner(k)
	f := token.Feed{Type: token.FeedType, Issuer: "clearance", Cluster: cluster, Seq: seq, IssuedAt: feedNow.Unix(),
		Expires: feedNow.Add(5 * time.Minute).Unix(), RecordsSeq: 3}
	var served []gate.FeedToken
	for _, id := range ids {
		tk, err := token.Issue(bg, s, token.Claims{Type: token.Type, Issuer: "clearance", Subject: id,
			IssuedAt: feedNow.Unix(), Expires: feedNow.Add(10 * time.Minute).Unix(), Nonce: "n-" + id,
			Clearance: token.Clearance{ID: id, ClearedBy: "policy"},
			Subjects:  token.Subjects{Kind: "manifest-tree", TreeRoot: strings.Repeat("c", 64)},
			Target:    token.Target{Cluster: cluster}})
		if err != nil {
			t.Fatal(err)
		}
		d, _ := token.PayloadDigest(tk.Envelope)
		f.Entries = append(f.Entries, token.FeedEntry{ChangeID: id, Nonce: "n-" + id, Expires: tk.Claims.Expires, PayloadSHA256: d})
		served = append(served, gate.FeedToken{ChangeID: id, TokenView: gate.TokenView{Nonce: "n-" + id, KeyID: tk.KeyID,
			IssuedAt: "2026-10-30T12:30:00Z", ExpiresAt: "2026-10-30T12:40:00Z", DSSE: tk.Envelope, JWT: tk.JWT}})
	}
	env, err := token.SignFeed(bg, s, f)
	if err != nil {
		t.Fatal(err)
	}
	rawEnv, _ := json.Marshal(env)
	rawToks, _ := json.Marshal(served)
	return store.Feed{Cluster: cluster, Seq: seq, KeyID: s.KeyID(), IssuedAt: feedNow, ExpiresAt: feedNow.Add(5 * time.Minute),
		Envelope: rawEnv, Tokens: rawToks}, s
}

func TestTheSignedGrantFeed(t *testing.T) {
	prod, s := signedFeed(t, "hangar-prod", 12, "c-2", "c-7")
	other, _ := signedFeed(t, "other-cluster", 1)
	each(t, world{feeds: []store.Feed{prod, other}}, func(t *testing.T, h *harness) {
		r := h.get("/v1/grant-feeds/hangar-prod", "sync")
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		var got GrantFeed
		if err := json.Unmarshal(r.body, &got); err != nil {
			t.Fatal(err)
		}
		// What G-ARGO-3 does: verify the feed whole against the core's key, then match the tokens to it.
		env, _ := json.Marshal(got.Feed)
		ks := token.KeySet{s.KeyID(): s.Public()}
		f, err := token.VerifyFeed(env, ks, token.FeedOptions{Issuer: "clearance", Cluster: "hangar-prod", MinSeq: 12,
			Now: func() time.Time { return feedNow }})
		if err != nil {
			t.Fatal(err)
		}
		byID := map[string]token.Envelope{}
		for _, tk := range got.Tokens {
			byID[tk.ChangeID] = tk.DSSE
		}
		if err := f.Match(byID); err != nil || len(byID) != 2 || got.Seq != 12 || got.KeyID != s.KeyID() ||
			got.ExpiresAt != "2026-10-30T12:35:00Z" {
			t.Fatalf("%+v %v", got, err)
		}
		// The feed reader reads its clusters' feeds only; an auditor any; a person none.
		h.status(t, 403, "GET", "/v1/grant-feeds/other-cluster", "sync", "")
		if h.get("/v1/grant-feeds/other-cluster", "audit").status != 200 {
			t.Error("the auditor cannot read a feed")
		}
		h.status(t, 403, "GET", "/v1/grant-feeds/hangar-prod", "erin", "")
		h.status(t, 403, "GET", "/v1/grant-feeds/hangar-prod", "tower", "user:erin")
		h.status(t, 404, "GET", "/v1/grant-feeds/no-such", "audit", "")
		h.status(t, 400, "GET", "/v1/grant-feeds/bad..%2F", "audit", "")
		h.status(t, 400, "GET", "/v1/grant-feeds/hangar-prod?x=1", "sync", "")
	})
}

// -- GitHub App installations ---------------------------------------------------------------------------------------

func installationEvents() []store.Event {
	evs := fixtureEvents() // seqs 0-10; receipts on jfillman/flight-api PRs 0-3
	return append(evs,
		// seq 11: the App installed on jfillman; 12: it checks flight-api#1; 13: a deployment request; 14: another
		// installation, suspended.
		ev(map[string]any{"ts": "2026-10-30T12:20:00Z", "principal": "app:177375213", "tool": "app.installation",
			"target": "jfillman", "result": "created: 3 repositories"}),
		ev(map[string]any{"ts": "2026-10-30T12:21:00Z", "principal": "app:177375213", "tool": "provenance.verify",
			"target": "jfillman/flight-api#1", "result": "identity:pass scope:pass"}),
		ev(map[string]any{"ts": "2026-10-30T12:22:00Z", "principal": "app:177375213", "tool": "deploy.request",
			"target": "jfillman/gitops-gate-api@1111111", "result": "deployment run 5 to prod: held"}),
		ev(map[string]any{"ts": "2026-10-30T12:23:00Z", "principal": "app:42", "tool": "app.installation",
			"target": "acme", "result": "suspend: 0 repositories"}),
	)
}

func TestGitHubInstallationsAndTheInstallationFilter(t *testing.T) {
	each(t, world{events: installationEvents()}, func(t *testing.T, h *harness) {
		r := h.get("/v1/github/installations", "tower") // a delegate without a person: refused
		if r.status != 403 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		var got InstallationList
		raw := mustJSON200raw(t, h, "/v1/github/installations", "tower", "user:erin")
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Items) != 2 {
			t.Fatalf("%s", raw)
		}
		a, b := got.Items[0], got.Items[1]
		if a.ID != "177375213" || a.Principal != "app:177375213" || a.Account == nil || *a.Account != "jfillman" ||
			a.Action == nil || *a.Action != "created" || a.Status != "active" || a.FirstSeq != 11 || a.LastSeq != 13 ||
			a.FirstTS != "2026-10-30T12:20:00Z" || a.LastTS != "2026-10-30T12:22:00Z" ||
			a.Records["provenance.verify"] != 1 || a.Records["deploy.request"] != 1 || a.Records["app.installation"] != 1 ||
			len(a.Repos) != 1 || a.Repos[0] != "jfillman/flight-api" {
			t.Errorf("first: %+v", a)
		}
		if b.ID != "42" || b.Status != "suspended" || *b.Account != "acme" || len(b.Repos) != 0 {
			t.Errorf("second: %+v", b)
		}
		// The installation filter: on evidence and counts (its records), verdicts (the ones it wrote), receipts (of
		// the pull requests it checked).
		eqSeqs(t, "its records", seqs(h.ok("/v1/evidence?installation=177375213", "audit")), 13, 12, 11)
		if c := h.ok("/v1/evidence/counts?by=tool&installation=177375213", "audit"); c["total"].(json.Number).String() != "3" {
			t.Errorf("counts: %v", c)
		}
		eqSeqs(t, "its verdicts", seqs(h.ok("/v1/provenance?repo=jfillman/flight-api&installation=177375213", "audit")), 12)
		eqSeqs(t, "all verdicts", seqs(h.ok("/v1/provenance?repo=jfillman/flight-api", "audit")), 12, 10)
		eqSeqs(t, "receipts of the PRs it checked", seqs(h.ok("/v1/receipts?repo=jfillman/flight-api&installation=177375213", "audit")), 5)
		eqSeqs(t, "and not of another installation", seqs(h.ok("/v1/receipts?repo=jfillman/flight-api&installation=42", "audit")))
		for _, p := range []string{"/v1/evidence?installation=app:1", "/v1/receipts?repo=a/b&installation=x", "/v1/evidence/counts?installation=-1"} {
			h.status(t, 400, "GET", p, "audit", "")
		}
	})
}

func mustJSON200raw(t *testing.T, h *harness, path, token, who string) []byte {
	t.Helper()
	r := h.do("GET", path, token, who)
	if r.status != 200 {
		t.Fatalf("GET %s as %s for %s: %d %s", path, token, who, r.status, r.body)
	}
	return r.body
}

// -- the stream -------------------------------------------------------------------------------------------------

type sse struct {
	id, event, data string
}

// openStream connects to /v1/stream and sends its events on the channel until the body ends.
func openStream(t *testing.T, url, token, lastID string) (*http.Response, <-chan sse) {
	t.Helper()
	ctx, cancel := context.WithCancel(bg)
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	out := make(chan sse, 256)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(res.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var cur sse
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if cur.event != "" {
					out <- cur
				}
				cur = sse{}
			case strings.HasPrefix(line, "id: "):
				cur.id = line[4:]
			case strings.HasPrefix(line, "event: "):
				cur.event = line[7:]
			case strings.HasPrefix(line, "data: "):
				cur.data = line[6:]
			}
		}
	}()
	return res, out
}

func next(t *testing.T, ch <-chan sse) sse {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("the stream ended")
		}
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	return sse{}
}

// deployEvent is a deploy.* record naming change c (as the gate writes it: the change summary).
func deployEvent(tool string, c store.Change, cluster, state string) store.Event {
	return ev(map[string]any{"ts": "2026-10-30T12:40:00Z", "principal": "policy", "tool": tool, "app": c.App,
		"boundary": "deployment", "target": c.Repo + "@" + c.Head[:7],
		"change": map[string]any{"id": c.ID, "app": c.App, "env": c.Env, "cluster": cluster, "head": c.Head,
			"tree": strings.Repeat("c", 64), "tier": json.Number("1"), "state": state, "objects": json.Number("1")}})
}

func TestTheStream(t *testing.T) {
	fast := func(o *Options) { o.StreamPoll = 20 * time.Millisecond }
	each(t, world{events: fixtureEvents()}, func(t *testing.T, h *harness) {
		add, _ := appenders.Load(h.srv.opt.Store)
		appendTo := add.(appender)
		srv := httptest.NewServer(h.srv.Handler())
		t.Cleanup(srv.Close)

		// An auditor from after=8: records 9 and 10 at once, in order, each with its seq as id.
		res, all := openStream(t, srv.URL+"/v1/stream?after=8", "audit", "")
		if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" {
			t.Fatal(res.StatusCode, res.Header)
		}
		if e := next(t, all); e.event != "record" || e.id != "9" || !strings.Contains(e.data, `"seq":9`) {
			t.Fatalf("%+v", e)
		}
		if e := next(t, all); e.id != "10" {
			t.Fatalf("%+v", e)
		}
		// From the head: a feed reader (clearance events of its cluster only) and erin (team-gate: the gate-api change).
		_, feed := openStream(t, srv.URL+"/v1/stream", "sync", "")
		_, erin := openStream(t, srv.URL+"/v1/stream", "erin", "")
		time.Sleep(100 * time.Millisecond) // both streams are open at the head before the writes
		mine := onCluster(change("c-9", "gate-api", "cleared", "group:default/team-gate", 1, "2026-10-30T12:40:00Z", nil), "hangar-prod")
		theirs := onCluster(change("c-8", "other-app", "cleared", "group:default/team-other", 1, "2026-10-30T12:40:00Z", nil), "other-cluster")
		appendTo(t, []store.Event{deployEvent("deploy.clear", theirs, "other-cluster", "cleared"),
			deployEvent("deploy.clear", mine, "hangar-prod", "cleared")}, []store.Change{mine, theirs})

		// The auditor: both records, each followed by its clearance event, the id on the last of each seq.
		for _, want := range []struct{ seq int64 }{{11}, {12}} {
			rec, cl := next(t, all), next(t, all)
			if rec.event != "record" || rec.id != "" || cl.event != "clearance" || cl.id != strconv.FormatInt(want.seq, 10) {
				t.Fatalf("%d: %+v %+v", want.seq, rec, cl)
			}
		}
		// The feed reader: only its cluster's clearance event; no record.
		e := next(t, feed)
		var sev StreamEvent
		if err := json.Unmarshal([]byte(e.data), &sev); err != nil || e.event != "clearance" || e.id != "12" ||
			sev.Change["id"] != "c-9" || sev.Tool != "deploy.clear" || sev.Change["state"] != "cleared" {
			t.Fatalf("%+v %+v %v", e, sev, err)
		}
		// erin: the deploy.clear record is not hers (no session of hers, no app she owns); the change is (her
		// group owns it), so she gets its clearance event alone.
		if e := next(t, erin); e.event != "clearance" || e.id != "12" {
			t.Fatalf("%+v", e)
		}
		select {
		case e := <-feed:
			t.Fatalf("the feed reader saw %+v", e)
		case e := <-erin:
			t.Fatalf("erin saw %+v", e)
		case <-time.After(200 * time.Millisecond):
		}
		// Resume with Last-Event-ID: only what follows it.
		_, again := openStream(t, srv.URL+"/v1/stream?types=clearances", "audit", "11")
		if e := next(t, again); e.event != "clearance" || e.id != "12" {
			t.Fatalf("%+v", e)
		}
		// Refusals: the query, the feed reader's records, the per-caller cap.
		h.status(t, 400, "GET", "/v1/stream?types=sessions", "audit", "")
		h.status(t, 400, "GET", "/v1/stream?after=x", "audit", "")
		h.status(t, 403, "GET", "/v1/stream?types=records", "sync", "")
		h.status(t, 401, "GET", "/v1/stream", "", "")
		for i := 0; i < MaxStreamsPerCaller-1; i++ {
			openStream(t, srv.URL+"/v1/stream", "carol", "")
		}
		res, _ = openStream(t, srv.URL+"/v1/stream", "carol", "")
		if res.StatusCode != 200 {
			t.Fatal("the last allowed stream", res.StatusCode)
		}
		if r, _ := openStream(t, srv.URL+"/v1/stream", "carol", ""); r.StatusCode != 503 || r.Header.Get("Retry-After") == "" {
			t.Fatal("past the per-caller cap", r.StatusCode)
		}
	}, fast)
}

func TestTheHubStopsWithItsLastStream(t *testing.T) {
	m := &memStore{}
	h := newHub(m, 10*time.Millisecond, quiet)
	leave, err := h.join(bg, "x")
	if err != nil {
		t.Fatal(err)
	}
	leave()
	leave() // once
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		running := h.running
		h.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the poller kept running with no stream")
}

func TestTheHubRefusesWhenTheStoreIsDown(t *testing.T) {
	m := &memStore{fail: errors.New("down")}
	if _, err := newHub(m, time.Second, quiet).join(bg, "x"); err == nil {
		t.Fatal("joined a hub that cannot read the head")
	}
}
