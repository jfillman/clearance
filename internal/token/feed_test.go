package token_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/token"
)

func feedOf(t *testing.T, s *token.KeySigner, seq int64, toks ...token.Token) (token.Feed, []byte) {
	t.Helper()
	f := token.Feed{Type: token.FeedType, Issuer: "clearance", Cluster: "prod-1", Seq: seq, IssuedAt: t0.Unix(),
		Expires: t0.Add(5 * time.Minute).Unix(), RecordsSeq: 41}
	for _, tk := range toks {
		d, err := token.PayloadDigest(tk.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		f.Entries = append(f.Entries, token.FeedEntry{ChangeID: tk.Claims.Subject, Nonce: tk.Claims.Nonce,
			Expires: tk.Claims.Expires, PayloadSHA256: d})
	}
	env, err := token.SignFeed(bg, s, f)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	return f, raw
}

func issued(t *testing.T, s *token.KeySigner, id, nonce string) token.Token {
	t.Helper()
	c := claims()
	c.Subject, c.Clearance.ID, c.Nonce = id, id, nonce
	tk, err := token.Issue(bg, s, c)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func feedOpts(now time.Time, minSeq int64) token.FeedOptions {
	return token.FeedOptions{Issuer: "clearance", Cluster: "prod-1", MinSeq: minSeq, Now: func() time.Time { return now }}
}

func TestGrantFeed(t *testing.T) {
	s := newSigner(t)
	ks := keys(t, s)
	b, a := issued(t, s, "ch-b", "nb"), issued(t, s, "ch-a", "na")
	_, raw := feedOf(t, s, 7, b, a)

	f, err := token.VerifyFeed(raw, ks, feedOpts(t0.Add(time.Minute), 7))
	if err != nil {
		t.Fatal(err)
	}
	if f.Seq != 7 || f.RecordsSeq != 41 || len(f.Entries) != 2 || f.Entries[0].ChangeID != "ch-a" {
		t.Fatalf("feed: %+v", f)
	}
	// The tokens served beside it must be exactly the entries, each the issuance listed.
	all := map[string]token.Envelope{"ch-a": a.Envelope, "ch-b": b.Envelope}
	if err := f.Match(all); err != nil {
		t.Fatal(err)
	}
	if err := f.Match(map[string]token.Envelope{"ch-a": a.Envelope}); !errors.Is(err, token.ErrFeedIncomplete) {
		t.Errorf("a withheld token: %v", err)
	}
	extra := map[string]token.Envelope{"ch-a": a.Envelope, "ch-b": b.Envelope, "ch-c": a.Envelope}
	if err := f.Match(extra); !errors.Is(err, token.ErrFeedIncomplete) {
		t.Errorf("an added token: %v", err)
	}
	// A re-issue (same nonce, a later iat) is not the issuance the feed lists.
	c2 := claims()
	c2.Subject, c2.Clearance.ID, c2.Nonce, c2.IssuedAt = "ch-b", "ch-b", "nb", t0.Unix()+60
	again, _ := token.Issue(bg, s, c2)
	if err := f.Match(map[string]token.Envelope{"ch-a": a.Envelope, "ch-b": again.Envelope}); !errors.Is(err, token.ErrFeedIncomplete) {
		t.Errorf("another issuance: %v", err)
	}

	// Replay, staleness, another cluster, another issuer, another key, tampering.
	if _, err := token.VerifyFeed(raw, ks, feedOpts(t0.Add(time.Minute), 8)); !errors.Is(err, token.ErrFeedReplay) {
		t.Errorf("an older feed: %v", err)
	}
	if _, err := token.VerifyFeed(raw, ks, feedOpts(t0.Add(6*time.Minute), 0)); !errors.Is(err, token.ErrExpired) {
		t.Errorf("a stale feed: %v", err)
	}
	o := feedOpts(t0, 0)
	o.Cluster = "prod-2"
	if _, err := token.VerifyFeed(raw, ks, o); !errors.Is(err, token.ErrFeedCluster) {
		t.Errorf("another cluster's feed: %v", err)
	}
	o = feedOpts(t0, 0)
	o.Issuer = "other"
	if _, err := token.VerifyFeed(raw, ks, o); !errors.Is(err, token.ErrIssuer) {
		t.Errorf("another issuer: %v", err)
	}
	if _, err := token.VerifyFeed(raw, keys(t, newSigner(t)), feedOpts(t0, 0)); !errors.Is(err, token.ErrUnknownKey) {
		t.Errorf("another key: %v", err)
	}
	var env token.Envelope
	_ = json.Unmarshal(raw, &env)
	env.Payload = strings.Replace(env.Payload, env.Payload[10:14], "AAAA", 1)
	bad, _ := json.Marshal(env)
	if _, err := token.VerifyFeed(bad, ks, feedOpts(t0, 0)); err == nil {
		t.Error("a tampered feed verified")
	}
	// A token envelope is not a feed, and a feed is not a token.
	tokRaw, _ := json.Marshal(a.Envelope)
	if _, err := token.VerifyFeed(tokRaw, ks, feedOpts(t0, 0)); !errors.Is(err, token.ErrMalformed) {
		t.Errorf("a token as a feed: %v", err)
	}
	if _, err := token.Verify(bg, raw, ks, opts(t0)); !errors.Is(err, token.ErrMalformed) {
		t.Errorf("a feed as a token: %v", err)
	}
	// An empty feed is a feed: the cluster has no live token (its grants are removed).
	_, empty := feedOf(t, s, 8)
	if f, err := token.VerifyFeed(empty, ks, feedOpts(t0, 7)); err != nil || len(f.Entries) != 0 || f.Match(nil) != nil {
		t.Fatalf("empty feed: %v %v", f, err)
	}
}

func TestSignFeedRefuses(t *testing.T) {
	s := newSigner(t)
	base := token.Feed{Type: token.FeedType, Issuer: "clearance", Cluster: "c", Seq: 1, IssuedAt: t0.Unix(),
		Expires: t0.Add(time.Minute).Unix()}
	e := token.FeedEntry{ChangeID: "x", Nonce: "n", PayloadSHA256: strings.Repeat("a", 64)}
	for name, mut := range map[string]func(f *token.Feed){
		"type":     func(f *token.Feed) { f.Type = "x" },
		"cluster":  func(f *token.Feed) { f.Cluster = "" },
		"seq":      func(f *token.Feed) { f.Seq = 0 },
		"lifetime": func(f *token.Feed) { f.Expires = f.IssuedAt + int64(token.MaxFeedLifetime/time.Second) + 1 },
		"dup":      func(f *token.Feed) { f.Entries = []token.FeedEntry{e, e} },
		"digest":   func(f *token.Feed) { x := e; x.PayloadSHA256 = "ab"; f.Entries = []token.FeedEntry{x} },
	} {
		f := base
		mut(&f)
		if _, err := token.SignFeed(bg, s, f); !errors.Is(err, token.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzVerifyFeed(f *testing.F) {
	s := newSigner(f)
	ks := keys(f, s)
	env, _ := token.SignFeed(bg, s, token.Feed{Type: token.FeedType, Issuer: "clearance", Cluster: "prod-1", Seq: 1,
		IssuedAt: t0.Unix(), Expires: t0.Add(time.Minute).Unix()})
	raw, _ := json.Marshal(env)
	f.Add(raw)
	f.Add([]byte(`{"payloadType":"application/vnd.clearance.grant-feed.v1+json","payload":"e30=","signatures":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = token.VerifyFeed(b, ks, feedOpts(t0, 0))
	})
}

func TestGrantFeedEpoch(t *testing.T) {
	s := newSigner(t)
	f := token.Feed{Type: token.FeedType, Issuer: "clearance", Cluster: "prod-1", Epoch: "e1", Seq: 3, IssuedAt: t0.Unix(),
		Expires: t0.Add(5 * time.Minute).Unix(), RecordsSeq: 1}
	env, err := token.SignFeed(bg, s, f)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	o := feedOpts(t0, 9)
	o.Epoch = "e1"
	if _, err := token.VerifyFeed(raw, keys(t, s), o); !errors.Is(err, token.ErrFeedReplay) {
		t.Errorf("same epoch, lower seq: %v", err)
	}
	o.Epoch = "e0" // the reader last saw another epoch: a rebuilt core, seq starts again
	got, err := token.VerifyFeed(raw, keys(t, s), o)
	if err != nil || got.Epoch != "e1" {
		t.Errorf("new epoch: %v %+v", err, got)
	}
}
