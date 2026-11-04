package gate_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/gate"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

// feed reads the stored feed of cluster and verifies it as a grant-sync agent would: the envelope against the keys,
// the cluster, the seq not below minSeq, and the tokens beside it against the entries.
func (f *fixture) feed(t *testing.T, ks token.KeySet, cluster string, minSeq int64) (*token.Feed, []gate.FeedToken) {
	t.Helper()
	row, err := f.st.Feed(f.ctx, cluster)
	if err != nil {
		t.Fatal(err)
	}
	feed, err := token.VerifyFeed(row.Envelope, ks, token.FeedOptions{Issuer: "clearance-test", Cluster: cluster,
		MinSeq: minSeq, Now: f.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	var toks []gate.FeedToken
	if err := json.Unmarshal(row.Tokens, &toks); err != nil {
		t.Fatal(err)
	}
	byID := map[string]token.Envelope{}
	for _, tk := range toks {
		byID[tk.ChangeID] = tk.DSSE
	}
	if err := feed.Match(byID); err != nil {
		t.Fatal(err)
	}
	if row.Seq != feed.Seq || row.KeyID == "" {
		t.Fatalf("row %+v vs feed %+v", row, feed)
	}
	return feed, toks
}

func TestTheGrantFeedIsSignedWithEveryTokenWrite(t *testing.T) {
	f, ks := withTokens(t)
	if _, err := f.st.Feed(f.ctx, "hangar-prod"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a feed before any token", err)
	}
	c := f.register(t, "ci", change(map[string]any{"objects": imageBump}))
	feed, toks := f.feed(t, ks, "hangar-prod", 0)
	if feed.Seq != 1 || len(feed.Entries) != 1 || feed.Entries[0].ChangeID != c.ID || toks[0].Nonce != f.token(t, c.ID).Nonce ||
		feed.RecordsSeq < 0 || feed.Expires-feed.IssuedAt != int64(gate.FeedTTL/time.Second) {
		t.Fatalf("feed %+v", feed)
	}
	// Every listed token verifies on its own, bound to this cluster.
	for _, tk := range toks {
		env, _ := json.Marshal(tk.DSSE)
		if _, err := token.Verify(f.ctx, env, ks, token.Options{Issuer: "clearance-test", Now: f.clock.now,
			Expect: token.Expect{Cluster: "hangar-prod"}, Nonces: f.svc}); err != nil {
			t.Fatal(err)
		}
	}
	// A re-issue re-signs the feed (a new seq, the new issuance listed).
	f.clock.advance(8 * time.Minute)
	if n, _, err := f.svc.Refresh(f.ctx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	feed2, _ := f.feed(t, ks, "hangar-prod", feed.Seq)
	if feed2.Seq != 2 || feed2.Entries[0].PayloadSHA256 == feed.Entries[0].PayloadSHA256 {
		t.Fatalf("after refresh %+v", feed2)
	}
	// A new head revokes the token: the feed is re-signed empty, so grant-sync removes the grant.
	f.clock.advance(time.Minute)
	f.register(t, "ci", change(map[string]any{"objects": replicas, "head": strings.Repeat("f", 40)}))
	feed3, toks3 := f.feed(t, ks, "hangar-prod", feed2.Seq)
	if feed3.Seq != 3 || len(feed3.Entries) != 0 || len(toks3) != 0 {
		t.Fatalf("after revoke %+v", feed3)
	}
	// RefreshFeeds: nothing due within FeedResign; past it, a re-signed feed (fresh exp) with the same entries.
	if n, err := f.svc.RefreshFeeds(f.ctx); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	f.clock.advance(gate.FeedResign)
	if n, err := f.svc.RefreshFeeds(f.ctx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if feed4, _ := f.feed(t, ks, "hangar-prod", feed3.Seq); feed4.Seq != 4 || feed4.IssuedAt <= feed3.IssuedAt {
		t.Fatalf("heartbeat %+v", feed4)
	}
	// A stale feed (the core stopped re-signing) is refused by the reader.
	row, _ := f.st.Feed(f.ctx, "hangar-prod")
	f.clock.advance(gate.FeedTTL + time.Minute)
	if _, err := token.VerifyFeed(row.Envelope, ks, token.FeedOptions{Issuer: "clearance-test", Cluster: "hangar-prod",
		Now: f.clock.now}); !errors.Is(err, token.ErrExpired) {
		t.Fatal(err)
	}
}

func TestTheNotifierWakesAWaiterOnTheWrite(t *testing.T) {
	f, _ := withTokens(t)
	held := f.register(t, "ci", change(map[string]any{"objects": secret})) // tier 3: holding for people
	woken, cancel, err := f.svc.Watch(held.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	other, cancelOther, _ := f.svc.Watch("ch-other")
	defer cancelOther()
	select {
	case <-woken:
		t.Fatal("woken before any write")
	default:
	}
	if _, err := f.svc.Expire(f.ctx); err != nil { // writes nothing for a change not yet expired
		t.Fatal(err)
	}
	f.clock.advance(8 * 24 * time.Hour)
	if _, err := f.svc.Expire(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-woken:
	case <-time.After(time.Second):
		t.Fatal("the expiry did not wake the waiter")
	}
	select {
	case <-other:
		t.Fatal("another change's waiter woke")
	default:
	}
	if f.svc.Waiting() != 2 {
		t.Fatal(f.svc.Waiting())
	}
	cancel()
	cancel() // idempotent
	cancelOther()
	if f.svc.Waiting() != 0 {
		t.Fatal(f.svc.Waiting())
	}
}

func TestTheNotifierCapsWaiters(t *testing.T) {
	var n gate.Notifier
	var cancels []func()
	for i := 0; i < gate.MaxWaiters; i++ {
		_, c, err := n.Watch("x")
		if err != nil {
			t.Fatal(i, err)
		}
		cancels = append(cancels, c)
	}
	if _, _, err := n.Watch("y"); !errors.Is(err, gate.ErrTooManyWaiters) {
		t.Fatal(err)
	}
	for _, c := range cancels {
		c()
	}
	if _, c, err := n.Watch("y"); err != nil {
		t.Fatal(err)
	} else {
		c()
	}
}
