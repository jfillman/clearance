package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/store"
)

// The harness clock is 2026-10-30T12:30:00Z.
var feedNow = time.Date(2026, 10, 30, 12, 30, 0, 0, time.UTC)

func onCluster(c store.Change, cluster string) store.Change {
	var m map[string]any
	_ = json.Unmarshal(c.Record, &m)
	m["cluster"] = cluster
	c.Record, _ = json.Marshal(m)
	return c
}

func tok(id, cluster string, exp time.Duration, revoked bool) store.Token {
	t := store.Token{ChangeID: id, Cluster: cluster, Nonce: "nonce-" + id, KeyID: "kid-1", IssuedAt: feedNow.Add(-time.Minute),
		ExpiresAt: feedNow.Add(exp), JWT: "h.p.s-" + id,
		Envelope: json.RawMessage(`{"payloadType":"application/vnd.clearance.token.v1+json","payload":"e30=","signatures":[{"keyid":"kid-1","sig":"MEU="}]}`)}
	if revoked {
		at := feedNow.Add(-time.Second)
		t.RevokedAt = &at
	}
	return t
}

func feedWorld() world {
	return world{
		changes: []store.Change{
			onCluster(change("c-1", "gate-api", "holding", "group:default/team-gate", 2, "2026-11-01T10:00:00Z", []string{platform}), "hangar-prod"),
			onCluster(change("c-2", "other-app", "cleared", "group:default/team-other", 0, "2026-11-01T11:00:00Z", nil), "hangar-prod"),
			onCluster(change("c-3", "gate-api", "cleared", "group:default/team-gate", 1, "2026-11-01T12:00:00Z", nil), "hangar-prod"),
			onCluster(change("c-4", "gate-api", "cleared", "group:default/team-gate", 1, "2026-11-01T13:00:00Z", nil), "hangar-prod"),
			onCluster(change("c-5", "gate-api", "cleared", "group:default/team-gate", 1, "2026-11-01T14:00:00Z", nil), "other-cluster"),
			onCluster(change("c-6", "gate-api", "cleared", "group:default/team-gate", 1, "2026-11-01T15:00:00Z", nil), "hangar-prod"),
		},
		tokens: []store.Token{
			tok("c-2", "hangar-prod", 10*time.Minute, false),
			tok("c-3", "hangar-prod", 10*time.Minute, true), // revoked: a new head superseded it
			tok("c-4", "hangar-prod", -time.Minute, false),  // lapsed
			tok("c-5", "other-cluster", 10*time.Minute, false),
			// c-6: cleared, no token (a core without a signing key)
		},
		keys: []store.SigningKey{{KeyID: "kid-1", CreatedAt: feedNow.Add(-time.Hour),
			JWK: json.RawMessage(`{"kty":"EC","crv":"P-256","x":"x","y":"y","kid":"kid-1","alg":"ES256","use":"sig"}`)}},
	}
}

func TestTheGrantFeed(t *testing.T) {
	each(t, feedWorld(), func(t *testing.T, h *harness) {
		// The feed: the cluster's cleared changes with a live token, each with it.
		feed := items(h.ok("/v1/clearances?cluster=hangar-prod&state=cleared", "sync"))
		if len(feed) != 1 || feed[0]["id"] != "c-2" {
			t.Fatalf("feed: %v", feed)
		}
		tk := feed[0]["token"].(map[string]any)
		if tk["nonce"] != "nonce-c-2" || tk["key_id"] != "kid-1" || tk["jwt"] != "h.p.s-c-2" ||
			tk["expires_at"] != "2026-10-30T12:40:00Z" || tk["dsse"].(map[string]any)["payloadType"] != "application/vnd.clearance.token.v1+json" {
			t.Fatalf("token: %v", tk)
		}
		// An auditor reads the same feed; a plain list carries no tokens.
		if f := items(h.ok("/v1/clearances?cluster=hangar-prod&state=cleared", "audit")); len(f) != 1 || f[0]["token"] == nil {
			t.Fatalf("auditor feed: %v", f)
		}
		for _, it := range items(h.ok("/v1/clearances?state=cleared", "audit")) {
			if _, has := it["token"]; has {
				t.Fatalf("a token outside the feed: %v", it)
			}
		}
		if n := len(items(h.ok("/v1/clearances?cluster=hangar-prod", "audit"))); n != 5 {
			t.Errorf("cluster filter: %d", n)
		}
		// A feed reader reads its own cluster's feed and nothing else.
		h.status(t, 403, "GET", "/v1/clearances?cluster=other-cluster&state=cleared", "sync", "")
		h.status(t, 403, "GET", "/v1/clearances?cluster=hangar-prod", "sync", "")
		h.status(t, 403, "GET", "/v1/clearances", "sync", "")
		h.status(t, 403, "GET", "/v1/evidence", "sync", "")
		h.status(t, 403, "GET", "/v1/clearances/counts", "sync", "")
		one := h.ok("/v1/clearances/c-2", "sync")
		if one["token"].(map[string]any)["nonce"] != "nonce-c-2" {
			t.Fatalf("one: %v", one)
		}
		h.status(t, 404, "GET", "/v1/clearances/c-5", "sync", "") // another cluster's
		// One change, for a person who may read it: its token, or null.
		if one := h.ok("/v1/clearances/c-3", "erin"); one["token"] != nil {
			t.Fatalf("a revoked token is served: %v", one)
		}
		if one := h.ok("/v1/clearances/c-5", "erin"); one["token"].(map[string]any)["nonce"] != "nonce-c-5" {
			t.Fatalf("erin's change: %v", one)
		}
		// The keys are public.
		r := h.get("/v1/keys", "")
		if r.status != 200 || !strings.Contains(string(r.body), `"kid":"kid-1"`) {
			t.Fatalf("keys: %d %s", r.status, r.body)
		}
	})
}

func TestFeedReadersParse(t *testing.T) {
	got, err := ParseFeedReaders(" hangar-prod/clearance-system/*=hangar-prod, ci/*=* ")
	if err != nil || len(got) != 2 || got[0] != (FeedReader{"hangar-prod/clearance-system/*", "hangar-prod"}) || got[1].Cluster != "*" {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"nocluster", "=c", "a=", "a=b c"} {
		if _, err := ParseFeedReaders(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
