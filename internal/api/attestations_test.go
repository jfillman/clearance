package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/token"
)

var attTree = strings.Repeat("a", 64)

func edit(c store.Change, fn func(m map[string]any)) store.Change {
	var m map[string]any
	_ = json.Unmarshal(c.Record, &m)
	fn(m)
	c.Record, _ = json.Marshal(m)
	return c
}

// signAs signs a statement about change id (whose tree is tree) with a fresh static key.
func signAs(t *testing.T, id, tree string, key *token.KeySigner) (store.Attestation, token.KeySet) {
	t.Helper()
	st := &attest.Statement{Type: attest.StatementType, PredicateType: attest.PredicateType,
		Subject: []attest.Subject{{Name: "manifest-tree:o/r/app/prod", Digest: map[string]string{"sha256": tree}}},
		Predicate: attest.Predicate{Clearance: token.Clearance{ID: id, ClearedBy: "policy", DecidedAt: "2026-11-07T00:00:00Z"},
			Approvals: []token.Approval{}, Provenance: token.Provenance{Level: "unknown", Proposer: "p", ProposerKind: "person"},
			Cleared: token.Subjects{Kind: "manifest-tree", Repo: "o/r", PR: 1, TreeRoot: "sha256:" + tree, Images: []string{}},
			Tier:    1, Coverage: "authorized-and-verified", Limitations: []string{"x"},
			Outcome: attest.Outcome{Seq: 5, Provider: "argocd-agent", Applied: true, At: "2026-11-07T00:01:00Z"}}}
	payload, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := (&attest.Static{Signer: key}).Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed.Bundle)
	return store.Attestation{ChangeID: id, Digest: attest.EnvelopeDigest(signed.Bundle.DSSEEnvelope), Backend: "static", KeyID: key.KeyID(),
		Bundle: raw}, token.KeySet{key.KeyID(): key.Public()}
}

func newKey(t *testing.T) *token.KeySigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.NewKeySigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// attWorld is feedWorld with deploy.* records for c-3 and c-1, c-3 applied and attested (twice over: c-2 of
// another app too), c-6 applied and not attested, and the trust that verifies them.
func attWorld(t *testing.T) (world, *AttestTrust) {
	w := feedWorld()
	key := newKey(t)
	idx := int64(41)
	a3, keys := signAs(t, "c-3", attTree, key)
	a3.OutcomeSeq, a3.RecordSeq, a3.RekorLogIndex, a3.RekorUUID, a3.CreatedAt = 5, 6, &idx, "uuid-3", feedNow.Add(-2*time.Hour)
	a2, _ := signAs(t, "c-2", attTree, key)
	a2.OutcomeSeq, a2.RecordSeq, a2.CreatedAt = 9, 10, feedNow.Add(-time.Hour)
	a1, _ := signAs(t, "c-1", attTree, key)
	a1.OutcomeSeq, a1.RecordSeq, a1.CreatedAt = 11, 12, feedNow.Add(-time.Minute)
	w.atts = []store.Attestation{a3, a2, a1}
	applied := func(m map[string]any) {
		m["tree_digest"] = "sha256:" + attTree
		m["outcome"] = map[string]any{"seq": 5, "applied": true, "matched": true, "at": "2026-11-01T12:30:00Z", "release": "chain-1:hangar-prod/prod"}
	}
	for i, c := range w.changes {
		switch c.ID {
		case "c-1", "c-2", "c-3", "c-6":
			w.changes[i] = edit(c, applied)
		}
	}
	w.events = append(w.events,
		deployEvent("deploy.request", w.changes[2], "hangar-prod", "holding"),
		deployEvent("deploy.request", w.changes[0], "hangar-prod", "holding"),
		deployEvent("deploy.clear", w.changes[2], "hangar-prod", "cleared"),
		deployEvent("deploy.outcome", w.changes[2], "hangar-prod", "cleared"),
		deployEvent("deploy.attestation", w.changes[2], "hangar-prod", "cleared"),
		deployEvent("deploy.request", w.changes[1], "hangar-prod", "holding"))
	return w, &AttestTrust{Keys: keys, RekorURL: "https://rekor.example.test"}
}

func withTrust(tr *AttestTrust) option { return func(o *Options) { o.Attest = tr } }

func TestChangeRecordsAndTheRequestReference(t *testing.T) {
	w, _ := attWorld(t)
	each(t, w, func(t *testing.T, h *harness) {
		page := h.ok("/v1/clearances/c-3/records", "erin")
		its := items(page)
		var tools []string
		var last int64 = -1
		for _, it := range its {
			tools = append(tools, it["tool"].(string))
			seq, _ := it["seq"].(json.Number).Int64()
			if seq <= last || len(it["hash"].(string)) != 64 || it["principal"] != "policy" || it["ts"] == "" ||
				it["record"].(map[string]any)["hash"] != it["hash"] {
				t.Fatalf("item %v after seq %d", it, last)
			}
			last = seq
		}
		if strings.Join(tools, ",") != "deploy.request,deploy.clear,deploy.outcome,deploy.attestation" || page["next"] != nil {
			t.Fatalf("history: %v next %v", tools, page["next"])
		}
		// Paged: a full page names the cursor, after= continues from it.
		p1 := h.ok("/v1/clearances/c-3/records?limit=2", "erin")
		if len(items(p1)) != 2 || p1["next"] == nil {
			t.Fatalf("page 1: %v", p1)
		}
		p2 := h.ok("/v1/clearances/c-3/records?limit=2&after="+string(p1["next"].(json.Number)), "erin")
		if len(items(p2)) != 2 || items(p2)[0]["tool"] != "deploy.outcome" {
			t.Fatalf("page 2: %v", p2)
		}
		// Only that change's records.
		if got := items(h.ok("/v1/clearances/c-1/records", "bob")); len(got) != 1 || got[0]["tool"] != "deploy.request" {
			t.Fatalf("c-1: %v", got)
		}
		// getClearance names the first deploy.request.
		one := h.ok("/v1/clearances/c-3", "erin")
		req, _ := one["request"].(map[string]any)
		if req["seq"] != its[0]["seq"] || req["hash"] != its[0]["hash"] {
			t.Fatalf("request %v, first record %v", one["request"], its[0])
		}
		if h.ok("/v1/clearances/c-6", "erin")["request"] != nil {
			t.Fatal("a change with no deploy.request names none")
		}
		if got := items(h.ok("/v1/clearances/c-6/records", "erin")); len(got) != 0 {
			t.Fatalf("c-6: %v", got)
		}
		// The change's visibility: not erin's, no such change, a bad cursor.
		h.status(t, 404, "GET", "/v1/clearances/c-2/records", "erin", "")
		h.status(t, 404, "GET", "/v1/clearances/nope/records", "audit", "")
		h.status(t, 400, "GET", "/v1/clearances/c-3/records?after=x", "erin", "")
		h.status(t, 400, "GET", "/v1/clearances/c-3/records?bogus=1", "erin", "")
		if len(items(h.ok("/v1/clearances/c-2/records", "audit"))) != 1 {
			t.Fatal("an auditor reads every change's history")
		}
		// A feed reader reads its cluster's change history only.
		h.status(t, 404, "GET", "/v1/clearances/c-5/records", "sync", "")
		h.status(t, 200, "GET", "/v1/clearances/c-3/records", "sync", "")
	})
}

func TestAttestationList(t *testing.T) {
	w, _ := attWorld(t)
	each(t, w, func(t *testing.T, h *harness) {
		all := items(h.ok("/v1/attestations", "audit"))
		if len(all) != 3 || all[0]["change_id"] != "c-1" || all[1]["change_id"] != "c-2" || all[2]["change_id"] != "c-3" {
			t.Fatalf("newest first: %v", all)
		}
		c3 := all[2]
		idx, _ := c3["rekor_log_index"].(json.Number).Int64()
		if c3["app"] != "gate-api" || c3["env"] != "prod" || c3["release_id"] != "chain-1:hangar-prod/prod" || c3["tree_digest"] != "sha256:"+attTree ||
			!strings.HasPrefix(c3["signed_at"].(string), "2026-10-30T10:30:00") ||
			c3["backend"] != "static" || c3["rekor_uuid"] != "uuid-3" || idx != 41 || c3["outcome_seq"].(json.Number).String() != "5" ||
			c3["record_seq"].(json.Number).String() != "6" || c3["verification"] != nil || !strings.HasPrefix(c3["digest"].(string), "sha256:") || c3["key_id"] == "" {
			t.Fatalf("row: %v", c3)
		}
		if _, leaked := c3["bundle"]; leaked {
			t.Fatal("the list carries bundles")
		}
		// Filters.
		if got := items(h.ok("/v1/attestations?app=other-app", "audit")); len(got) != 1 || got[0]["change_id"] != "c-2" {
			t.Fatalf("app: %v", got)
		}
		if got := items(h.ok("/v1/attestations?env=staging", "audit")); len(got) != 0 {
			t.Fatalf("env: %v", got)
		}
		since := feedNow.Add(-90 * time.Minute).Format(time.RFC3339)
		until := feedNow.Add(-30 * time.Minute).Format(time.RFC3339)
		if got := items(h.ok("/v1/attestations?since="+since+"&until="+until, "audit")); len(got) != 1 || got[0]["change_id"] != "c-2" {
			t.Fatalf("window: %v", got)
		}
		// Paged by record_seq.
		p1 := h.ok("/v1/attestations?limit=2", "audit")
		if len(items(p1)) != 2 || p1["next"].(json.Number).String() != "10" {
			t.Fatalf("page 1: %v", p1)
		}
		p2 := h.ok("/v1/attestations?limit=2&after=10", "audit")
		if got := items(p2); len(got) != 1 || got[0]["change_id"] != "c-3" || p2["next"] != nil {
			t.Fatalf("page 2: %v", p2)
		}
		// Viewer scope: erin sees team-gate's changes (c-1 and c-3), not other-app's.
		var ids []string
		for _, it := range items(h.ok("/v1/attestations", "erin")) {
			ids = append(ids, it["change_id"].(string))
		}
		if strings.Join(ids, ",") != "c-1,c-3" {
			t.Fatalf("erin: %v", ids)
		}
		// A feed reader reads the grant feed only.
		h.status(t, 403, "GET", "/v1/attestations", "sync", "")
		h.status(t, 400, "GET", "/v1/attestations?since=yesterday", "audit", "")
		h.status(t, 400, "GET", "/v1/attestations?after=x", "audit", "")
		h.status(t, 400, "GET", "/v1/attestations?bogus=1", "audit", "")
		// The change list carries attested and the reference.
		byID := map[string]map[string]any{}
		for _, it := range items(h.ok("/v1/clearances", "audit")) {
			byID[it["id"].(string)] = it
		}
		att, _ := byID["c-3"]["attestation"].(map[string]any)
		if byID["c-3"]["attested"] != true || att["digest"] != c3["digest"] || byID["c-4"]["attested"] != false || byID["c-4"]["attestation"] != nil {
			t.Fatalf("list rows: c-3 %v c-4 %v", byID["c-3"], byID["c-4"])
		}
	})
}

func TestCountsByAttestation(t *testing.T) {
	w, _ := attWorld(t)
	each(t, w, func(t *testing.T, h *harness) {
		got := map[string]int64{}
		for _, it := range items(h.ok("/v1/clearances/counts?by=attestation", "audit")) {
			n, _ := it["count"].(json.Number).Int64()
			got[it["key"].(string)] = n
		}
		// c-1, c-2, c-3 attested; c-6 applied and not attested; c-4 and c-5 have no applied outcome.
		if got["attested"] != 3 || got["pending"] != 1 || got["none"] != 2 || len(got) != 3 {
			t.Fatalf("counts: %v", got)
		}
		if h.ok("/v1/clearances/counts?by=attestation&app=gate-api", "audit")["total"].(json.Number).String() != "5" {
			t.Fatal("app filter")
		}
	})
}

func TestVerifyTheStoredAttestation(t *testing.T) {
	w, trust := attWorld(t)
	each(t, w, func(t *testing.T, h *harness) {
		// Without trust nothing is verified, and the config says so.
		h.status(t, 404, "GET", "/v1/clearances/c-3/attestation/verify", "erin", "")
		if h.ok("/v1/attestation-config", "erin")["verifiable"] != false {
			t.Fatal("verifiable without trust")
		}
	})
	each(t, w, func(t *testing.T, h *harness) {
		ans := h.ok("/v1/clearances/c-3/attestation/verify", "erin")
		rk, _ := ans["rekor"].(map[string]any)
		if ans["verified"] != true || ans["cached"] != false || ans["subject"] != "sha256:"+attTree || ans["mode"] != "static" ||
			ans["key_id"] == "" || ans["checked_at"] == "" || len(ans["errors"].([]any)) != 0 || rk["verified"] != false {
			t.Fatalf("verify: %v", ans)
		}
		again := h.ok("/v1/clearances/c-3/attestation/verify", "erin")
		if again["cached"] != true || again["checked_at"] != ans["checked_at"] || again["verified"] != true {
			t.Fatalf("cached: %v", again)
		}
		// The lists show the last check; an attestation never checked shows null.
		one := h.ok("/v1/clearances/c-3", "erin")
		v, _ := one["attestation"].(map[string]any)["verification"].(map[string]any)
		if v["verified"] != true || v["checked_at"] != ans["checked_at"] {
			t.Fatalf("change view: %v", one["attestation"])
		}
		rows := items(h.ok("/v1/attestations", "audit"))
		if rows[2]["verification"] == nil || rows[0]["verification"] != nil {
			t.Fatalf("list: %v", rows)
		}
		// 404s: not erin's change, no attestation, no change.
		h.status(t, 404, "GET", "/v1/clearances/c-2/attestation/verify", "erin", "")
		h.status(t, 404, "GET", "/v1/clearances/c-6/attestation/verify", "erin", "")
		h.status(t, 404, "GET", "/v1/clearances/nope/attestation/verify", "audit", "")
		// The config: public values only.
		cfg := h.ok("/v1/attestation-config", "erin")
		if cfg["verifiable"] != true || cfg["rekor_url"] != "https://rekor.example.test" ||
			cfg["rekor_entry_url"] != "https://rekor.example.test/api/v1/log/entries?logIndex={log_index}" ||
			len(cfg["key_ids"].([]any)) != 1 || cfg["modes"].([]any)[0] != "static" || len(cfg["verify_commands"].([]any)) != 1 {
			t.Fatalf("config: %v", cfg)
		}
	}, withTrust(trust))
}

func TestVerifyRefusesWhatDoesNotMatchTheChange(t *testing.T) {
	w, trust := attWorld(t)
	other := newKey(t)
	// c-3's stored bundle is signed by a key the api does not trust.
	untrusted, _ := signAs(t, "c-3", attTree, other)
	w.atts[0].Bundle, w.atts[0].Digest = untrusted.Bundle, untrusted.Digest
	each(t, w, func(t *testing.T, h *harness) {
		ans := h.ok("/v1/clearances/c-3/attestation/verify", "erin")
		if ans["verified"] != false || len(ans["errors"].([]any)) == 0 || ans["subject"] != "sha256:"+attTree {
			t.Fatalf("untrusted signer: %v", ans)
		}
		if one := h.ok("/v1/clearances/c-3", "erin"); one["attestation"].(map[string]any)["verification"].(map[string]any)["verified"] != false {
			t.Fatalf("a failed check is shown as failed: %v", one["attestation"])
		}
	}, withTrust(trust))

	w, trust = attWorld(t)
	key := newKey(t)
	trust.Keys = token.KeySet{key.KeyID(): key.Public()}
	bad, _ := signAs(t, "c-9", attTree, key) // the statement is about another change
	w.atts[0].Bundle, w.atts[0].Digest = bad.Bundle, bad.Digest
	wrongTree, _ := signAs(t, "c-1", strings.Repeat("b", 64), key) // names a tree the change was not cleared for
	w.atts[2].Bundle, w.atts[2].Digest = wrongTree.Bundle, wrongTree.Digest
	badDigest, _ := signAs(t, "c-2", attTree, key) // the stored digest is not the envelope's
	w.atts[1].Bundle, w.atts[1].Digest = badDigest.Bundle, "sha256:"+strings.Repeat("0", 64)
	each(t, w, func(t *testing.T, h *harness) {
		for id, want := range map[string]string{"c-3": "about change", "c-1": "does not name subject", "c-2": "envelope digest"} {
			ans := h.ok("/v1/clearances/"+id+"/attestation/verify", "audit")
			errs, _ := ans["errors"].([]any)
			if ans["verified"] != false || len(errs) != 1 || !strings.Contains(errs[0].(string), want) {
				t.Fatalf("%s: %v", id, ans)
			}
		}
	}, withTrust(trust))
}

func TestAttestTrustFromEnv(t *testing.T) {
	dir := t.TempDir()
	key := newKey(t)
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if tr, err := attestTrustFromEnv(env(nil)); tr != nil || err != nil {
		t.Fatalf("nothing set: %v %v", tr, err)
	}
	tr, err := attestTrustFromEnv(env(map[string]string{"CLEARANCE_API_ATTEST_KEY": pub, "CLEARANCE_API_ATTEST_REKOR_URL": "https://rekor.example.test"}))
	if err != nil || !tr.static() || tr.keyless() || tr.Keys[key.KeyID()] == nil || tr.RekorURL != "https://rekor.example.test" {
		t.Fatalf("static: %+v %v", tr, err)
	}
	for name, m := range map[string]map[string]string{
		"missing file":          {"CLEARANCE_API_ATTEST_KEY": filepath.Join(dir, "none.pem")},
		"identity without root": {"CLEARANCE_API_ATTEST_KEY": pub, "CLEARANCE_API_ATTEST_IDENTITY": "x"},
		"root without identity": {"CLEARANCE_API_ATTEST_TRUST_ROOT": pub},
		"pem root without rekor key": {"CLEARANCE_API_ATTEST_TRUST_ROOT": pub, "CLEARANCE_API_ATTEST_IDENTITY": "x",
			"CLEARANCE_API_ATTEST_ISSUER": "https://issuer.example.test"},
		"bad rekor url": {"CLEARANCE_API_ATTEST_REKOR_URL": "ftp://rekor.example.test"},
	} {
		if _, err := attestTrustFromEnv(env(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
