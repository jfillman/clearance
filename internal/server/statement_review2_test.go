package server_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/server"
	"github.com/jfillman/clearance/internal/statement"
)

// doctored publishes a copy of the lab's packet changed by mutate (files edited or removed), with its manifest rewritten to match:
// a valid bundle that is not the packet the log committed to. It returns the new packet's id.
func (l *p3lab) doctored(t *testing.T, mutate func(dir string)) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "doctored")
	if err := copyDir(l.dir, dir); err != nil {
		t.Fatal(err)
	}
	mutate(dir)
	mp := filepath.Join(dir, "MANIFEST.json")
	var man map[string]any
	raw, _ := os.ReadFile(mp)
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	files := man["files"].(map[string]any)
	for name := range files {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			delete(files, name)
			continue
		}
		sum := sha256.Sum256(b)
		files[name] = hex.EncodeToString(sum[:])
	}
	raw, _ = json.Marshal(man)
	if err := os.WriteFile(mp, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := packet.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.f.do("POST", "/v1/packets", "user:admin", b.JSON).want(t, 200, "")
	return b.ID
}

// ---- F: a statement is never signed over proofs nobody checked ----

func TestP3APacketWithoutItsProofsOrACheckpointOrWithAForgedOneIsRefusedAtIssue(t *testing.T) {
	l := p3Lab(t, p3opts{})
	refuse := func(name, pid, want string) {
		t.Helper()
		a := l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"packet": pid}))
		if a.status != 422 || !strings.Contains(fmt.Sprint(a.body["error"]), want) {
			t.Errorf("%s: %d %v (want 422 mentioning %q)", name, a.status, a.body, want)
		}
	}
	refuse("no proofs", l.doctored(t, func(dir string) { _ = os.Remove(filepath.Join(dir, "evidence", "proofs.json")) }), "does not carry its inclusion proofs")
	refuse("no checkpoint file", l.doctored(t, func(dir string) { _ = os.Remove(filepath.Join(dir, "ledger", "checkpoint.txt")) }), "does not carry its inclusion proofs")
	refuse("a forged checkpoint", l.doctored(t, func(dir string) {
		p := filepath.Join(dir, "ledger", "checkpoint.txt")
		b, _ := os.ReadFile(p)
		i := strings.LastIndex(string(b), "— ")
		forged := []byte(string(b[:i+len("— ")]) + "p3-test-ledger AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
		_ = os.WriteFile(p, forged, 0o644)
	}), "so none was signed")
	refuse("on no checkpoint", l.doctored(t, func(dir string) {
		_ = os.Remove(filepath.Join(dir, "ledger", "checkpoint.txt"))
		_ = os.Remove(filepath.Join(dir, "evidence", "proofs.json"))
		p := filepath.Join(dir, "packet.json")
		b, _ := os.ReadFile(p)
		var doc map[string]any
		_ = json.Unmarshal(b, &doc)
		doc["verification"].(map[string]any)["ledger"].(map[string]any)["state"] = "no-checkpoint"
		b, _ = json.Marshal(doc)
		_ = os.WriteFile(p, b, 0o644)
	}), "no witnessed ledger checkpoint")
	if n := len(l.f.toolRecords(server.ToolStatementIssue)); n != 0 {
		t.Errorf("%d statements were signed over a packet that did not check", n)
	}
	l.issue(t, l.req()) // the real packet is issued
	// With no log keys configured the checkpoint and proofs cannot be checked, so nothing is signed over them.
	nk := p3Lab(t, p3opts{stmt: func(o *server.StatementOptions) { o.LogKeys = nil }})
	a := nk.f.do("POST", "/v1/statements", "user:admin", nk.req())
	if a.status != 422 || !strings.Contains(fmt.Sprint(a.body["error"]), "no log keys configured") {
		t.Errorf("no log keys: %d %v", a.status, a.body)
	}
	if n := len(nk.f.toolRecords(server.ToolStatementIssue)); n != 0 {
		t.Errorf("%d statements without log keys", n)
	}
}

// ---- G: the hosted page never reads as the all-green VERIFIED ----

func TestP3TheHostedHeadlineIsNeverThePlainGreenVerifiedAndABareWitnessNameCountsForNothing(t *testing.T) {
	l := p3Lab(t, p3opts{independent: true})
	st := l.issue(t, l.req())
	pg := l.get(t, "/s/"+st.ID)
	if pg.word() != "VERIFIED, WITNESS INDEPENDENCE DECLARED" || !strings.Contains(pg.body, `class="word warn"`) || strings.Contains(pg.body, `class="word ok"`) {
		t.Errorf("headline %q", pg.word())
	}
	// Offline, a bare name is refused outright (exit 2, a usage error), and a name=key that the policy holds is what passes.
	if code, out := l.offline(t, st.ID, []string{"--independent-witness", "indep-witness"}); code != 2 || !strings.Contains(out, "<name>=<key>") {
		t.Errorf("a bare name: exit %d\n%s", code, out)
	}
	if code, _ := l.offline(t, st.ID, []string{"--independent-witness", l.indep(t)}); code != 0 {
		t.Errorf("name=key: exit %d", code)
	}
}

// ---- lower priority ----

func TestP3AReissueRepeatsTheRevokedContentAndOnlyTheLatestRevokedOneIsReissuedAgain(t *testing.T) {
	l := p3Lab(t, p3opts{})
	old := l.issue(t, l.req())
	l.f.do("POST", "/v1/statements/"+old.ID+"/revoke", "user:admin", map[string]any{"reason": "x"}).want(t, 200, "")
	// A reissue that changes the content is not a reissue.
	for name, edit := range map[string]map[string]any{"scope": {"scope": "Another scope"}, "policy": {"policy_version": "gate-9"}, "profile": {"profile": "insurer"}} {
		body := l.req(map[string]any{"reissue": old.ID})
		for k, v := range edit {
			body[k] = v
		}
		if a := l.f.do("POST", "/v1/statements", "user:admin", body); a.status != 409 || !strings.Contains(fmt.Sprint(a.body["error"]), "repeats the revoked statement's content") {
			t.Errorf("%s: %d %v", name, a.status, a.body)
		}
	}
	nw := l.issue(t, l.req(map[string]any{"reissue": old.ID}))
	if a := l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"reissue": old.ID})).want(t, 200, ""); a.body["created"] != false || a.body["id"] != nw.ID {
		t.Errorf("the repeat of a live reissue: %v", a.body)
	}
	if n := len(l.f.toolRecords(server.ToolStatementIssue)); n != 2 {
		t.Errorf("%d issue records", n)
	}
	// When that reissue is revoked too, the first revoked statement is not reissued again (the request names a revoked statement
	// and is refused); the latest revoked one is.
	l.f.do("POST", "/v1/statements/"+nw.ID+"/revoke", "user:admin", map[string]any{"reason": "again"}).want(t, 200, "")
	if a := l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"reissue": old.ID})); a.status != 409 || !strings.Contains(fmt.Sprint(a.body["error"]), nw.ID) {
		t.Errorf("the first revoked statement again: %d %v", a.status, a.body)
	}
	if again := l.issue(t, l.req(map[string]any{"reissue": nw.ID})); again.ID == nw.ID || !again.Created {
		t.Errorf("%+v", again)
	}
}

func TestP3AChainOfCorrectionsEndingInARevokedStatementIsNotCurrentAndARevokedCorrectionCanBeCorrectedAgain(t *testing.T) {
	l := p3Lab(t, p3opts{})
	a := l.issue(t, l.req())
	b := l.issue(t, l.req(map[string]any{"policy_version": "gate-b", "supersedes": a.ID}))
	c := l.issue(t, l.req(map[string]any{"policy_version": "gate-c", "supersedes": b.ID}))
	if pg := l.get(t, "/s/"+a.ID); strings.Contains(pg.body, "itself revoked") {
		t.Fatal("before the revocation")
	}
	l.f.do("POST", "/v1/statements/"+c.ID+"/revoke", "user:admin", map[string]any{"reason": "bad"}).want(t, 200, "")
	for _, id := range []string{a.ID, b.ID} {
		if pg := l.get(t, "/s/"+id); !strings.Contains(pg.body, "was itself revoked") || pg.word() != "SUPERSEDED" {
			t.Errorf("%s: %q: the chain A, B, C with C revoked is not said to have no current statement", id, pg.word())
		}
	}
	// B was superseded by C, which was revoked: B may be corrected again, and A's chain then ends in a standing statement.
	d := l.issue(t, l.req(map[string]any{"policy_version": "gate-d", "supersedes": b.ID}))
	if pg := l.get(t, "/s/"+a.ID); strings.Contains(pg.body, "was itself revoked") {
		t.Error("a chain that now ends in a statement that stands still says it is dead")
	}
	_ = d
	// A statement that was superseded by a standing one cannot be superseded again.
	l.f.do("POST", "/v1/statements", "user:admin", l.req(map[string]any{"policy_version": "gate-e", "supersedes": a.ID})).want(t, 409, "")
}

func TestP3ASignedStatusIsSignedOncePerSnapshotNotOncePerRequest(t *testing.T) {
	l := p3Lab(t, p3opts{})
	st := l.issue(t, l.req())
	same := 0
	for i := 0; i < 6; i++ {
		a := l.get(t, "/s/"+st.ID+"/status.json").body
		b := l.get(t, "/s/"+st.ID+"/status.json").body
		if a == b {
			same++
		}
	}
	// ECDSA signatures differ every time they are made: two identical answers are one signature served twice.
	if same < 3 {
		t.Errorf("only %d of 6 back-to-back pairs of status answers were identical: the core signs per request", same)
	}
}

func TestP3TheResultCacheIsLeastRecentlyUsedAndItsSizeIsASetting(t *testing.T) {
	l := p3Lab(t, p3opts{stmt: func(o *server.StatementOptions) { o.ResultCacheSize = 2 }})
	a := l.issue(t, l.req())
	b := l.issue(t, l.req(map[string]any{"policy_version": "gate-b"}))
	c := l.issue(t, l.req(map[string]any{"policy_version": "gate-c"}))
	l.get(t, "/s/"+a.ID)
	l.get(t, "/s/"+b.ID)
	l.get(t, "/s/"+a.ID) // a is used again: b is now the least recently used
	l.get(t, "/s/"+c.ID)
	cached := func(id string) bool { return l.f.core.Server.StatementResultCachedForTest(id) }
	if !cached(a.ID) || cached(b.ID) || !cached(c.ID) {
		t.Errorf("a %v b %v c %v: the least recently used was not the one evicted", cached(a.ID), cached(b.ID), cached(c.ID))
	}
	_ = time.Second
	_ = statement.Schema
}
