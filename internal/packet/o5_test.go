package packet_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/store"
	"github.com/jfillman/clearance/internal/store/memory"
	"github.com/jfillman/clearance/internal/verify"
)

// O-5's "done when": a 30-day lab packet shows a blind window for a scope whose collector was stopped and a clean window
// for one that was not, a person's resolution cause is on the record with the person's name, a trail verification
// reaches the evidence of an observation the EventBridge copy recorded first, and the offline verifier (C-4)
// verifies all of it and fails on a flipped byte.

const (
	scopeStopped = "aws-stopped" // the collector's last health record is on 2026-10-21; then StopLogging succeeded
	scopeRunning = "aws-running" // the collector reported daily for the whole window
)

func verification(ts, scope string, about int64, event string) store.Event {
	return store.Event{"ts": ts, "tool": evidence.KindVerification, "boundary": "deployment", "coverage": "observed-not-attributed", "scope": scope,
		"source":       map[string]any{"name": "cloudtrail", "event_id": event + "/verification"},
		"about":        map[string]any{"seq": json.Number(fmt.Sprint(about))},
		"verification": map[string]any{"method": "cloudtrail-digest-chain", "verified": true},
		"principal":    nil, "agent": nil, "decision": "allow", "args_sha256": hexOf('0'), "result": "verified"}
}

func eventbridge(ts, scope, api, id string) store.Event {
	return observation(ts, scope, api, "bucket", map[string]any{
		"source":    map[string]any{"name": "cloudtrail", "event_id": id},
		"integrity": map[string]any{"sourceVerified": false, "completenessClaimed": true, "method": "eventbridge-delivery"}})
}

func personResolution(ts, scope string, about int64, person, cause string) store.Event {
	r := resolution(ts, scope, about, "reverted", cause)
	r["principal"] = person
	r["resolution"].(map[string]any)["by"] = person
	r["initiator"] = map[string]any{"sub": person, "iss": "https://idp.example"}
	return r
}

type o5Lab struct {
	st                                *memory.Store
	stopSeq, exceptionSeq, clearedSeq int64
	stopTS                            string
	resolveFirstSeq, resolveEditSeq   int64
}

func buildO5Chain(t *testing.T) *o5Lab {
	t.Helper()
	st := memory.New()
	t.Cleanup(st.Close)
	l := &labber{t: t, st: st}
	lab := &o5Lab{st: st, stopTS: "2026-10-22T03:00:00Z"}
	const day = 86400
	// Daily health. The stopped scope's collector reports until 2026-10-21; the running one for the whole window.
	t0 := mustTime(t, "2026-10-09T23:00:00Z")
	for d := 0; d < 31; d++ {
		ts := t0.Add(time.Duration(d) * 24 * time.Hour).Format(time.RFC3339)
		l.add(obsW, health(ts, scopeRunning, "healthy", day))
		if d <= 12 {
			l.add(obsW, health(ts, scopeStopped, "healthy", day))
		}
	}
	// The running scope: one change, cleared and verified by the trail only after the EventBridge copy was recorded.
	cl := l.add(obsW, eventbridge("2026-10-15T10:00:00Z", scopeRunning, "PutBucketPolicy", "evt-running-1"))
	lab.clearedSeq = seqI(cl)
	l.add(obsW, assessment("2026-10-15T10:00:05Z", scopeRunning, lab.clearedSeq, evidence.CoverageAuthorizedAndVerified, nil))
	l.add(obsW, verification("2026-10-15T11:20:00Z", scopeRunning, lab.clearedSeq, "evt-running-1"))
	// The stopped scope: an out-of-band change (the trail verified it later), a person's resolution and an edit of it,
	// then StopLogging, which succeeded: the core flips the scope blind (a check named monitoring-protection).
	ex := l.add(obsW, eventbridge("2026-10-18T09:00:00Z", scopeStopped, "PutBucketPolicy", "evt-stopped-1"))
	lab.exceptionSeq = seqI(ex)
	l.add(obsW, assessment("2026-10-18T09:00:05Z", scopeStopped, lab.exceptionSeq, "out-of-band-detected", nil))
	l.add(obsW, resolution("2026-10-18T09:00:06Z", scopeStopped, lab.exceptionSeq, "still-live", ""))
	l.add(obsW, verification("2026-10-18T10:20:00Z", scopeStopped, lab.exceptionSeq, "evt-stopped-1"))
	lab.resolveFirstSeq = seqI(l.add(coreW, personResolution("2026-10-19T08:00:00Z", scopeStopped, lab.exceptionSeq, "user:dana", "human-initiated")))
	lab.resolveEditSeq = seqI(l.add(coreW, personResolution("2026-10-19T09:30:00Z", scopeStopped, lab.exceptionSeq, "user:erin", "automated-remediation")))
	stop := l.add(obsTier, observation(lab.stopTS, scopeStopped, "StopLogging", "trail", map[string]any{"tier": json.Number("3"),
		"source":    map[string]any{"name": "cloudtrail", "event_id": "evt-stopped-stop"},
		"integrity": map[string]any{"sourceVerified": false, "completenessClaimed": true, "method": "eventbridge-delivery"}}))
	lab.stopSeq = seqI(stop)
	blind := health(lab.stopTS, scopeStopped, "blind", 900)
	blind["health"].(map[string]any)["checks"] = []any{map[string]any{"name": "monitoring-protection", "ok": false, "detail": "an operation on the controls that watch the account succeeded"}}
	blind["about"] = map[string]any{"seq": json.Number(fmt.Sprint(lab.stopSeq))}
	l.add(coreW, blind)
	return lab
}

func scopeOf(t *testing.T, pk *packet.Packet, scope string) packet.ScopeState {
	t.Helper()
	for _, s := range pk.Coverage.Scopes {
		if s.Scope == scope {
			return s
		}
	}
	t.Fatalf("no scope %s in the packet", scope)
	return packet.ScopeState{}
}

func TestThirtyDayPacketShowsABlindWindowAndACleanOneAndVerifiesOffline(t *testing.T) {
	lab := buildO5Chain(t)
	p := packet.Params{From: mustTime(t, winFrom), To: mustTime(t, winTo), Now: mustTime(t, nowAt), Version: "test",
		Scopes: []string{scopeStopped, scopeRunning}}
	vkey, policy := witnessedLab(t, lab.st)
	p.LogKeys, p.WitnessPolicy = []string{vkey}, policy
	res, err := packet.Build(bg, lab.st, p)
	if err != nil {
		t.Fatal(err)
	}
	pk := res.Packet

	// The stopped scope is blind from the StopLogging flip to the end of the window; the running one is clean.
	stopped, running := scopeOf(t, pk, scopeStopped), scopeOf(t, pk, scopeRunning)
	wantBlind := int64(mustTime(t, winTo).Sub(mustTime(t, lab.stopTS)).Seconds())
	if stopped.Statement.State != "blind" || stopped.Statement.Clean || stopped.Statement.Blind.Seconds != wantBlind || wantBlind < 15*86400 {
		t.Errorf("the stopped scope: state %s clean %v could-not-see %ds, want blind, not clean, %ds", stopped.Statement.State, stopped.Statement.Clean,
			stopped.Statement.Blind.Seconds, wantBlind)
	}
	if running.Statement.State != "healthy" || !running.Statement.Clean || running.Statement.Blind.Seconds != 0 {
		t.Errorf("the running scope: state %s clean %v could-not-see %ds, want healthy, clean, 0", running.Statement.State, running.Statement.Clean, running.Statement.Blind.Seconds)
	}
	if pk.Coverage.WindowVerified {
		t.Error("a window with a blind scope is not verified")
	}
	if !strings.Contains(stopped.Text, "Could not see") || !strings.Contains(running.Text, "every feed was healthy") {
		t.Errorf("the statements' words:\n%s\n%s", stopped.Text, running.Text)
	}
	// The three parts: cleared and verified, seen not cleared, could not see.
	if running.Statement.Cleared.Count != 1 || running.Statement.Seen.Count != 0 {
		t.Errorf("running: cleared %d seen %d", running.Statement.Cleared.Count, running.Statement.Seen.Count)
	}
	if stopped.Statement.Seen.Count != 2 || stopped.Statement.Cleared.Count != 0 { // the exception and the StopLogging
		t.Errorf("stopped: cleared %d seen %d", stopped.Statement.Cleared.Count, stopped.Statement.Seen.Count)
	}
	// The trail's verification counts the observations it verified, once each, without a second observation.
	if si := stopped.Statement.Integrity; si.Observations != 2 || si.Verified != 1 || si.Later != 1 || si.Unverified != 1 {
		t.Errorf("stopped source integrity %+v, want 2 observations, 1 verified later", si)
	}
	if si := running.Statement.Integrity; si.Observations != 1 || si.Verified != 1 || si.Later != 1 {
		t.Errorf("running source integrity %+v", si)
	}
	if si := pk.Coverage.Integrity; si.Observations != 3 || si.Verified != 2 || !strings.Contains(pk.Coverage.Text, "Source verified for 2 of 3 observations") {
		t.Errorf("packet source integrity %+v: %s", si, pk.Coverage.Text)
	}
	// The exceptions section: one row per exception (the trail's verification is not a second one), with the newest
	// resolution and the person it names.
	var oob, mon *packet.Exception
	for i := range pk.Exceptions.Rows {
		r := &pk.Exceptions.Rows[i]
		switch r.Class {
		case packet.ClassOutOfBand:
			oob = r
		case packet.ClassMonitoring:
			mon = r
		}
	}
	if len(pk.Exceptions.Rows) != 2 || oob == nil || mon == nil { // the out-of-band change and StopLogging; the verifications add none
		t.Fatalf("exception rows: %d %+v", len(pk.Exceptions.Rows), pk.Exceptions.Rows)
	}
	if oob.Seq != lab.exceptionSeq || oob.Resolution != "reverted" || oob.Cause != "automated-remediation" || oob.ResolvedBy != "user:erin" ||
		oob.ResolutionSeq == nil || *oob.ResolutionSeq != lab.resolveEditSeq || !oob.SourceVerified || oob.VerifiedBy != "later" {
		t.Errorf("the out-of-band row (newest resolution wins, naming the person who set it): %+v", *oob)
	}
	if mon.Seq != lab.stopSeq || mon.Actor == "" || mon.Diff == "" {
		t.Errorf("the monitoring-protection row has actor, diff: %+v", *mon)
	}

	dir := filepath.Join(t.TempDir(), "packet")
	if _, err := packet.Write(bg, dir, res, nil, nil); err != nil {
		t.Fatal(err)
	}
	noNetwork(t)
	opts := verify.Options{LogKeys: []byte(vkey + "\n"), LogKeysSrc: "log-vkeys.txt", WitnessPolicy: policy, WitnessPolicySrc: "witness-policy.txt"}
	rep := verify.Verify(dir, opts)
	for _, c := range rep.Checks {
		if c.Status == verify.Fail {
			t.Fatalf("a good packet failed %q:\n%s", c.Name, render(rep))
		}
	}
	if c := check(rep, "coverage statement recomputes"); c == nil || c.Status != verify.Pass {
		t.Fatalf("the statements check:\n%s", render(rep))
	}
	if c := check(rep, "records: hashes"); c == nil || c.Status != verify.Pass {
		t.Fatalf("the records check:\n%s", render(rep))
	}

	// A flipped byte in a carried record fails the verification.
	flip := copyDir(t, dir)
	raw := string(rd(t, flip, "evidence/records.jsonl"))
	if !strings.Contains(raw, scopeStopped) {
		t.Fatal("the carried records do not hold the stopped scope")
	}
	wr(t, flip, "evidence/records.jsonl", []byte(strings.Replace(raw, `"user:erin"`, `"user:erio"`, 1)))
	rewriteManifest(t, flip)
	wantFail(t, verify.Verify(flip, opts), "records: hashes", "ALTERED")

	// A packet whose statement claims the stopped scope was healthy and clean does not verify, even with its manifest
	// made to match: the verifier rebuilds the statement from the records.
	lie := copyDir(t, dir)
	editJSON(t, lie, "packet.json", func(m map[string]any) {
		for _, s := range m["coverage_statement"].(map[string]any)["observation_health"].([]any) {
			sc := s.(map[string]any)
			if sc["scope"] == scopeStopped {
				st := sc["statement"].(map[string]any)
				st["state"], st["clean"] = "healthy", true
				st["could_not_see"].(map[string]any)["seconds"] = json.Number("0")
			}
		}
	})
	rewriteManifest(t, lie)
	wantFail(t, verify.Verify(lie, opts), "coverage statement recomputes", "scope "+scopeStopped, "feed state")
}

// The freeze and incident views carry the observed changes of their windows, cleared ones too.
func TestFreezeAndIncidentViewsCarryTheObservedChanges(t *testing.T) {
	lab := buildO5Chain(t)
	for _, view := range []string{packet.ViewFreeze, packet.ViewIncident} {
		p := packet.Params{From: mustTime(t, "2026-10-14T00:00:00Z"), To: mustTime(t, "2026-10-20T00:00:00Z"), Now: mustTime(t, nowAt), Version: "test",
			Scopes: []string{scopeStopped, scopeRunning}, View: view, Title: "Q4 freeze"}
		res, err := packet.Build(bg, lab.st, p)
		if err != nil {
			t.Fatal(err)
		}
		oc := res.Packet.Observed
		if oc == nil || oc.Count != 2 || len(oc.Rows) != 2 {
			t.Fatalf("%s: observed changes %+v, want the two observations of the window", view, oc)
		}
		got := map[string]packet.ObservedChange{}
		for _, r := range oc.Rows {
			got[r.Scope] = r
		}
		if r := got[scopeRunning]; r.Coverage != "authorized-and-verified" || !r.SourceVerified || r.VerifiedBy != "later" {
			t.Errorf("%s: the cleared change is listed with its coverage and verification: %+v", view, r)
		}
		if r := got[scopeStopped]; r.Resolution != "reverted" || r.ResolvedBy != "user:erin" || r.Actor == "" {
			t.Errorf("%s: the uncleared change names its actor and who resolved it: %+v", view, r)
		}
	}
	// The packet view does not carry the section.
	res, err := packet.Build(bg, lab.st, packet.Params{From: mustTime(t, winFrom), To: mustTime(t, winTo), Now: mustTime(t, nowAt), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Packet.Observed != nil {
		t.Error("the packet view carries observed changes")
	}
}
