package packet_test

import (
	"testing"

	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/store/memory"
)

// An observation can carry several resolutions: the collector's still-live when it was emitted, and a later reverted
// when a change put it back (in another pass, with the revert memory). The packet reads the newest, by seq.
func TestLaterRevertedResolutionReplacesStillLive(t *testing.T) {
	st := memory.New()
	t.Cleanup(st.Close)
	l := &labber{t: t, st: st}
	l.add(obsW, health("2026-10-09T23:00:00Z", scopeRunning, "healthy", 86400*31))
	ex := l.add(obsW, eventbridge("2026-10-18T09:00:00Z", scopeRunning, "AuthorizeSecurityGroupIngress", "evt-add"))
	seq := seqI(ex)
	l.add(obsW, assessment("2026-10-18T09:00:05Z", scopeRunning, seq, "out-of-band-detected", nil))
	first := seqI(l.add(obsW, resolution("2026-10-18T09:00:06Z", scopeRunning, seq, "still-live", "")))
	later := seqI(l.add(obsW, resolution("2026-10-18T10:00:00Z", scopeRunning, seq, "reverted", "unattributed")))
	res, err := packet.Build(bg, st, packet.Params{From: mustTime(t, winFrom), To: mustTime(t, winTo), Now: mustTime(t, nowAt), Version: "test",
		Scopes: []string{scopeRunning}})
	if err != nil {
		t.Fatal(err)
	}
	var row *packet.Exception
	for i := range res.Packet.Exceptions.Rows {
		if res.Packet.Exceptions.Rows[i].Seq == seq {
			row = &res.Packet.Exceptions.Rows[i]
		}
	}
	if row == nil {
		t.Fatalf("no row for seq %d: %+v", seq, res.Packet.Exceptions.Rows)
	}
	if row.Resolution != "reverted" || row.ResolutionSeq == nil || *row.ResolutionSeq != later || *row.ResolutionSeq == first {
		t.Fatalf("the newest resolution wins: %+v", *row)
	}
}
