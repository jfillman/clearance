package packet_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jfillman/clearance/internal/packet"
	"github.com/jfillman/clearance/internal/store/memory"
)

// The live gate: StopLogging succeeded and the core flipped the account blind; the collector's routine health record a
// minute later said degraded (the trail was still stopped). That record must not end the blind window: only the
// collector's healthy record does.
func TestAMonitoringFlipStaysBlindUntilTheCollectorReportsHealthy(t *testing.T) {
	st := memory.New()
	t.Cleanup(st.Close)
	l := &labber{t: t, st: st}
	const sc = "aws-flip"
	l.add(obsW, health("2026-11-01T00:00:00Z", sc, "healthy", 300))
	stop := l.add(obsTier, observation("2026-11-01T00:10:00Z", sc, "StopLogging", "trail", map[string]any{"tier": json.Number("3")}))
	blind := health("2026-11-01T00:10:00Z", sc, "blind", 300)
	blind["health"].(map[string]any)["checks"] = []any{map[string]any{"name": "monitoring-protection", "ok": false, "detail": "an operation on the controls succeeded"}}
	blind["about"] = map[string]any{"seq": json.Number(fmt.Sprint(seqI(stop)))}
	l.add(coreW, blind)
	l.add(obsW, health("2026-11-01T00:11:00Z", sc, "degraded", 300)) // routine: trail still stopped
	l.add(obsW, health("2026-11-01T00:16:00Z", sc, "degraded", 300))
	l.add(obsW, health("2026-11-01T00:30:00Z", sc, "healthy", 300)) // the trail was restarted
	res, err := packet.Build(bg, st, packet.Params{From: mustTime(t, "2026-11-01T00:00:00Z"), To: mustTime(t, "2026-11-01T00:40:00Z"),
		Now: mustTime(t, "2026-11-01T01:00:00Z"), Version: "test", Scopes: []string{sc}})
	if err != nil {
		t.Fatal(err)
	}
	var blindS, degradedS int64
	for _, d := range res.Packet.Coverage.Degraded {
		switch d.Kind {
		case "feed-blind":
			blindS += d.Seconds
		case "feed-degraded":
			degradedS += d.Seconds
		}
	}
	// blind 00:10 to 00:30 (1200s); stale holds after each record are blind too, so the sum is at least the flip window
	if blindS < 1200 || degradedS != 0 {
		t.Fatalf("blind %ds degraded %ds: %+v", blindS, degradedS, res.Packet.Coverage.Degraded)
	}
	if got := scopeOf(t, res.Packet, sc).Statement.State; got != "blind" {
		t.Fatalf("state %s", got)
	}
}
