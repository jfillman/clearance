package server

import (
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/store"
)

func TestAReportOlderThanTheLimitIsStale(t *testing.T) {
	at := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	set := store.ProtectionSet{Cluster: "c", Digest: "d", Doc: []byte(`[{"app":"web","env":"dev"}]`), ReportedAt: at, ChangedAt: at.Add(-time.Hour)}
	for _, tc := range []struct {
		age   time.Duration
		stale bool
	}{{0, false}, {ProtectionStaleAfter, false}, {ProtectionStaleAfter + time.Second, true}, {24 * time.Hour, true}} {
		c, err := protectionCluster(set, at.Add(tc.age))
		if err != nil || c.Stale != tc.stale || c.AgeSeconds != int64(tc.age/time.Second) || len(c.Pairs) != 1 {
			t.Errorf("age %s: %+v %v", tc.age, c, err)
		}
	}
	if _, err := protectionCluster(store.ProtectionSet{Doc: []byte(`{`)}, at); err == nil {
		t.Error("a stored set that is not a list of pairs is an error, not an empty set")
	}
}
