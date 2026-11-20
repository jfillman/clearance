package pg

import (
	"testing"

	"github.com/jfillman/clearance/internal/store"
)

func TestCheckpointedRange(t *testing.T) {
	for _, c := range []struct {
		name         string
		held         *store.LedgerCheckpoint
		size, lo, hi int64
	}{
		{"first checkpoint covers the whole chain", nil, 40, 0, 40},
		{"later checkpoint covers only the new records", &store.LedgerCheckpoint{Size: 328837}, 328872, 328837, 328872},
		{"same size re-recorded covers nothing", &store.LedgerCheckpoint{Size: 10}, 10, 10, 10},
	} {
		t.Run(c.name, func(t *testing.T) {
			lo, hi := checkpointedRange(c.held, store.LedgerCheckpoint{Size: c.size})
			if lo != c.lo || hi != c.hi {
				t.Fatalf("got [%d, %d), want [%d, %d)", lo, hi, c.lo, c.hi)
			}
		})
	}
}
