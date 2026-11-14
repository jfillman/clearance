// Package grc is clearance-grc (P-4, docs/grc-push.md): it pushes a summary of each production change, and a periodic
// coverage report, to a GRC hub (Vanta first) as evidence items that point back at Clearance. The signed record stays
// in Clearance; the hub holds a pointer. It is a separate service and a reader of clearance-api (the notifier role),
// never on the core's decision path, and it writes what it did to the ledger as grc.push and grc.report records.
//
// A second hub is a new Target implementation: nothing outside vanta.go knows a hub's wire format.
package grc

import (
	"context"
	"fmt"
	"time"
)

// Item is one evidence item as a hub takes it: an identifier that is stable for the change (so a repeat replaces,
// never duplicates), a title, a link back to Clearance and flat scalar properties (string, int64, bool, time.Time).
// It is the whole of what leaves the tenant for an item: Fields lists the properties a change carries.
type Item struct {
	ID    string
	Title string
	Link  string
	Props map[string]any
}

// Target is a GRC hub. PushEvidence and PushReport each send the COMPLETE current set of their kind (the hub
// replaces its set with it, which is what makes a repeat or a restart harmless). Implementations return *Error.
type Target interface {
	Name() string
	PushEvidence(ctx context.Context, items []Item) error
	// PushReport sends the coverage report items; ErrNoReport when the hub is not set up to take one.
	PushReport(ctx context.Context, items []Item) error
}

// Error is a failed push. It carries a class and a status, never a body or a credential: what a hub's error text
// says is not printed, because it can echo what was sent.
type Error struct {
	Target     string
	Class      string // auth, rate-limited, unavailable, rejected, bad-response, network, config
	Status     int
	Retryable  bool
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("%s: %s (HTTP %d)", e.Target, e.Class, e.Status)
	}
	return fmt.Sprintf("%s: %s", e.Target, e.Class)
}

// ErrNoReport is PushReport on a target with no report resource configured.
var ErrNoReport = &Error{Target: "grc", Class: "config"}

// MaxResponse caps what is read of any hub answer.
const MaxResponse = 64 << 10
