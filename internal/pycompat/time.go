package pycompat

import (
	"fmt"
	"time"
)

// ISO is audit.iso: UTC, whole seconds, "Z".
func ISO(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// Isoformat is datetime.isoformat() of an aware datetime: microseconds only when non-zero, "+HH:MM".
func Isoformat(t time.Time) string {
	if t.Nanosecond()/1000 != 0 {
		return t.Format("2006-01-02T15:04:05.000000-07:00")
	}
	return t.Format("2006-01-02T15:04:05-07:00")
}

// ParseIsoformat is datetime.fromisoformat for the forms Isoformat and ISO write.
func ParseIsoformat(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-07:00", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("not an ISO timestamp: %q", s)
}
