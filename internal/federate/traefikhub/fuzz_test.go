package traefikhub_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/jfillman/clearance/internal/federate/traefikhub"
)

// FuzzIngest: no Hub log or access log line makes the adapter panic, and every record it builds is one the core
// takes in shape (the kind, a decision of allow or deny, a coverage the core allows, a task with an attributed one).
func FuzzIngest(f *testing.F) {
	for _, pair := range [][2]string{{"published-hub.log", "published-access.log"}, {"lab-hub.log", "lab-access.log"}} {
		h, err := os.ReadFile("testdata/" + pair[0])
		if err != nil {
			f.Fatal(err)
		}
		a, err := os.ReadFile("testdata/" + pair[1])
		if err != nil {
			f.Fatal(err)
		}
		f.Add(h, a)
	}
	f.Add([]byte(`{"middlewareType":"authzen","decision":"allow","middlewareType":"jwt"}`), []byte("{}\n\n{"))
	f.Fuzz(func(t *testing.T, hub, access []byte) {
		recs, _, err := traefikhub.Ingest(bytes.NewReader(hub), bytes.NewReader(access), traefikhub.Options{})
		if err != nil {
			return
		}
		for _, r := range recs {
			e := r.Record
			if r.Kind != traefikhub.Kind || e.Decision == nil || (*e.Decision != "allow" && *e.Decision != "deny") ||
				e.Result == nil || *e.Result == "" || e.Coverage == nil || e.Rule != nil || e.Tier != nil {
				t.Fatalf("%+v", r)
			}
			switch *e.Coverage {
			case traefikhub.CoverageObserved:
				if e.TaskID != nil {
					t.Fatal("observed with a task")
				}
			case traefikhub.CoverageAttributed:
				if e.TaskID == nil || *e.TaskID == "" {
					t.Fatal("attributed without a task")
				}
			default:
				t.Fatal(*e.Coverage)
			}
		}
	})
}
