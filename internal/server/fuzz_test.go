package server

import (
	"bytes"
	"testing"
)

// FuzzProviderBodies feeds the outcome and record bodies' decoding and validation: never a panic, and an accepted
// record always names its kind's required fields.
func FuzzProviderBodies(f *testing.F) {
	f.Add([]byte(`{"result":"ok","effect":{"repo":"a/b","pr":1,"commit":"abcdef1","paths":["x","./y"]}}`))
	f.Add([]byte(`{"provider":"p","kind":"run.launch","record":{"session":"s","principal":"p","agent":"a","result":"r"}}`))
	f.Add([]byte(`{"provider":"p","kind":"deploy.outcome","record":{"app":"a","target":"t","outcome":{"applied":true}}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var o OutcomeRequest
		if strictDecode(bytes.NewReader(raw), &o) == nil {
			_, _ = o.validate()
		}
		var r RecordRequest
		if strictDecode(bytes.NewReader(raw), &r) == nil {
			if spec, ok := recordKinds[r.Kind]; ok {
				ev, err := r.Record.event(r.Kind, spec, "2026-11-03T00:00:00Z")
				if err == nil {
					for _, k := range spec.required {
						if ev[k] == nil || ev[k] == "" {
							t.Fatalf("accepted a %s without %s", r.Kind, k)
						}
					}
				}
			}
		}
		_, _ = ParseProviders(string(raw))
	})
}
