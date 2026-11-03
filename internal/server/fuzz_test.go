package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/profile"
)

// FuzzProviderBodies feeds the outcome and record bodies' decoding and validation: never a panic, and an accepted
// record always names its kind's required fields.
func FuzzProviderBodies(f *testing.F) {
	f.Add([]byte(`{"result":"ok","effect":{"repo":"a/b","pr":1,"commit":"abcdef1","paths":["x","./y"]}}`))
	f.Add([]byte(`{"provider":"p","kind":"run.launch","record":{"session":"s","principal":"p","agent":"a","result":"r"}}`))
	f.Add([]byte(`{"provider":"p","kind":"deploy.outcome","record":{"app":"a","target":"t","outcome":{"applied":true}}}`))
	f.Add([]byte(`{"provider":"p","kind":"tool.call","record":{"session":"s","task_id":"t","principal":"p","agent":"a",` +
		`"tool":"catalog.read","tier":0,"args_sha256":"` + strings.Repeat("a", 64) + `","result":"ok","coverage":"coverage-unavailable"}}`))
	f.Add([]byte(`{"result":"refused","refusal":{"rule":"HR-003","message":"m"}}`))
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

// FuzzDefinitionsBody feeds PUT /v1/definitions's decoding and pin decisions: never a panic, and every pin is
// either loaded (its document parsed, its name the XR's) or rejected with a reason.
func FuzzDefinitionsBody(f *testing.F) {
	f.Add([]byte(`{"provider":"p","pins":[{"source":{"repo":"a/b","path":"x.yaml","commit":"abcdef1","namespace":"n",` +
		`"xr":"x"},"owner":"group:default/t","doc":{"name":"x","owner":"group:default/t","kind":"task"}}],` +
		`"rejected":[{"name":"y","source":{"repo":""},"reason":"no source"}]}`))
	s := &Server{opt: Options{Definitions: &definitions.Service{Registry: definitions.NewRegistry(nil)},
		ParseDefinition: profile.Parser()}}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var b DefinitionsRequest
		if strictDecode(bytes.NewReader(raw), &b) != nil {
			return
		}
		loaded, rejected, err := s.decidePins(&b)
		if err != nil {
			return
		}
		if len(loaded)+len(rejected) != len(b.Pins)+len(b.Rejected) {
			t.Fatalf("%d pins and %d rejections became %d and %d", len(b.Pins), len(b.Rejected), len(loaded), len(rejected))
		}
		for _, l := range loaded {
			if l.Source.XR == nil || l.Definition.Name != *l.Source.XR {
				t.Fatalf("loaded %q from xr %v", l.Definition.Name, l.Source.XR)
			}
		}
		for _, r := range rejected {
			if r.Reason == "" {
				t.Fatal("a rejection without a reason")
			}
		}
	})
}
