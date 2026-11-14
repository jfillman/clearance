package server

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/profile"
	"github.com/jfillman/clearance/internal/pycompat"
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

// FuzzRevokeBodies feeds the revoke routes' bodies to the decoding and validation the handlers use: never a panic; an accepted reason
// is valid UTF-8 with no control character and within the bound (checked here without cleanText); an accepted as_of survives the
// time the handler records (truncated to the second, as pycompat.ISO writes it) and reads back as the same instant.
func FuzzRevokeBodies(f *testing.F) {
	f.Add([]byte(`{"reason":"credential leaked"}`))
	f.Add([]byte(`{"reason":"lost","as_of":"2026-11-13T10:00:00Z"}`))
	f.Add([]byte(`{"reason":"` + strings.Repeat("x", 300) + `"}`))
	f.Add([]byte(`{"reason":"a\u0000b","extra":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var a RevokeRequest
		if strictDecode(bytes.NewReader(raw), &a) == nil && cleanTextStrict(a.Reason, MaxRevokeReason) {
			if !utf8.ValidString(a.Reason) || utf8.RuneCountInString(a.Reason) > MaxRevokeReason {
				t.Fatalf("an accepted reason is not valid or too long: %q", a.Reason)
			}
			for _, r := range a.Reason {
				if unicode.IsControl(r) {
					t.Fatalf("an accepted reason holds a control character: %q", a.Reason)
				}
			}
		}
		var b RecipientKeyRevokeRequest
		if strictDecode(bytes.NewReader(raw), &b) == nil && b.AsOf != "" {
			if at, err := time.Parse(time.RFC3339, b.AsOf); err == nil {
				at = at.UTC().Truncate(time.Second)
				if back, err := time.Parse(time.RFC3339, pycompat.ISO(at)); err != nil || !back.Equal(at) {
					t.Fatalf("an accepted as_of does not round-trip: %q", b.AsOf)
				}
			}
		}
	})
}
