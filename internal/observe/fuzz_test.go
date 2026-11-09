package observe

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jfillman/clearance/internal/evidence"
	"github.com/jfillman/clearance/internal/vocab"
)

// FuzzCheck: whatever a provider posts, Check answers or refuses and never panics, and what it accepts as an
// observation carries no Secret body.
func FuzzCheck(f *testing.F) {
	f.Add(`{"scope":"a","source":{"name":"t","event_id":"1"},"resource":{"kind":"Secret","name":"x"},"actor":{"subject":"s"},"action":{"verb":"get","api":"x","succeeded":true},"integrity":{"sourceVerified":true,"completenessClaimed":false},"times":{"observed":"2026-11-09T10:00:00Z"}}`)
	f.Add(`{"scope":"a","source":{"name":"t"},"health":{"state":"healthy","checks":[{"name":"a","ok":true}]}}`)
	f.Add(`{"scope":"a","about":{"seq":1},"resolution":{"state":"reverted","cause":"unattributed"}}`)
	v := vocab.Default()
	f.Fuzz(func(t *testing.T, raw string) {
		dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
		dec.UseNumber()
		var ev map[string]any
		if dec.Decode(&ev) != nil || ev == nil {
			return
		}
		for _, kind := range append(Kinds(), "deploy.outcome") {
			c := map[string]any{}
			for k, x := range ev {
				c[k] = x
			}
			if _, err := Check(kind, c, v); err == nil && kind == evidence.KindObservation {
				if isSecretKind(c["resource"].(map[string]any)["kind"]) && c["state_change"] != nil {
					t.Fatalf("a Secret observation with a state change was accepted: %s", raw)
				}
				if hasSecretBody(c["state_change"]) {
					t.Fatalf("a Secret body was accepted: %s", raw)
				}
			}
		}
	})
}
