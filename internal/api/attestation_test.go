package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jfillman/clearance/internal/store"
)

func TestTheAttestationReferenceAndTheEnvelope(t *testing.T) {
	w := feedWorld()
	idx := int64(77)
	w.atts = []store.Attestation{{ChangeID: "c-3", Digest: "sha256:" + strings.Repeat("a", 64), Backend: "keyless", RekorLogIndex: &idx,
		RekorUUID: "uuid-1", OutcomeSeq: 5, RecordSeq: 6, CreatedAt: feedNow.Add(-time.Minute),
		Bundle: json.RawMessage(`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.2","dsseEnvelope":{"payloadType":"p","payload":"e30=","signatures":[]}}`)}}
	each(t, w, func(t *testing.T, h *harness) {
		// The reference rides on the change; a change without one says null.
		one := h.ok("/v1/clearances/c-3", "erin")
		ref, _ := one["attestation"].(map[string]any)
		if ref["digest"] != "sha256:"+strings.Repeat("a", 64) || ref["backend"] != "keyless" || num(ref["rekor_log_index"]) != 77 ||
			ref["rekor_uuid"] != "uuid-1" || num(ref["outcome_seq"]) != 5 || num(ref["record_seq"]) != 6 {
			t.Fatalf("reference: %v", one["attestation"])
		}
		if one := h.ok("/v1/clearances/c-6", "erin"); one["attestation"] != nil {
			t.Fatalf("a change with no attestation: %v", one["attestation"])
		}
		// The envelope is its own route, with the change's visibility.
		env := h.ok("/v1/clearances/c-3/attestation", "erin")
		if env["dsseEnvelope"].(map[string]any)["payloadType"] != "p" {
			t.Fatalf("bundle: %v", env)
		}
		h.status(t, 404, "GET", "/v1/clearances/c-6/attestation", "erin", "") // none yet
		h.status(t, 404, "GET", "/v1/clearances/c-2/attestation", "erin", "") // not erin's change
		h.status(t, 404, "GET", "/v1/clearances/nope/attestation", "audit", "")
		// A feed reader reads its own cluster's attestations only.
		h.status(t, 404, "GET", "/v1/clearances/c-5/attestation", "sync", "")
		if h.get("/v1/clearances/c-3/attestation", "sync").status != 200 {
			t.Fatal("a feed reader cannot read its cluster's attestation")
		}
	})
}
