package packet

import (
	"context"
	"crypto/sha1" //nolint:gosec // RFC 4122 version 5 UUIDs are defined over SHA-1; this is an identifier, not a security use
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/token"
)

// OSCALVersion is the OSCAL release the component definition is written against (the latest at the time of writing,
// v1.2.3, checked against the usnistgov/OSCAL releases and its component-definition metaschema).
const OSCALVersion = "1.2.3"

// OSCALPayloadType is the DSSE payload type of the signed component definition.
const OSCALPayloadType = "application/vnd.oscal.component-definition+json"

// uuidNamespace is the fixed namespace the component definition's identifiers are derived under, so the same
// mappings always publish the same document.
var uuidNamespace = [16]byte{0xc1, 0xea, 0x4a, 0x4c, 0xe5, 0x0c, 0x4c, 0x7e, 0x9a, 0x3b, 0x5e, 0x61, 0x70, 0x61, 0x6b, 0x01}

// uuid5 is an RFC 4122 version 5 UUID of name under uuidNamespace.
func uuid5(name string) string {
	h := sha1.New() //nolint:gosec // see the import
	h.Write(uuidNamespace[:])
	h.Write([]byte(name))
	s := h.Sum(nil)[:16]
	s[6] = s[6]&0x0f | 0x50
	s[8] = s[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}

type oscalProp struct {
	Name  string `json:"name"`
	NS    string `json:"ns"`
	Value string `json:"value"`
}

// OSCAL is the mappings as an OSCAL component definition (canonical JSON): one component, Clearance, with a control
// implementation per framework version and an implemented requirement per control, each assertion a statement naming
// its evaluator. The document is dated by the mappings' own revisions, not the clock, so it is reproducible.
func OSCAL(maps []Mapping) ([]byte, error) {
	const ns = "urn:clearance:oscal"
	last := ""
	var impls []map[string]any
	for _, m := range maps {
		if m.Revision > last {
			last = m.Revision
		}
		var reqs []map[string]any
		for _, c := range m.Controls {
			var stmts []map[string]any
			for _, a := range c.Assertions {
				sid := c.ID + "_smt." + a.ID
				stmts = append(stmts, map[string]any{
					"statement-id": sid, "uuid": uuid5(m.Key() + "#" + sid), "description": a.Statement,
					"props": []oscalProp{{Name: "evaluator", NS: ns, Value: a.Evaluator}},
				})
			}
			reqs = append(reqs, map[string]any{
				"uuid": uuid5(m.Key() + "#" + c.ID), "control-id": c.ID,
				"description": c.Title, "statements": stmts,
			})
		}
		impls = append(impls, map[string]any{
			"uuid": uuid5("impl#" + m.Key()), "source": "urn:clearance:mapping:" + strings.ReplaceAll(m.Key(), "/", ":"),
			"description":              m.Title + ": what an evidence packet asserts for each control, and the evaluator that tests it against the records.",
			"props":                    []oscalProp{{Name: "mapping", NS: ns, Value: m.Key()}},
			"implemented-requirements": reqs,
		})
	}
	if last == "" {
		return nil, fmt.Errorf("packet: no mapping to publish")
	}
	doc := map[string]any{"component-definition": map[string]any{
		"uuid": uuid5("component-definition"),
		"metadata": map[string]any{"title": "Clearance evidence packet: control mappings", "last-modified": last + "T00:00:00Z",
			"version": last, "oscal-version": OSCALVersion},
		"components": []map[string]any{{
			"uuid": uuid5("component#clearance"), "type": "service", "title": "Clearance",
			"description":             "The change-assurance core's evidence packet: the controls it asserts and the records each assertion rests on.",
			"control-implementations": impls,
		}},
	}}
	return canonJSON(doc)
}

// canonJSON is v's canonical JSON (sorted keys, no whitespace).
func canonJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	parsed, err := canon.Parse(raw)
	if err != nil {
		return nil, err
	}
	return canon.Canonical(parsed)
}

// SignOSCAL wraps doc in a DSSE envelope signed with signer (ECDSA P-256 over the SHA-256 of the pre-authentication
// encoding, the same signature the clearance token and the change attestation carry).
func SignOSCAL(ctx context.Context, doc []byte, signer token.Signer) (token.Envelope, error) {
	d := sha256.Sum256(token.PAE(OSCALPayloadType, doc))
	sig, err := signer.Sign(ctx, d[:])
	if err != nil {
		return token.Envelope{}, fmt.Errorf("packet: signing the component definition: %w", err)
	}
	return token.Envelope{PayloadType: OSCALPayloadType, Payload: base64.StdEncoding.EncodeToString(doc),
		Signatures: []token.Signature{{KeyID: signer.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)}}}, nil
}
