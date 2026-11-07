package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/jfillman/clearance/internal/token"
)

// Rekor is a client of a Rekor v1 transparency log: it logs a DSSE envelope.
type Rekor struct {
	base string
	hc   *http.Client
}

// NewRekor is a client of the Rekor at rawURL (CheckURL).
func NewRekor(rawURL string, hc *http.Client) (*Rekor, error) {
	u, err := CheckURL("the Rekor URL", rawURL)
	if err != nil {
		return nil, err
	}
	if hc == nil {
		hc = &http.Client{Timeout: DefaultTimeout}
	}
	return &Rekor{base: u.String(), hc: hc}, nil
}

// rekorEntry is Rekor's answer: uuid -> entry.
type rekorEntry struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
		InclusionProof       *struct {
			LogIndex   int64    `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
			Hashes     []string `json:"hashes"`
			Checkpoint string   `json:"checkpoint"`
		} `json:"inclusionProof"`
	} `json:"verification"`
}

// Log records env in Rekor as a dsse entry, verified by verifier (a PEM certificate or public key), and returns the
// entry as a bundle writes it, with the entry's uuid.
func (r *Rekor) Log(ctx context.Context, env token.Envelope, verifierPEM []byte) (TlogEntry, string, error) {
	envJSON, err := json.Marshal(env)
	if err != nil {
		return TlogEntry{}, "", err
	}
	req := map[string]any{"apiVersion": "0.0.1", "kind": "dsse", "spec": map[string]any{
		"proposedContent": map[string]any{"envelope": string(envJSON),
			"verifiers": []string{base64.StdEncoding.EncodeToString(verifierPEM)}}}}
	var resp map[string]rekorEntry
	if err := postJSON(ctx, r.hc, r.base+"/api/v1/log/entries", nil, req, &resp); err != nil {
		return TlogEntry{}, "", fmt.Errorf("rekor: %w", err)
	}
	if len(resp) != 1 {
		return TlogEntry{}, "", fmt.Errorf("rekor: the answer holds %d entries, want 1", len(resp))
	}
	for uuid, e := range resp {
		body, err := base64.StdEncoding.DecodeString(e.Body)
		if err != nil {
			return TlogEntry{}, "", fmt.Errorf("rekor: the entry body: %w", err)
		}
		set, err := base64.StdEncoding.DecodeString(e.Verification.SignedEntryTimestamp)
		if err != nil || len(set) == 0 {
			return TlogEntry{}, "", errors.New("rekor: the entry carries no signed entry timestamp")
		}
		logID, err := hex.DecodeString(e.LogID)
		if err != nil {
			return TlogEntry{}, "", fmt.Errorf("rekor: the log id: %w", err)
		}
		te := TlogEntry{LogIndex: strconv.FormatInt(e.LogIndex, 10), LogID: LogID{KeyID: logID},
			KindVersion: KindVersion{Kind: "dsse", Version: "0.0.1"}, IntegratedTime: strconv.FormatInt(e.IntegratedTime, 10),
			InclusionPromise: &Promise{SignedEntryTimestamp: set}, CanonicalizedBody: body}
		if p := e.Verification.InclusionProof; p != nil {
			cp, _ := json.Marshal(p.Checkpoint)
			te.InclusionProof = &InclProof{LogIndex: strconv.FormatInt(p.LogIndex, 10), RootHash: p.RootHash,
				TreeSize: strconv.FormatInt(p.TreeSize, 10), Hashes: p.Hashes, Checkpoint: cp}
		}
		return te, uuid, nil
	}
	return TlogEntry{}, "", errors.New("rekor: empty answer")
}

// setPayload is what Rekor signs for a signed entry timestamp: the canonical JSON (RFC 8785: keys sorted, no
// space) of these four fields. The field order below is the sorted order.
type setPayload struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
}

// verifySET checks the entry's signed entry timestamp against Rekor's public key, and that the entry's body names
// this envelope: the dsse entry's payload hash and signatures. It returns the log index and the integration time.
func verifySET(te TlogEntry, env token.Envelope, payload []byte, key *ecdsa.PublicKey) (int64, int64, error) {
	idx, err := strconv.ParseInt(te.LogIndex, 10, 64)
	if err != nil || idx < 0 {
		return 0, 0, errors.New("the log index is not a number")
	}
	at, err := strconv.ParseInt(te.IntegratedTime, 10, 64)
	if err != nil || at <= 0 {
		return 0, 0, errors.New("the integrated time is not a number")
	}
	if te.InclusionPromise == nil || len(te.InclusionPromise.SignedEntryTimestamp) == 0 {
		return 0, 0, errors.New("the entry carries no signed entry timestamp")
	}
	msg, _ := json.Marshal(setPayload{Body: base64.StdEncoding.EncodeToString(te.CanonicalizedBody), IntegratedTime: at,
		LogID: hex.EncodeToString(te.LogID.KeyID), LogIndex: idx})
	d := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(key, d[:], te.InclusionPromise.SignedEntryTimestamp) {
		return 0, 0, errors.New("the signed entry timestamp is not Rekor's")
	}
	var body struct {
		Kind string `json:"kind"`
		Spec struct {
			PayloadHash struct{ Algorithm, Value string } `json:"payloadHash"`
			Signatures  []struct{ Signature string }      `json:"signatures"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(te.CanonicalizedBody, &body); err != nil || body.Kind != "dsse" {
		return 0, 0, errors.New("the entry is not a dsse entry")
	}
	ph := sha256.Sum256(payload)
	if body.Spec.PayloadHash.Algorithm != "sha256" || body.Spec.PayloadHash.Value != hex.EncodeToString(ph[:]) {
		return 0, 0, errors.New("the entry logs a different payload")
	}
	found := false
	for _, s := range body.Spec.Signatures {
		for _, es := range env.Signatures {
			if s.Signature == es.Sig {
				found = true
			}
		}
	}
	if !found {
		return 0, 0, errors.New("the entry logs a different signature")
	}
	return idx, at, nil
}

func pemPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
