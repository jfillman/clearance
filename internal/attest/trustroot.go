package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"time"
)

// TrustedRootMediaType is the Sigstore TrustedRoot document's media type.
const TrustedRootMediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

// Window is the span a CA or a log key is trusted for. A zero end is open; a zero start is the beginning of time.
type Window struct{ Start, End time.Time }

// Contains reports whether t is inside the window (both ends inclusive).
func (w Window) Contains(t time.Time) bool {
	return (w.Start.IsZero() || !t.Before(w.Start)) && (w.End.IsZero() || !t.After(w.End))
}

// TrustedCA is one Fulcio chain, leaf-most certificate first, root last.
type TrustedCA struct {
	URI    string
	Chain  []*x509.Certificate
	Window Window
}

// TrustedLog is one Rekor key.
type TrustedLog struct {
	BaseURL string
	Key     *ecdsa.PublicKey
	LogID   []byte // sha256 of the key's DER, as Rekor v1 reports it
	Window  Window
}

// TrustedRoot is the Sigstore TrustedRoot as Clearance reads it: every Fulcio chain and Rekor key with its window.
// Certificate transparency logs and timestamp authorities are ignored: Hangar's Fulcio has no CT log.
type TrustedRoot struct {
	CAs  []TrustedCA
	Logs []TrustedLog
}

// BuildCA is one chain going into a trusted root.
type BuildCA struct {
	URI    string
	PEM    []byte // the chain: intermediate(s) then root, or the root alone
	Window Window
}

// BuildLog is one Rekor public key going into a trusted root.
type BuildLog struct {
	BaseURL string
	PEM     []byte
	Window  Window
}

// check refuses a window that ends before it starts: the document would not parse back.
func (w Window) check() error {
	if !w.Start.IsZero() && !w.End.IsZero() && w.End.Before(w.Start) {
		return errors.New("the window ends before it starts")
	}
	return nil
}

type jWindow struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

func (w Window) json() *jWindow {
	var j jWindow
	if !w.Start.IsZero() {
		j.Start = w.Start.UTC().Format(time.RFC3339)
	}
	if !w.End.IsZero() {
		j.End = w.End.UTC().Format(time.RFC3339)
	}
	if j == (jWindow{}) {
		return nil
	}
	return &j
}

func (j *jWindow) window() (Window, error) {
	var w Window
	if j == nil {
		return w, nil
	}
	var err error
	if j.Start != "" {
		if w.Start, err = time.Parse(time.RFC3339Nano, j.Start); err != nil {
			return w, err
		}
	}
	if j.End != "" {
		if w.End, err = time.Parse(time.RFC3339Nano, j.End); err != nil {
			return w, err
		}
	}
	if !w.Start.IsZero() && !w.End.IsZero() && w.End.Before(w.Start) {
		return w, errors.New("the window ends before it starts")
	}
	return w, nil
}

type jRawCert struct {
	RawBytes string `json:"rawBytes"`
}

type jCA struct {
	Subject   map[string]string `json:"subject"`
	URI       string            `json:"uri,omitempty"`
	CertChain struct {
		Certificates []jRawCert `json:"certificates"`
	} `json:"certChain"`
	ValidFor *jWindow `json:"validFor,omitempty"`
}

type jLog struct {
	BaseURL       string `json:"baseUrl"`
	HashAlgorithm string `json:"hashAlgorithm"`
	PublicKey     struct {
		RawBytes   string   `json:"rawBytes"`
		KeyDetails string   `json:"keyDetails"`
		ValidFor   *jWindow `json:"validFor,omitempty"`
	} `json:"publicKey"`
	LogID struct {
		KeyID string `json:"keyId"`
	} `json:"logId"`
}

type jRoot struct {
	MediaType              string            `json:"mediaType"`
	Tlogs                  []jLog            `json:"tlogs"`
	CertificateAuthorities []jCA             `json:"certificateAuthorities"`
	Ctlogs                 []json.RawMessage `json:"ctlogs"`
	TimestampAuthorities   []json.RawMessage `json:"timestampAuthorities"`
}

// maxRootBytes bounds a trusted root document.
const maxRootBytes = 1 << 20

// BuildTrustedRoot makes the Sigstore TrustedRoot JSON from PEM chains and Rekor public keys. It checks every chain
// (each certificate signed by the next, the last self-signed, ordered leaf-most first whatever the file's order)
// and refuses a key that is not ECDSA P-256 or P-384. Entries are sorted so the same inputs give the same bytes.
func BuildTrustedRoot(cas []BuildCA, logs []BuildLog) ([]byte, error) {
	if len(cas) == 0 {
		return nil, errors.New("trust root: at least one Fulcio chain is needed")
	}
	if len(logs) == 0 {
		return nil, errors.New("trust root: at least one Rekor key is needed")
	}
	out := jRoot{MediaType: TrustedRootMediaType, Tlogs: []jLog{}, CertificateAuthorities: []jCA{},
		Ctlogs: []json.RawMessage{}, TimestampAuthorities: []json.RawMessage{}}
	for i, c := range cas {
		chain, err := orderChain(c.PEM)
		if err != nil {
			return nil, fmt.Errorf("trust root: fulcio chain %d: %w", i+1, err)
		}
		w := c.Window
		if w.Start.IsZero() {
			w.Start = chain[len(chain)-1].NotBefore // never trusted before the root exists
		}
		if err := w.check(); err != nil {
			return nil, fmt.Errorf("trust root: fulcio chain %d: %w", i+1, err)
		}
		var j jCA
		// The CA is named by its trust anchor, the root (last): for a lone root that is what cosign trusted-root create writes.
		anchor := chain[len(chain)-1]
		j.Subject = map[string]string{"commonName": anchor.Subject.CommonName}
		if len(anchor.Subject.Organization) > 0 {
			j.Subject["organization"] = anchor.Subject.Organization[0]
		}
		j.URI = c.URI
		for _, cert := range chain {
			j.CertChain.Certificates = append(j.CertChain.Certificates, jRawCert{base64.StdEncoding.EncodeToString(cert.Raw)})
		}
		j.ValidFor = w.json()
		out.CertificateAuthorities = append(out.CertificateAuthorities, j)
	}
	for i, l := range logs {
		key, der, err := parseECKey(l.PEM)
		if err != nil {
			return nil, fmt.Errorf("trust root: rekor key %d: %w", i+1, err)
		}
		details := "PKIX_ECDSA_P256_SHA_256"
		if key.Curve == elliptic.P384() {
			details = "PKIX_ECDSA_P384_SHA_384"
		}
		id := sha256.Sum256(der)
		w := l.Window
		if w.Start.IsZero() {
			w.Start = time.Unix(0, 0) // cosign and sigstore-go always read a start; open means the beginning of time
		}
		if err := w.check(); err != nil {
			return nil, fmt.Errorf("trust root: rekor key %d: %w", i+1, err)
		}
		var j jLog
		j.BaseURL, j.HashAlgorithm = l.BaseURL, "SHA2_256"
		j.PublicKey.RawBytes = base64.StdEncoding.EncodeToString(der)
		j.PublicKey.KeyDetails = details
		j.PublicKey.ValidFor = w.json()
		j.LogID.KeyID = base64.StdEncoding.EncodeToString(id[:])
		out.Tlogs = append(out.Tlogs, j)
	}
	sort.SliceStable(out.CertificateAuthorities, func(a, b int) bool {
		return out.CertificateAuthorities[a].CertChain.Certificates[0].RawBytes < out.CertificateAuthorities[b].CertChain.Certificates[0].RawBytes
	})
	sort.SliceStable(out.Tlogs, func(a, b int) bool { return out.Tlogs[a].LogID.KeyID < out.Tlogs[b].LogID.KeyID })
	return json.MarshalIndent(out, "", "  ")
}

func parseECKey(raw []byte) (*ecdsa.PublicKey, []byte, error) {
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, nil, errors.New("not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || (k.Curve != elliptic.P256() && k.Curve != elliptic.P384()) {
		return nil, nil, errors.New("not an ECDSA P-256 or P-384 public key")
	}
	der, err := x509.MarshalPKIXPublicKey(k)
	return k, der, err
}

// orderChain reads PEM certificates and returns them leaf-most first, root last, refusing a set that is not exactly
// one chain ending in a self-signed certificate.
func orderChain(raw []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for rest := raw; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("a %s block, want CERTIFICATE", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 || len(certs) > 8 {
		return nil, errors.New("no certificate, or more than 8")
	}
	var chain []*x509.Certificate
	remaining := certs
	// Start from the self-signed root and walk down to the certificate nothing else in the set issued.
	var root *x509.Certificate
	rootAt := -1
	for i, c := range remaining {
		if bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
			if root != nil {
				return nil, errors.New("more than one self-signed certificate")
			}
			root, rootAt = c, i
		}
	}
	if root == nil {
		return nil, errors.New("no self-signed root in the chain")
	}
	remaining = append(append([]*x509.Certificate{}, remaining[:rootAt]...), remaining[rootAt+1:]...)
	chain = []*x509.Certificate{root}
	for len(remaining) > 0 {
		found := -1
		for i, c := range remaining {
			if c.CheckSignatureFrom(chain[0]) == nil && bytes.Equal(c.RawIssuer, chain[0].RawSubject) {
				found = i
				break
			}
		}
		if found < 0 {
			return nil, errors.New("the certificates are not one chain")
		}
		chain = append([]*x509.Certificate{remaining[found]}, chain...)
		remaining = append(append([]*x509.Certificate{}, remaining[:found]...), remaining[found+1:]...)
	}
	return chain, nil
}

// ParseTrustedRoot reads a Sigstore TrustedRoot JSON (Hangar's from `clearance trust-root build`, or any with Fulcio
// CAs and Rekor v1 ECDSA keys).
func ParseTrustedRoot(raw []byte) (*TrustedRoot, error) {
	if len(raw) > maxRootBytes {
		return nil, errors.New("the trusted root is too large")
	}
	var j jRoot
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("the trusted root: %w", err)
	}
	if j.MediaType != "" && j.MediaType != TrustedRootMediaType {
		return nil, fmt.Errorf("the trusted root's media type is %q", j.MediaType)
	}
	tr := &TrustedRoot{}
	for i, c := range j.CertificateAuthorities {
		ca := TrustedCA{URI: c.URI}
		for _, rc := range c.CertChain.Certificates {
			der, err := base64.StdEncoding.DecodeString(rc.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("certificate authority %d: %w", i+1, err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("certificate authority %d: %w", i+1, err)
			}
			ca.Chain = append(ca.Chain, cert)
		}
		if len(ca.Chain) == 0 {
			return nil, fmt.Errorf("certificate authority %d has no certificates", i+1)
		}
		w, err := c.ValidFor.window()
		if err != nil {
			return nil, fmt.Errorf("certificate authority %d: %w", i+1, err)
		}
		ca.Window = w
		tr.CAs = append(tr.CAs, ca)
	}
	for i, l := range j.Tlogs {
		der, err := base64.StdEncoding.DecodeString(l.PublicKey.RawBytes)
		if err != nil {
			return nil, fmt.Errorf("log %d: %w", i+1, err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("log %d: %w", i+1, err)
		}
		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			id := sha256.Sum256(der) // computed, never taken from the document
			w, err := l.PublicKey.ValidFor.window()
			if err != nil {
				return nil, fmt.Errorf("log %d: %w", i+1, err)
			}
			tr.Logs = append(tr.Logs, TrustedLog{BaseURL: l.BaseURL, Key: k, LogID: id[:], Window: w})
		case ed25519.PublicKey:
			// Rekor v1 signs entries with ECDSA; a log with another key type cannot check a signed entry timestamp.
		}
	}
	if len(tr.CAs) == 0 {
		return nil, errors.New("the trusted root has no certificate authority")
	}
	// Certificate chains may be any key type (the legacy Fulcio root is Ed25519); a Rekor key must be ECDSA.
	if len(tr.Logs) == 0 {
		return nil, errors.New("the trusted root has no usable Rekor key (ECDSA P-256 or P-384)")
	}
	return tr, nil
}
