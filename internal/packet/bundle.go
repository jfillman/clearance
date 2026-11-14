package packet

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The packet bundle (P-1): a packet directory as one JSON document, so a packet can be published to a core, kept by
// it and handed to a recipient unchanged. {"schema": "clearance.packet-bundle/v1", "files": {path: base64}} with the
// files exactly as the packet job wrote them, MANIFEST.json included. Nothing is added and nothing is rewritten:
// unpacking a bundle gives a directory `clearance verify` reads, byte for byte the one that was packed.
//
// A packet's identity is the content address of its manifest: the manifest lists the SHA-256 of every other file, so
// the SHA-256 of MANIFEST.json (the packet's digest) changes when any file does, and the packet's id is the first 128
// bits of it. The same chain, window and parameters give the same packet (docs/packet.md), so the same id.
const (
	BundleSchema = "clearance.packet-bundle/v1"
	// MaxBundleBytes caps a bundle's JSON (the base64 of every file).
	MaxBundleBytes = 64 << 20
	// MaxBundleFiles caps the files in a bundle: a 366-day packet carries one attestation per change.
	MaxBundleFiles = 5000
)

// The parts of a packet a delivery may be scoped to. MANIFEST.json goes with every part, so a part can be checked
// against the manifest; a bundle cut to one part is not a whole packet and `clearance verify` says so.
const (
	// PartSummary is the packet's presentations: packet.json, the PDF and the CSV files.
	PartSummary = "summary"
	// PartEvidence is what an offline check needs: the originals, proofs, checkpoint, keys, attestations and OSCAL.
	PartEvidence = "evidence"
)

// Parts are the parts, in print order.
var Parts = []string{PartSummary, PartEvidence}

// PartOf is the part a packet file belongs to ("" for MANIFEST.json, which belongs to every part).
func PartOf(name string) string {
	switch {
	case name == "MANIFEST.json":
		return ""
	case name == "packet.json", name == "packet.pdf", strings.HasPrefix(name, "csv/"):
		return PartSummary
	default:
		return PartEvidence
	}
}

type bundleDoc struct {
	Schema string            `json:"schema"`
	Files  map[string]string `json:"files"`
}

// Bundle is a validated bundle: the files, the packet's identity and what its packet.json says of it.
type Bundle struct {
	ID     string
	Digest string // the SHA-256 of MANIFEST.json, in hex
	Files  map[string][]byte
	Meta   Meta
	// JSON is the bundle in its canonical encoding: what a core stores and serves.
	JSON []byte
}

// Meta is what a core reads of packet.json to place a packet: it does not interpret the rest.
type Meta struct {
	View     string   `json:"view"`
	Title    string   `json:"title,omitempty"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Mappings []string `json:"mappings"`
	// Chain is the chain the packet was read from: the core checks its own chain agrees.
	ChainCount int64  `json:"chain_count"`
	ChainHead  string `json:"chain_head"`
	// Checkpoint is the ledger checkpoint the packet stood on (nil when it had none).
	Checkpoint *CheckpointRef `json:"checkpoint,omitempty"`
	// Controls and Assertions are the mapping rows of the packet: each control's id and each assertion's id. A receipt's
	// notes are keyed to them.
	Controls   []string `json:"controls"`
	Assertions []string `json:"assertions"`
	Receipts   int      `json:"receipts"`
}

// CheckpointRef names the checkpoint a packet carried.
type CheckpointRef struct {
	Origin string `json:"origin"`
	Size   int64  `json:"size"`
	Root   string `json:"root"`
}

// IDOf is the packet id and digest of a manifest's bytes.
func IDOf(manifest []byte) (id, digest string) {
	d := sha256.Sum256(manifest)
	digest = hex.EncodeToString(d[:])
	return "pk-" + digest[:32], digest
}

// ValidID says whether s is a packet id.
func ValidID(s string) bool {
	if len(s) != 35 || s[:3] != "pk-" {
		return false
	}
	_, err := hex.DecodeString(s[3:])
	return err == nil && s == strings.ToLower(s)
}

// PackDir reads the packet in dir into a bundle (validated as ParseBundle does, so a directory that does not match
// its own manifest is refused here, not at the core).
func PackDir(dir string) (*Bundle, error) { return packDir(dir, true) }

// ReadDir reads a packet directory a recipient was given (possibly one part of it: the files the manifest lists that
// are not there are skipped) and checks what is there against the manifest.
func ReadDir(dir string) (*Bundle, error) { return packDir(dir, false) }

func packDir(dir string, whole bool) (*Bundle, error) {
	man, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		return nil, fmt.Errorf("packet: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(man, &m); err != nil || m.Files == nil {
		return nil, errors.New("packet: MANIFEST.json is not a packet manifest")
	}
	files := map[string]string{"MANIFEST.json": base64.StdEncoding.EncodeToString(man)}
	for name := range m.Files {
		if !safeName(name) {
			return nil, fmt.Errorf("packet: %q is not a path inside the packet", name)
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if errors.Is(err, os.ErrNotExist) && !whole {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("packet: %w", err)
		}
		files[name] = base64.StdEncoding.EncodeToString(b)
	}
	raw, err := json.Marshal(bundleDoc{Schema: BundleSchema, Files: files})
	if err != nil {
		return nil, err
	}
	return parseBundle(raw, whole)
}

func safeName(n string) bool {
	return n != "" && len(n) <= 256 && !strings.HasPrefix(n, "/") && !strings.Contains(n, "\\") && !strings.Contains(n, "..") &&
		!strings.Contains(n, "//") && !strings.HasSuffix(n, "/") && !strings.ContainsRune(n, 0)
}

// ParseBundle validates a bundle: the schema, safe file names, every file the manifest lists present with the SHA-256
// it states and no other file, a packet.json that is a clearance packet, and the identity derived from the manifest.
func ParseBundle(raw []byte) (*Bundle, error) { return parseBundle(raw, true) }

// parseBundle is ParseBundle; whole false accepts a bundle cut to a part (files the manifest lists may be absent, and
// packet.json may be).
func parseBundle(raw []byte, whole bool) (*Bundle, error) {
	if len(raw) > MaxBundleBytes {
		return nil, fmt.Errorf("packet: a bundle is at most %d bytes", MaxBundleBytes)
	}
	var d bundleDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("packet: the bundle is not valid: %v", err)
	}
	if dec.More() {
		return nil, errors.New("packet: trailing data after the bundle")
	}
	if d.Schema != BundleSchema {
		return nil, fmt.Errorf("packet: the bundle's schema is %q, not %s", d.Schema, BundleSchema)
	}
	if len(d.Files) == 0 || len(d.Files) > MaxBundleFiles {
		return nil, fmt.Errorf("packet: a bundle has 1 to %d files", MaxBundleFiles)
	}
	files := make(map[string][]byte, len(d.Files))
	for n, v := range d.Files {
		if !safeName(n) {
			return nil, fmt.Errorf("packet: %q is not a path inside the packet", n)
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("packet: %s is not base64", n)
		}
		files[n] = b
	}
	man, ok := files["MANIFEST.json"]
	if !ok {
		return nil, errors.New("packet: the bundle has no MANIFEST.json")
	}
	var m Manifest
	if err := json.Unmarshal(man, &m); err != nil || m.Files == nil || m.Schema != "clearance.packet-manifest/v1" {
		return nil, errors.New("packet: MANIFEST.json is not a packet manifest")
	}
	var bad []string
	for n, want := range m.Files {
		b, ok := files[n]
		if !ok {
			if whole {
				bad = append(bad, n+": listed in the manifest and missing from the bundle")
			}
			continue
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != want {
			bad = append(bad, n+": does not match the manifest's SHA-256")
		}
	}
	for n := range files {
		if _, ok := m.Files[n]; !ok && n != "MANIFEST.json" {
			bad = append(bad, n+": in the bundle and not in the manifest")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return nil, fmt.Errorf("packet: the bundle does not match its manifest: %s", strings.Join(bad, "; "))
	}
	var meta Meta
	var err error
	if pj, ok := files["packet.json"]; ok {
		if meta, err = readMeta(pj); err != nil {
			return nil, err
		}
	} else if whole {
		return nil, errors.New("packet: the bundle has no packet.json: a core keeps packets it can describe")
	}
	id, digest := IDOf(man)
	b := &Bundle{ID: id, Digest: digest, Files: files, Meta: meta}
	if b.JSON, err = json.Marshal(bundleDoc{Schema: BundleSchema, Files: d.Files}); err != nil {
		return nil, err
	}
	return b, nil
}

func readMeta(pj []byte) (Meta, error) {
	var p struct {
		Schema string `json:"schema"`
		Header struct {
			View     string   `json:"view"`
			Title    string   `json:"title"`
			From     string   `json:"from"`
			To       string   `json:"to"`
			Mappings []string `json:"mappings"`
			Chain    struct {
				Count int64  `json:"count"`
				Head  string `json:"head"`
			} `json:"chain"`
		} `json:"header"`
		Assertions []struct {
			Control    string `json:"control"`
			Assertions []struct {
				ID string `json:"id"`
			} `json:"assertions"`
		} `json:"control_assertions"`
		Verification struct {
			Ledger struct {
				State  string `json:"state"`
				Origin string `json:"origin"`
				Size   int64  `json:"size"`
				Root   string `json:"root"`
			} `json:"ledger"`
		} `json:"verification"`
		Acceptances struct {
			Receipts []json.RawMessage `json:"receipts"`
		} `json:"acceptances"`
	}
	if err := json.Unmarshal(pj, &p); err != nil {
		return Meta{}, fmt.Errorf("packet: packet.json is not readable: %v", err)
	}
	if p.Schema != Schema {
		return Meta{}, fmt.Errorf("packet: packet.json's schema is %q, not %s", p.Schema, Schema)
	}
	m := Meta{View: p.Header.View, Title: p.Header.Title, From: p.Header.From, To: p.Header.To, Mappings: p.Header.Mappings,
		ChainCount: p.Header.Chain.Count, ChainHead: p.Header.Chain.Head, Receipts: len(p.Acceptances.Receipts)}
	if l := p.Verification.Ledger; l.State == "checkpointed" && l.Origin != "" {
		m.Checkpoint = &CheckpointRef{Origin: l.Origin, Size: l.Size, Root: l.Root}
	}
	for _, c := range p.Assertions {
		m.Controls = append(m.Controls, c.Control)
		for _, a := range c.Assertions {
			m.Assertions = append(m.Assertions, a.ID)
		}
	}
	if m.Mappings == nil {
		m.Mappings = []string{}
	}
	if m.Assertions == nil {
		m.Assertions = []string{}
	}
	if m.Controls == nil {
		m.Controls = []string{}
	}
	return m, nil
}

// Restrict is the bundle cut to the parts (MANIFEST.json is always kept), in its canonical encoding. An empty parts
// is every part.
func (b *Bundle) Restrict(parts []string) ([]byte, error) {
	if len(parts) == 0 {
		return b.JSON, nil
	}
	want := map[string]bool{}
	for _, p := range parts {
		want[p] = true
	}
	if want[PartSummary] && want[PartEvidence] {
		return b.JSON, nil
	}
	d := bundleDoc{Schema: BundleSchema, Files: map[string]string{}}
	for n, v := range b.Files {
		if p := PartOf(n); p == "" || want[p] {
			d.Files[n] = base64.StdEncoding.EncodeToString(v)
		}
	}
	return json.Marshal(d)
}

// Unpack writes the bundle into dir (which must not exist or be empty), the files exactly as packed.
func (b *Bundle) Unpack(dir string) error {
	if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 {
		return fmt.Errorf("packet: %s is not empty", dir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	names := make([]string, 0, len(b.Files))
	for n := range b.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, b.Files[n], 0o644); err != nil {
			return err
		}
	}
	return nil
}

// LoadBundle reads bundle JSON for unpacking (a partial bundle, cut to a part, is accepted: its files are checked
// against the manifest it carries, and the files it does not carry are listed as absent by `clearance verify`).
func LoadBundle(raw []byte) (*Bundle, error) {
	return parseBundle(raw, false)
}
