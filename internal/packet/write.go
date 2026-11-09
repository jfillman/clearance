package packet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/jfillman/clearance/internal/canon"
	"github.com/jfillman/clearance/internal/token"
)

// Formats of a written packet.
const (
	FormatJSON = "json"
	FormatCSV  = "csv"
	FormatPDF  = "pdf"
)

// Manifest lists every file of a written packet with its SHA-256.
type Manifest struct {
	Schema string            `json:"schema"`
	Files  map[string]string `json:"files"`
}

// Write puts the packet in dir (which must not exist or be empty): packet.json (canonical), csv/*.csv, packet.pdf,
// evidence/records.jsonl, evidence/proofs.json, ledger/*, attestations/*, oscal/component-definition.json (and its
// .dsse.json when signer is not nil), and MANIFEST.json. formats limits the three presentations (nil is all); the
// evidence an offline verifier needs is always written, because a packet without it cannot be checked.
func Write(ctx context.Context, dir string, res *Result, formats []string, signer token.Signer) (Manifest, error) {
	if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 {
		return Manifest{}, fmt.Errorf("packet: %s is not empty", dir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	want := map[string]bool{FormatJSON: true, FormatCSV: true, FormatPDF: true}
	if len(formats) > 0 {
		want = map[string]bool{}
		for _, f := range formats {
			if f != FormatJSON && f != FormatCSV && f != FormatPDF {
				return Manifest{}, fmt.Errorf("packet: format is json, csv or pdf, not %q", f)
			}
			want[f] = true
		}
	}
	files := map[string][]byte{}
	pk := res.Packet
	oscal, err := OSCAL(res.Mappings)
	if err != nil {
		return Manifest{}, err
	}
	files[FileOSCAL] = oscal
	if signer != nil {
		env, err := SignOSCAL(ctx, oscal, signer)
		if err != nil {
			return Manifest{}, err
		}
		raw, err := json.Marshal(env)
		if err != nil {
			return Manifest{}, err
		}
		files[FileOSCAL[:len(FileOSCAL)-len(".json")]+".dsse.json"] = raw
		pk.Verification.OSCAL = FileOSCAL + " (signed: oscal/component-definition.dsse.json, key " + signer.KeyID() + ")"
	} else {
		pk.Verification.OSCAL = FileOSCAL + " (unsigned: no signing key was given to the job)"
	}
	// records.jsonl: one canonical record a line, hash included.
	var rec []byte
	for _, r := range res.Records {
		c, err := canon.Canonical(r)
		if err != nil {
			return Manifest{}, err
		}
		rec = append(append(rec, c...), '\n')
	}
	files[FileRecords] = rec
	if len(res.Proofs) > 0 {
		raw, err := canonJSON(map[string]any{"schema": "clearance.packet-proofs/v1", "origin": pk.Verification.Ledger.Origin,
			"tree_size": pk.Verification.Ledger.Size, "root": pk.Verification.Ledger.Root, "proofs": res.Proofs})
		if err != nil {
			return Manifest{}, err
		}
		files[FileProofs] = raw
	}
	if len(res.Checkpoint) > 0 {
		files[FileCheckpoint] = res.Checkpoint
	}
	if len(res.LogKeys) > 0 {
		files[FileLogKeys] = res.LogKeys
	}
	if len(res.WitnessPolicy) > 0 {
		files[FilePolicy] = res.WitnessPolicy
	}
	for id, b := range res.Bundles {
		files[DirAttestations+"/"+id+".json"] = b
	}
	if want[FormatJSON] {
		raw, err := canonJSON(pk)
		if err != nil {
			return Manifest{}, err
		}
		files["packet.json"] = append(raw, '\n')
	}
	if want[FormatCSV] {
		cs, err := CSVs(pk)
		if err != nil {
			return Manifest{}, err
		}
		for n, b := range cs {
			files["csv/"+n] = b
		}
	}
	if want[FormatPDF] {
		files["packet.pdf"] = PDF(pk)
	}
	m := Manifest{Schema: "clearance.packet-manifest/v1", Files: map[string]string{}}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return m, err
		}
		if err := os.WriteFile(p, files[n], 0o644); err != nil {
			return m, err
		}
		s := sha256.Sum256(files[n])
		m.Files[n] = hex.EncodeToString(s[:])
	}
	raw, err := canonJSON(m)
	if err != nil {
		return m, err
	}
	return m, os.WriteFile(filepath.Join(dir, "MANIFEST.json"), append(raw, '\n'), 0o644)
}
