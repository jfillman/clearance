package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Packet file names (the layout docs/packet.md describes).
const (
	fileManifest   = "MANIFEST.json"
	filePacket     = "packet.json"
	fileRecords    = "evidence/records.jsonl"
	fileProofs     = "evidence/proofs.json"
	fileCheckpoint = "ledger/checkpoint.txt"
	fileLogKeys    = "ledger/log-keys.txt"
	filePolicy     = "ledger/witness-policy.txt"
	dirAttest      = "attestations"

	maxFile = 1 << 30
)

// Options are the trust inputs and the local state. Everything is bytes the caller already read: the package opens
// nothing but the packet and the seen-checkpoints note.
type Options struct {
	// LogKeys are the log's signed-note vkeys, one per line, the key in use first. Empty: the packet's own copy is
	// used and reported as taken from the packet.
	LogKeys    []byte
	LogKeysSrc string // where they came from, for the report
	// WitnessPolicy is the witness policy (Tessera's text form). Empty: the packet's own copy.
	WitnessPolicy    []byte
	WitnessPolicySrc string
	// TrustRoot is a Sigstore TrustedRoot JSON (`clearance trust-root build`), or a PEM of Fulcio certificates with
	// RekorKey (PEM). Without it keyless attestations are not checked.
	TrustRoot    []byte
	TrustRootSrc string
	RekorKey     []byte
	// AttestKeys verifies a static-key attestation (PEM public key or JWKS).
	AttestKeys    []byte
	AttestKeysSrc string
	// Identity and Issuer pin a keyless attestation's signer. Empty: the signer's own certificate is read and the
	// report says the identity was taken from the attestation.
	Identity, Issuer string
	// RecipientKeys are the public keys of the assurance recipients whose acceptance receipts the packet carries (PEM, or
	// a JWKS), as the verifier's user got them from the recipients: what a receipt's signature is checked with. Empty:
	// each receipt's own carried copy of the recipient's key is used and reported as taken from the packet.
	// It is by recipient name: a receipt that names recipient A is checked only under keys supplied for A, so a key
	// supplied for B never vouches for a receipt that claims A. A recipient with no entry falls back to the receipt's
	// own carried key (SELF-VOUCHED).
	RecipientKeys    map[string][]byte
	RecipientKeysSrc map[string]string
	// SampleRecord is the packet.sample record of a sample as the core serves it (GET /v1/evidence/{seq}), for `--sample`: what
	// the sample's record is compared with. Empty: the check that the core drew the sample is NOT CHECKED.
	SampleRecord    []byte
	SampleRecordSrc string
	// SeenFile is the local note of checkpoints seen (the weak-witness behaviour). Empty: none is kept.
	SeenFile string
	Now      func() time.Time
}

// ctx carries what the checks share.
type ctx struct {
	dir  string
	opts Options
	rep  *Report

	manifest map[string]string // file -> sha256, nil when there is no manifest
	pk       *packetDoc        // packet.json, nil when absent or unreadable
	recs     []rec
	cp       *checkpoint // the checkpoint as verified or, with no key, as stated
	cpTrust  trust       // how far the checkpoint's root is authenticated
	// mem, when not nil, is the whole file set (a sample document's carried checkpoint, keys and proofs): reads and
	// existence checks are answered from it and never from disk.
	mem map[string][]byte
}

type trust int

const (
	trustNone     trust = iota // not authenticated: no key to check it with
	trustPacket                // authenticated by keys from the packet
	trustSupplied              // authenticated by keys the user supplied
)

// Verify checks the packet in dir. It never panics on hostile input and never returns an error: a packet it cannot
// read is a failed check, named.
func Verify(dir string, opts Options) *Report {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	c := &ctx{dir: dir, opts: opts, rep: &Report{Packet: dir}}
	c.manifestCheck()
	c.loadPacket()
	c.recordsCheck()
	c.inputs()
	c.ledgerCheck()
	c.figuresCheck()
	c.statementsCheck()
	c.acceptancesCheck()
	c.attestationsCheck()
	c.seenCheck()
	return c.rep
}

// read reads a packet file (a slash path inside dir), refusing anything outside it or over the cap.
func (c *ctx) read(name string) ([]byte, error) {
	if c.mem != nil {
		if b, ok := c.mem[name]; ok {
			return b, nil
		}
		return nil, fmt.Errorf("%s: not in the sample", name)
	}
	if name == "" || strings.Contains(name, "..") || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return nil, fmt.Errorf("%q is not a path inside the packet", name)
	}
	f, err := os.Open(filepath.Join(c.dir, filepath.FromSlash(name)))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, maxFile)
	}
	return b, nil
}

func (c *ctx) exists(name string) bool {
	if c.mem != nil {
		b, ok := c.mem[name]
		return ok && len(bytes.TrimSpace(b)) > 0
	}
	_, err := os.Stat(filepath.Join(c.dir, filepath.FromSlash(name)))
	return err == nil
}

// inputs prints where each trust input came from, after the checks have settled which they used.
func (c *ctx) inputs() {
	src := func(supplied bool, from, packetFile string, have bool) string {
		switch {
		case supplied:
			return "supplied by you (" + from + ")"
		case have:
			return "TAKEN FROM THE PACKET (" + packetFile + "): proves nothing about who the log is"
		}
		return "none"
	}
	o := c.opts
	c.rep.Inputs = []Input{
		{"log keys", src(len(o.LogKeys) > 0, o.LogKeysSrc, fileLogKeys, c.exists(fileLogKeys))},
		{"witness policy", src(len(o.WitnessPolicy) > 0, o.WitnessPolicySrc, filePolicy, c.exists(filePolicy))},
	}
	if c.receiptCount() > 0 || len(o.RecipientKeys) > 0 {
		names := sortedKeys(o.RecipientKeys)
		for _, n := range names {
			c.rep.Inputs = append(c.rep.Inputs, Input{"recipient keys: " + n, "supplied by you (" + o.RecipientKeysSrc[n] + ")"})
		}
		if c.receiptCount() > 0 {
			c.rep.Inputs = append(c.rep.Inputs, Input{"recipient keys: any other recipient", src(false, "", "the receipts' own key copies", true)})
		}
	}
	tr := "none (keyless attestations are not checked)"
	if len(o.TrustRoot) > 0 {
		tr = "supplied by you (" + o.TrustRootSrc + ")"
	}
	c.rep.Inputs = append(c.rep.Inputs, Input{"attestation trust root", tr})
	id := "taken from each attestation's own certificate (not pinned)"
	if o.Identity != "" && o.Issuer != "" {
		id = "supplied by you (" + o.Identity + " via " + o.Issuer + ")"
	}
	c.rep.Inputs = append(c.rep.Inputs, Input{"attestation identity", id})
	if len(o.AttestKeys) > 0 {
		c.rep.Inputs = append(c.rep.Inputs, Input{"attestation keys", "supplied by you (" + o.AttestKeysSrc + ")"})
	}
}

// manifestCheck: every file the manifest names is there with that SHA-256, and nothing else is in the directory.
func (c *ctx) manifestCheck() {
	chk := Check{Name: "manifest"}
	raw, err := c.read(fileManifest)
	if err != nil {
		chk.Status, chk.Detail = Fail, "MANIFEST.json cannot be read: "+err.Error()
		c.rep.add(chk)
		return
	}
	var m struct {
		Schema string            `json:"schema"`
		Files  map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.Files == nil {
		chk.Status, chk.Detail = Fail, "MANIFEST.json is not a packet manifest"
		c.rep.add(chk)
		return
	}
	c.manifest = m.Files
	for _, name := range sortedKeys(m.Files) {
		b, err := c.read(name)
		if err != nil {
			chk.Findings = append(chk.Findings, fmt.Sprintf("%s: listed in the manifest and not readable (%v)", name, err))
			continue
		}
		if got := sha256Hex(b); got != m.Files[name] {
			chk.Findings = append(chk.Findings, fmt.Sprintf("%s: changed since the manifest was written (SHA-256 %s, manifest says %s)", name, short8(got), short8(m.Files[name])))
		}
	}
	_ = filepath.WalkDir(c.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(c.dir, p)
		rel = filepath.ToSlash(rel)
		if _, ok := m.Files[rel]; !ok && rel != fileManifest {
			chk.Findings = append(chk.Findings, fmt.Sprintf("%s: in the packet and not in the manifest", rel))
		}
		return nil
	})
	if len(chk.Findings) > 0 {
		chk.Status, chk.Detail = Fail, fmt.Sprintf("%d file(s) do not match", len(chk.Findings))
	} else {
		chk.Status, chk.Detail = Pass, fmt.Sprintf("%d files, every SHA-256 matches", len(m.Files))
	}
	c.rep.add(chk)
	c.rep.note("MANIFEST.json is not signed: it catches a changed file, not a changed file with a rewritten manifest. What binds the records is the checkpoint and the inclusion proofs; what binds the attestations is their signatures.")
}
