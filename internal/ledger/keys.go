package ledger

import (
	"errors"
	"fmt"
	"os"
	"strings"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// LogKey is the log's signing key and the verifiers of its checkpoints: the key in use, and the vkeys of keys it
// replaced. A rotation keeps the key's name (the checkpoint's origin) and changes the key; the retired vkeys keep
// every checkpoint the old key signed verifiable (and the witnesses trust old and new under the one name until the
// old key's last checkpoint is no longer needed).
type LogKey struct {
	Signer    note.Signer
	Verifiers []note.Verifier // the key in use first, then the retired ones
}

// Origin is the log's identity: its key name.
func (k LogKey) Origin() string { return k.Signer.Name() }

// LoadLogKey reads the log's signing key from keyFile (the C2SP signed-note secret key text, as `clearance ledger
// keygen` writes it) and the vkeys of retired keys from retiredFile (one vkey per line; "" for none). The key
// material is read, never printed, and an error names the file, not its content.
func LoadLogKey(keyFile, retiredFile string) (LogKey, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return LogKey{}, fmt.Errorf("ledger: reading the log key %s: %w", keyFile, err)
	}
	s, v, err := f_note.NewEd25519SignerVerifier(strings.TrimSpace(string(raw)))
	if err != nil {
		return LogKey{}, fmt.Errorf("ledger: the log key %s is not an Ed25519 signed-note secret key", keyFile)
	}
	k := LogKey{Signer: s, Verifiers: []note.Verifier{v}}
	if retiredFile == "" {
		return k, nil
	}
	rv, err := os.ReadFile(retiredFile)
	if err != nil {
		return LogKey{}, fmt.Errorf("ledger: reading the retired log keys %s: %w", retiredFile, err)
	}
	for i, line := range strings.Split(string(rv), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		ov, err := f_note.NewVerifier(line)
		if err != nil {
			return LogKey{}, fmt.Errorf("ledger: %s line %d is not a verifier key", retiredFile, i+1)
		}
		if ov.Name() != s.Name() {
			return LogKey{}, fmt.Errorf("ledger: %s line %d is a key named %q; a rotation keeps the log's name %q", retiredFile, i+1, ov.Name(), s.Name())
		}
		k.Verifiers = append(k.Verifiers, ov)
	}
	return k, nil
}

// LoadWitnessKey reads a witness's signing key (a signed-note Ed25519 secret key). The witness signs as C2SP
// tlog-cosignature/v1.
func LoadWitnessKey(keyFile string) (note.Signer, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("ledger: reading the witness key %s: %w", keyFile, err)
	}
	s, err := f_note.NewSignerForCosignatureV1(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("ledger: the witness key %s is not an Ed25519 signed-note secret key", keyFile)
	}
	return s, nil
}

// LoadLogVerifiers reads the logs a witness trusts: one vkey per line ('#' starts a comment). A log's name is the
// origin it signs checkpoints under; several lines with one name are a rotation in progress.
func LoadLogVerifiers(file string) ([]note.Verifier, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("ledger: reading the trusted logs %s: %w", file, err)
	}
	var out []note.Verifier
	for i, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		v, err := f_note.NewVerifier(line)
		if err != nil {
			return nil, fmt.Errorf("ledger: %s line %d is not a verifier key", file, i+1)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, errors.New("ledger: " + file + " lists no log")
	}
	return out, nil
}

// GenerateKey makes a signed-note Ed25519 key pair named name. skey is the secret (write it with WriteKeyFile; never
// print it), vkey the public half, and cosigVKey the same key as a tlog-cosignature/v1 verifier key (type 0x04),
// the form a witness policy lists a witness under.
func GenerateKey(name string) (skey, vkey, cosigVKey string, err error) {
	skey, vkey, err = note.GenerateKey(nil, name)
	if err != nil {
		return "", "", "", err
	}
	cosigVKey, err = f_note.VKeyToCosignatureV1(vkey)
	if err != nil {
		return "", "", "", err
	}
	return skey, vkey, cosigVKey, nil
}

// WriteKeyFile writes a secret key to a new file readable by its owner only; it refuses to replace a file.
func WriteKeyFile(path, skey string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	if _, err := f.WriteString(skey + "\n"); err != nil {
		f.Close()
		return fmt.Errorf("ledger: writing %s: %w", path, err)
	}
	return f.Close()
}
