package verify

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Main is `clearance verify` and the clearance-verify binary: args are the arguments after the command name. It
// returns the exit code: 0 verified, 1 failed, 2 nothing failed but something could not be established (and for a
// usage error).
func Main(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	logKeys := fs.String("log-keys", "", "the log's public keys (signed-note vkeys, one per line, the key in use first, retired keys after). Without it the packet's own copy is used and reported as taken from the packet")
	policy := fs.String("witness-policy", "", "the witness policy file. Without it the packet's own copy is used and reported as taken from the packet")
	trustRoot := fs.String("trust-root", "", "attestations: a Sigstore TrustedRoot JSON (`clearance trust-root build`), or Fulcio certificates (PEM) with --rekor-key. Without it keyless attestations are not checked")
	rekorKey := fs.String("rekor-key", "", "attestations: Rekor's public key (PEM), with a PEM --trust-root")
	attestKey := fs.String("attest-key", "", "attestations: the public key (PEM) or JWKS that verifies a static-key attestation")
	recipientKeys := fs.String("recipient-keys", "", "acceptance receipts: the recipients' public keys (PEM, or a JWKS), as the recipients gave them to you. Without it each receipt's own copy of the key is used and reported as taken from the packet")
	identity := fs.String("identity", "", "attestations: the identity the signing certificate must name. Without --identity and --issuer the signer is read from each attestation and reported as unpinned")
	issuer := fs.String("issuer", "", "attestations: the OIDC issuer the signing certificate must record")
	seen := fs.String("seen-file", "", "the local note of checkpoints seen (default: <user config dir>/clearance/verify-seen.json)")
	noSeen := fs.Bool("no-seen", false, "neither read nor write the note of checkpoints seen")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: clearance verify <packet-dir> [flags]\n\nChecks an evidence packet offline: no call to Clearance, a database or the recorder.\n"+
			"Exit 0 verified; 1 failed; 2 nothing failed but something could not be established (a trust input missing, keys taken from the packet, not checkpointed).")
		fs.PrintDefaults()
	}
	var dir string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if dir == "" && fs.NArg() == 1 {
		dir = fs.Arg(0)
	} else if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	if dir == "" {
		fs.Usage()
		return 2
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		fmt.Fprintf(stderr, "verify: %s is not a packet directory\n", dir)
		return 2
	}
	o := Options{Identity: *identity, Issuer: *issuer}
	read := func(flagName, path string, into *[]byte, src *string) bool {
		if path == "" {
			return true
		}
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "verify: --%s: %v\n", flagName, err)
			return false
		}
		*into = b
		if src != nil {
			*src = path
		}
		return true
	}
	if !read("log-keys", *logKeys, &o.LogKeys, &o.LogKeysSrc) || !read("witness-policy", *policy, &o.WitnessPolicy, &o.WitnessPolicySrc) ||
		!read("trust-root", *trustRoot, &o.TrustRoot, &o.TrustRootSrc) || !read("rekor-key", *rekorKey, &o.RekorKey, nil) ||
		!read("attest-key", *attestKey, &o.AttestKeys, &o.AttestKeysSrc) || !read("recipient-keys", *recipientKeys, &o.RecipientKeys, &o.RecipientKeysSrc) {
		return 2
	}
	if (o.Identity == "") != (o.Issuer == "") {
		fmt.Fprintln(stderr, "verify: --identity and --issuer go together")
		return 2
	}
	switch {
	case *noSeen:
	case *seen != "":
		o.SeenFile = *seen
	default:
		if d, err := os.UserConfigDir(); err == nil {
			o.SeenFile = filepath.Join(d, "clearance", "verify-seen.json")
		}
	}
	rep := Verify(dir, o)
	rep.Write(stdout)
	return rep.ExitCode()
}
