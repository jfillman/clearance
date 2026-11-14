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
	var recipientKeys recipientFlag
	fs.Var(&recipientKeys, "recipient-keys", "acceptance receipts: <recipient name>=<file>, repeatable: the recipient's public keys (PEM, or a JWKS), as that recipient gave them to you. A receipt naming a recipient is checked only under keys supplied for that name. A recipient with none: the receipt's own copy of the key is used and reported as taken from the packet")
	identity := fs.String("identity", "", "attestations: the identity the signing certificate must name. Without --identity and --issuer the signer is read from each attestation and reported as unpinned")
	issuer := fs.String("issuer", "", "attestations: the OIDC issuer the signing certificate must record")
	seen := fs.String("seen-file", "", "the local note of checkpoints seen (default: <user config dir>/clearance/verify-seen.json)")
	sample := fs.String("sample", "", "check a sample file (the answer of GET /v1/packets/{id}/sample) instead of a packet directory")
	samplePacket := fs.String("packet", "", "with --sample: the packet directory the sample was drawn from, which the sample is then checked against")
	noSeen := fs.Bool("no-seen", false, "neither read nor write the note of checkpoints seen")
	fs.Usage = func() {
		fmt.Fprintln(stderr, sampleUsage+"\n\nor, for a packet:\n\nusage: clearance verify <packet-dir> [flags]\n\nChecks an evidence packet offline: no call to Clearance, a database or the recorder.\n"+
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
	if *sample != "" {
		if dir != "" || fs.NArg() > 0 {
			fmt.Fprintln(stderr, "verify: --sample takes a file, not a packet directory (use --packet <dir> for the packet it was drawn from)")
			return 2
		}
	} else if *samplePacket != "" {
		fmt.Fprintln(stderr, "verify: --packet goes with --sample")
		return 2
	}
	if *sample != "" {
		return verifySampleMain(*sample, *samplePacket, [2]string{*logKeys, *policy}, stdout, stderr)
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
		!read("attest-key", *attestKey, &o.AttestKeys, &o.AttestKeysSrc) {
		return 2
	}
	for _, kv := range recipientKeys {
		name, path, ok := strings.Cut(kv, "=")
		if !ok || name == "" || path == "" {
			fmt.Fprintf(stderr, "verify: --recipient-keys %q is <recipient name>=<file>\n", kv)
			return 2
		}
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "verify: --recipient-keys: %v\n", err)
			return 2
		}
		if o.RecipientKeys == nil {
			o.RecipientKeys, o.RecipientKeysSrc = map[string][]byte{}, map[string]string{}
		}
		o.RecipientKeys[name] = append(o.RecipientKeys[name], b...)
		o.RecipientKeysSrc[name] = path
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

// recipientFlag is a repeatable <name>=<file> flag.
type recipientFlag []string

func (r *recipientFlag) String() string     { return strings.Join(*r, ",") }
func (r *recipientFlag) Set(v string) error { *r = append(*r, v); return nil }

// verifySampleMain is `clearance verify --sample`; trust is the paths of the log keys and the witness policy.
func verifySampleMain(sample, packetDir string, trust [2]string, stdout, stderr io.Writer) int {
	var o Options
	for _, in := range []struct {
		flag, path string
		into       *[]byte
		src        *string
	}{{"log-keys", trust[0], &o.LogKeys, &o.LogKeysSrc}, {"witness-policy", trust[1], &o.WitnessPolicy, &o.WitnessPolicySrc}} {
		if in.path == "" {
			continue
		}
		b, err := os.ReadFile(in.path)
		if err != nil {
			fmt.Fprintf(stderr, "verify: --%s: %v\n", in.flag, err)
			return 2
		}
		*in.into, *in.src = b, in.path
	}
	if packetDir != "" {
		if st, err := os.Stat(packetDir); err != nil || !st.IsDir() {
			fmt.Fprintf(stderr, "verify: %s is not a packet directory\n", packetDir)
			return 2
		}
	}
	rep := VerifySample(sample, packetDir, o)
	rep.Write(stdout)
	return rep.ExitCode()
}
