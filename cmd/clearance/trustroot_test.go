package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfillman/clearance/internal/attest"
	"github.com/jfillman/clearance/internal/attest/attesttest"
	"github.com/jfillman/clearance/internal/cli"
	"github.com/jfillman/clearance/internal/token"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := cli.Main(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestTrustRootBuildThenAttestVerifyWithIt(t *testing.T) {
	const identity = "clearance-recorder@hangar-dev"
	f, r := attesttest.NewFulcio(t), attesttest.NewRekor(t)
	rk, _ := attest.NewRekor(r.URL(), nil)
	signer := &attest.Keyless{Fulcio: f.URL(), Rekor: rk, TokenFile: attesttest.WriteToken(t, attesttest.Issuer, identity)}
	const tree, commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1111111111111111111111111111111111111111"
	st := attest.Statement{Type: attest.StatementType, PredicateType: attest.PredicateType,
		Subject: []attest.Subject{{Name: "manifest-tree:o/r/app/prod", Digest: map[string]string{"sha256": tree}},
			{Name: "commit:o/r", Digest: map[string]string{"gitCommit": commit}}},
		Predicate: attest.Predicate{Clearance: token.Clearance{ID: "chg-1", ClearedBy: "policy", DecidedAt: "2026-11-07T00:00:00Z"},
			Approvals: []token.Approval{}, Provenance: token.Provenance{Level: "unknown", Proposer: "p", ProposerKind: "person"},
			Cleared: token.Subjects{Kind: "manifest-tree", Repo: "o/r", PR: 1, Commit: commit, TreeRoot: "sha256:" + tree, Images: []string{}},
			Tier:    1, Coverage: "authorized-and-verified", Limitations: []string{"x"},
			Outcome: attest.Outcome{Seq: 7, Provider: "argocd-agent", Applied: true, At: "2026-11-07T00:01:00Z"}}}
	payload, _ := json.Marshal(st)
	signed, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ := json.Marshal(signed.Bundle)

	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	chain, key, bundleFile := write("chain.pem", f.RootPEM), write("rekor.pem", r.KeyPEM), write("b.json", bundle)
	trustFile := filepath.Join(dir, "trusted-root.json")

	code, _, errs := runCLI("trust-root", "build", "--fulcio", chain+",start=2020-01-01T00:00:00Z", "--rekor", key+",end=2099-01-01T00:00:00Z",
		"--fulcio-uri", "http://fulcio", "--rekor-url", "http://rekor", "--out", trustFile)
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	var doc struct {
		MediaType string
		Tlogs     []struct{ BaseUrl string }
	}
	raw, _ := os.ReadFile(trustFile)
	if err := json.Unmarshal(raw, &doc); err != nil || doc.MediaType != attest.TrustedRootMediaType || doc.Tlogs[0].BaseUrl != "http://rekor" {
		t.Fatalf("%v %s", err, raw)
	}

	code, out, errs := runAttest("--file", bundleFile, "--trust-root", trustFile, "--identity", identity, "--issuer", attesttest.Issuer)
	if code != 0 || !strings.Contains(out, "rekor entry 0 verified") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	// --rekor-key beside a TrustedRoot JSON is refused; a wrong identity still fails.
	if code, _, _ := runAttest("--file", bundleFile, "--trust-root", trustFile, "--rekor-key", key, "--identity", identity, "--issuer", attesttest.Issuer); code != 1 {
		t.Fatal("--rekor-key with a JSON trust root was accepted")
	}
	if code, _, _ := runAttest("--file", bundleFile, "--trust-root", trustFile, "--identity", "someone-else", "--issuer", attesttest.Issuer); code != 1 {
		t.Fatal("a wrong identity verified")
	}
	// The PEM form still works with --rekor-key.
	if code, out, errs := runAttest("--file", bundleFile, "--trust-root", chain, "--rekor-key", key, "--identity", identity, "--issuer", attesttest.Issuer); code != 0 {
		t.Fatalf("pem form: %d %q %q", code, out, errs)
	}
}

func TestTrustRootBuildRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	_ = os.WriteFile(junk, []byte("nope"), 0o600)
	for name, args := range map[string][]string{
		"no flags":       {},
		"no rekor":       {"--fulcio", junk},
		"junk chain":     {"--fulcio", junk, "--rekor", junk},
		"unknown option": {"--fulcio", junk + ",bogus=1", "--rekor", junk},
		"bad time":       {"--fulcio", junk + ",end=tomorrow", "--rekor", junk},
		"missing file":   {"--fulcio", filepath.Join(dir, "none.pem"), "--rekor", junk},
	} {
		if code, _, _ := runCLI(append([]string{"trust-root", "build"}, args...)...); code == 0 {
			t.Errorf("%s: exit 0", name)
		}
	}
}
