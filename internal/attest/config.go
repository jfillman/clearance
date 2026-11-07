package attest

import (
	"errors"
	"fmt"

	"github.com/jfillman/clearance/internal/token"
)

// Environment variables that select the backend (docs/core.md, Change attestations). Neither CLEARANCE_ATTEST_KEY_FILE
// nor CLEARANCE_ATTEST_FULCIO_URL set: attestations are off, and /readyz says so.
const (
	EnvKeyFile   = "CLEARANCE_ATTEST_KEY_FILE"        // static: a PEM ECDSA P-256 private key (token.LoadKeyFile)
	EnvFulcio    = "CLEARANCE_ATTEST_FULCIO_URL"      // keyless: the Fulcio base URL
	EnvRekor     = "CLEARANCE_ATTEST_REKOR_URL"       // keyless: required; static: optional
	EnvTokenFile = "CLEARANCE_ATTEST_OIDC_TOKEN_FILE" // keyless: the OIDC identity token (default DefaultOIDCTokenFile)
)

// Off is the status /readyz reports when no backend is configured.
const Off = "off: set " + EnvFulcio + " and " + EnvRekor + " (keyless), or " + EnvKeyFile + " (static key)"

// FromEnv builds the backend the environment selects: nil and no error when it selects none (attestations off).
func FromEnv(getenv func(string) string) (Backend, error) {
	key, fulcio, rekor, tokFile := getenv(EnvKeyFile), getenv(EnvFulcio), getenv(EnvRekor), getenv(EnvTokenFile)
	switch {
	case key != "" && fulcio != "":
		return nil, fmt.Errorf("%s and %s are both set: choose one backend", EnvKeyFile, EnvFulcio)
	case key == "" && fulcio == "" && rekor == "" && tokFile == "":
		return nil, nil
	case key == "" && fulcio == "":
		return nil, fmt.Errorf("%s and %s configure nothing without %s or %s", EnvRekor, EnvTokenFile, EnvFulcio, EnvKeyFile)
	}
	var rk *Rekor
	if rekor != "" {
		var err error
		if rk, err = NewRekor(rekor, nil); err != nil {
			return nil, fmt.Errorf("%s: %w", EnvRekor, err)
		}
	}
	if key != "" {
		if tokFile != "" {
			return nil, fmt.Errorf("%s is for the keyless backend", EnvTokenFile)
		}
		s, err := token.LoadKeyFile(key)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvKeyFile, err)
		}
		return &Static{Signer: s, Rekor: rk}, nil
	}
	if rk == nil {
		return nil, errors.New(EnvRekor + " is required with " + EnvFulcio + ": a keyless signature is verified through Rekor")
	}
	if _, err := CheckURL(EnvFulcio, fulcio); err != nil {
		return nil, err
	}
	return &Keyless{Fulcio: fulcio, Rekor: rk, TokenFile: tokFile}, nil
}
