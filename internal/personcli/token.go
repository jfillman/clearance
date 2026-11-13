package personcli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

// MaxTokenAge caps the use of any ID token, whatever its exp says.
const MaxTokenAge = time.Hour

// TokenStore keeps the one signed-in ID token. The real one is the OS keychain; tests use an in-memory fake.
type TokenStore interface {
	// Get returns the stored entry, or ErrNoToken.
	Get() (Stored, error)
	Set(Stored) error
	// Delete removes the entry; there being none is not an error.
	Delete() error
}

// ErrNoToken is no stored token; ErrNoKeychain is a store that cannot keep one on this machine.
var (
	ErrNoToken    = errors.New("no stored token")
	ErrNoKeychain = errors.New("no OS keychain is available")
	// ErrTokenTooBig is a token the keychain entry cannot hold (macOS limits the entry to about 4 KiB).
	ErrTokenTooBig = errors.New("the ID token is too large for the keychain")
)

// Stored is what the keychain holds: the ID token, never a refresh token, and when it was saved.
type Stored struct {
	IDToken string `json:"id_token"`
	Issuer  string `json:"issuer,omitempty"`
	SavedAt int64  `json:"saved_at"`
}

// Keychain is the OS keychain through go-keyring (macOS Keychain, Windows Credential Manager, the Secret Service on
// Linux). Without one, login fails: the token is never written to a file.
//
// On macOS go-keyring (v0.2.8) runs `security -i` and writes the add-generic-password command to its standard input,
// so the token is in a pipe and never in any process's argument list (checked by polling `ps` through repeated
// saves). It reads with `find-generic-password -w`, which prints to a pipe. No cgo is needed, so the static,
// cross-compiled release binary and the distroless image are unaffected; a cgo Keychain binding
// (keybase/go-keychain) would add nothing here and would break CGO_ENABLED=0 builds.
type Keychain struct{}

const (
	keychainService = "clearance-cli"
	keychainAccount = "id-token"
)

func (Keychain) Get() (Stored, error) {
	s, err := keyring.Get(keychainService, keychainAccount)
	switch {
	case errors.Is(err, keyring.ErrNotFound):
		return Stored{}, ErrNoToken
	case err != nil:
		return Stored{}, fmt.Errorf("%w: %v", ErrNoKeychain, err)
	}
	var st Stored
	if json.Unmarshal([]byte(s), &st) != nil || st.IDToken == "" {
		return Stored{}, ErrNoToken
	}
	return st, nil
}

func (Keychain) Set(st Stored) error {
	b, _ := json.Marshal(st)
	if err := keyring.Set(keychainService, keychainAccount, string(b)); err != nil {
		if errors.Is(err, keyring.ErrSetDataTooBig) {
			return fmt.Errorf("%w (an ID token this large does not fit one macOS keychain entry; use --token-stdin)", ErrTokenTooBig)
		}
		return fmt.Errorf("%w: %v", ErrNoKeychain, err)
	}
	return nil
}

func (Keychain) Delete() error {
	if err := keyring.Delete(keychainService, keychainAccount); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("%w: %v", ErrNoKeychain, err)
	}
	return nil
}

// Claims are the few ID-token claims the CLI reads. The CLI does not verify the signature: the token came from the
// IdP over TLS at login, and clearance-api verifies it on every call. It reads exp and iat to refuse use of an
// expired token and to cap use at one hour.
type Claims struct {
	Issuer   string
	Audience []string
	Subject  string
	Username string
	Email    string
	Exp, Iat time.Time
}

// ParseClaims decodes a JWT's payload without verifying it.
func ParseClaims(tok string) (Claims, error) {
	parts := strings.Split(strings.TrimSpace(tok), ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return Claims{}, errors.New("not a JWT")
	}
	var p struct {
		Iss   string          `json:"iss"`
		Aud   json.RawMessage `json:"aud"`
		Sub   string          `json:"sub"`
		User  string          `json:"preferred_username"`
		Email string          `json:"email"`
		Exp   float64         `json:"exp"`
		Iat   float64         `json:"iat"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return Claims{}, errors.New("not a JWT")
	}
	c := Claims{Issuer: p.Iss, Subject: p.Sub, Username: p.User, Email: p.Email}
	var one string
	var many []string
	if json.Unmarshal(p.Aud, &one) == nil && one != "" {
		c.Audience = []string{one}
	} else if json.Unmarshal(p.Aud, &many) == nil {
		c.Audience = many
	}
	if p.Exp > 0 {
		c.Exp = time.Unix(int64(p.Exp), 0).UTC()
	}
	if p.Iat > 0 {
		c.Iat = time.Unix(int64(p.Iat), 0).UTC()
	}
	return c, nil
}

// Expiry is when a token stops being used: its exp, and one hour after the earlier of its iat and when it was saved
// (the caller passes savedAt; zero for an in-memory token).
func Expiry(c Claims, savedAt time.Time) time.Time {
	end := c.Exp
	for _, from := range []time.Time{c.Iat, savedAt} {
		if !from.IsZero() {
			if capped := from.Add(MaxTokenAge); end.IsZero() || capped.Before(end) {
				end = capped
			}
		}
	}
	return end
}

// who is the name a person knows themselves by.
func (c Claims) who() string {
	switch {
	case c.Username != "":
		return "user:" + c.Username
	case c.Email != "":
		return "user:" + c.Email
	}
	return c.Subject
}

// ReadTokenStdin reads one token from r (a single line, at most 16 KiB), for --token-stdin.
func ReadTokenStdin(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 16<<10+1))
	if err != nil {
		return "", err
	}
	if len(b) > 16<<10 {
		return "", errors.New("the token on stdin is longer than 16 KiB")
	}
	t := strings.TrimSpace(string(b))
	if t == "" || strings.ContainsAny(t, " \t\r\n") {
		return "", errors.New("stdin holds no token (one token, no spaces)")
	}
	return t, nil
}
