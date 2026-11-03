package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// TokenSource gives the bearer token for one request. The client asks for it on every request (retries included),
// so a source that re-reads a rotating credential, such as a projected service-account token, never sends a
// stale one.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenFunc adapts a function to a TokenSource.
type TokenFunc func(ctx context.Context) (string, error)

// Token calls f.
func (f TokenFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// StaticToken is a fixed token (tests and `clearance core --insecure-dev-auth`, where the token is the principal).
func StaticToken(token string) TokenSource {
	return TokenFunc(func(context.Context) (string, error) { return token, nil })
}

// MaxTokenBytes caps a token file.
const MaxTokenBytes = 64 << 10

// FileToken reads the token from path on every request: a projected service-account token
// (/var/run/secrets/tokens/clearance, audience-bound) that the kubelet rotates in place.
func FileToken(path string) TokenSource {
	return TokenFunc(func(context.Context) (string, error) {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, MaxTokenBytes+1))
		if err != nil {
			return "", err
		}
		if len(raw) > MaxTokenBytes {
			return "", fmt.Errorf("token file %s is over %d bytes", path, MaxTokenBytes)
		}
		return string(bytes.TrimSpace(raw)), nil
	})
}

// validToken refuses a token that would break or smuggle a header.
func validToken(t string) error {
	if t == "" {
		return errors.New("the token is empty")
	}
	if strings.ContainsAny(t, " \t\r\n") || strings.ContainsFunc(t, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return errors.New("the token has whitespace or control characters")
	}
	return nil
}
