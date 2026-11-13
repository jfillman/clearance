package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/authn"
)

// The sign-in is the OIDC authorization code flow with PKCE (S256) as a confidential client. The verification of
// the ID token (signature from the issuer's JWKS, exp, iat, iss, aud) is internal/authn's, the code the core runs on
// the same token at every call; this file adds what only the relying party checks (state, nonce, azp, auth_time).

const maxIdPBody = 1 << 20

// Discovery is the part of the IdP's discovery document the flow needs.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// idp is a discovered IdP and the keys that verify its tokens.
type idp struct {
	d    Discovery
	keys *authn.JWKS
}

func discover(ctx context.Context, hc *http.Client, issuer string) (Discovery, error) {
	var d Discovery
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return d, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return d, fmt.Errorf("OIDC discovery: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxIdPBody))
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("OIDC discovery: HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, errors.New("OIDC discovery: not JSON")
	}
	if strings.TrimRight(d.Issuer, "/") != issuer {
		return d, fmt.Errorf("OIDC discovery: the document is for issuer %q, not %q", d.Issuer, issuer)
	}
	for _, e := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if err := checkURL(e, false); err != nil {
			return d, fmt.Errorf("OIDC discovery: %v", err)
		}
	}
	return d, nil
}

// pkceChallenge is the S256 code challenge of a verifier (RFC 7636).
func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// authURL is the authorization request. A fresh login adds prompt=login and max_age.
func authURL(d Discovery, clientID, redirect, state, nonce, verifier string, maxAge time.Duration) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	if maxAge > 0 {
		q.Set("prompt", "login")
		q.Set("max_age", fmt.Sprint(int(maxAge.Seconds())))
	}
	sep := "?"
	if strings.Contains(d.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return d.AuthorizationEndpoint + sep + q.Encode()
}

// exchange trades the code (with the PKCE verifier) for the ID token at the token endpoint, authenticating with the
// client secret (client_secret_basic). The access and refresh tokens the IdP returns are dropped unread.
func exchange(ctx context.Context, hc *http.Client, d Discovery, clientID, secret, redirect, code, verifier string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	resp, err := hc.Do(req)
	if err != nil {
		return "", errors.New("token endpoint unreachable")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxIdPBody))
	var r struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(b, &r) != nil {
		return "", fmt.Errorf("token endpoint: HTTP %d, not JSON", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || r.Error != "" {
		return "", fmt.Errorf("token endpoint refused the code (HTTP %d, %q)", resp.StatusCode, r.Error)
	}
	if r.IDToken == "" {
		return "", errors.New("the IdP returned no id_token (is the openid scope allowed for this client?)")
	}
	return r.IDToken, nil
}

// idClaims are what the server keeps of a verified ID token.
type idClaims struct {
	User     string
	Exp, Iat time.Time
	AuthTime time.Time // zero when the token has none
}

// checkIDToken verifies the token and the checks only the relying party makes: the nonce, that it is for this
// client when it names several audiences (azp), and, for a fresh login, that auth_time is within maxAge.
func (p *idp) checkIDToken(ctx context.Context, token, clientID, nonce string, maxAge time.Duration, now time.Time) (idClaims, error) {
	cl, err := authn.VerifyIDToken(ctx, token, p.d.Issuer, clientID, p.keys, authn.DefaultLeeway, func() time.Time { return now })
	if err != nil {
		return idClaims{}, err
	}
	if n, _ := cl["nonce"].(string); n == "" || !equalStrings(n, nonce) {
		return idClaims{}, errors.New("nonce mismatch")
	}
	if aud, ok := cl["aud"].([]any); ok && len(aud) > 1 {
		if azp, _ := cl["azp"].(string); azp != clientID {
			return idClaims{}, errors.New("azp is not this client")
		}
	}
	out := idClaims{User: displayName(cl)}
	out.Exp = unixClaim(cl["exp"])
	out.Iat = unixClaim(cl["iat"])
	out.AuthTime = unixClaim(cl["auth_time"])
	if maxAge > 0 {
		if out.AuthTime.IsZero() {
			return idClaims{}, errors.New("a fresh login was asked for but the token has no auth_time")
		}
		if now.Sub(out.AuthTime) > maxAge+authn.DefaultLeeway {
			return idClaims{}, errors.New("the IdP did not reauthenticate the person (auth_time too old)")
		}
	}
	return out, nil
}

func unixClaim(v any) time.Time {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}
	}
	f, err := n.Float64()
	if err != nil || f <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(f), 0)
}

func displayName(cl map[string]any) string {
	for _, k := range []string{"preferred_username", "email", "name", "sub"} {
		if s, ok := cl[k].(string); ok && s != "" {
			if len(s) > 200 {
				s = s[:200]
			}
			return s
		}
	}
	return ""
}
