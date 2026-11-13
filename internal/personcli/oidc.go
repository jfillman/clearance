package personcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Discovery is the part of the OIDC discovery document the device flow needs.
type Discovery struct {
	Issuer                      string `json:"issuer"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
}

// DeviceCode is the IdP's answer to the device authorization request (RFC 8628 section 3.2).
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

const maxBody = 1 << 20

func getJSON(ctx context.Context, hc *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return json.Unmarshal(b, out)
}

// Discover reads issuer/.well-known/openid-configuration and checks the document names the issuer asked for.
func Discover(ctx context.Context, hc *http.Client, issuer string) (Discovery, error) {
	var d Discovery
	if err := getJSON(ctx, hc, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", &d); err != nil {
		return d, fmt.Errorf("OIDC discovery: %v", err)
	}
	if strings.TrimRight(d.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return d, fmt.Errorf("OIDC discovery: the document is for issuer %q, not %q", d.Issuer, issuer)
	}
	if d.DeviceAuthorizationEndpoint == "" {
		return d, errors.New("the issuer does not offer the device authorization flow (no device_authorization_endpoint); the IdP must enable it for the public client (docs/cli.md)")
	}
	for _, e := range []string{d.DeviceAuthorizationEndpoint, d.TokenEndpoint} {
		if err := checkURL(e); err != nil {
			return d, fmt.Errorf("OIDC discovery: %v", err)
		}
	}
	return d, nil
}

func postForm(ctx context.Context, hc *http.Client, u string, form url.Values, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err := json.Unmarshal(b, out); err != nil {
		return resp.StatusCode, fmt.Errorf("%s: HTTP %d, not JSON", u, resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// StartDevice asks the IdP for a device and user code. There is no client secret: the client is public.
func StartDevice(ctx context.Context, hc *http.Client, d Discovery, clientID, scopes string) (DeviceCode, error) {
	var dc DeviceCode
	var errBody struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	form := url.Values{"client_id": {clientID}, "scope": {scopes}}
	var raw json.RawMessage
	status, err := postForm(ctx, hc, d.DeviceAuthorizationEndpoint, form, &raw)
	if err != nil {
		return dc, err
	}
	if status != 200 {
		_ = json.Unmarshal(raw, &errBody)
		return dc, fmt.Errorf("device authorization refused (HTTP %d): %s %s", status, errBody.Error, errBody.Desc)
	}
	if err := json.Unmarshal(raw, &dc); err != nil || dc.DeviceCode == "" || dc.UserCode == "" || dc.VerificationURI == "" {
		return dc, errors.New("device authorization: the answer lacks device_code, user_code or verification_uri")
	}
	return dc, nil
}

// PollDevice polls the token endpoint until the person approves, denies or the code expires (RFC 8628 section 3.5:
// authorization_pending keeps waiting, slow_down adds five seconds). It returns the ID token; the access token and
// any refresh token the IdP returned are dropped unread.
func PollDevice(ctx context.Context, hc *http.Client, d Discovery, clientID string, dc DeviceCode,
	now func() time.Time, sleep func(context.Context, time.Duration) error) (string, error) {
	interval := time.Duration(dc.Interval) * time.Second
	if interval < time.Second {
		interval = 5 * time.Second
	}
	life := time.Duration(dc.ExpiresIn) * time.Second
	if life <= 0 || life > 30*time.Minute {
		life = 10 * time.Minute
	}
	deadline := now().Add(life)
	for {
		if err := sleep(ctx, interval); err != nil {
			return "", err
		}
		if !now().Before(deadline) {
			return "", errors.New("the sign-in code expired; run login again")
		}
		var r struct {
			IDToken string `json:"id_token"`
			Error   string `json:"error"`
			Desc    string `json:"error_description"`
		}
		_, err := postForm(ctx, hc, d.TokenEndpoint, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {dc.DeviceCode},
			"client_id": {clientID}}, &r)
		if err != nil {
			return "", err
		}
		switch r.Error {
		case "":
			if r.IDToken == "" {
				return "", errors.New("the IdP returned no id_token (is the openid scope allowed for this client?)")
			}
			return r.IDToken, nil
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return "", errors.New("sign-in was denied")
		case "expired_token":
			return "", errors.New("the sign-in code expired; run login again")
		default:
			return "", fmt.Errorf("sign-in failed: %s %s", r.Error, r.Desc)
		}
	}
}
