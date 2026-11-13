package personcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Login is `clearance login`: the OIDC device-code flow against the people IdP. The ID token goes to the OS keychain
// and nowhere else; the access token and any refresh token the IdP returns are dropped unread.
func (e *Env) Login(ctx context.Context, args []string) int {
	s, pos, ee := e.begin("login", "[--issuer URL] [--client-id ID]", args, func(fs *flag.FlagSet) {})
	if ee != nil {
		return e.finish("login", ee)
	}
	if len(pos) > 0 {
		return e.finish("login", s.usageErr())
	}
	err := func() error {
		if s.cfg.Issuer == "" || s.cfg.ClientID == "" {
			return fail(ExitUsage, "login needs the people IdP: set CLEARANCE_OIDC_ISSUER and CLEARANCE_OIDC_CLIENT_ID (or oidc_issuer and oidc_client_id in %s)", cfgHint(e))
		}
		d, err := Discover(ctx, e.HTTP, s.cfg.Issuer)
		if err != nil {
			return fail(ExitUnavailable, "%v", err)
		}
		dc, err := StartDevice(ctx, e.HTTP, d, s.cfg.ClientID, s.cfg.Scopes)
		if err != nil {
			return fail(ExitError, "%v", err)
		}
		fmt.Fprintf(e.Stderr, "To sign in, open  %s\nand enter the code  %s\n", dc.VerificationURI, dc.UserCode)
		if dc.VerificationURIComplete != "" {
			fmt.Fprintf(e.Stderr, "(or open %s directly)\n", dc.VerificationURIComplete)
		}
		fmt.Fprintln(e.Stderr, "Waiting for you to approve...")
		tok, err := PollDevice(ctx, e.HTTP, d, s.cfg.ClientID, dc, e.Now, e.Sleep)
		if err != nil {
			return fail(ExitError, "%v", err)
		}
		c, err := ParseClaims(tok)
		if err != nil {
			return fail(ExitError, "the IdP's id_token is not a JWT")
		}
		if c.Issuer != "" && strings.TrimRight(c.Issuer, "/") != s.cfg.Issuer {
			return fail(ExitError, "the ID token is from issuer %q, not %q", c.Issuer, s.cfg.Issuer)
		}
		if len(c.Audience) > 0 && !slices.Contains(c.Audience, s.cfg.ClientID) {
			return fail(ExitError, "the ID token is not for client %q", s.cfg.ClientID)
		}
		end := Expiry(c, e.Now())
		if !end.After(e.Now()) {
			return fail(ExitError, "the IdP issued an already expired token")
		}
		if err := e.Store.Set(Stored{IDToken: tok, Issuer: s.cfg.Issuer, SavedAt: e.Now().Unix()}); err != nil {
			if errors.Is(err, ErrNoKeychain) || errors.Is(err, ErrTokenTooBig) {
				return fail(ExitError, "%v: the token was not saved (it is never written to a file). Use --token-stdin per command instead", err)
			}
			return fail(ExitError, "%v", err)
		}
		fmt.Fprintf(e.Stdout, "signed in as %s; the token is kept in the OS keychain and used until %s (at most 1 hour)\n",
			c.who(), end.UTC().Format(time.RFC3339))
		return nil
	}()
	return e.finish("login", err)
}

// Logout is `clearance logout`: the keychain entry is removed. The IdP has no revocation here, so the token stays
// valid at the api until its exp (at most an hour); it is simply no longer held.
func (e *Env) Logout(_ context.Context, args []string) int {
	_, pos, ee := e.begin("logout", "", args, nil)
	if ee != nil {
		return e.finish("logout", ee)
	}
	if len(pos) > 0 {
		fmt.Fprintf(e.Stderr, "usage: %s logout\n", e.prog())
		return ExitUsage
	}
	if err := e.Store.Delete(); err != nil {
		return e.finish("logout", fail(ExitError, "%v", err))
	}
	fmt.Fprintln(e.Stdout, "signed out: the token is removed from the keychain")
	return ExitOK
}

// Whoami is `clearance whoami`: who clearance-api takes the token for.
func (e *Env) Whoami(ctx context.Context, args []string) int {
	s, pos, ee := e.begin("whoami", "", args, nil)
	if ee != nil {
		return e.finish("whoami", ee)
	}
	if len(pos) > 0 {
		return e.finish("whoami", s.usageErr())
	}
	err := func() error {
		c, err := s.client(false)
		if err != nil {
			return err
		}
		_, end, _ := s.token()
		var raw json.RawMessage
		if err := c.Get(ctx, "/v1/whoami", nil, &raw); err != nil {
			if isMissingRoute(err) {
				return fail(ExitNotFound, "this clearance-api has no /v1/whoami (it predates the person CLI release)")
			}
			return err
		}
		if wrote, err := emit(e.Stdout, s.format, raw, ""); wrote || err != nil {
			return err
		}
		var w map[string]any
		if err := json.Unmarshal(raw, &w); err != nil {
			return err
		}
		rows := [][2]string{{"principal", str(w, "principal")}, {"person", str(w, "person")}}
		if v := str(w, "via"); v != "" {
			rows = append(rows, [2]string{"via (delegate)", v})
		}
		rows = append(rows, [2]string{"roles", join(w["roles"])}, [2]string{"admin", str(w, "admin")},
			[2]string{"groups", join(w["groups"])}, [2]string{"apps", join(w["apps"])})
		if !end.IsZero() {
			rows = append(rows, [2]string{"token valid until", end.UTC().Format(time.RFC3339)})
		}
		kv(e.Stdout, rows)
		return nil
	}()
	return e.finish("whoami", err)
}

func join(v any) string {
	a, _ := v.([]any)
	if len(a) == 0 {
		return "-"
	}
	out := make([]string, len(a))
	for i, x := range a {
		out[i], _ = x.(string)
	}
	return strings.Join(out, ", ")
}
