package authn

// Authenticators that turn a bearer token into a Principal, ported from auth.py (interim, until agent identity
// comes from ID-JAG; Hangar decision D19 picks the issuer):
//
//	WorkloadAuthenticator        a Kubernetes service-account token, checked by the API server's TokenReview for the
//	                             clearance audience. Principal "<namespace>/<name>", KindServiceAccount.
//	OIDCAuthenticator            a person's OIDC ID token (Dex in the lab), checked against the issuer's JWKS.
//	                             Principal "user:<claim>", KindPerson.
//	ForeignWorkloadAuthenticator another cluster's service-account token, against that cluster's public issuer.
//	                             Principal "<cluster>/<namespace>/<sa>", KindForeignWorkload.
//	GitHubActionsAuthenticator   a GitHub Actions OIDC ID token. Principal "github:<sub by name>", KindGitHubActions,
//	                             with the token's repository (lower-cased) in Claims, which the gate's DG-REPO reads.
//	RoutingAuthenticator         reads the token's unverified iss only to choose which verifier checks it.
//	CachingAuthenticator         remembers a verified token for a short time, never past its exp, never a failure.
//
// Every failure is an *Error with no detail about the token: a caller learns it was refused, not why.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/pycompat"
)

// Authenticator verifies a bearer token. Any error is a refusal.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (Principal, error)
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(ctx context.Context, token string) (Principal, error)

// Authenticate calls f.
func (f AuthenticatorFunc) Authenticate(ctx context.Context, token string) (Principal, error) {
	return f(ctx, token)
}

// Error is AuthError: a refusal. Its text is for logs, never for the caller.
type Error struct{ Reason string }

func (e *Error) Error() string { return e.Reason }

func refuse(reason string) error { return &Error{reason} }

// IsRefusal reports whether err is (or wraps) an *Error.
func IsRefusal(err error) bool {
	var e *Error
	return errors.As(err, &e)
}

// DefaultLeeway is the clock skew every ID-token verifier allows (leeway=30).
const DefaultLeeway = 30 * time.Second

// SAPrefix is a service account's username prefix.
const SAPrefix = "system:serviceaccount:"

// tokenVerifier is the shared part of the three JWKS verifiers: signature under one of algs by a key from Keys,
// then the claim checks.
type tokenVerifier struct {
	issuer, audience string
	keys             *JWKS
	algs             []string
	leeway           time.Duration
	now              func() time.Time
}

func (v tokenVerifier) verify(ctx context.Context, token, rejected string) (map[string]any, error) {
	t, err := ParseJWT(token)
	if err != nil {
		return nil, refuse(rejected)
	}
	// The alg is checked before the key is looked up, so a token with a disallowed alg never triggers a fetch.
	if !slices.Contains(v.algs, t.Alg()) {
		return nil, refuse(rejected)
	}
	key, err := v.keys.Key(ctx, t.Kid())
	if err != nil {
		return nil, err
	}
	if err := t.verifySignature(key, v.algs); err != nil {
		return nil, refuse(rejected)
	}
	now := time.Now
	if v.now != nil {
		now = v.now
	}
	if err := (claimChecks{v.issuer, v.audience, v.leeway}).verify(t.Claims, now()); err != nil {
		return nil, refuse(rejected)
	}
	return t.Claims, nil
}

// OIDCAuthenticator is a person's ID token: signed by the issuer (RS256 or ES256 only, never none or HMAC), for
// this audience, not expired. The principal is "user:" + UserClaim (email by default, which Dex sets from the
// connector), with the token's sub and the issuer as its Claims. Allowed names who may sign in at all (fnmatch globs on the claim's value): an issuer that federates a
// public identity provider authenticates anyone with an account there, so a valid token alone is not a grant.
// Empty allows nobody.
type OIDCAuthenticator struct {
	Issuer, Audience string
	Keys             *JWKS
	UserClaim        string
	Leeway           time.Duration
	Allowed          []string
	Now              func() time.Time
}

// The claims of a person's Principal that say when they signed in (G3).
const (
	ClaimAuthTime       = "auth_time"        // int64 unix seconds
	ClaimAuthTimeSource = "auth_time_source" // "auth_time" (the IdP said when) or "iat" (the token's issue time)
)

// OIDCAlgorithms are the algorithms a person's ID token may be signed with.
var OIDCAlgorithms = []string{"RS256", "ES256"}

// NewOIDCAuthenticator has the Python defaults: user claim email, leeway 30 s.
func NewOIDCAuthenticator(issuer, audience string, keys *JWKS, allowed []string) *OIDCAuthenticator {
	return &OIDCAuthenticator{Issuer: issuer, Audience: audience, Keys: keys, UserClaim: "email", Leeway: DefaultLeeway, Allowed: allowed}
}

// Authenticate verifies a person's ID token.
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, token string) (Principal, error) {
	claims, err := tokenVerifier{a.Issuer, a.Audience, a.Keys, OIDCAlgorithms, a.Leeway, a.Now}.verify(ctx, token, "ID token rejected")
	if err != nil {
		return Principal{}, err
	}
	uc := a.UserClaim
	if uc == "" {
		uc = "email"
	}
	who, ok := claims[uc].(string)
	if !ok || who == "" {
		return Principal{}, refuse("ID token has no " + uc)
	}
	if v, ok := claims["email_verified"].(bool); uc == "email" && ok && !v {
		return Principal{}, refuse("email not verified")
	}
	if !pycompat.MatchAny(who, a.Allowed) {
		return Principal{}, refuse(uc + " is not allowed to sign in to this Clearance")
	}
	// The person at their identity provider (sub and iss, as signed): what an approval records (C-1).
	id := map[string]any{"iss": a.Issuer}
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		id["sub"] = sub
	}
	if sid, ok := claims["sid"].(string); ok && sid != "" {
		id["sid"] = sid
	}
	// When the person signed in (G3): the token's auth_time, else its iat (verified present, an integer). The gate's
	// freshness rule reads it; ClaimAuthTime is unix seconds and ClaimAuthTimeSource says which claim it came from.
	if at, ok := claimInt(claims["auth_time"]); ok && at > 0 {
		id[ClaimAuthTime], id[ClaimAuthTimeSource] = int64(at), "auth_time"
	} else if iat, ok := claimInt(claims["iat"]); ok {
		id[ClaimAuthTime], id[ClaimAuthTimeSource] = int64(iat), "iat"
	}
	return Principal{ID: "user:" + who, Kind: KindPerson, Claims: id}, nil
}

// ForeignWorkloadAuthenticator is a service-account token from another cluster, verified against that cluster's
// public issuer (its JWKS), since this cluster's TokenReview cannot. The principal is
// "<Name>/<namespace>/<serviceaccount>" (hangar-prod/app-backstage-prod/backstage), and only the service accounts
// Allowed names (globs on "<namespace>/<serviceaccount>") get in: an issuer signs a token for every pod of its
// cluster. Used for delegates such as Tower's backend; routed by issuer like an OIDC verifier.
type ForeignWorkloadAuthenticator struct {
	Name, Issuer, Audience string
	Keys                   *JWKS
	Allowed                []string
	Leeway                 time.Duration
	Now                    func() time.Time
}

// NewForeignWorkloadAuthenticator has the Python default leeway (30 s).
func NewForeignWorkloadAuthenticator(name, issuer, audience string, keys *JWKS, allowed []string) *ForeignWorkloadAuthenticator {
	return &ForeignWorkloadAuthenticator{Name: name, Issuer: issuer, Audience: audience, Keys: keys, Allowed: allowed, Leeway: DefaultLeeway}
}

// Authenticate verifies another cluster's service-account token.
func (a *ForeignWorkloadAuthenticator) Authenticate(ctx context.Context, token string) (Principal, error) {
	claims, err := tokenVerifier{a.Issuer, a.Audience, a.Keys, OIDCAlgorithms, a.Leeway, a.Now}.verify(ctx, token, "workload token rejected")
	if err != nil {
		return Principal{}, err
	}
	sub, _ := claims["sub"].(string)
	if !strings.HasPrefix(sub, SAPrefix) || strings.Count(sub, ":") != 3 {
		return Principal{}, refuse("not a service-account token")
	}
	nsSA := strings.Replace(sub[len(SAPrefix):], ":", "/", 1)
	if !pycompat.MatchAny(nsSA, a.Allowed) {
		return Principal{}, refuse(fmt.Sprintf("%s/%s may not call this Clearance", a.Name, nsSA))
	}
	return Principal{ID: a.Name + "/" + nsSA, Kind: KindForeignWorkload}, nil
}

// VerifyIDToken checks an ID token the way OIDCAuthenticator does (RS256 or ES256 signature from keys, then exp,
// iat, iss and aud) and returns its claims, without the sign-in allowlist: for a relying party that completes an
// authorization-code login and then leaves who may do what to Clearance, which sees the same token on every call
// (the web server, internal/web). nonce, azp and auth_time are the caller's to check.
func VerifyIDToken(ctx context.Context, token, issuer, audience string, keys *JWKS, leeway time.Duration, now func() time.Time) (map[string]any, error) {
	return tokenVerifier{issuer, audience, keys, OIDCAlgorithms, leeway, now}.verify(ctx, token, "ID token rejected")
}
