package authn

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/jfillman/clearance/internal/pycompat"
)

// GitHubActionsIssuer is GitHub Actions' OIDC issuer.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// GitHubActionsJWKS is its JWKS URL.
const GitHubActionsJWKS = GitHubActionsIssuer + "/.well-known/jwks"

// immutableRepo is auth._IMMUTABLE_REPO. Python's `.` stops at a newline and its `$` also matches before a final
// newline; the [^\n] and \n? reproduce both.
var immutableRepo = regexp.MustCompile(`^repo:([^/@:]+)(?:@[0-9]+)?/([^/@:]+)(?:@[0-9]+)?(:[^\n]*)?\n?$`)

// CanonicalSub is a workflow token's sub by name: GitHub's immutable-ID form (repo:owner@<id>/name@<id>:ref:...,
// the default for newer repositories) without the @<id> parts, so allow-lists and verifier globs are written by
// name (repo:acme/shop:*). The ids stay on the principal's claims (sub, repository_id, repository_owner_id).
func CanonicalSub(sub string) string {
	m := immutableRepo.FindStringSubmatch(sub)
	if m == nil {
		return sub
	}
	return "repo:" + m[1] + "/" + m[2] + m[3]
}

// GitHubActionsAuthenticator is a GitHub Actions workflow's OIDC ID token (clearance register in a customer's CI):
// signed by GitHub (RS256), for this audience, not expired. The principal is "github:" + the token's sub by name
// (github:repo:acme/shop:environment:prod), KindGitHubActions; who may do what is still the verifier lists
// (CLEARANCE_VERIFIERS globs on that id). Allowed (globs on the sub by name) narrows which workflows get in at all;
// empty allows none.
//
// Claims carries the verified attributes: "repository" (lower-cased; the gate's DG-REPO binds the caller to it),
// "sub" (as signed), and, when the token has them as strings, repository_id, repository_owner_id, environment,
// ref, sha, workflow_ref, run_id and actor.
type GitHubActionsAuthenticator struct {
	Issuer, Audience string
	Keys             *JWKS
	Allowed          []string
	Leeway           time.Duration
	Now              func() time.Time
}

// GitHubActionsAlgorithms: GitHub signs with RS256 only.
var GitHubActionsAlgorithms = []string{"RS256"}

// NewGitHubActionsAuthenticator has the Python defaults: GitHub's issuer, leeway 30 s. A nil allowed is
// ["repo:*"]; an empty non-nil one allows none.
func NewGitHubActionsAuthenticator(audience string, keys *JWKS, allowed []string) *GitHubActionsAuthenticator {
	if allowed == nil {
		allowed = []string{"repo:*"}
	}
	return &GitHubActionsAuthenticator{Issuer: GitHubActionsIssuer, Audience: audience, Keys: keys, Allowed: allowed, Leeway: DefaultLeeway}
}

var githubAttrs = []string{"repository_id", "repository_owner_id", "environment", "ref", "sha", "workflow_ref", "run_id", "actor"}

// Authenticate verifies a workflow's token.
func (a *GitHubActionsAuthenticator) Authenticate(ctx context.Context, token string) (Principal, error) {
	claims, err := tokenVerifier{a.Issuer, a.Audience, a.Keys, GitHubActionsAlgorithms, a.Leeway, a.Now}.verify(ctx, token, "GitHub Actions token rejected")
	if err != nil {
		return Principal{}, err
	}
	raw, _ := claims["sub"].(string)
	repo, _ := claims["repository"].(string)
	if !strings.HasPrefix(raw, "repo:") || repo == "" {
		return Principal{}, refuse("not a GitHub Actions repository token")
	}
	sub := CanonicalSub(raw)
	if !pycompat.MatchAny(sub, a.Allowed) {
		return Principal{}, refuse("this workflow may not call this Clearance")
	}
	attrs := map[string]any{"repository": strings.ToLower(repo), "sub": raw}
	for _, k := range githubAttrs {
		if s, ok := claims[k].(string); ok {
			attrs[k] = s
		}
	}
	return Principal{ID: "github:" + sub, Kind: KindGitHubActions, Claims: attrs}, nil
}
