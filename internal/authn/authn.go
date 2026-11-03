// Package authn carries the authenticated caller through a request's context. Authentication itself (TokenReview,
// OIDC, GitHub Actions OIDC, foreign workloads) is R-1d's middleware; handlers only read what it put here.
package authn

import "context"

// The kinds of caller. Python's Principal.kind was "user" for a person and "workload" for everything else.
const (
	KindServiceAccount  = "service-account"
	KindPerson          = "person"
	KindGitHubActions   = "github-actions"
	KindForeignWorkload = "foreign-workload"
)

// OnBehalfOfHeader names the person a delegate (Tower's backend) acts for. Hangar vocabulary, kept for the
// delegates already deployed; R-5 renames it.
const OnBehalfOfHeader = "X-Hangar-On-Behalf-Of"

// Principal is who called: its id ("user:<login>", "<ns>/<sa>", "github:repo:...", "<cluster>/<ns>/<sa>"), its
// kind, and the verified claims its authenticator vouches for (a GitHub Actions token's "repository").
type Principal struct {
	ID     string
	Kind   string /* "service-account" | "person" | "github-actions" | "foreign-workload" */
	Claims map[string]any
}

// IsPerson is Python's `principal.kind == "user"`.
func (p Principal) IsPerson() bool { return p.Kind == KindPerson }

type key struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, key{}, p)
}

// From returns the principal on ctx, if authentication put one there.
func From(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(key{}).(Principal)
	return p, ok
}
