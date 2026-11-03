package authn

import (
	"errors"
	"strings"
)

// EnvVars are the variables FromEnv reads (autopilot serve.py's config_from_env and build_auth). An empty value is
// an unset one.
//
//	CLEARANCE_AUDIENCE              TokenReview audience for this cluster's workloads, and the audience of the
//	                                Tower cluster's tokens (default "clearance")
//	CLEARANCE_OIDC_ISSUER           people's OIDC issuer (trailing "/" dropped); with CLEARANCE_OIDC_AUDIENCE
//	CLEARANCE_OIDC_AUDIENCE         their ID tokens' audience; set together with the issuer or not at all
//	CLEARANCE_OIDC_JWKS_URL         default <issuer>/keys
//	CLEARANCE_OIDC_USER_CLAIM       default email
//	CLEARANCE_OIDC_ALLOWED_USERS    comma-separated globs on the claim; required with an issuer
//	TOWER_ISSUER                    another cluster's service-account issuer (trailing "/" dropped)
//	TOWER_CLUSTER                   that cluster's name; required with TOWER_ISSUER
//	TOWER_SERVICE_ACCOUNTS          comma-separated <namespace>/<sa> globs; required with TOWER_ISSUER
//	TOWER_JWKS_URL                  default <issuer>/jwks.json
//	CLEARANCE_GITHUB_OIDC_AUDIENCE  GitHub Actions tokens' audience; GitHub Actions callers are off when unset
//	CLEARANCE_GITHUB_OIDC_ALLOWED   comma-separated globs on the sub by name (default "repo:*")
var EnvVars = []string{
	"CLEARANCE_AUDIENCE",
	"CLEARANCE_OIDC_ISSUER", "CLEARANCE_OIDC_AUDIENCE", "CLEARANCE_OIDC_JWKS_URL", "CLEARANCE_OIDC_USER_CLAIM",
	"CLEARANCE_OIDC_ALLOWED_USERS",
	"TOWER_ISSUER", "TOWER_CLUSTER", "TOWER_SERVICE_ACCOUNTS", "TOWER_JWKS_URL",
	"CLEARANCE_GITHUB_OIDC_AUDIENCE", "CLEARANCE_GITHUB_OIDC_ALLOWED",
}

// splitList is serve.py's _list: comma-separated, blanks dropped.
func splitList(v string) []string {
	out := []string{}
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// FromEnv builds the authenticator serve.py's build_auth builds: a CachingAuthenticator over a
// RoutingAuthenticator whose issuers are the people's OIDC issuer, the Tower cluster's issuer and GitHub Actions
// (each only when configured, a later one replacing an earlier one with the same issuer), falling back to
// TokenReview for this cluster's workloads. The errors are config_from_env's for these variables.
func FromEnv(getenv func(string) string) (Authenticator, error) {
	get := func(k, def string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return def
	}
	audience := get("CLEARANCE_AUDIENCE", "clearance")
	issuer, oidcAud := get("CLEARANCE_OIDC_ISSUER", ""), get("CLEARANCE_OIDC_AUDIENCE", "")
	if (issuer != "") != (oidcAud != "") {
		return nil, errors.New("CLEARANCE_OIDC_ISSUER and CLEARANCE_OIDC_AUDIENCE are set together or not at all")
	}
	issuer = strings.TrimRight(issuer, "/")
	allowed := splitList(get("CLEARANCE_OIDC_ALLOWED_USERS", ""))
	if issuer != "" && len(allowed) == 0 {
		return nil, errors.New("CLEARANCE_OIDC_ISSUER needs CLEARANCE_OIDC_ALLOWED_USERS: an issuer that federates GitHub " +
			"signs in anyone with a GitHub account")
	}
	towerIssuer := strings.TrimRight(get("TOWER_ISSUER", ""), "/")
	towerCluster, towerSAs := get("TOWER_CLUSTER", ""), splitList(get("TOWER_SERVICE_ACCOUNTS", ""))
	if towerIssuer != "" && (towerCluster == "" || len(towerSAs) == 0) {
		return nil, errors.New("TOWER_ISSUER needs TOWER_CLUSTER and TOWER_SERVICE_ACCOUNTS (namespace/name globs): the " +
			"issuer signs a token for every pod of that cluster")
	}
	byIssuer := map[string]Authenticator{}
	if issuer != "" {
		o := NewOIDCAuthenticator(issuer, oidcAud, NewJWKS(get("CLEARANCE_OIDC_JWKS_URL", issuer+"/keys")), allowed)
		o.UserClaim = get("CLEARANCE_OIDC_USER_CLAIM", "email")
		byIssuer[issuer] = o
	}
	if towerIssuer != "" {
		byIssuer[towerIssuer] = NewForeignWorkloadAuthenticator(towerCluster, towerIssuer, audience,
			NewJWKS(get("TOWER_JWKS_URL", towerIssuer+"/jwks.json")), towerSAs)
	}
	if ghAud := get("CLEARANCE_GITHUB_OIDC_AUDIENCE", ""); ghAud != "" {
		byIssuer[GitHubActionsIssuer] = NewGitHubActionsAuthenticator(ghAud, NewJWKS(GitHubActionsJWKS),
			splitList(get("CLEARANCE_GITHUB_OIDC_ALLOWED", "repo:*")))
	}
	return NewCachingAuthenticator(&RoutingAuthenticator{ByIssuer: byIssuer, Workload: NewWorkloadAuthenticator(audience)}), nil
}
