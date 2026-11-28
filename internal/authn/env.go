package authn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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
//	CLEARANCE_FOREIGN_ISSUER                    another cluster's service-account issuer (trailing "/" dropped)
//	CLEARANCE_FOREIGN_CLUSTER                   that cluster's name; required with CLEARANCE_FOREIGN_ISSUER
//	CLEARANCE_FOREIGN_SERVICE_ACCOUNTS          comma-separated <namespace>/<sa> globs; required with CLEARANCE_FOREIGN_ISSUER
//	CLEARANCE_FOREIGN_JWKS_URL                  default <issuer>/jwks.json
//	CLEARANCE_FOREIGN_CLUSTERS                  several other clusters, as a JSON list (the CLEARANCE_PROVIDERS form):
//	                                [{"cluster":"c","issuer":"https://...","serviceAccounts":["ns/sa"],"jwksURL":"optional"}];
//	                                each needs cluster, an https issuer and serviceAccounts; no two share an issuer or a
//	                                cluster name, and none repeats the CLEARANCE_FOREIGN_ISSUER one. The single form above stays.
//	CLEARANCE_GITHUB_OIDC_AUDIENCE  GitHub Actions tokens' audience; GitHub Actions callers are off when unset
//	CLEARANCE_GITHUB_OIDC_ALLOWED   comma-separated globs on the sub by name (default "repo:*")
var EnvVars = []string{
	"CLEARANCE_AUDIENCE",
	"CLEARANCE_OIDC_ISSUER", "CLEARANCE_OIDC_AUDIENCE", "CLEARANCE_OIDC_JWKS_URL", "CLEARANCE_OIDC_USER_CLAIM",
	"CLEARANCE_OIDC_ALLOWED_USERS",
	"CLEARANCE_FOREIGN_ISSUER", "CLEARANCE_FOREIGN_CLUSTER", "CLEARANCE_FOREIGN_SERVICE_ACCOUNTS", "CLEARANCE_FOREIGN_JWKS_URL",
	"CLEARANCE_FOREIGN_CLUSTERS",
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

// ForeignCluster is one entry of CLEARANCE_FOREIGN_CLUSTERS.
type ForeignCluster struct {
	Cluster         string   `json:"cluster"`
	Issuer          string   `json:"issuer"`
	ServiceAccounts []string `json:"serviceAccounts"`
	JWKSURL         string   `json:"jwksURL"`
}

// parseForeignClusters reads CLEARANCE_FOREIGN_CLUSTERS and refuses an entry that is incomplete, an issuer that is not
// https, and two entries (or an entry and the single-cluster form, named by single) with the same issuer or cluster name.
// Issuers are returned without a trailing "/".
func parseForeignClusters(raw string, single *ForeignCluster) ([]ForeignCluster, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var list []ForeignCluster
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("CLEARANCE_FOREIGN_CLUSTERS is not a JSON list of {cluster, issuer, serviceAccounts, jwksURL}: %w", err)
	}
	issuers, names := map[string]bool{}, map[string]bool{}
	if single != nil {
		issuers[single.Issuer], names[single.Cluster] = true, true
	}
	for i := range list {
		c := &list[i]
		c.Cluster, c.Issuer = strings.TrimSpace(c.Cluster), strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
		sas := []string{}
		for _, sa := range c.ServiceAccounts {
			if sa = strings.TrimSpace(sa); sa != "" {
				sas = append(sas, sa)
			}
		}
		c.ServiceAccounts = sas
		where := fmt.Sprintf("CLEARANCE_FOREIGN_CLUSTERS[%d]", i)
		if c.Cluster == "" || c.Issuer == "" || len(c.ServiceAccounts) == 0 {
			return nil, fmt.Errorf("%s needs cluster, issuer and serviceAccounts (namespace/name globs): the issuer signs a token for every pod of that cluster", where)
		}
		if u, err := url.Parse(c.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("%s (%s): issuer %q is not an https URL", where, c.Cluster, c.Issuer)
		}
		if issuers[c.Issuer] {
			return nil, fmt.Errorf("%s (%s): issuer %q is already named by another foreign cluster", where, c.Cluster, c.Issuer)
		}
		if names[c.Cluster] {
			return nil, fmt.Errorf("%s: cluster name %q is already used by another foreign cluster", where, c.Cluster)
		}
		issuers[c.Issuer], names[c.Cluster] = true, true
	}
	return list, nil
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
	towerIssuer := strings.TrimRight(get("CLEARANCE_FOREIGN_ISSUER", ""), "/")
	towerCluster, towerSAs := get("CLEARANCE_FOREIGN_CLUSTER", ""), splitList(get("CLEARANCE_FOREIGN_SERVICE_ACCOUNTS", ""))
	if towerIssuer != "" && (towerCluster == "" || len(towerSAs) == 0) {
		return nil, errors.New("CLEARANCE_FOREIGN_ISSUER needs CLEARANCE_FOREIGN_CLUSTER and CLEARANCE_FOREIGN_SERVICE_ACCOUNTS (namespace/name globs): the " +
			"issuer signs a token for every pod of that cluster")
	}
	var single *ForeignCluster
	if towerIssuer != "" {
		single = &ForeignCluster{Cluster: towerCluster, Issuer: towerIssuer}
	}
	foreign, err := parseForeignClusters(getenv("CLEARANCE_FOREIGN_CLUSTERS"), single)
	if err != nil {
		return nil, err
	}
	byIssuer := map[string]Authenticator{}
	if issuer != "" {
		o := NewOIDCAuthenticator(issuer, oidcAud, NewJWKS(get("CLEARANCE_OIDC_JWKS_URL", issuer+"/keys")), allowed)
		o.UserClaim = get("CLEARANCE_OIDC_USER_CLAIM", "email")
		byIssuer[issuer] = o
	}
	if towerIssuer != "" {
		byIssuer[towerIssuer] = NewForeignWorkloadAuthenticator(towerCluster, towerIssuer, audience,
			NewJWKS(get("CLEARANCE_FOREIGN_JWKS_URL", towerIssuer+"/jwks.json")), towerSAs)
	}
	for _, c := range foreign {
		jwks := c.JWKSURL
		if jwks == "" {
			jwks = c.Issuer + "/jwks.json"
		}
		byIssuer[c.Issuer] = NewForeignWorkloadAuthenticator(c.Cluster, c.Issuer, audience, NewJWKS(jwks), c.ServiceAccounts)
	}
	if ghAud := get("CLEARANCE_GITHUB_OIDC_AUDIENCE", ""); ghAud != "" {
		byIssuer[GitHubActionsIssuer] = NewGitHubActionsAuthenticator(ghAud, NewJWKS(GitHubActionsJWKS),
			splitList(get("CLEARANCE_GITHUB_OIDC_ALLOWED", "repo:*")))
	}
	return NewCachingAuthenticator(&RoutingAuthenticator{ByIssuer: byIssuer, Workload: NewWorkloadAuthenticator(audience)}), nil
}
