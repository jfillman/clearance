package gate

import (
	"fmt"
	"strings"

	"github.com/jfillman/clearance/internal/pycompat"
)

// Protected environments (C-6). Clearance decides which environments it protects from its own deployment
// configuration (CLEARANCE_PROTECTED_ENVIRONMENTS: "<cluster glob>/<env glob>" entries, fnmatch); the caller's
// `protected` field no longer decides anything. An empty list protects every environment: a deployment that has
// not said which environments it protects fails closed. A change to an environment the list does not name is
// cleared at tier 0 with the reason `unprotected`, and recorded like any other change.

// ParseProtected checks the configured entries: each is "<cluster>/<env>", both non-empty fnmatch globs.
func ParseProtected(entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		cluster, env, ok := strings.Cut(e, "/")
		if !ok || cluster == "" || env == "" || strings.Contains(env, "/") || strings.ContainsAny(e, " \t\r\n") ||
			len(e) > 200 {
			return nil, fmt.Errorf("%q is not <cluster>/<env> (globs allowed: prod-*/*, */prod)", e)
		}
		out = append(out, e)
	}
	return out, nil
}

// Protects says whether the deployment protects env on cluster: true when no environment is listed.
func (s *Service) Protects(cluster, env string) bool {
	if len(s.Config.Protected) == 0 {
		return true
	}
	return pycompat.MatchAny(cluster+"/"+env, s.Config.Protected)
}

// unprotected is the classification of a change to an environment Clearance does not protect.
func unprotected(req ChangeRequest, pol Policy) Classification {
	where := req.Cluster + "/" + req.Env
	return Classification{0, []Reason{{where, "unprotected", 0}}, "clear", nil,
		fmt.Sprintf("tier 0: cleared (%s is not a protected environment)", where), nil, pol}
}
