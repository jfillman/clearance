// Package auditpolicy ships the kube-apiserver audit policy the collector needs, as a template, and holds any audit
// policy to the one rule that must not break: no rule may record a Secret's body.
//
// The policy semantics here are the API server's (k8s.io/apiserver/pkg/audit/policy): the first rule that matches a
// request decides its level; no rule matching is level None. Evaluate is that matcher, small enough to read, and
// Check probes it: a Secret in every namespace the policy names (and one it does not), by every verb and every user
// and group the policy names (and one it does not), must come out None or Metadata. The build runs Check on the
// shipped template (a failing build is the point); `observe-k8s policy check` runs it on a policy from a node; the
// collector's health check runs it on the mirror of the live policy when the pod can read one.
package auditpolicy

import (
	"bytes"
	_ "embed"
	"fmt"
	"slices"
	"sort"
	"strings"
	"text/template"

	"go.yaml.in/yaml/v3"
)

//go:embed audit-policy.yaml.tmpl
var tmplSrc string

// Levels.
const (
	None                 = "None"
	Metadata             = "Metadata"
	LevelRequest         = "Request"
	LevelRequestResponse = "RequestResponse"
)

// Policy is audit.k8s.io/v1 Policy, the parts the matcher reads.
type Policy struct {
	APIVersion        string   `yaml:"apiVersion"`
	Kind              string   `yaml:"kind"`
	OmitStages        []string `yaml:"omitStages"`
	OmitManagedFields bool     `yaml:"omitManagedFields"`
	Rules             []Rule   `yaml:"rules"`
}

// Rule is one PolicyRule.
type Rule struct {
	Level           string          `yaml:"level"`
	Users           []string        `yaml:"users"`
	UserGroups      []string        `yaml:"userGroups"`
	Verbs           []string        `yaml:"verbs"`
	Resources       []GroupResource `yaml:"resources"`
	Namespaces      []string        `yaml:"namespaces"`
	NonResourceURLs []string        `yaml:"nonResourceURLs"`
	OmitStages      []string        `yaml:"omitStages"`
}

// GroupResource is a rule's resources entry: a group ("" is core) and its resources, optionally narrowed by name.
type GroupResource struct {
	Group         string   `yaml:"group"`
	Resources     []string `yaml:"resources"`
	ResourceNames []string `yaml:"resourceNames"`
}

// Parse reads a Policy and refuses one the API server would refuse, or this matcher cannot judge.
func Parse(b []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("audit policy: %w", err)
	}
	if p.Kind != "Policy" || !strings.HasPrefix(p.APIVersion, "audit.k8s.io/") {
		return nil, fmt.Errorf("audit policy: kind %q apiVersion %q: want audit.k8s.io/v1 Policy", p.Kind, p.APIVersion)
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("audit policy: no rules")
	}
	for i, r := range p.Rules {
		if !slices.Contains([]string{None, Metadata, LevelRequest, LevelRequestResponse}, r.Level) {
			return nil, fmt.Errorf("audit policy: rule %d: level %q", i, r.Level)
		}
	}
	return &p, nil
}

// Params are what the template is rendered with.
type Params struct {
	// ProtectedNamespaces are the namespaces whose desired-state writes are recorded with bodies.
	ProtectedNamespaces []string
	// StatusGroups are the API groups whose status writes drop to Metadata ("" is core). Empty: DefaultStatusGroups.
	StatusGroups []string
}

// DefaultStatusGroups are the API groups of the kinds the Hangar clusters run.
var DefaultStatusGroups = []string{"", "apps", "batch", "autoscaling", "networking.k8s.io", "policy", "argoproj.io",
	"apiextensions.k8s.io", "admissionregistration.k8s.io", "cert-manager.io", "gateway.networking.k8s.io", "clearance.hangar.io"}

// Render renders the template and holds the result to Check: a Params that makes a policy recording a Secret's body is
// an error, not a policy.
func Render(p Params) ([]byte, error) {
	if len(p.StatusGroups) == 0 {
		p.StatusGroups = DefaultStatusGroups
	}
	for _, ns := range p.ProtectedNamespaces {
		if ns == "" || strings.ContainsAny(ns, " \t\n\"\\") {
			return nil, fmt.Errorf("audit policy: namespace %q", ns)
		}
	}
	t, err := template.New("audit-policy").Parse(tmplSrc)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, p); err != nil {
		return nil, err
	}
	pol, err := Parse(buf.Bytes())
	if err != nil {
		return nil, err
	}
	if vs := Check(pol); len(vs) > 0 {
		return nil, fmt.Errorf("audit policy: the rendered policy records a Secret body: %s", vs[0])
	}
	return buf.Bytes(), nil
}

// Request is the part of an API request the matcher reads.
type Request struct {
	User, Verb                          string
	Groups                              []string
	APIGroup, Resource, Subresource, Ns string
	Name                                string
	NonResourceURL                      string // set for a request that is not a resource request
}

func (r Request) isResource() bool { return r.NonResourceURL == "" }

// Evaluate is the level the policy gives the request: the first matching rule's, else None.
func (p *Policy) Evaluate(r Request) string {
	for i := range p.Rules {
		if p.Rules[i].matches(r) {
			return p.Rules[i].Level
		}
	}
	return None
}

func (ru *Rule) matches(r Request) bool {
	return ru.matchesUser(r) && ru.matchesVerb(r) && ru.matchesResource(r) && ru.matchesNamespace(r) && ru.matchesNonResource(r)
}

// matchesUser follows the API server: when a rule names users, the user must be one of them; when it names groups,
// one of the user's groups must be one of them; a rule naming both needs both.
func (ru *Rule) matchesUser(r Request) bool {
	if len(ru.Users) > 0 && !slices.Contains(ru.Users, r.User) {
		return false
	}
	if len(ru.UserGroups) > 0 {
		for _, g := range r.Groups {
			if slices.Contains(ru.UserGroups, g) {
				return true
			}
		}
		return false
	}
	return true
}

func (ru *Rule) matchesVerb(r Request) bool {
	return len(ru.Verbs) == 0 || slices.Contains(ru.Verbs, r.Verb)
}

// matchesResource is the API server's: a group entry with no resources matches the whole group (and then
// resourceNames is not consulted); otherwise a resource matches as "*", exactly (resource or resource/subresource),
// as "*/subresource", or as "resource/*" (which also matches the resource itself), narrowed by resourceNames.
func (ru *Rule) matchesResource(r Request) bool {
	if !r.isResource() {
		return len(ru.Resources) == 0
	}
	if len(ru.Resources) == 0 {
		return true
	}
	combined := r.Resource
	if r.Subresource != "" {
		combined += "/" + r.Subresource
	}
	for _, gr := range ru.Resources {
		if gr.Group != r.APIGroup {
			continue
		}
		if len(gr.Resources) == 0 {
			return true
		}
		for _, res := range gr.Resources {
			if len(gr.ResourceNames) > 0 && !slices.Contains(gr.ResourceNames, r.Name) {
				continue
			}
			switch {
			case res == "*", res == combined:
				return true
			case r.Subresource != "" && strings.HasPrefix(res, "*/") && res[2:] == r.Subresource:
				return true
			case strings.HasSuffix(res, "/*") && res[:len(res)-2] == r.Resource:
				return true
			}
		}
	}
	return false
}

func (ru *Rule) matchesNamespace(r Request) bool {
	if len(ru.Namespaces) == 0 {
		return true
	}
	if !r.isResource() {
		return false
	}
	return slices.Contains(ru.Namespaces, r.Ns)
}

func (ru *Rule) matchesNonResource(r Request) bool {
	if r.isResource() {
		return len(ru.NonResourceURLs) == 0
	}
	if len(ru.NonResourceURLs) == 0 {
		return true
	}
	for _, u := range ru.NonResourceURLs {
		if u == r.NonResourceURL || (strings.HasSuffix(u, "*") && strings.HasPrefix(r.NonResourceURL, u[:len(u)-1])) {
			return true
		}
	}
	return false
}

// Verbs a probe tries: every verb the API server audits.
var probeVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "proxy", "connect"}

// credentialResources are resources that carry a credential in their body, besides Secrets themselves: a policy must
// give them Metadata at most too.
var credentialResources = []struct{ Group, Resource, Subresource string }{
	{"", "secrets", ""}, {"", "secrets", "status"}, {"", "secrets", "data"}, {"", "serviceaccounts", "token"},
}

// Check probes the policy for a rule that would record a credential's body (level Request or RequestResponse) for a
// Secret, in any namespace (the ones the policy names, a cluster-scoped request and one it does not name), by any
// verb, user and group (the ones the policy names and one it does not), with any name the policy narrows to. It returns
// one violation per distinct rule at fault; none means the policy never records a Secret body.
func Check(p *Policy) []string {
	users, groups, nss, names := []string{"probe-user", "system:serviceaccount:probe:probe"}, []string{"probe-group", ""},
		[]string{"", "probe-ns"}, []string{"", "probe-name"}
	for _, r := range p.Rules {
		users = append(users, r.Users...)
		groups = append(groups, r.UserGroups...)
		nss = append(nss, r.Namespaces...)
		for _, gr := range r.Resources {
			names = append(names, gr.ResourceNames...)
		}
	}
	for _, s := range [][]string{users, groups, nss, names} {
		sort.Strings(s)
	}
	users, groups, nss, names = slices.Compact(users), slices.Compact(groups), slices.Compact(nss), slices.Compact(names)
	seen := map[int]bool{}
	var out []string
	for _, c := range credentialResources {
		for _, v := range probeVerbs {
			for _, u := range users {
				for _, g := range groups {
					var gs []string
					if g != "" {
						gs = []string{g}
					}
					for _, ns := range nss {
						for _, n := range names {
							req := Request{User: u, Groups: gs, Verb: v, APIGroup: c.Group, Resource: c.Resource,
								Subresource: c.Subresource, Ns: ns, Name: n}
							lvl, idx := p.evaluate(req)
							if lvl == LevelRequest || lvl == LevelRequestResponse {
								if !seen[idx] {
									seen[idx] = true
									out = append(out, fmt.Sprintf("rule %d (%s) records the body of %s: %s %s%s in %q by %q", idx, lvl,
										c.Resource, v, c.Resource, sub(c.Subresource), ns, u))
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

func sub(s string) string {
	if s == "" {
		return ""
	}
	return "/" + s
}

// evaluate is Evaluate with the index of the deciding rule (-1: none matched).
func (p *Policy) evaluate(r Request) (string, int) {
	for i := range p.Rules {
		if p.Rules[i].matches(r) {
			return p.Rules[i].Level, i
		}
	}
	return None, -1
}
