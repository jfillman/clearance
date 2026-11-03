// Package deftest is for tests only: a stand-in for profile.parse (the agent-definition schema's checks the ported
// tests exercise, not the whole JSON schema) and the core plus Hangar read-tool registry the Python tests used.
// Production wiring passes R-1a's real parser and the deployment's registry.
package deftest

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/jfillman/clearance/internal/definitions"
	"github.com/jfillman/clearance/internal/pycompat"
)

var (
	nameRx  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,40}$`)
	ownerRx = regexp.MustCompile(`^group:[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9._-]*$`)
	saRx    = regexp.MustCompile(`^[a-z0-9-]+/[a-z0-9-]+$`)
	imageRx = regexp.MustCompile(`^[^\s@]+@sha256:[a-f0-9]{64}$`)
	kinds   = map[string]bool{"task": true, "session": true, "service": true, "scheduled": true, "event": true, "team": true}
	ceil    = map[string]int{"T0": 0, "T1": 1, "T2": 2}
	limits  = []string{"ttlMinutes", "toolCalls", "githubCalls", "openPrs", "modelTokens", "children"}
)

// BaselineDenyPaths is profile.BASELINE_DENY_PATHS.
var BaselineDenyPaths = []string{".tekton/**", "**/.tekton/**", "CODEOWNERS", "**/CODEOWNERS", ".github/**",
	"**/appproject*.yaml", "**/AppProject*.yaml", "release.yaml", "**/release.yaml", "*.release.yaml", "**/*.release.yaml"}

func strs(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("is not of type 'array'")
	}
	var out []string
	for _, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, errors.New("is not of type 'string'")
		}
		out = append(out, s)
	}
	return out, nil
}

// Parse is a stand-in for profile.parse.
func Parse(doc map[string]any) (definitions.Definition, error) {
	name, _ := doc["name"].(string)
	fail := func(path, msg string) (definitions.Definition, error) {
		if name == "" {
			name = "?"
		}
		return definitions.Definition{}, fmt.Errorf("%s: %s: %s", name, path, msg)
	}
	for _, k := range []string{"name", "description", "kind", "identity", "profile"} {
		if _, ok := doc[k]; !ok {
			return fail("<root>", pycompat.Repr(k)+" is a required property")
		}
	}
	if !nameRx.MatchString(name) {
		return fail("name", "does not match")
	}
	d := definitions.Definition{Name: name, Raw: doc}
	d.Description, _ = doc["description"].(string)
	d.Kind, _ = doc["kind"].(string)
	if !kinds[d.Kind] {
		return fail("kind", "is not one of the kinds")
	}
	if o, ok := doc["owner"]; ok {
		s, _ := o.(string)
		if !ownerRx.MatchString(s) {
			return fail("owner", "does not match")
		}
		d.Owner, d.HasOwner = s, true
	}
	id, _ := doc["identity"].(map[string]any)
	d.IdentityType, _ = id["type"].(string)
	if d.IdentityType != "workload" && d.IdentityType != "delegated" {
		return fail("identity/type", "is not one of ['delegated', 'workload']")
	}
	if sa, ok := id["serviceAccount"].(string); ok {
		if !saRx.MatchString(sa) {
			return fail("identity/serviceAccount", "does not match")
		}
		d.ServiceAccount = sa
	} else if d.IdentityType == "workload" {
		return fail("identity", "'serviceAccount' is a required property")
	}
	p, _ := doc["profile"].(map[string]any)
	tc, _ := p["tierCeiling"].(string)
	c, ok := ceil[tc]
	if !ok {
		return fail("profile/tierCeiling", pycompat.Repr(p["tierCeiling"])+" is not one of ['T0', 'T1', 'T2']")
	}
	d.TierCeiling = c
	tools, err := strs(p["tools"])
	if err != nil || p["tools"] == nil {
		return fail("profile/tools", "is required")
	}
	d.Tools = tools
	for _, t := range tools {
		if t == "human.request" {
			d.Tools = append(d.Tools, "human.request.get")
		}
	}
	lim, ok := p["limits"].(map[string]any)
	if !ok {
		return fail("profile", "'limits' is a required property")
	}
	for _, k := range limits {
		if _, ok := pycompat.AsInt(lim[k]); !ok {
			return fail("profile/limits/"+k, "is not of type 'integer'")
		}
	}
	if d.Models, err = strs(p["models"]); err != nil {
		return fail("profile/models", err.Error())
	}
	repos, _ := p["repos"].(map[string]any)
	if d.ReposAllow, err = strs(repos["allow"]); err != nil {
		return fail("profile/repos/allow", err.Error())
	}
	extra, err := strs(repos["denyPaths"])
	if err != nil {
		return fail("profile/repos/denyPaths", err.Error())
	}
	d.DenyPaths = append(append([]string(nil), BaselineDenyPaths...), extra...)
	if rt, ok := doc["runtime"].(map[string]any); ok {
		if img, ok := rt["image"].(string); ok {
			if !imageRx.MatchString(img) {
				return fail("runtime/image", pycompat.Repr(img)+" does not match")
			}
			d.Image = img
		}
	}
	return d, nil
}
