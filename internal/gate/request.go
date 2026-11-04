package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/pycompat"
)

// ObjectChange is one Kubernetes object the change touches, as the verifier describes it.
type ObjectChange struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Namespace  string   `json:"namespace"`
	Name       string   `json:"name"`
	Op         string   `json:"op"`     // added | changed | removed
	Fields     []string `json:"fields"` // JSON pointers of the fields that changed; empty = the whole object
	Images     []string `json:"images"`
	Digest     string   `json:"digest"`
}

// Subject is "Kind ns/name" (or "Kind name").
func (o ObjectChange) Subject() string {
	if o.Namespace != "" {
		return o.Kind + " " + o.Namespace + "/" + o.Name
	}
	return o.Kind + " " + o.Name
}

// Checks is what each check says now (ci, provenance, render, admission). JSON output is in key order; gate.py
// kept the order the verifier sent until the row went through Postgres jsonb, which reorders it anyway.
type Checks = map[string]string

// ChangeRequest is what the verifier registers (gate.ChangeRequest).
type ChangeRequest struct {
	App, Env, Cluster, Repo string
	PR                      int64
	Head, Base              string
	Proposer, ProposerKind  string
	Owner                   string // the app's owner group; "" = the core looks it up
	Protected               bool
	TreeDigest              string
	Paths                   []string
	LinesChanged            int64
	Objects                 []ObjectChange
	Checks                  Checks
	Policy                  map[string]any // the repo's clearance.yaml at head, if any (nil = none)
	Agent                   *string
	// Definition is an agent definition's release: {name, path, old, new}; old nil = a new agent, new nil = removed.
	Definition map[string]any
	// Subject is a saved Terraform plan (kind terraform-plan); nil for a manifest tree or a definition release,
	// which treeDigest and objects (or definition) describe.
	Subject *Subject
}

// Kind is the subject's kind: terraform-plan, definition or manifest-tree.
func (r ChangeRequest) Kind() string {
	switch {
	case r.Subject != nil:
		return r.Subject.Kind
	case r.Definition != nil:
		return KindDefinition
	}
	return KindManifestTree
}

// ID is "ch-" + the first 16 hex of sha256("repo#pr@head").
func (r ChangeRequest) ID() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s#%d@%s", r.Repo, r.PR, r.Head)))
	return "ch-" + hex.EncodeToString(h[:])[:16]
}

var requestKeys = setOf("app", "env", "cluster", "repo", "pr", "head", "base", "proposer", "proposerKind", "owner",
	"protected", "treeDigest", "paths", "linesChanged", "objects", "checks", "policy", "agent", "definition", "subject")
var objectKeys = setOf("apiVersion", "kind", "namespace", "name", "op", "fields", "images", "digest")
var definitionKeys = setOf("name", "path", "old", "new")

func setOf(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func unknownKey(m map[string]any, allowed map[string]bool) string {
	var unknown []string
	for k := range m {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return ""
	}
	sort.Strings(unknown)
	return unknown[0]
}

// ParseRequest is ChangeRequest.from_dict, with one deliberate tightening: an unknown field is refused (strict
// decoding), where gate.py ignored it. A terraform-plan subject (G-TF-1) needs no cluster and no treeDigest (the
// change's tree digest is the plan's digest; a treeDigest that is not it is refused), and has no objects or
// definition. schemas/change-request.schema.json is the same shape.
func ParseRequest(v any) (ChangeRequest, error) {
	d, ok := v.(map[string]any)
	if !ok {
		return ChangeRequest{}, bad("the body is a JSON object")
	}
	if k := unknownKey(d, requestKeys); k != "" {
		return ChangeRequest{}, bad("unknown field %s", pycompat.Repr(k))
	}
	var plan *Subject
	if v := d["subject"]; v != nil {
		p, err := parsePlanSubject(v)
		if err != nil {
			return ChangeRequest{}, err
		}
		plan = p
	}
	var err error
	s := func(k string, rx interface{ MatchString(string) bool }, required bool, def string) string {
		if err != nil {
			return ""
		}
		val, present := d[k]
		if !present {
			val = def
		}
		if (val == nil || val == "") && !required {
			return def
		}
		str, isStr := val.(string)
		if !isStr || str == "" || (rx != nil && !rx.MatchString(str)) {
			err = bad("%s is missing or malformed", k)
			return ""
		}
		return str
	}
	r := ChangeRequest{Subject: plan}
	r.App, r.Env, r.Cluster = s("app", nameRx, true, ""), s("env", nameRx, true, ""), s("cluster", nameRx, plan == nil, "")
	r.Repo, r.Head = strings.ToLower(s("repo", repoRx, true, "")), s("head", shaRx, true, "")
	r.Base = s("base", shaRx, false, "")
	if err != nil {
		return r, err
	}
	pr, isInt := pycompat.AsInt(d["pr"])
	if !isInt || pr < 0 {
		return r, bad("pr is a non-negative integer (0: no pull request)")
	}
	r.PR = pr
	r.Proposer = s("proposer", principalRx, true, "")
	r.ProposerKind = s("proposerKind", nil, false, "person")
	if err != nil {
		return r, err
	}
	if !slices.Contains(ProposerKinds, r.ProposerKind) {
		return r, bad("proposerKind is person, agent or unknown")
	}
	r.Owner = s("owner", groupRx, false, "")
	if err != nil {
		return r, err
	}
	r.Protected = true
	if v, present := d["protected"]; present {
		b, isBool := v.(bool)
		if !isBool {
			return r, bad("protected is a boolean")
		}
		r.Protected = b
	}
	r.TreeDigest = s("treeDigest", nil, plan == nil, "")
	if err != nil {
		return r, err
	}
	if plan != nil {
		if r.TreeDigest != "" && bareHex(r.TreeDigest) != plan.PlanDigest {
			return r, bad("treeDigest is the plan's digest (subject.planDigest) or absent")
		}
		r.TreeDigest = plan.PlanDigest
	}
	if !treeRx.MatchString(r.TreeDigest) {
		return r, bad("treeDigest is a sha256")
	}
	paths, okp := listOfStrings(d, "paths", func(s string) bool { return s != "" })
	if !okp || len(paths) > MaxPaths {
		return r, bad("paths is a list of at most %d strings", MaxPaths)
	}
	r.Paths = paths
	if v, present := d["linesChanged"]; present {
		n, isInt := pycompat.AsInt(v)
		if !isInt || n < 0 {
			return r, bad("linesChanged is a non-negative integer")
		}
		r.LinesChanged = n
	}
	rawObjects := []any{}
	if v, present := d["objects"]; present {
		l, isList := v.([]any)
		if !isList {
			return r, bad("objects is a list of at most %d", MaxObjects)
		}
		rawObjects = l
	}
	if len(rawObjects) > MaxObjects {
		return r, bad("objects is a list of at most %d", MaxObjects)
	}
	r.Objects = []ObjectChange{}
	for _, raw := range rawObjects {
		o, isMap := raw.(map[string]any)
		if !isMap {
			return r, bad("objects[] are objects")
		}
		if k := unknownKey(o, objectKeys); k != "" {
			return r, bad("objects[] has an unknown field %s", pycompat.Repr(k))
		}
		op := any("changed")
		if v, present := o["op"]; present {
			op = v
		}
		opS, _ := op.(string)
		if !slices.Contains(ops, opS) {
			return r, bad("objects[].op is added, changed or removed")
		}
		fields, okf := listOfStrings(o, "fields", func(s string) bool { return strings.HasPrefix(s, "/") })
		if !okf || len(fields) > MaxFields {
			return r, bad("objects[].fields is a list of at most %d JSON pointers", MaxFields)
		}
		images, oki := listOfStrings(o, "images", func(string) bool { return true })
		if !oki {
			return r, bad("objects[].images is a list of strings")
		}
		for _, k := range []string{"apiVersion", "kind", "name"} {
			if str, isStr := o[k].(string); !isStr || str == "" {
				return r, bad("objects[].%s is required", k)
			}
		}
		ns := ""
		if v, present := o["namespace"]; present {
			str, isStr := v.(string)
			if !isStr {
				return r, bad("objects[].namespace is a string")
			}
			ns = str
		}
		digest := ""
		if v, present := o["digest"]; present {
			str, isStr := v.(string)
			if !isStr {
				return r, bad("objects[].digest is a string")
			}
			digest = str
		}
		r.Objects = append(r.Objects, ObjectChange{o["apiVersion"].(string), o["kind"].(string), ns, o["name"].(string), opS, fields, images, digest})
	}
	r.Checks = Checks{}
	if v, present := d["checks"]; present {
		m, isMap := v.(map[string]any)
		if !isMap {
			return r, bad("checks is an object of strings")
		}
		for k, x := range m {
			str, isStr := x.(string)
			if !isStr {
				return r, bad("checks is an object of strings")
			}
			r.Checks[k] = str
		}
	}
	if v := d["policy"]; v != nil {
		m, isMap := v.(map[string]any)
		if !isMap {
			return r, bad("policy (clearance.yaml) is an object")
		}
		r.Policy = m
	}
	if v := d["agent"]; v != nil {
		str, isStr := v.(string)
		if !isStr || !nameRx.MatchString(str) {
			return r, bad("agent is an agent name")
		}
		r.Agent = &str
	}
	if v := d["definition"]; v != nil {
		m, isMap := v.(map[string]any)
		name, isStr := m["name"].(string)
		if !isMap || !isStr || !nameRx.MatchString(name) {
			return r, bad("definition is {name, path, old, new}")
		}
		if k := unknownKey(m, definitionKeys); k != "" {
			return r, bad("definition has an unknown field %s", pycompat.Repr(k))
		}
		for _, k := range []string{"old", "new"} {
			if x := m[k]; x != nil {
				if _, isMap := x.(map[string]any); !isMap {
					return r, bad("definition.%s is the definition document or null", k)
				}
			}
		}
		if m["old"] == nil && m["new"] == nil {
			return r, bad("definition needs old or new")
		}
		r.Definition = m
	}
	if plan != nil && (len(r.Objects) > 0 || r.Definition != nil) {
		return r, bad("a terraform-plan change lists its resources in subject.resources, not objects or definition")
	}
	return r, nil
}

// listOfStrings reads an optional list of strings (default empty); ok is false when it is not one, or an item
// fails want.
func listOfStrings(d map[string]any, k string, want func(string) bool) ([]string, bool) {
	v, present := d[k]
	if !present {
		return []string{}, true
	}
	l, isList := v.([]any)
	if !isList {
		return nil, false
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, isStr := x.(string)
		if !isStr || !want(s) {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}
