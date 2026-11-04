package gate

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/jfillman/clearance/internal/pycompat"
)

// Subject kinds: what a change binds to (the evidence record's subject.kind, schemas/evidence.schema.json).
const (
	KindManifestTree  = "manifest-tree"
	KindTerraformPlan = "terraform-plan"
	KindDefinition    = "definition"
)

// FlagUnboundTree marks a manifest-tree (or definition) change registered with a placeholder digest: it binds to its
// commit only (docs/gate.md, "The manifest-tree digest").
const FlagUnboundTree = "unbound-tree"

// MaxResources is how many resource changes a terraform-plan subject may list (the gate's MaxObjects).
const MaxResources = MaxObjects

// emptyDigest is sha256 of nothing: the tree of an empty render.
const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Workspace is a Terraform workspace: the backend type (s3, gcs, azurerm, remote, cloud, ...), the state key (for
// HCP Terraform, organization/workspace) and the workspace name ("default" unless `terraform workspace` chose one).
type Workspace struct {
	Backend string `json:"backend"`
	Key     string `json:"key"`
	Name    string `json:"name"`
}

// Ref is "backend:key#name", the workspace's one-line name.
func (w Workspace) Ref() string { return w.Backend + ":" + w.Key + "#" + w.Name }

// Versions are what made the plan: Terraform's version and each provider's (source address to version).
type Versions struct {
	Terraform string            `json:"terraform"`
	Providers map[string]string `json:"providers"`
}

// PlanSummary is the plan's counts and the addresses it destroys. The core checks it against resources.
type PlanSummary struct {
	Create             int64    `json:"create"`
	Update             int64    `json:"update"`
	Replace            int64    `json:"replace"`
	Destroy            int64    `json:"destroy"`
	DestroyedAddresses []string `json:"destroyedAddresses"`
}

// Resource is one resource change in the plan (terraform show -json's resource_changes[]): its address and type,
// the actions, the JSON pointers of the attributes an update changes (names only; never a value) and Terraform's
// action_reason (replace_by_request is a -replace).
type Resource struct {
	Address      string   `json:"address"`
	Type         string   `json:"type"`
	Actions      []string `json:"actions"`
	Fields       []string `json:"fields"`
	ActionReason string   `json:"actionReason,omitempty"`
}

// Changes is whether the resource changes anything (not a no-op or a data source read).
func (r Resource) Changes() bool {
	return !slices.Equal(r.Actions, []string{"no-op"}) && !slices.Equal(r.Actions, []string{"read"})
}

func (r Resource) action() string {
	switch {
	case len(r.Actions) == 2:
		return "replace"
	case slices.Equal(r.Actions, []string{"delete"}):
		return "destroy"
	}
	return r.Actions[0]
}

// Subject is what a change binds to: the rendered manifest tree (kind manifest-tree, from treeDigest and objects),
// an agent definition's release (definition, named for the agent), or a saved Terraform plan (terraform-plan, the
// request's subject).
// Digests are the evidence record's subject digests: sha256 (the tree, the definition or the saved plan file),
// gitCommit (the head) and, for a plan, planJson (the redacted plan JSON) and variableSet (the variable-set hash).
// The record never holds a variable's value.
type Subject struct {
	Kind              string            `json:"kind"`
	Name              string            `json:"name,omitempty"`
	Digests           map[string]string `json:"digests"`
	Flags             []string          `json:"flags,omitempty"`
	PlanDigest        string            `json:"planDigest,omitempty"`
	PlanJSONDigest    string            `json:"planJsonDigest,omitempty"`
	Workspace         *Workspace        `json:"workspace,omitempty"`
	Versions          *Versions         `json:"versions,omitempty"`
	Summary           *PlanSummary      `json:"summary,omitempty"`
	Targeted          *bool             `json:"targeted,omitempty"`
	VariableSetDigest string            `json:"variableSetDigest,omitempty"`
	Resources         []Resource        `json:"resources,omitempty"`
}

// Unbound says whether a digest is a placeholder rather than a digest of anything: 64 copies of one hex digit (the
// all-zero tree hangar-dev saw on 2026-11-01, seq 402 to 405) or sha256 of nothing (an empty render).
func Unbound(digest string) bool {
	d := bareHex(digest)
	return d == emptyDigest || (len(d) == 64 && strings.Count(d, d[:1]) == 64)
}

func bareHex(d string) string { return strings.TrimPrefix(d, "sha256:") }

var (
	backendRx      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,39}\z`)
	workspaceRx    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,89}\z`)
	resourceTypeRx = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,127}\z`)
	actionReasonRx = regexp.MustCompile(`^[a-z_]{1,64}\z`)
	versionRx      = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}([-+][0-9A-Za-z.+-]{1,64})?\z`)
	providerRx     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\z`)
)

var subjectKeys = setOf("kind", "planDigest", "planJsonDigest", "workspace", "versions", "summary", "targeted",
	"variableSetDigest", "resources")
var workspaceKeys = setOf("backend", "key", "name")
var versionsKeys = setOf("terraform", "providers")
var summaryKeys = setOf("create", "update", "replace", "destroy", "destroyedAddresses")
var resourceKeys = setOf("address", "type", "actions", "fields", "actionReason")

// planActions are the action lists Terraform writes (plans.Action as JSON).
var planActions = [][]string{{"no-op"}, {"create"}, {"read"}, {"update"}, {"delete"}, {"delete", "create"}, {"create", "delete"}}

// printable: 1 to max characters, none a control character.
func printable(s string, max int) bool {
	if s == "" || pycompat.Len(s) > max {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

// parsePlanSubject is the request's subject for a saved Terraform plan. Every digest is a sha256 (bare hex or
// "sha256:"); a placeholder digest is refused (DG-UNBOUND). The summary must be what the resources say.
func parsePlanSubject(v any) (*Subject, error) {
	d, ok := v.(map[string]any)
	if !ok {
		return nil, bad("subject is an object")
	}
	if kind, _ := d["kind"].(string); kind != KindTerraformPlan {
		return nil, bad("subject.kind is terraform-plan (a manifest tree is described by treeDigest and objects)")
	}
	if k := unknownKey(d, subjectKeys); k != "" {
		return nil, bad("subject has an unknown field %s", pycompat.Repr(k))
	}
	s := &Subject{Kind: KindTerraformPlan}
	for _, f := range []struct {
		key string
		dst *string
	}{{"planDigest", &s.PlanDigest}, {"planJsonDigest", &s.PlanJSONDigest}, {"variableSetDigest", &s.VariableSetDigest}} {
		str, isStr := d[f.key].(string)
		if !isStr || !treeRx.MatchString(str) {
			return nil, bad("subject.%s is a sha256", f.key)
		}
		if Unbound(str) {
			return nil, gerr("DG-UNBOUND", fmt.Sprintf("subject.%s is a placeholder, not a digest of the plan", f.key),
				"Send the sha256 of the saved plan file, of the redacted plan JSON and of the variable set (docs/gate.md, The terraform-plan subject).", 400)
		}
		*f.dst = bareHex(str)
	}
	ws, isMap := d["workspace"].(map[string]any)
	if !isMap || unknownKey(ws, workspaceKeys) != "" {
		return nil, bad("subject.workspace is {backend, key, name}")
	}
	backend, _ := ws["backend"].(string)
	key, _ := ws["key"].(string)
	name, _ := ws["name"].(string)
	if !backendRx.MatchString(backend) || !printable(key, 1024) || !workspaceRx.MatchString(name) {
		return nil, bad("subject.workspace is {backend, key, name}: a backend type, the state key and the workspace name")
	}
	s.Workspace = &Workspace{backend, key, name}
	vs, isMap := d["versions"].(map[string]any)
	if !isMap || unknownKey(vs, versionsKeys) != "" {
		return nil, bad("subject.versions is {terraform, providers}")
	}
	tf, _ := vs["terraform"].(string)
	if !versionRx.MatchString(tf) {
		return nil, bad("subject.versions.terraform is a version")
	}
	s.Versions = &Versions{Terraform: tf, Providers: map[string]string{}}
	if p, present := vs["providers"]; present && p != nil {
		pm, isMap := p.(map[string]any)
		if !isMap || len(pm) > 200 {
			return nil, bad("subject.versions.providers maps at most 200 provider sources to versions")
		}
		for src, ver := range pm {
			vstr, isStr := ver.(string)
			if !providerRx.MatchString(src) || !isStr || !versionRx.MatchString(vstr) {
				return nil, bad("subject.versions.providers maps provider sources to versions")
			}
			s.Versions.Providers[src] = vstr
		}
	}
	targeted := false
	if t, present := d["targeted"]; present {
		b, isBool := t.(bool)
		if !isBool {
			return nil, bad("subject.targeted is a boolean (the plan was made with -target)")
		}
		targeted = b
	}
	s.Targeted = &targeted
	rawRes, isList := d["resources"].([]any)
	if !isList || len(rawRes) > MaxResources {
		return nil, bad("subject.resources is a list of at most %d resource changes", MaxResources)
	}
	s.Resources = []Resource{}
	seen := map[string]bool{}
	for _, raw := range rawRes {
		r, err := parseResource(raw)
		if err != nil {
			return nil, err
		}
		if seen[r.Address] {
			return nil, bad("subject.resources lists %s twice", pycompat.Repr(r.Address))
		}
		seen[r.Address] = true
		s.Resources = append(s.Resources, r)
	}
	sum, err := parseSummary(d["summary"])
	if err != nil {
		return nil, err
	}
	s.Summary = sum
	if err := checkSummary(*sum, s.Resources); err != nil {
		return nil, err
	}
	return s, nil
}

func parseResource(raw any) (Resource, error) {
	o, isMap := raw.(map[string]any)
	if !isMap {
		return Resource{}, bad("subject.resources[] are objects")
	}
	if k := unknownKey(o, resourceKeys); k != "" {
		return Resource{}, bad("subject.resources[] has an unknown field %s", pycompat.Repr(k))
	}
	addr, _ := o["address"].(string)
	typ, _ := o["type"].(string)
	if !printable(addr, 1024) || !resourceTypeRx.MatchString(typ) {
		return Resource{}, bad("subject.resources[] needs an address and a resource type")
	}
	// The address names its type (aws_iam_role.ci, module.net.aws_security_group.web["a"]): a type that is not in
	// the address is a claim the core will not tier on.
	if !strings.HasPrefix(addr, typ+".") && !strings.Contains(addr, "."+typ+".") {
		return Resource{}, bad("subject.resources[]: %s is not a %s", pycompat.Repr(addr), typ)
	}
	acts, ok := listOfStrings(o, "actions", func(string) bool { return true })
	if !ok || !slices.ContainsFunc(planActions, func(a []string) bool { return slices.Equal(a, acts) }) {
		return Resource{}, bad("subject.resources[].actions is one of Terraform's action lists (no-op, create, read, update, delete, delete+create, create+delete)")
	}
	fields, ok := listOfStrings(o, "fields", func(s string) bool { return strings.HasPrefix(s, "/") && printable(s, 1024) })
	if !ok || len(fields) > MaxFields {
		return Resource{}, bad("subject.resources[].fields is a list of at most %d JSON pointers (attribute names, never values)", MaxFields)
	}
	r := Resource{Address: addr, Type: typ, Actions: acts, Fields: fields}
	if v, present := o["actionReason"]; present && v != nil && v != "" {
		str, isStr := v.(string)
		if !isStr || !actionReasonRx.MatchString(str) {
			return Resource{}, bad("subject.resources[].actionReason is Terraform's action_reason")
		}
		r.ActionReason = str
	}
	return r, nil
}

func parseSummary(v any) (*PlanSummary, error) {
	m, isMap := v.(map[string]any)
	if !isMap || unknownKey(m, summaryKeys) != "" {
		return nil, bad("subject.summary is {create, update, replace, destroy, destroyedAddresses}")
	}
	s := &PlanSummary{}
	for _, f := range []struct {
		key string
		dst *int64
	}{{"create", &s.Create}, {"update", &s.Update}, {"replace", &s.Replace}, {"destroy", &s.Destroy}} {
		n, isInt := pycompat.AsInt(m[f.key])
		if !isInt || n < 0 {
			return nil, bad("subject.summary.%s is a non-negative integer", f.key)
		}
		*f.dst = n
	}
	addrs, ok := listOfStrings(m, "destroyedAddresses", func(s string) bool { return printable(s, 1024) })
	if !ok || len(addrs) > MaxResources {
		return nil, bad("subject.summary.destroyedAddresses is a list of resource addresses")
	}
	s.DestroyedAddresses = addrs
	return s, nil
}

// checkSummary: the counts and the destroyed addresses are exactly what the resources say, so a verifier cannot
// describe a destroy in the summary and leave it out of what the core tiers (or the other way round).
func checkSummary(s PlanSummary, rs []Resource) error {
	var n PlanSummary
	var destroyed []string
	for _, r := range rs {
		if !r.Changes() {
			continue
		}
		switch r.action() {
		case "create":
			n.Create++
		case "update":
			n.Update++
		case "replace":
			n.Replace++
		case "destroy":
			n.Destroy++
			destroyed = append(destroyed, r.Address)
		}
	}
	if n.Create != s.Create || n.Update != s.Update || n.Replace != s.Replace || n.Destroy != s.Destroy {
		return bad("subject.summary (%d create, %d update, %d replace, %d destroy) is not what subject.resources says (%d, %d, %d, %d)",
			s.Create, s.Update, s.Replace, s.Destroy, n.Create, n.Update, n.Replace, n.Destroy)
	}
	got := append([]string(nil), s.DestroyedAddresses...)
	sort.Strings(got)
	sort.Strings(destroyed)
	if !slices.Equal(got, destroyed) {
		return bad("subject.summary.destroyedAddresses is not the resources subject.resources destroys")
	}
	return nil
}

// subjectFor is the subject a change records: the request's plan, or its tree (or definition) and the commit. A
// placeholder tree is left out of the digests and flagged, so the subject binds to the commit only.
func subjectFor(req ChangeRequest) *Subject {
	if req.Subject != nil {
		s := *req.Subject
		s.Digests = map[string]string{"sha256": s.PlanDigest, "planJson": s.PlanJSONDigest, "variableSet": s.VariableSetDigest,
			"gitCommit": req.Head}
		return &s
	}
	kind := KindManifestTree
	if req.Definition != nil {
		kind = KindDefinition
	}
	s := &Subject{Kind: kind, Digests: map[string]string{"gitCommit": req.Head}}
	if kind == KindDefinition {
		s.Name, _ = req.Definition["name"].(string)
	}
	if Unbound(req.TreeDigest) {
		s.Flags = []string{FlagUnboundTree}
	} else {
		s.Digests["sha256"] = bareHex(req.TreeDigest)
	}
	return s
}

// recordSubject is the evidence record's subject for a change: {kind, name, digests}. Name is the agent's for a
// definition release, else app/env.
func (c *Change) recordSubject() any {
	s := c.Subject
	if s == nil {
		return nil
	}
	d := map[string]any{}
	for k, v := range s.Digests {
		d[k] = v
	}
	name := c.App + "/" + c.Env
	if s.Name != "" {
		name = s.Name
	}
	return map[string]any{"kind": s.Kind, "name": name, "digests": d}
}

// legacySubject is the subject of a change stored before subjects were (v0.30.0 and earlier): its tree and commit.
func (c *Change) legacySubject() *Subject {
	s := &Subject{Kind: KindManifestTree, Digests: map[string]string{}}
	if shaRx.MatchString(c.Head) {
		s.Digests["gitCommit"] = c.Head
	}
	if Unbound(c.TreeDigest) || !treeRx.MatchString(c.TreeDigest) {
		s.Flags = []string{FlagUnboundTree}
	} else {
		s.Digests["sha256"] = bareHex(c.TreeDigest)
	}
	return s
}
