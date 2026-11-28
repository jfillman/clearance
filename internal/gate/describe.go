package gate

import (
	"slices"
	"strings"

	"github.com/jfillman/clearance/internal/describe"
	"github.com/jfillman/clearance/internal/kinds"
)

// SDK-1: the built-in kinds on the generic change description (internal/describe). A verifier still registers a
// manifest-tree or terraform-plan change in the request it always sent (schemas/change-request.schema.json); the
// core maps the request onto a description, and tiers the description's items. The mapping is lossless for what
// tiering reads, and the roots are the digests the request carried (tree/1 and plan/1), so tiers, reasons and digests
// are what they were (testdata/golden/subjects.jsonl replays that). An agent definition's release is not a subject
// kind on the description: it is tiered by review.Classify as before.

// KindVersion is the version of each built-in kind, as its embedded kind (internal/kinds builtin/) declares it.
const KindVersion = 1

// Describe is the request's change description: a manifest-tree's or a terraform-plan's. A definition release has
// none (nil, nil).
func Describe(req ChangeRequest) (*describe.Description, error) {
	d := &describe.Description{
		Target:      describe.Target{Scope: req.Cluster, Environment: req.Env, App: req.App},
		Source:      describe.Source{Repo: req.Repo, Commit: req.Head, Base: req.Base, PR: req.PR},
		DescribedBy: describe.DescribedBy{Provider: describe.CoreProvider},
	}
	switch req.Kind() {
	case KindTerraformPlan:
		s := req.Subject
		d.Subject = describe.Subject{Kind: kinds.TerraformPlan, Version: KindVersion, RootFn: describe.RootPlan1,
			Root: s.PlanDigest, Facts: planFacts(s)}
		d.Items = planItems(s.Resources)
	case KindManifestTree:
		d.Subject = describe.Subject{Kind: kinds.ManifestTree, Version: KindVersion, RootFn: describe.RootTree1,
			Root: bareHex(req.TreeDigest)}
		d.Items = make([]describe.Item, 0, len(req.Objects))
		for _, o := range req.Objects {
			if it, ok := objectItem(o); ok {
				d.Items = append(d.Items, it)
			}
		}
	default:
		return nil, nil
	}
	return d, nil
}

// -- manifest-tree ------------------------------------------------------------------------------------------------

var objectOps = map[string]string{"added": describe.OpCreate, "changed": describe.OpUpdate, "removed": describe.OpDelete}
var itemObjectOps = map[string]string{describe.OpCreate: "added", describe.OpUpdate: "changed", describe.OpDelete: "removed"}

// pointerEscape is a JSON pointer token's escaping (RFC 6901): "~" as "~0", "/" as "~1". A Kubernetes kind, namespace
// or name never holds either, so the escape is the identity for every real object; it keeps the mapping lossless
// for a malformed one.
var (
	pointerEscape   = strings.NewReplacer("~", "~0", "/", "~1")
	pointerUnescape = strings.NewReplacer("~1", "/", "~0", "~")
)

// ObjectItemType is an object's item type: "apiVersion/Kind" (apps/v1/Deployment, v1/Secret).
func ObjectItemType(o ObjectChange) string { return o.APIVersion + "/" + pointerEscape.Replace(o.Kind) }

// ObjectItemID is an object's item id: "namespace/name", or the name of a cluster-scoped object.
func ObjectItemID(o ObjectChange) string {
	if o.Namespace == "" {
		return pointerEscape.Replace(o.Name)
	}
	return pointerEscape.Replace(o.Namespace) + "/" + pointerEscape.Replace(o.Name)
}

// objectItem is the item of an object the change touches; an unchanged object (in the tree, not the change) is none.
func objectItem(o ObjectChange) (describe.Item, bool) {
	op, changes := objectOps[o.Op]
	if !changes {
		return describe.Item{}, false
	}
	it := describe.Item{Type: ObjectItemType(o), ID: ObjectItemID(o), Op: op, Fields: slices.Clone(o.Fields)}
	attrs := map[string]any{}
	if len(o.Images) > 0 {
		attrs["images"] = slices.Clone(o.Images)
	}
	if describe.IsSHA256(o.Digest) {
		it.Hash = o.Digest
	} else if o.Digest != "" {
		attrs["digest"] = o.Digest
	}
	if len(attrs) > 0 {
		it.Attrs = attrs
	}
	return it, true
}

// itemObject is the object an item describes: objectItem's inverse.
func itemObject(it describe.Item) ObjectChange {
	i := strings.LastIndexByte(it.Type, '/')
	o := ObjectChange{APIVersion: it.Type[:max(i, 0)], Kind: pointerUnescape.Replace(it.Type[i+1:]), Op: itemObjectOps[it.Op],
		Fields: append([]string{}, it.Fields...), Images: strings1(it.Attrs["images"]), Digest: it.Hash}
	if ns, name, namespaced := strings.Cut(it.ID, "/"); namespaced {
		o.Namespace, o.Name = pointerUnescape.Replace(ns), pointerUnescape.Replace(name)
	} else {
		o.Name = pointerUnescape.Replace(it.ID)
	}
	if d, ok := it.Attrs["digest"].(string); ok && o.Digest == "" {
		o.Digest = d
	}
	return o
}

// strings1 is a list of strings from an attr ([]string from the core's mapping, []any from a decoded description).
func strings1(v any) []string {
	out := []string{}
	switch x := v.(type) {
	case []string:
		out = append(out, x...)
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// -- terraform-plan -----------------------------------------------------------------------------------------------

// planFacts are a plan's change-level facts: its workspace and versions, whether -target was used, and the digests of
// the redacted plan JSON and of the variable set.
func planFacts(s *Subject) map[string]any {
	f := map[string]any{"planJsonDigest": s.PlanJSONDigest, "variableSetDigest": s.VariableSetDigest}
	if s.Workspace != nil {
		f["workspace"] = map[string]any{"backend": s.Workspace.Backend, "key": s.Workspace.Key, "name": s.Workspace.Name}
	}
	if s.Versions != nil {
		providers := map[string]any{}
		for k, v := range s.Versions.Providers {
			providers[k] = v
		}
		f["versions"] = map[string]any{"terraform": s.Versions.Terraform, "providers": providers}
	}
	if s.Targeted != nil {
		f["targeted"] = *s.Targeted
	}
	return f
}

var planOps = map[string]string{"create": describe.OpCreate, "update": describe.OpUpdate, "destroy": describe.OpDelete,
	"replace": describe.OpReplace}

// planItems are the items of the resource changes that change something (a no-op or a read is not an item).
func planItems(rs []Resource) []describe.Item {
	out := make([]describe.Item, 0, len(rs))
	for _, r := range rs {
		if !r.Changes() {
			continue
		}
		attrs := map[string]any{"actions": slices.Clone(r.Actions)}
		if r.ActionReason != "" {
			attrs["actionReason"] = r.ActionReason
		}
		out = append(out, describe.Item{Type: r.Type, ID: r.Address, Op: planOps[r.action()], Fields: slices.Clone(r.Fields), Attrs: attrs})
	}
	return out
}

// itemResource is the resource change an item describes: planItems' inverse.
func itemResource(it describe.Item) Resource {
	r := Resource{Address: it.ID, Type: it.Type, Actions: strings1(it.Attrs["actions"]), Fields: append([]string(nil), it.Fields...)}
	if len(r.Actions) == 0 { // a description from elsewhere names only the op
		r.Actions = map[string][]string{describe.OpCreate: {"create"}, describe.OpUpdate: {"update"},
			describe.OpDelete: {"delete"}, describe.OpReplace: {"delete", "create"}}[it.Op]
	}
	r.ActionReason, _ = it.Attrs["actionReason"].(string)
	return r
}

// planSummary is the plan's summary, derived from its items: the core never takes the caller's.
func planSummary(items []describe.Item) PlanSummary {
	s := (&describe.Description{Items: items}).Summarize()
	return PlanSummary{Create: s.Create, Update: s.Update, Replace: s.Replace, Destroy: s.Delete, DestroyedAddresses: s.Deleted}
}

// -- replay -------------------------------------------------------------------------------------------------------

// ReplayRequest is the request a stored change was registered with, as far as the change keeps it: what SDK-1's
// replay over an exported chain (TestReplayStoredChanges) re-describes and re-tiers. A change keeps no clearance.yaml
// (only its digest) and no provenance reason, so a change registered with either is not re-tiered by the replay.
func ReplayRequest(c *Change) ChangeRequest {
	r := ChangeRequest{App: c.App, Env: c.Env, Cluster: c.Cluster, Repo: c.Repo, PR: c.PR, Head: c.Head, Base: c.Base,
		Proposer: c.Proposer, ProposerKind: c.ProposerKind, Source: c.Source.clone(), Owner: c.Owner, Protected: c.Protected,
		TreeDigest: c.TreeDigest, Paths: slices.Clone(c.Paths), LinesChanged: c.LinesChanged, Objects: slices.Clone(c.Objects),
		Checks: copyChecks(c.Checks), Admission: copyAdmission(c.Admission), Agent: c.Agent, TaskID: c.TaskID}
	if s := c.Subject; s != nil && s.Kind == KindTerraformPlan {
		cp := *s
		cp.Digests = nil
		r.Subject = &cp
	}
	return r
}
