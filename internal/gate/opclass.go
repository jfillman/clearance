package gate

import (
	_ "embed"
	"encoding/json"
	"slices"
	"strings"
)

// The operational class (I-1) says what a change does to the thing it changes, apart from the tier. The tier is the
// customer's policy and varies by tenant; the class is the only axis a cross-tenant comparison may use. A change has
// one or more of the five classes below, or OpClassNone when it changes nothing operational.
//
// The mapping is data (opclass.json, embedded) with a version, like the control mappings: the version is stored in
// every record beside the classes, so a record says which mapping computed them.
const (
	ClassAvailability       = "availability"
	ClassPrivilege          = "privilege"
	ClassDataIntegrity      = "data-integrity"
	ClassSecurityBoundary   = "security-boundary"
	ClassCredentialExposure = "credential-exposure"

	// OpClassNone is the defined result for a change with no operational effect: only release stamps or metadata, no
	// object changed, only non-runtime paths, a plan that changes nothing or only tags, or an agent definition whose
	// authority did not change. It stands alone, never beside another class, so no record is ever left without a class.
	OpClassNone = "none"
)

//go:embed opclass.json
var opclassJSON []byte

type opMapping struct {
	Version string              `json:"version"`
	Classes []string            `json:"classes"`
	Kinds   map[string][]string `json:"kinds"`
	Fields  []struct {
		Contains string   `json:"contains"`
		Classes  []string `json:"classes"`
	} `json:"fields"`
	Paths []struct {
		Glob    string   `json:"glob"`
		Classes []string `json:"classes"`
	} `json:"paths"`
	Terraform []struct {
		Types   []string `json:"types"`
		Classes []string `json:"classes"`
	} `json:"terraform"`
	Fallback []string `json:"fallback"`
}

var opMap = func() opMapping {
	var m opMapping
	if err := json.Unmarshal(opclassJSON, &m); err != nil {
		panic("gate: opclass.json: " + err.Error())
	}
	return m
}()

// OperationalClassMapping is the version of the mapping the classes were computed with ("opclass/1").
func OperationalClassMapping() string { return opMap.Version }

// OperationalClasses computes the classes for c from what it stores (objects, subject, paths, reasons), sorted and
// without duplicates. It never returns an empty list: OpClassNone when nothing operational changed. A release stamp
// is a metadata field (objectTier's release-stamp rule), so a change of only stamps is OpClassNone. pol supplies the
// non-runtime paths and tag fields the tier rules use.
func OperationalClasses(c *Change, pol Policy) []string {
	got := map[string]bool{}
	add := func(cs []string) {
		for _, x := range cs {
			got[x] = true
		}
	}
	switch {
	case c.Subject != nil && c.Subject.Kind == KindDefinition:
		// An agent definition's release: any change in what the agent may do is a change of privilege. The reasons
		// carry review.Classify's changes, whose subject is "agent <name>: <field>". Provenance and tree notes, a
		// definition that would not load (DG-DEFINITION) and a loosening clearance.yaml (policy:loosens) are not
		// changes of authority: the definition never took effect.
		for _, r := range c.Reasons {
			if strings.HasPrefix(r.Subject, "agent ") && strings.Contains(r.Subject, ": ") {
				add([]string{ClassPrivilege})
			}
		}
	case c.Subject != nil && c.Subject.Kind == KindTerraformPlan:
		for _, r := range c.Subject.Resources {
			if !r.Changes() {
				continue
			}
			cs := typeClasses(r.Type)
			// A tag or description on a type that is only an availability concern (or unmapped) is no operational
			// change; on an IAM role, a key or a database it still is (a tag can drive access).
			if r.action() == "update" && tagOnly(r.Fields, pol.TFTagFields) && (len(cs) == 0 || slices.Equal(cs, []string{ClassAvailability})) {
				continue
			}
			add(orFallback(cs))
		}
	default:
		for _, ch := range c.Objects {
			if ch.Op == "unchanged" {
				continue
			}
			if ch.Op == "changed" && len(ch.Fields) > 0 && allMetadata(ch.Fields) {
				continue // a release stamp or metadata only: no change to the object
			}
			add(orFallback(opMap.Kinds[ch.Kind]))
			if ch.Op == "changed" {
				for _, f := range ch.Fields {
					for _, rule := range opMap.Fields {
						if strings.Contains(f, rule.Contains) {
							add(rule.Classes)
						}
					}
				}
			}
		}
	}
	for _, p := range c.Paths {
		if globs(p, pol.NonruntimePaths) {
			continue
		}
		for _, rule := range opMap.Paths {
			if globs(p, []string{rule.Glob}) {
				add(rule.Classes)
			}
		}
	}
	if len(got) == 0 {
		return []string{OpClassNone}
	}
	out := make([]string, 0, len(got))
	for x := range got {
		out = append(out, x)
	}
	slices.Sort(out)
	return out
}

func typeClasses(typ string) []string {
	var out []string
	for _, r := range opMap.Terraform {
		if globs(typ, r.Types) {
			for _, c := range r.Classes {
				if !slices.Contains(out, c) {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

func orFallback(cs []string) []string {
	if len(cs) == 0 {
		return opMap.Fallback
	}
	return cs
}

// stampClass puts c's operational classes and the mapping version on a record about c (the evidence schema's
// Decision group). A change registered before I-1 has none stored, so they are computed from what it stores, under pol.
func stampClass(ev map[string]any, c *Change, pol Policy) {
	classes, mapping := c.OperationalClasses, c.ClassMapping
	if len(classes) == 0 {
		classes, mapping = OperationalClasses(c, pol), OperationalClassMapping()
	}
	ev["operational_class"], ev["class_mapping"] = classes, mapping
}
