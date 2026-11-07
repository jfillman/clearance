// Package tfplan computes a terraform-plan subject (docs/gate.md, The terraform-plan subject) from a saved plan file
// and its `terraform show -json` output, locally. Nothing here is sent anywhere but the subject: the digests, the
// attribute names an update changes, and the counts. A variable's or an attribute's value is never in the result.
package tfplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/jfillman/clearance/internal/gate"
)

// Subject is the request's `subject` for a terraform-plan change (the wire shape of gate.Subject's request fields).
type Subject struct {
	Kind              string           `json:"kind"`
	PlanDigest        string           `json:"planDigest"`
	PlanJSONDigest    string           `json:"planJsonDigest"`
	Workspace         gate.Workspace   `json:"workspace"`
	Versions          gate.Versions    `json:"versions"`
	Summary           gate.PlanSummary `json:"summary"`
	Targeted          bool             `json:"targeted"`
	VariableSetDigest string           `json:"variableSetDigest"`
	Resources         []gate.Resource  `json:"resources"`
}

// Options are what the plan JSON does not say.
type Options struct {
	Workspace gate.Workspace
	Targeted  bool
	// Providers are the provider versions (source address to version), from the dependency lock file.
	Providers map[string]string
}

// Digest is "sha256:" and the hex sha256 of b.
func Digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func decode(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return nil, errors.New("the plan JSON is not a JSON object (terraform show -json <plan>)")
	}
	if _, ok := doc["resource_changes"]; !ok && doc["format_version"] == nil {
		return nil, errors.New("the plan JSON has no format_version or resource_changes (terraform show -json <plan>)")
	}
	return doc, nil
}

// Compute builds the subject from the saved plan file's bytes and the plan's JSON.
func Compute(planFile, planJSON []byte, o Options) (*Subject, error) {
	doc, err := decode(planJSON)
	if err != nil {
		return nil, err
	}
	s := &Subject{Kind: gate.KindTerraformPlan, PlanDigest: Digest(planFile), Workspace: o.Workspace, Targeted: o.Targeted,
		Resources: []gate.Resource{}}
	tf, _ := doc["terraform_version"].(string)
	provs := o.Providers
	if provs == nil {
		provs = map[string]string{}
	}
	s.Versions = gate.Versions{Terraform: tf, Providers: provs}
	rcs, _ := doc["resource_changes"].([]any)
	for _, raw := range rcs {
		rc, _ := raw.(map[string]any)
		ch, _ := rc["change"].(map[string]any)
		r := gate.Resource{Address: str(rc["address"]), Type: str(rc["type"]), ActionReason: str(rc["action_reason"])}
		for _, a := range asList(ch["actions"]) {
			r.Actions = append(r.Actions, str(a))
		}
		if r.Address == "" || r.Type == "" || len(r.Actions) == 0 {
			return nil, errors.New("a resource_changes entry has no address, type or change.actions")
		}
		if slices.Equal(r.Actions, []string{"update"}) {
			r.Fields = changedFields(ch)
		}
		s.Resources = append(s.Resources, r)
	}
	// The summary is what the resources say, by the core's own rule (gate checkSummary): no-op and read are not changes.
	for _, r := range s.Resources {
		if !r.Changes() {
			continue
		}
		switch {
		case len(r.Actions) == 2:
			s.Summary.Replace++
		case slices.Equal(r.Actions, []string{"delete"}):
			s.Summary.Destroy++
			s.Summary.DestroyedAddresses = append(s.Summary.DestroyedAddresses, r.Address)
		case r.Actions[0] == "create":
			s.Summary.Create++
		case r.Actions[0] == "update":
			s.Summary.Update++
		}
	}
	if s.PlanJSONDigest, err = redactedDigest(doc); err != nil {
		return nil, err
	}
	s.VariableSetDigest = variableSetDigest(doc)
	return s, nil
}

func str(v any) string { s, _ := v.(string); return s }

func asList(v any) []any { l, _ := v.([]any); return l }

// changedFields are the JSON pointers of the attributes an update changes: where before and after differ, or after
// is unknown until apply. Names only; a changed list or scalar is named at its own pointer.
func changedFields(ch map[string]any) []string {
	set := map[string]bool{}
	walkDiff("", ch["before"], ch["after"], ch["after_unknown"], set)
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	if len(out) > gate.MaxFields {
		// Too many to list: name the top-level attributes (the core takes any pointer; a prefix is a coarser claim).
		top := map[string]bool{}
		for _, p := range out {
			top["/"+strings.SplitN(p[1:], "/", 2)[0]] = true
		}
		out = out[:0]
		for p := range top {
			out = append(out, p)
		}
		sort.Strings(out)
		if len(out) > gate.MaxFields {
			out = out[:gate.MaxFields]
		}
	}
	return out
}

var pointerEscape = strings.NewReplacer("~", "~0", "/", "~1")

func walkDiff(path string, before, after, unknown any, set map[string]bool) {
	if u, ok := unknown.(bool); ok && u {
		set[path] = true
		return
	}
	bm, bok := before.(map[string]any)
	am, aok := after.(map[string]any)
	if bok && aok {
		um, _ := unknown.(map[string]any)
		keys := map[string]bool{}
		for k := range bm {
			keys[k] = true
		}
		for k := range am {
			keys[k] = true
		}
		for k := range um {
			keys[k] = true
		}
		for k := range keys {
			walkDiff(path+"/"+pointerEscape.Replace(k), bm[k], am[k], um[k], set)
		}
		return
	}
	if !reflect.DeepEqual(before, after) {
		if path == "" {
			path = "/"
		}
		set[path] = true
	}
}

// keepKeys are the plan JSON's structural keys whose whole subtree holds no value (names, types, actions, versions).
var keepKeys = map[string]bool{"format_version": true, "terraform_version": true, "address": true, "previous_address": true,
	"type": true, "mode": true, "name": true, "provider_name": true, "provider_config_key": true, "module_address": true,
	"actions": true, "action_reason": true, "replace_paths": true, "full_name": true, "version_constraint": true}

const redacted = "(redacted)"

// redact keeps a document's shape and structural keys and replaces every other scalar: the redacted plan JSON.
func redact(v any, keep bool) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = redact(e, keep || keepKeys[k])
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redact(e, keep)
		}
		return out
	default:
		if keep {
			return x
		}
		return redacted
	}
}

func canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil // map keys marshal sorted
}

// Redacted is the redacted plan JSON (canonical, keys sorted) that PlanJSONDigest is the sha256 of.
func Redacted(planJSON []byte) ([]byte, error) {
	doc, err := decode(planJSON)
	if err != nil {
		return nil, err
	}
	return canonical(redact(doc, false))
}

func redactedDigest(doc map[string]any) (string, error) {
	b, err := canonical(redact(doc, false))
	if err != nil {
		return "", err
	}
	return Digest(b), nil
}

// variableSetDigest is the sha256 of the sorted variables: a name with the sha256 of its JSON value, or a sensitive
// variable (configuration marks it) with only "sensitive". A secret's value never enters the digest, so a hash of
// it cannot be brute-forced out of the request; the saved plan's own digest covers a changed secret.
func variableSetDigest(doc map[string]any) string {
	sens := map[string]bool{}
	if cfg, ok := doc["configuration"].(map[string]any); ok {
		if rm, ok := cfg["root_module"].(map[string]any); ok {
			if vs, ok := rm["variables"].(map[string]any); ok {
				for name, d := range vs {
					if m, ok := d.(map[string]any); ok && m["sensitive"] == true {
						sens[name] = true
					}
				}
			}
		}
	}
	vars, _ := doc["variables"].(map[string]any)
	names := make([]string, 0, len(vars))
	for n := range vars {
		names = append(names, n)
	}
	sort.Strings(names)
	entries := make([][2]string, 0, len(names))
	for _, n := range names {
		if sens[n] {
			entries = append(entries, [2]string{n, "sensitive"})
			continue
		}
		m, _ := vars[n].(map[string]any)
		vb, _ := canonical(m["value"])
		entries = append(entries, [2]string{n, Digest(vb)})
	}
	b, _ := canonical(entries)
	return Digest(b)
}

var lockRx = regexp.MustCompile(`(?s)provider\s+"([^"]+)"\s*\{[^}]*?version\s*=\s*"([^"]+)"`)

// ProvidersFromLock reads provider versions from a .terraform.lock.hcl.
func ProvidersFromLock(lock []byte) map[string]string {
	out := map[string]string{}
	for _, m := range lockRx.FindAllStringSubmatch(string(lock), -1) {
		out[m[1]] = m[2]
	}
	return out
}

// Hex is a digest's bare hex ("" if it is not a sha256 digest).
func Hex(d string) string {
	h := strings.TrimPrefix(d, "sha256:")
	if len(h) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(h); err != nil {
		return ""
	}
	return h
}

// Describe is a one-line summary for logs: counts only.
func (s *Subject) Describe() string {
	return fmt.Sprintf("%d create, %d update, %d replace, %d destroy", s.Summary.Create, s.Summary.Update, s.Summary.Replace, s.Summary.Destroy)
}
